"""Unauthenticated AI/ML infrastructure.

Ollama, vLLM, Gradio, Ray, MLflow and the common vector databases all ship with
no authentication, and the standard deployment advice tells people to bind them
to 0.0.0.0. The result is a class of exposure that is both very common and
genuinely impactful, and it is young enough that it is often outside the
patching and inventory processes that cover everything else on the network.

Every probe is a read-only GET or a protocol handshake. Nothing here uploads a
model, submits a job, or runs an inference: reachability plus the service's own
identification is the finding, and exercising it would cost the client compute
or change their state.
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

import yaml

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, Port, Target
from assay.modules import Module, register

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

_SERVICES: Optional[List[dict]] = None


def load_services() -> List[dict]:
    global _SERVICES
    if _SERVICES is None:
        with open(os.path.join(DATA, "ai_surface.yaml"), "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        svcs = doc.get("services", [])
        for s in svcs:
            s["_re"] = re.compile(s["match"], re.I | re.M)
            if s.get("sibling_match"):
                s["_sib"] = re.compile(s["sibling_match"], re.I)
            if s.get("version_match"):
                s["_ver"] = re.compile(s["version_match"], re.I)
        _SERVICES = svcs
    return _SERVICES


def version_below(found: str, floor: str) -> bool:
    """Compare dotted versions without assuming equal length."""
    def parts(v: str) -> List[int]:
        return [int(x) for x in re.findall(r"\d+", v)] or [0]
    a, b = parts(found), parts(floor)
    a += [0] * (len(b) - len(a))
    b += [0] * (len(a) - len(b))
    return a < b


@register
class AiSurfaceModule(Module):
    name = "aisurface"
    stage = "analyze"
    scope = "host"
    impact_class = "read"
    desc = "Unauthenticated LLM, vector database and ML platform endpoints"

    # Tried directly in deeper profiles even when a port scan did not run.
    WELL_KNOWN = [11434, 8265, 6333, 7860, 5000, 8081, 9091]

    def run_host(self, ctx: Context, target: Target) -> List[Finding]:
        host = target.ip or target.host
        open_ports = {p.port for p in target.ports if p.proto == "tcp"}
        if not open_ports and ctx.cfg.profile == "deep":
            open_ports = set(self.WELL_KNOWN)
        if not open_ports:
            return []

        out: List[Finding] = []
        seen: set = set()
        for svc in load_services():
            for port in svc["ports"]:
                if port not in open_ports or (svc["name"], port) in seen:
                    continue
                f = self._probe(ctx, host, port, svc)
                if f:
                    seen.add((svc["name"], port))
                    out.append(f)
                    break          # one hit per service is enough
        return out

    # ------------------------------------------------------------------
    def _probe(self, ctx: Context, host: str, port: int,
               svc: dict) -> Optional[Finding]:
        for scheme in ("http", "https"):
            base = "%s://%s:%d" % (scheme, host, port)
            r = ctx.http.get(base + svc["path"])
            if not r.ok or r.status not in (svc.get("status") or [200]):
                continue
            if not svc["_re"].search(r.body[:40000]):
                continue

            # Some services share a port with unrelated software; a second
            # endpoint disambiguates before we name the product.
            if svc.get("require_sibling"):
                sr = ctx.http.get(base + svc["require_sibling"])
                if not (sr.ok and svc.get("_sib")
                        and svc["_sib"].search(sr.body[:20000])):
                    continue

            evidence = [r.evidence(label="Unauthenticated %s response" % svc["path"],
                                   matched=svc["match"][:80], body_limit=600)]
            severity = svc.get("severity", "medium")
            cve_note = ""

            # Version check, where the service reports one and a known
            # unauthenticated CVE has a floor.
            if svc.get("version_path") and svc.get("vulnerable_below"):
                vr = ctx.http.get(base + svc["version_path"])
                if vr.ok and svc.get("_ver"):
                    m = svc["_ver"].search(vr.body[:4000])
                    if m and version_below(m.group(1), svc["vulnerable_below"]):
                        severity = "critical"
                        cve_note = (
                            " This instance reports version %s, below the %s that "
                            "fixed %s - an unauthenticated heap disclosure that "
                            "returns system prompts, chat history and process "
                            "environment variables including API keys and database "
                            "credentials. Do not exploit it; the version and the "
                            "open port are the finding."
                            % (m.group(1), svc["vulnerable_below"], svc["cve"]))
                        evidence.append(vr.evidence(
                            label="Version %s (fixed in %s)"
                                  % (m.group(1), svc["vulnerable_below"]),
                            matched=m.group(1)))

            step = (svc.get("step") or "").replace("{host}", host).replace(
                "{port}", str(port))
            return Finding(
                title=svc["name"],
                target="%s:%d" % (host, port),
                severity=severity,
                confidence="confirmed",
                category=owasp.HOST,
                cwe=svc.get("cwe", "CWE-306"),
                module=self.name,
                impact=" ".join((svc.get("impact") or "").split()) + cve_note,
                detail="CIA impact: %s. Matched %s on %s."
                       % (svc.get("cia", "-"), svc["path"], base),
                repro=step,
                refs=svc.get("refs", []) or [],
                tags=["ai", "host", "verified", "unauth"] +
                     ([svc["cve"].lower()] if cve_note and svc.get("cve") else []),
                chainable=True,
                evidence=evidence,
                dedupe_key="ai|%s|%s|%d" % (svc["name"], host, port),
            )
        return None


@register
class McpModule(Module):
    name = "mcp"
    stage = "analyze"
    scope = "host"
    impact_class = "read"
    desc = "Unauthenticated Model Context Protocol servers"

    # MCP over HTTP is usually mounted at one of these.
    PATHS = ["/mcp", "/sse", "/messages", "/rpc", "/api/mcp"]
    PORTS = [3000, 3001, 5173, 8000, 8080, 8081, 8765, 9000]

    # A protocol handshake, not a tool call. Nothing is executed.
    INIT = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18",
                   "capabilities": {},
                   "clientInfo": {"name": "assay", "version": "1.0"}},
    })

    def run_host(self, ctx: Context, target: Target) -> List[Finding]:
        host = target.ip or target.host
        open_ports = {p.port for p in target.ports if p.proto == "tcp"}
        ports = [p for p in self.PORTS if p in open_ports]
        if not ports:
            return []

        for port in ports:
            for path in self.PATHS:
                url = "http://%s:%d%s" % (host, port, path)
                r = ctx.http.post(url, data=self.INIT, headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream"})
                if not r.ok:
                    continue
                body = r.body[:20000]
                if '"serverInfo"' not in body and '"protocolVersion"' not in body:
                    continue

                name = re.search(r'"name"\s*:\s*"([^"]{1,60})"', body)
                caps = sorted(set(re.findall(
                    r'"(tools|resources|prompts|logging|sampling)"\s*:', body)))
                return [Finding(
                    title="Model Context Protocol server exposed without authentication",
                    target="%s:%d%s" % (host, port, path),
                    severity="critical",
                    confidence="confirmed",
                    category=owasp.HOST,
                    cwe="CWE-306",
                    module=self.name,
                    impact=(
                        "An MCP server completed a protocol handshake with an "
                        "unauthenticated client%s. MCP servers exist to give a model "
                        "real capabilities, so whatever this one wraps - filesystem, "
                        "shell, database, cloud API - is now callable directly by "
                        "anyone who can reach the port, with the server's own "
                        "credentials. Enumerate tools/list to establish what it can "
                        "reach and stop there; calling a tool executes it for real."
                        % (" advertising %s" % ", ".join(caps) if caps else "")
                    ),
                    detail="Server: %s. Capabilities: %s."
                           % (name.group(1) if name else "unnamed",
                              ", ".join(caps) or "not advertised"),
                    repro=("curl -sS -X POST %s -H 'Content-Type: application/json' "
                           "--data '%s'" % (url, self.INIT)),
                    refs=["https://modelcontextprotocol.io/specification"],
                    tags=["ai", "mcp", "host", "verified", "unauth"],
                    chainable=True,
                    evidence=[r.evidence(label="MCP initialize handshake succeeded",
                                         matched="serverInfo", body_limit=700)],
                    dedupe_key="mcp|%s|%d" % (host, port),
                )]
        return []
