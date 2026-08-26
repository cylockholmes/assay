"""Deep unauthenticated host analysis via nmap's NSE library.

The service module answers "what is listening". This one answers "does it let
me in". Every rule requires the script output to actually contain the condition
- nmap runs a script against every candidate port regardless of whether the
condition holds, so presence of output proves nothing on its own.

UDP services are scanned separately and only in the deeper profiles, because a
UDP scan is slow and noisy enough that it should be a deliberate choice.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

import yaml

from assay import owasp, tools
from assay.context import Context
from assay.models import Evidence, Finding, Target
from assay.modules import Module, register

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

_RULES: Optional[List[dict]] = None


def load_rules() -> List[dict]:
    global _RULES
    if _RULES is None:
        with open(os.path.join(DATA, "nse.yaml"), "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        rules = doc.get("rules", [])
        for r in rules:
            r["_re"] = re.compile(r["match"], re.I | re.M)
        _RULES = rules
    return _RULES


@register
class HostDeepModule(Module):
    name = "hostdeep"
    stage = "analyze"
    scope = "host"
    impact_class = "probe"
    desc = "Unauthenticated service checks: anonymous access, null sessions, weak auth"

    def applicable(self, ctx: Context) -> bool:
        if not Module.applicable(self, ctx):
            return False
        return ctx.has("nmap")

    def run_host(self, ctx: Context, target: Target) -> List[Finding]:
        host = target.ip or target.host
        open_ports = {p.port for p in target.ports if p.proto == "tcp"}
        if not open_ports:
            return []

        rules = load_rules()
        tcp_rules = [r for r in rules if not r.get("udp")]
        udp_rules = [r for r in rules if r.get("udp")]

        out: List[Finding] = []
        out += self._sweep(ctx, target, host, tcp_rules, open_ports, udp=False)

        # UDP is slow; only worth it when the profile has already opted into depth.
        if ctx.cfg.profile == "deep":
            udp_ports = {p for r in udp_rules for p in r["ports"]}
            out += self._sweep(ctx, target, host, udp_rules, udp_ports, udp=True)
        return out

    # ------------------------------------------------------------------
    def _sweep(self, ctx: Context, target: Target, host: str, rules: List[dict],
               candidate_ports: set, udp: bool) -> List[Finding]:
        # Only run scripts whose port is actually open (or, for UDP, plausible).
        applicable: List[dict] = []
        for r in rules:
            if candidate_ports & set(r["ports"]):
                applicable.append(r)
        if not applicable:
            return []

        ports = sorted({p for r in applicable for p in r["ports"]}
                       & candidate_ports) if not udp else sorted(
                           {p for r in applicable for p in r["ports"]})
        scripts = sorted({r["script"] for r in applicable})
        ctx.say("hostdeep", "%s: %d %s script(s) on %d port(s)"
                % (host, len(scripts), "UDP" if udp else "TCP", len(ports)))

        results = tools.nmap_script_scan(host, ports, scripts, ctx.cfg.out_dir,
                                         udp=udp)
        if not results:
            return []

        out: List[Finding] = []
        for rule in applicable:
            for port, scripts_out in results.items():
                output = scripts_out.get(rule["script"])
                if not output:
                    continue
                m = rule["_re"].search(output)
                if not m:
                    continue
                out.append(self._finding(rule, host, port, output, m.group(0)))
        return out

    @staticmethod
    def _finding(rule: dict, host: str, port: int, output: str,
                 matched: str) -> Finding:
        where = "%s:%d" % (host, port) if port else host
        step = (rule.get("step") or "").replace("{host}", host).replace(
            "PORT", str(port))
        return Finding(
            title=rule["name"],
            target=where,
            severity=rule.get("severity", "medium"),
            # NSE output is a direct observation of the service's own answer.
            confidence="confirmed",
            category=owasp.INFO if rule.get("severity") == "info" else owasp.HOST,
            cwe=rule.get("cwe", ""),
            module="hostdeep",
            impact=" ".join((rule.get("impact") or "").split()),
            detail="nmap --script %s matched: %s" % (rule["script"], matched[:120]),
            repro=step,
            tags=["host", "nse", "verified"] +
                 (["noise-prone"] if rule.get("severity") == "info" else []),
            evidence=[Evidence(kind="command",
                               label="nmap NSE: %s" % rule["script"],
                               request="nmap -p%d --script %s %s"
                                       % (port, rule["script"], host),
                               output=output[:1200],
                               matched=matched[:180])],
            dedupe_key="nse|%s|%s|%d" % (rule["script"], host, port),
        )
