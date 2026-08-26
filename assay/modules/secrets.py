"""Secrets and internal detail leaked through client-side assets.

Front-end bundles are the most reliably productive place to look on a modern
target: they name internal API hosts, contain keys that were assumed to be
private, and often ship a source map that reconstructs the original source.
"""

from __future__ import annotations

import json
import re
from typing import Dict, List, Optional, Pattern, Tuple
from urllib.parse import urljoin, urlsplit

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register

# (label, severity, regex, why it matters)
SECRET_PATTERNS: List[Tuple[str, str, Pattern, str]] = [
    ("AWS access key id", "high",
     re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
     "An IAM key shipped to browsers. Confirm it is live with "
     "`aws sts get-caller-identity` and report the identity only - do not "
     "enumerate the account."),
    ("Google API key", "medium",
     re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
     "Often restricted by referrer and therefore low impact; check whether it is "
     "unrestricted (billable abuse) before reporting."),
    ("Slack token", "high",
     re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
     "A live Slack token reads and posts to the workspace - direct internal access."),
    ("Stripe live secret key", "critical",
     re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
     "A live Stripe secret key permits charges and refunds against the merchant "
     "account. Do not exercise it; report on discovery."),
    ("GitHub token", "high",
     re.compile(r"\b(?:ghp|gho|ghu|ghs|github_pat)_[A-Za-z0-9_]{20,}\b"),
     "Repository access, frequently including private source."),
    ("Private key material", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
     "A private key in a client-side asset is unconditionally reportable."),
    ("SendGrid API key", "high",
     re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
     "Permits sending mail as the organisation - a strong phishing primitive."),
    ("Firebase database URL", "low",
     re.compile(r"https://[a-z0-9-]+\.firebaseio\.com"),
     "Check whether the database allows unauthenticated reads by appending /.json."),
    ("Cloud storage bucket URL", "low",
     re.compile(r"https?://(?:[a-z0-9.-]+\.s3[a-z0-9.-]*\.amazonaws\.com|"
                r"s3[a-z0-9.-]*\.amazonaws\.com/[a-z0-9._-]{3,63}|"
                r"storage\.googleapis\.com/[a-z0-9._-]{3,63}|"
                r"[a-z0-9-]+\.blob\.core\.windows\.net|"
                r"[a-z0-9-]+\.[a-z0-9-]+\.digitaloceanspaces\.com)", re.I),
     "A cloud storage bucket referenced from client-side code. Check whether it "
     "permits anonymous listing or reads - a public bucket is a direct data "
     "exposure, and a public-writable one is a defacement or malware-hosting "
     "primitive."),
    ("Hardcoded bearer token", "medium",
     re.compile(r"['\"]Bearer\s+[A-Za-z0-9._-]{24,}['\"]"),
     "A static bearer token in shipped JavaScript is usable by anyone who reads it."),
]

# Hosts referenced from JS that are not public. Worth surfacing as scope leads.
INTERNAL_HOST_RE = re.compile(
    r"https?://(?:"
    r"(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|[A-Za-z0-9-]+\.(?:internal|local|corp|intra|intranet|test|dev|staging|qa)"
    r"(?:\.[A-Za-z0-9.-]+)?"
    r")(?::\d+)?[^\s\"'`<>]*",
    re.I,
)

SCRIPT_RE = re.compile(r"""<script[^>]+src=["']?([^"'\s>]+)""", re.I)
SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s*]+)")


@register
class SecretsModule(Module):
    name = "secrets"
    stage = "analyze"
    scope = "web"
    impact_class = "read"
    desc = "Credentials, internal hosts and source maps in client-side assets"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        base = wt.final_url or wt.url
        scripts = self._script_urls(ctx, wt, base)
        out: List[Finding] = []
        seen_secret: set = set()

        budget = 6 if ctx.cfg.profile == "quick" else (
            15 if ctx.cfg.profile == "standard" else 40)

        for url in scripts[:budget]:
            r = ctx.http.get(url)
            if not r.ok or r.status != 200 or len(r.body) < 32:
                continue
            body = r.body[:600000]

            for label, sev, rx, why in SECRET_PATTERNS:
                m = rx.search(body)
                if not m:
                    continue
                token = m.group(0)
                if token in seen_secret:
                    continue
                seen_secret.add(token)
                out.append(Finding(
                    title="%s exposed in client-side asset" % label,
                    target=url,
                    severity=sev,
                    confidence="firm",
                    category=owasp.A05,
                    cwe="CWE-798",
                    module=self.name,
                    impact=why,
                    detail="Matched in %s" % urlsplit(url).path,
                    repro="curl -sSk %s | grep -Eo '%s'" % (url, rx.pattern[:60]),
                    tags=["secrets", "manual-followup"],
                    evidence=[Evidence(kind="http", label="Asset excerpt",
                                       output=self._context(body, m.start()),
                                       matched=token[:16] + "...")],
                    dedupe_key="secret|%s|%s" % (label, token[:24]),
                ))

            hosts = {h.rstrip(".,);") for h in INTERNAL_HOST_RE.findall(body)}
            if hosts:
                out.append(Finding(
                    title="Internal hosts referenced from client-side JavaScript",
                    target=url,
                    severity="info",
                    confidence="firm",
                    category=owasp.INFO,
                    cwe="CWE-200",
                    module=self.name,
                    impact=(
                        "Not a finding by itself. These are names and addresses the "
                        "application expects to reach; if any is reachable from your "
                        "testing position it is unintended surface, and they make good "
                        "SSRF targets when an SSRF primitive turns up elsewhere."
                    ),
                    repro="curl -sSk %s | grep -Eo 'https?://[^\"'\\'']+'" % url,
                    tags=["recon", "chain"],
                    chainable=True,
                    evidence=[Evidence(kind="http", label="Internal references",
                                       output="\n".join(sorted(hosts)[:25]))],
                    dedupe_key="internalhosts|%s" % url,
                ))

            sm = SOURCEMAP_RE.search(body[-4000:]) or SOURCEMAP_RE.search(body)
            if sm:
                f = self._sourcemap(ctx, url, sm.group(1), out)
                if f:
                    out.append(f)
        return out

    def _script_urls(self, ctx: Context, wt: WebTarget, base: str) -> List[str]:
        urls: List[str] = []
        r = ctx.http.get(base)
        if r.ok:
            for src in SCRIPT_RE.findall(r.body[:400000]):
                if src.startswith("data:"):
                    continue
                full = urljoin(r.url, src)
                if full not in urls:
                    urls.append(full)
        origin = re.sub(r"(https?://[^/]+).*", r"\1", base)
        for u in ctx.urls.get(origin, []):
            if u.split("?")[0].endswith(".js") and u not in urls:
                urls.append(u)
        return urls

    def _scan_map_sources(self, ctx: Context, url: str, body: str,
                          out: List[Finding]) -> None:
        """Run the secret patterns over sourcesContent inside a source map."""
        try:
            doc = json.loads(body)
        except ValueError:
            return
        contents = doc.get("sourcesContent") or []
        names = doc.get("sources") or []
        for i, source in enumerate(contents[:60]):
            if not isinstance(source, str) or len(source) < 16:
                continue
            for label, sev, rx, why in SECRET_PATTERNS:
                m = rx.search(source[:200000])
                if not m:
                    continue
                token = m.group(0)
                name = names[i] if i < len(names) else "(unknown)"
                out.append(Finding(
                    title="%s exposed in source map original source" % label,
                    target=url,
                    severity=sev,
                    confidence="firm",
                    category=owasp.A05,
                    cwe="CWE-798",
                    module=self.name,
                    impact="%s Found in the pre-minification source embedded in "
                           "the map (%s), which retains literals and comments the "
                           "shipped bundle no longer shows." % (why, name),
                    detail="sourcesContent entry: %s" % name,
                    repro="curl -sSk %s | jq -r '.sourcesContent[%d]'" % (url, i),
                    tags=["secrets", "sourcemap", "manual-followup"],
                    evidence=[Evidence(kind="http",
                                       label="Original source: %s" % name,
                                       output=self._context(source, m.start()),
                                       matched=token[:16] + "...")],
                    dedupe_key="mapsecret|%s|%s" % (label, token[:24]),
                ))
                break

    def _sourcemap(self, ctx: Context, script_url: str, ref: str,
                   out_findings: List[Finding]) -> Optional[Finding]:
        if ref.startswith("data:"):
            return None
        url = urljoin(script_url, ref)
        r = ctx.http.get(url)
        if not r.ok or r.status != 200:
            return None
        if '"sources"' not in r.body[:4000]:
            return None
        has_content = '"sourcesContent"' in r.body[:20000]
        srcs = re.findall(r'"([^"]+\.(?:ts|tsx|jsx|vue|js))"', r.body[:40000])

        # The original sources embedded in the map are pre-minification, so
        # they carry comments and literals the bundle no longer shows. Secrets
        # that were stripped from the shipped file often survive here.
        if has_content:
            self._scan_map_sources(ctx, url, r.body, out_findings)
        return Finding(
            title="JavaScript source map published in production",
            target=url,
            severity="low" if not has_content else "medium",
            confidence="confirmed",
            category=owasp.A05,
            cwe="CWE-540",
            module=self.name,
            impact=(
                "The source map %s, which reconstructs the original front-end source: "
                "internal route names, feature flags, admin-only components and commented "
                "code. Read it for endpoints the UI never calls, then test those for "
                "missing authorization - that is where the reportable bug usually is."
                % ("embeds the original sources verbatim" if has_content
                   else "lists the original source files")
            ),
            repro="curl -sSk %s | head -c 400" % url,
            tags=["secrets", "verified", "manual-followup"],
            chainable=True,
            evidence=[Evidence(kind="http", label="Source map",
                               output="sourcesContent present: %s\n%s"
                                      % (has_content, "\n".join(srcs[:25])))],
            dedupe_key="sourcemap|%s" % url,
        )

    @staticmethod
    def _context(body: str, pos: int, width: int = 90) -> str:
        start = max(0, pos - width)
        return body[start:pos + width].replace("\n", " ")
