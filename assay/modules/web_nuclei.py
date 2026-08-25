"""Bridge nuclei's template results into assay findings.

nuclei supplies volume; this module supplies the filter. Templates whose job is
fingerprinting rather than finding bugs are dropped, results duplicating a
native assay check are dropped, and everything that survives is re-scored on
assay's own scale so a nuclei 'high' cannot outrank a locally verified critical.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from assay import owasp, tools
from assay.context import Context
from assay.models import Evidence, Finding
from assay.modules import Module, register

# Template ids / prefixes that describe the stack rather than a weakness, or
# that assay already covers natively with better evidence.
DROP_IDS = {
    "tech-detect", "waf-detect", "favicon-detect", "robots-txt", "robots-txt-endpoint",
    "metatags-cms", "options-method", "http-missing-security-headers",
    "ssl-issuer", "ssl-dns-names", "tls-version", "weak-cipher-suites",
    "self-signed-ssl", "expired-ssl", "mismatched-ssl-certificate",
    "deprecated-tls", "revoked-ssl-certificate", "untrusted-root-certificate",
    "wordpress-detect", "nginx-version", "apache-detect", "openssh-detect",
    "waf-fingerprint", "dns-saas-service-detection", "caa-fingerprint",
    "http-trace", "cookies-without-httponly", "cookies-without-secure",
    "xss-fuzz", "dir-listing",
}
DROP_PREFIXES = ("tech/", "detect-", "fingerprint", "screenshot")
DROP_TAGS = {"tech", "detect", "fingerprint", "favicon", "osint"}

SEV_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info", "unknown": "info",
}

# nuclei tag -> OWASP bucket, best effort.
TAG_CATEGORY = [
    (("rce", "injection", "sqli", "ssti", "xxe", "cmdi", "deserialization"), owasp.A03),
    (("ssrf",), owasp.A10),
    (("lfi", "traversal", "idor", "auth-bypass", "unauth"), owasp.A01),
    (("exposure", "disclosure", "files", "config", "debug", "logs"), owasp.A05),
    (("cve", "wordpress", "joomla", "drupal", "struts", "confluence"), owasp.A06),
    (("default-login", "weak-password", "brute-force"), owasp.A07),
    (("xss",), owasp.A03),
    (("ssl", "tls", "crypto"), owasp.A02),
]


@register
class NucleiModule(Module):
    name = "nuclei"
    stage = "external"
    scope = "global"
    desc = "Community template scanning (CVEs, misconfigurations, default logins)"

    def applicable(self, ctx: Context) -> bool:
        if not Module.applicable(self, ctx):
            return False
        return bool(ctx.cfg.opts.get("nuclei")) and ctx.has("nuclei")

    def run_global(self, ctx: Context) -> List[Finding]:
        urls = [w.final_url or w.url for w in ctx.web]
        if not urls:
            return []
        sev = ctx.cfg.opts.get("nuclei_severity", "critical,high,medium")
        ctx.say("nuclei", "scanning %d endpoint(s) at severity %s" % (len(urls), sev))

        out: List[Finding] = []
        kept = dropped = 0
        headers: Dict[str, str] = {}
        auth = ctx.cfg.auth_header()
        if auth:
            headers["Authorization"] = auth
        headers.update(ctx.cfg.headers)
        for obj in tools.nuclei_scan(urls, sev, ctx.tune, proxy=ctx.cfg.burp.proxy,
                                     headers=headers or None):
            f = self._convert(obj)
            if f is None:
                dropped += 1
                continue
            kept += 1
            ctx.emit(f)
            out.append(f)
            if kept % 10 == 0:
                ctx.say("nuclei", "%d kept / %d filtered" % (kept, dropped))
        ctx.say("nuclei", "done: %d kept, %d filtered as fingerprinting/duplicate"
                % (kept, dropped))
        return out

    # ------------------------------------------------------------------
    def _convert(self, obj: Dict) -> Optional[Finding]:
        tid = (obj.get("template-id") or "").lower()
        info = obj.get("info") or {}
        tags = [t.lower() for t in (info.get("tags") or [])]

        if tid in DROP_IDS or any(tid.startswith(p) for p in DROP_PREFIXES):
            return None
        if tags and set(tags) & DROP_TAGS and not (set(tags) & {"cve", "exposure"}):
            return None

        severity = SEV_MAP.get((info.get("severity") or "info").lower(), "info")
        if severity == "info" and not (set(tags) & {"exposure", "config", "disclosure"}):
            return None

        matched = obj.get("matched-at") or obj.get("host") or ""
        name = info.get("name") or tid
        desc = " ".join((info.get("description") or "").split())
        extracted = obj.get("extracted-results") or []

        ev = Evidence(
            kind="http",
            label="nuclei %s" % tid,
            request=(obj.get("request") or "")[:1200],
            response=(obj.get("response") or "")[:1200],
            matched=", ".join(str(x) for x in extracted[:5])[:300],
        )
        if not (ev.request or ev.response or ev.matched):
            ev.output = "matched-at: %s" % matched

        cve = next((t.upper() for t in tags if t.startswith("cve-")), "")
        refs = list(info.get("reference") or [])[:5]

        return Finding(
            title=name,
            target=matched,
            severity=severity,
            confidence="firm",
            category=self._category(tags),
            cwe=self._cwe(info),
            module=self.name,
            impact=self._impact(severity, name, desc, cve),
            detail=(desc or "")[:600],
            repro="nuclei -id %s -u %s -irr" % (tid, matched),
            refs=refs,
            tags=["nuclei"] + tags[:6],
            evidence=[ev],
            dedupe_key="nuclei|%s|%s" % (tid, matched),
        )

    @staticmethod
    def _category(tags: List[str]) -> str:
        for needles, cat in TAG_CATEGORY:
            if set(tags) & set(needles):
                return cat
        return owasp.A05

    @staticmethod
    def _cwe(info: Dict) -> str:
        classification = info.get("classification") or {}
        cwes = classification.get("cwe-id") or []
        if isinstance(cwes, str):
            cwes = [cwes]
        return ", ".join(str(c).upper() for c in cwes[:2])

    @staticmethod
    def _impact(severity: str, name: str, desc: str, cve: str) -> str:
        if cve:
            return (
                "Template matched %s. Confirm the version is genuinely affected before "
                "reporting - version-inference templates are the main source of "
                "duplicate and N/A submissions. If it is exploitable, demonstrate the "
                "primitive rather than citing the CVE." % cve
            )
        if severity in ("critical", "high"):
            return (
                "%s Verify the match by hand and capture the request/response that "
                "demonstrates the impact; a template match is a lead, and the report "
                "needs the proof." % (desc[:220] or name)
            )
        return (
            "%s Likely only reportable if it can be chained or if the affected data is "
            "genuinely sensitive." % (desc[:220] or name)
        )
