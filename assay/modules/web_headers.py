"""Transport, header, cookie and CORS analysis.

Bias: header hygiene alone is not a bug bounty finding, so all of it collapses
into a single low-noise summary row. CORS, on the other hand, is verified hard
because a reflected-origin + credentials combination is directly reportable.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register
from assay.net import rand_token

SENSITIVE_JSON = re.compile(
    r'"(?:email|e_mail|username|user_name|token|access_token|api_key|apikey|'
    r'secret|password|ssn|phone|first_name|last_name|address|balance|account)"\s*:',
    re.I,
)

SESSION_COOKIE = re.compile(
    r"(sess|sid|auth|token|jwt|login|remember|csrf|xsrf|asp\.net|jsessionid|phpsessid)",
    re.I,
)


@register
class CorsModule(Module):
    name = "cors"
    stage = "active"
    scope = "web"
    impact_class = "probe"
    desc = "Cross-origin resource sharing trust boundaries"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        url = wt.final_url or wt.url
        out: List[Finding] = []

        base = ctx.http.get(url)
        if not base.ok:
            return out

        evil = "https://assay-%s.example.net" % rand_token(8)
        r = ctx.http.get(url, headers={"Origin": evil})
        if not r.ok:
            return out

        acao = r.header("Access-Control-Allow-Origin")
        acac = r.header("Access-Control-Allow-Credentials").strip().lower() == "true"
        if not acao:
            out.extend(self._null_origin(ctx, url))
            out.extend(self._sibling_trust(ctx, url, wt))
            return out

        reflected = acao.strip() == evil

        if reflected and acac:
            # Re-confirm with a second, different origin so a cached or static
            # header cannot masquerade as reflection.
            evil2 = "https://assay-%s.example.net" % rand_token(8)
            r2 = ctx.http.get(url, headers={"Origin": evil2})
            confirmed = r2.ok and r2.header("Access-Control-Allow-Origin").strip() == evil2
            f = Finding(
                title="CORS reflects arbitrary Origin with credentials allowed",
                target=url,
                severity="high",
                confidence="confirmed" if confirmed else "firm",
                category=owasp.A01,
                cwe="CWE-942",
                module=self.name,
                impact=(
                    "Any website a victim visits can read this endpoint's authenticated "
                    "response cross-origin using the victim's session cookies, so the "
                    "response body is exfiltratable to an attacker-controlled origin."
                ),
                detail=(
                    "Access-Control-Allow-Origin echoes the request Origin verbatim while "
                    "Access-Control-Allow-Credentials is true. The two together defeat the "
                    "same-origin policy for this endpoint."
                ),
                repro=r.curl(),
                refs=["https://portswigger.net/web-security/cors",
                      "https://cwe.mitre.org/data/definitions/942.html"],
                tags=["cors", "verified" if confirmed else "single-observation"],
                chainable=True,
                evidence=[r.evidence(label="Origin reflected + credentials", matched=acao)],
                dedupe_key="cors-reflect|%s" % wt.origin,
            )
            if confirmed:
                f.evidence.append(r2.evidence(label="Second distinct Origin also reflected",
                                              matched=r2.header("Access-Control-Allow-Origin")))
            out.append(f)

        elif reflected and not acac:
            sev = "medium" if SENSITIVE_JSON.search(r.body[:8000]) else "low"
            out.append(Finding(
                title="CORS reflects arbitrary Origin (no credentials)",
                target=url,
                severity=sev,
                confidence="firm",
                category=owasp.A05,
                cwe="CWE-942",
                module=self.name,
                impact=(
                    "Any origin can read this response. Impact depends on the data: it is "
                    "reportable when the endpoint exposes data that is not otherwise public, "
                    "or when it sits behind an IP/network boundary a browser can pivot across."
                ),
                detail="ACAO echoes the Origin header but credentials are not permitted.",
                repro=r.curl(),
                tags=["cors", "needs-impact-review"],
                chainable=True,
                evidence=[r.evidence(label="Origin reflected", matched=acao)],
                dedupe_key="cors-reflect-nocreds|%s" % wt.origin,
            ))

        elif acao.strip() == "*" and SENSITIVE_JSON.search(r.body[:8000]):
            out.append(Finding(
                title="Wildcard CORS on an endpoint returning user-shaped data",
                target=url,
                severity="low",
                confidence="firm",
                category=owasp.A05,
                cwe="CWE-942",
                module=self.name,
                impact=(
                    "Any origin can read this endpoint. Because credentials are not sent "
                    "with a wildcard ACAO, this only matters if the data is sensitive but "
                    "unauthenticated, or the host is network-restricted."
                ),
                repro=r.curl(),
                tags=["cors", "needs-impact-review"],
                evidence=[r.evidence(label="Wildcard ACAO", matched=acao)],
                dedupe_key="cors-wildcard|%s" % wt.origin,
            ))

        out.extend(self._null_origin(ctx, url))
        out.extend(self._sibling_trust(ctx, url, wt))
        return out

    def _null_origin(self, ctx: Context, url: str) -> List[Finding]:
        r = ctx.http.get(url, headers={"Origin": "null"})
        if not r.ok:
            return []
        acao = r.header("Access-Control-Allow-Origin").strip()
        acac = r.header("Access-Control-Allow-Credentials").strip().lower() == "true"
        if acao == "null" and acac:
            return [Finding(
                title="CORS trusts the null origin with credentials",
                target=url,
                severity="high",
                confidence="confirmed",
                category=owasp.A01,
                cwe="CWE-942",
                module=self.name,
                impact=(
                    "A sandboxed iframe or a data:/file: document sends Origin: null. An "
                    "attacker embeds such a frame on any page and reads this endpoint's "
                    "authenticated response."
                ),
                detail="Trivially reachable: <iframe sandbox=\"allow-scripts\" srcdoc=\"...fetch...\">",
                repro=r.curl(),
                tags=["cors", "verified"],
                chainable=True,
                evidence=[r.evidence(label="null Origin accepted with credentials", matched=acao)],
                dedupe_key="cors-null|%s" % url,
            )]
        return []

    def _sibling_trust(self, ctx: Context, url: str, wt: WebTarget) -> List[Finding]:
        """Does the app trust *any* subdomain of its own registrable domain?"""
        host = urlsplit(url).hostname or ""
        parts = host.split(".")
        if len(parts) < 2 or wt.host.replace(".", "").isdigit():
            return []
        apex = ".".join(parts[-2:])
        probe = "https://assay%s.%s" % (rand_token(6), apex)
        r = ctx.http.get(url, headers={"Origin": probe})
        if not r.ok:
            return []
        acao = r.header("Access-Control-Allow-Origin").strip()
        acac = r.header("Access-Control-Allow-Credentials").strip().lower() == "true"
        if acao == probe and acac:
            return [Finding(
                title="CORS trusts any subdomain of the parent domain",
                target=url,
                severity="medium",
                confidence="confirmed",
                category=owasp.A01,
                cwe="CWE-942",
                module=self.name,
                impact=(
                    "A single XSS or a dangling/takeoverable subdomain anywhere under %s "
                    "becomes full authenticated read access to this endpoint. Pair it with "
                    "any subdomain takeover to escalate to high." % apex
                ),
                repro=r.curl(),
                tags=["cors", "verified", "chain"],
                chainable=True,
                evidence=[r.evidence(label="Non-existent sibling subdomain accepted",
                                     matched=acao)],
                dedupe_key="cors-sibling|%s" % wt.origin,
            )]
        return []


@register
class CookieModule(Module):
    name = "cookies"
    stage = "analyze"
    scope = "web"
    impact_class = "read"
    desc = "Session cookie attributes"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        raw = wt.headers.get("Set-Cookie") or wt.headers.get("set-cookie") or ""
        if not raw:
            return []
        problems: List[str] = []
        for chunk in re.split(r",\s*(?=[A-Za-z0-9_\-]+=)", raw):
            name = chunk.split("=", 1)[0].strip()
            low = chunk.lower()
            if not SESSION_COOKIE.search(name):
                continue
            missing = []
            if wt.scheme == "https" and "secure" not in low:
                missing.append("Secure")
            if "httponly" not in low:
                missing.append("HttpOnly")
            if "samesite" not in low:
                missing.append("SameSite")
            if missing:
                problems.append("%s: missing %s" % (name, ", ".join(missing)))

        if not problems:
            return []
        no_httponly = any("HttpOnly" in p for p in problems)
        return [Finding(
            title="Session cookie missing protective attributes",
            target=wt.url,
            severity="low",
            confidence="firm",
            category=owasp.A05,
            cwe="CWE-1004",
            module=self.name,
            impact=(
                "A session cookie readable from JavaScript turns any XSS on this origin "
                "into full account takeover instead of a scoped action."
                if no_httponly else
                "Missing SameSite/Secure widens CSRF and network-attacker exposure for the "
                "session cookie."
            ),
            detail="; ".join(problems),
            repro="curl -sSik %s | grep -i set-cookie" % wt.url,
            tags=["cookies", "chain"],
            chainable=True,
            evidence=[Evidence(kind="http", label="Set-Cookie", output=raw[:600])],
            dedupe_key="cookie-attrs|%s" % wt.origin,
        )]


@register
class HeaderHygieneModule(Module):
    name = "headers"
    stage = "analyze"
    scope = "web"
    impact_class = "read"
    desc = "Security header baseline (single consolidated row)"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        if "html" not in (wt.content_type or ""):
            return []
        h = {k.lower(): v for k, v in wt.headers.items()}
        missing = []
        if wt.scheme == "https" and "strict-transport-security" not in h:
            missing.append("Strict-Transport-Security")
        if "content-security-policy" not in h:
            missing.append("Content-Security-Policy")
        if "x-content-type-options" not in h:
            missing.append("X-Content-Type-Options")
        if "x-frame-options" not in h and "content-security-policy" not in h:
            missing.append("X-Frame-Options / frame-ancestors")
        if not missing:
            return []
        return [Finding(
            title="Security headers absent",
            target=wt.url,
            severity="info",
            confidence="firm",
            category=owasp.A05,
            cwe="CWE-693",
            module=self.name,
            impact=(
                "Not independently reportable on most programs. Recorded because it removes "
                "the mitigations that would otherwise downgrade an XSS or clickjacking "
                "finding on this origin."
            ),
            detail="Missing: " + ", ".join(missing),
            repro="curl -sSikI %s" % wt.url,
            tags=["hygiene", "noise-prone", "chain"],
            chainable=True,
            evidence=[Evidence(kind="http", label="Response headers",
                               output="\n".join("%s: %s" % kv for kv in wt.headers.items())[:900])],
            dedupe_key="headers|%s" % wt.origin,
        )]


@register
class MethodsModule(Module):
    name = "methods"
    stage = "analyze"
    scope = "web"
    impact_class = "probe"
    desc = "Dangerous HTTP methods"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        url = wt.final_url or wt.url
        r = ctx.http.request("OPTIONS", url)
        out: List[Finding] = []
        allow = (r.header("Allow") or r.header("Access-Control-Allow-Methods")).upper()
        risky = [m for m in ("PUT", "DELETE", "PATCH", "TRACE", "CONNECT") if m in allow]
        if risky:
            out.append(Finding(
                title="Server advertises write/debug HTTP methods: %s" % ", ".join(risky),
                target=url,
                severity="low",
                confidence="firm",
                category=owasp.A05,
                cwe="CWE-650",
                module=self.name,
                impact=(
                    "Advertised only. Confirm by hand whether PUT/DELETE actually mutate "
                    "content on a writable path - that is the difference between an info "
                    "note and an unauthenticated RCE via file upload."
                ),
                repro="curl -sSik -X OPTIONS %s -i" % url,
                tags=["methods", "manual-followup"],
                evidence=[r.evidence(label="OPTIONS response", matched=allow)],
                dedupe_key="methods|%s" % wt.origin,
            ))

        # TRACE is worth confirming because it is a single request to prove.
        t = ctx.http.request("TRACE", url, headers={"X-Assay-Probe": rand_token(8)})
        if t.ok and t.status == 200 and "TRACE " in t.body[:200].upper():
            out.append(Finding(
                title="HTTP TRACE enabled (Cross-Site Tracing)",
                target=url,
                severity="low",
                confidence="confirmed",
                category=owasp.A05,
                cwe="CWE-693",
                module=self.name,
                impact=(
                    "The server echoes the full request including headers. Historically a "
                    "path to reading HttpOnly cookies; today mainly a hardening finding "
                    "unless it fronts an internal proxy that adds auth headers."
                ),
                repro=t.curl(),
                tags=["methods", "verified"],
                evidence=[t.evidence(label="TRACE echoed request")],
                dedupe_key="trace|%s" % wt.origin,
            ))
        return out
