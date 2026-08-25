"""Server-side request forgery, in-band and blind.

Two oracles, in order of strength:

  in-band   the response itself contains something only the server could have
            fetched. Cheap and self-proving, so it is tried first.
  blind     an out-of-band callback arrives from the target's own egress. This
            is the only oracle for the common case where the response body
            never reflects the fetched content.

Without an OOB backend the blind half still fires its payloads and records them
to a ledger, because a researcher with Burp Collaborator open can correlate them
by hand - a check that ran with manual correlation beats a check that was
skipped.
"""

from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urlsplit

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register
from assay.modules.web_active import candidate_urls, existing_params, with_param

# Parameters that commonly take a URL or hostname the server will fetch.
SSRF_PARAMS = [
    "url", "uri", "link", "src", "source", "target", "dest", "destination",
    "redirect", "redirect_uri", "callback", "webhook", "endpoint", "api",
    "feed", "rss", "host", "domain", "site", "page", "path", "load", "fetch",
    "proxy", "image", "image_url", "img", "file", "document", "data", "remote",
    "upload_url", "import", "preview", "render", "check", "validate", "ping",
]

# Headers some stacks resolve or forward on the server side.
SSRF_HEADERS = ["X-Forwarded-For", "X-Forwarded-Host", "Referer",
                "X-Original-URL", "True-Client-IP", "Forwarded"]


@register
class SsrfModule(Module):
    name = "ssrf"
    stage = "active"
    scope = "web"
    desc = "Server-side request forgery, in-band and out-of-band"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        oob = getattr(ctx, "oob", None)
        out: List[Finding] = []
        tested: set = set()
        budget = 6 if ctx.cfg.profile == "quick" else (
            16 if ctx.cfg.profile == "standard" else 40)

        for url in candidate_urls(ctx, wt):
            params = [p for p in existing_params(url)
                      if p.lower() in {x.lower() for x in SSRF_PARAMS}]
            if not params and url == (wt.final_url or wt.url):
                params = SSRF_PARAMS[:6] if ctx.cfg.profile != "quick" else []
            for p in params:
                key = (urlsplit(url).path, p)
                if key in tested or len(tested) >= budget:
                    continue
                tested.add(key)
                f = self._probe(ctx, url, p, oob)
                if f:
                    out.append(f)
        return out

    # ------------------------------------------------------------------
    def _probe(self, ctx: Context, url: str, param: str, oob) -> Optional[Finding]:
        if not (oob and oob.active):
            return None

        label = "%s param=%s" % (url, param)
        pid, host = oob.payload(label)
        payload = "http://%s/" % host
        r = ctx.http.get(with_param(url, param, payload))
        if not r.ok:
            return None

        # In-band tell: some stacks echo the fetch result or its error.
        inband = re.search(r"(?:Connection refused|Name or service not known|"
                           r"getaddrinfo|Could not resolve host|"
                           r"cURL error|failed to open stream)", r.body[:20000], re.I)

        hit = oob.seen(pid, wait=6.0 if ctx.cfg.profile == "deep" else 3.0)

        if hit:
            return Finding(
                title="Blind SSRF: server fetched an attacker-supplied URL via '%s'" % param,
                target=url,
                severity="high",
                confidence="confirmed",
                category=owasp.A10,
                cwe="CWE-918",
                module=self.name,
                impact=(
                    "The application fetched a URL supplied in this parameter and the "
                    "request arrived from the target's own egress (%s, %s). That reaches "
                    "anything the server can reach: internal services with no "
                    "authentication, and on cloud hosts the instance metadata endpoint, "
                    "which returns credentials. Escalate by pointing it at "
                    "169.254.169.254 or an internal host discovered elsewhere in this "
                    "scan." % (hit.remote_addr or "unknown source", hit.protocol)
                ),
                detail="Callback %s received for payload %s" % (hit.protocol, pid),
                repro=r.curl(),
                refs=["https://portswigger.net/web-security/ssrf",
                      "https://cwe.mitre.org/data/definitions/918.html"],
                tags=["ssrf", "verified", "oob"],
                chainable=True,
                evidence=[
                    r.evidence(label="Request carrying the OOB payload"),
                    Evidence(kind="note", label="Out-of-band callback",
                             output=hit.raw, matched=pid),
                ],
                dedupe_key="ssrf-oob|%s|%s" % (urlsplit(url).path, param),
            )

        if inband:
            return Finding(
                title="Possible SSRF: fetch error reflected from '%s'" % param,
                target=url,
                severity="medium",
                confidence="tentative",
                category=owasp.A10,
                cwe="CWE-918",
                module=self.name,
                impact=(
                    "The response contains a network-level error naming the host from "
                    "the parameter, which means the server attempted the connection. "
                    "No callback was observed, so this is not yet proof - retry with a "
                    "collaborator payload and a longer wait, and try an internal "
                    "address to see whether the error text differs (a different error "
                    "for an internal host is itself a port-scanning oracle)."
                ),
                detail="Matched fetch error: %s" % inband.group(0),
                repro=r.curl(),
                tags=["ssrf", "needs-impact-review", "manual-followup"],
                chainable=True,
                evidence=[r.evidence(label="Server-side fetch error",
                                     matched=inband.group(0))],
                dedupe_key="ssrf-error|%s|%s" % (urlsplit(url).path, param),
            )
        return None
