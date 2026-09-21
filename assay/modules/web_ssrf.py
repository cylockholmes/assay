"""Server-side request forgery, in-band and blind.

Two oracles, in order of strength:

  in-band   the response itself contains something only the server could have
            fetched. Cheap and self-proving, so it is tried first.
  blind     an out-of-band callback arrives from the target's own egress. This
            is the only oracle for the common case where the response body
            never reflects the fetched content.

assay does not watch for the callback itself. The blind half fires uniquely
labelled payloads at the collaborator domain given with --oob-domain and
records each one to a ledger, for you to correlate - a check that ran with
manual correlation beats a check that was skipped.
"""

from __future__ import annotations

import re
from typing import List, Optional
from urllib.parse import urlsplit

from assay import owasp
from assay.context import Context
from assay.models import Finding, WebTarget
from assay.modules import Module, register
from assay import params as P
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
    impact_class = "probe"
    desc = "Server-side request forgery, in-band and out-of-band"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        oob = getattr(ctx, "oob", None)
        out: List[Finding] = []
        tested: set = set()
        budget = 6 if ctx.cfg.profile == "quick" else (
            16 if ctx.cfg.profile == "standard" else 40)

        for url in candidate_urls(ctx, wt):
            params = P.targets_for(
                "ssrf", url,
                fallback=(SSRF_PARAMS[:6]
                          if url == (wt.final_url or wt.url)
                          and ctx.cfg.profile != "quick" else []))
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
                    "No callback was correlated, so this is not yet proof - check "
                    "oob-payloads.txt against your collaborator, and try an internal "
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
