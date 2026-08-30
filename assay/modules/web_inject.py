"""Template and header injection, both with unambiguous oracles.

SSTI is proved by arithmetic the application had to perform: the payload goes
in as `{{7*7}}` and comes back as `49`. If the literal `{{7*7}}` is echoed
instead, nothing evaluated it and there is no finding. A second, different sum
rules out the coincidence of a `49` already on the page.

CRLF is proved by a header that only we could have put there. If the injected
name appears in the response headers, the application concatenated our input
into the status line - there is no benign reading of that.
"""

from __future__ import annotations

import re
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register
from assay.modules.web_active import candidate_urls, existing_params, with_param
from assay import params as P
from assay.net import rand_token

# (engine family, payload template, expected result) - %d pairs substituted.
SSTI_PAYLOADS: List[Tuple[str, str]] = [
    ("Jinja2/Twig/Nunjucks", "{{%d*%d}}"),
    ("Freemarker/JSP EL", "${%d*%d}"),
    ("ERB/ASP", "<%%= %d*%d %%>"),
    ("Ruby/Slim", "#{%d*%d}"),
    ("Velocity", "#set($x=%d*%d)$x"),
    ("Handlebars/Angular", "{{= %d*%d}}"),
]

COMMON_PARAMS = ["q", "search", "name", "title", "message", "template", "view",
                 "page", "lang", "id", "email", "user", "content", "text"]


@register
class SstiModule(Module):
    name = "ssti"
    stage = "active"
    scope = "web"
    impact_class = "probe"
    desc = "Server-side template injection, proved by evaluated arithmetic"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        out: List[Finding] = []
        tested: set = set()
        budget = 4 if ctx.cfg.profile == "quick" else (
            12 if ctx.cfg.profile == "standard" else 30)

        for url in candidate_urls(ctx, wt):
            params = P.targets_for(
                "ssti", url,
                fallback=(COMMON_PARAMS[:5]
                          if url == (wt.final_url or wt.url)
                          and ctx.cfg.profile != "quick" else []))
            for p in params:
                key = (urlsplit(url).path, p)
                if key in tested or len(tested) >= budget:
                    continue
                tested.add(key)
                f = self._probe(ctx, url, p)
                if f:
                    out.append(f)
        return out

    def _probe(self, ctx: Context, url: str, param: str) -> Optional[Finding]:
        for engine, template in SSTI_PAYLOADS:
            marker = "a%s" % rand_token(5)
            a, b = 733, 7                      # 5131 - unlikely to occur by chance
            payload = marker + (template % (a, b))
            r = ctx.http.get(with_param(url, param, payload))
            if not r.ok:
                continue
            expected = marker + str(a * b)
            # Evaluated, and not merely echoed back verbatim.
            if expected not in r.body or payload in r.body:
                continue

            # A different sum, so a stray 5131 on the page cannot carry it.
            marker2 = "a%s" % rand_token(5)
            c, d = 829, 3                      # 2487
            r2 = ctx.http.get(with_param(url, param, marker2 + (template % (c, d))))
            if not r2.ok or (marker2 + str(c * d)) not in r2.body:
                continue

            return Finding(
                title="Server-side template injection in '%s'" % param,
                target=url,
                severity="critical",
                confidence="confirmed",
                category=owasp.A03,
                cwe="CWE-1336",
                module=self.name,
                impact=(
                    "The application evaluated arithmetic supplied in this parameter, "
                    "so input reaches a template engine as template source rather than "
                    "as data. In most engines this escalates to reading server-side "
                    "files and to remote code execution through the object graph. "
                    "Establish the engine, then demonstrate the minimum needed - "
                    "reading a single file is enough; do not run commands."
                ),
                detail="Syntax matched %s. %d*%d returned %d, and a second sum "
                       "%d*%d returned %d." % (engine, a, b, a * b, c, d, c * d),
                repro=r.curl(),
                refs=["https://portswigger.net/web-security/server-side-template-injection",
                      "https://cwe.mitre.org/data/definitions/1336.html"],
                tags=["ssti", "verified"],
                evidence=[
                    r.evidence(label="%d*%d evaluated to %d" % (a, b, a * b),
                               matched=expected),
                    r2.evidence(label="Second sum confirms evaluation",
                                matched=marker2 + str(c * d)),
                ],
                dedupe_key="ssti|%s|%s" % (urlsplit(url).path, param),
            )
        return None


@register
class CrlfModule(Module):
    name = "crlf"
    stage = "active"
    scope = "web"
    impact_class = "probe"
    desc = "CRLF injection into response headers"

    ENCODINGS = ["%0d%0a", "%0D%0A", "%E5%98%8D%E5%98%8A", "\\r\\n", "%0a", "%0d"]

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        out: List[Finding] = []
        tested: set = set()
        budget = 3 if ctx.cfg.profile == "quick" else (
            10 if ctx.cfg.profile == "standard" else 24)

        for url in candidate_urls(ctx, wt):
            params = P.targets_for(
                "crlf", url,
                fallback=(["redirect", "url", "next", "lang"]
                          if url == (wt.final_url or wt.url) else []))
            for p in params:
                key = (urlsplit(url).path, p)
                if key in tested or len(tested) >= budget:
                    continue
                tested.add(key)
                f = self._probe(ctx, url, p)
                if f:
                    out.append(f)
        return out

    def _probe(self, ctx: Context, url: str, param: str) -> Optional[Finding]:
        for enc in self.ENCODINGS:
            token = rand_token(6)
            header = "X-Assay-%s" % token
            r = ctx.http.get(with_param(url, param, "1%s%s: injected" % (enc, header)))
            if not r.ok or not r.header(header):
                continue

            token2 = rand_token(6)
            header2 = "X-Assay-%s" % token2
            r2 = ctx.http.get(with_param(url, param,
                                         "1%s%s: injected" % (enc, header2)))
            if not (r2.ok and r2.header(header2)):
                continue

            return Finding(
                title="CRLF injection into response headers via '%s'" % param,
                target=url,
                severity="high",
                confidence="confirmed",
                category=owasp.A03,
                cwe="CWE-113",
                module=self.name,
                impact=(
                    "Input is concatenated into the response headers without stripping "
                    "line breaks, so arbitrary headers can be injected. That yields "
                    "session fixation by setting Set-Cookie, cache poisoning where a "
                    "shared cache stores the injected response, and - by injecting a "
                    "blank line - control of the response body itself, which makes it "
                    "an XSS vector on origins that would otherwise be safe."
                ),
                detail="Encoding %s produced header %s in the response." % (enc, header),
                repro=r.curl(),
                refs=["https://cwe.mitre.org/data/definitions/113.html",
                      "https://owasp.org/www-community/attacks/HTTP_Response_Splitting"],
                tags=["crlf", "verified"],
                chainable=True,
                evidence=[r.evidence(label="Injected header present in response",
                                     matched="%s: %s" % (header, r.header(header)))],
                dedupe_key="crlf|%s|%s" % (urlsplit(url).path, param),
            )
        return None
