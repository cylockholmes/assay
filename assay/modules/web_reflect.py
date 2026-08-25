"""Reflected-input analysis: the honest precursor to XSS.

This module does not claim XSS. Claiming XSS from a scanner is how tools earn
their false-positive reputation, because proving it requires knowing whether
the surviving characters actually break out of their context in a real browser.

What it does instead is answer the question a human needs answered before
spending time: *is my input reflected, in what context, and which dangerous
characters survive unencoded?* That is deterministic, cheap to verify, and
turns a vague "test for XSS" into a specific manual step.

Reported severity is driven by the combination of context and surviving
characters, never by reflection alone.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register
from assay.modules.web_active import candidate_urls, existing_params, with_param
from assay.net import Resp, rand_token

# Characters that decide whether a reflection is exploitable, and what each
# one unlocks if it survives.
BREAKOUT = {
    "<": "HTML tag injection",
    ">": "HTML tag closing",
    '"': "attribute breakout",
    "'": "attribute/JS string breakout",
    "`": "JS template literal breakout",
    "(": "JS call syntax",
    ")": "JS call syntax",
    "{": "JS/template expression",
    "}": "JS/template expression",
    ";": "JS statement separator",
}

# Parameters worth probing when a URL carries none of its own.
COMMON_PARAMS = ["q", "s", "search", "query", "id", "name", "page", "keyword",
                 "term", "lang", "ref", "callback", "message", "title", "email"]

REFLECTIVE_TYPES = ("text/html", "application/xhtml+xml", "text/javascript",
                    "application/javascript", "text/xml", "application/xml")


class Context_:
    HTML = "HTML body text"
    ATTR = "HTML attribute value"
    SCRIPT = "inline <script> block"
    COMMENT = "HTML comment"
    URL_ATTR = "URL-bearing attribute (href/src/action)"


def classify(body: str, canary: str) -> List[str]:
    """Where in the document did the canary land? Can be several places."""
    contexts: List[str] = []
    for m in re.finditer(re.escape(canary), body):
        pos = m.start()
        before = body[max(0, pos - 800):pos]

        # Inside a <script> block?
        last_open = before.rfind("<script")
        last_close = before.rfind("</script")
        if last_open > last_close:
            contexts.append(Context_.SCRIPT)
            continue

        if before.rfind("<!--") > before.rfind("-->"):
            contexts.append(Context_.COMMENT)
            continue

        # Inside a tag, i.e. after an unclosed '<'
        last_lt = before.rfind("<")
        last_gt = before.rfind(">")
        if last_lt > last_gt:
            attr = re.search(r"(href|src|action|formaction|data)\s*=\s*[\"']?[^\"'>]*$",
                             before, re.I)
            contexts.append(Context_.URL_ATTR if attr else Context_.ATTR)
            continue

        contexts.append(Context_.HTML)

    out: List[str] = []
    for c in contexts:
        if c not in out:
            out.append(c)
    return out


def build_probe(token: str, probe_chars: str) -> str:
    """Fence every test character between two unique markers.

    Scanning a window after a single token mis-attributes characters that were
    already in the surrounding markup. Fencing removes the ambiguity entirely:
    a character survived if and only if it appears verbatim between the two
    markers that bracket it.
    """
    parts = [token + "0"]
    for i, ch in enumerate(probe_chars):
        parts.append(ch)
        parts.append("%s%d" % (token, i + 1))
    return "".join(parts)


def surviving(body: str, token: str, probe_chars: str) -> str:
    """Exact set of probe characters returned unencoded, via marker fences."""
    survived = ""
    for i, ch in enumerate(probe_chars):
        left = "%s%d" % (token, i)
        right = "%s%d" % (token, i + 1)
        pos = body.find(left)
        while pos != -1:
            end = body.find(right, pos + len(left))
            if end != -1 and body[pos + len(left):end] == ch:
                survived += ch
                break
            pos = body.find(left, pos + 1)
    return survived


@register
class ReflectionModule(Module):
    name = "reflection"
    stage = "active"
    scope = "web"
    desc = "Reflected input, its context, and which characters survive encoding"

    PROBE_CHARS = "<>\"'`(){};"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        out: List[Finding] = []
        tested: set = set()
        budget = 6 if ctx.cfg.profile == "quick" else (
            18 if ctx.cfg.profile == "standard" else 45)

        for url in candidate_urls(ctx, wt):
            params = existing_params(url)
            if not params and url == (wt.final_url or wt.url):
                params = COMMON_PARAMS[:6]
            for p in params:
                if p.startswith("sift_"):
                    continue
                key = (urlsplit(url).path, p)
                if key in tested or len(tested) >= budget:
                    continue
                tested.add(key)
                f = self._probe(ctx, url, p)
                if f:
                    out.append(f)
        return out

    def _probe(self, ctx: Context, url: str, param: str) -> Optional[Finding]:
        # Step 1: is a plain alphanumeric canary reflected at all?
        canary = "sf%s" % rand_token(7)
        r1 = ctx.http.get(with_param(url, param, canary))
        if not r1.ok or canary not in r1.body:
            return None
        if r1.content_type and r1.content_type not in REFLECTIVE_TYPES:
            # Reflection into a JSON API response is not a browser-rendered sink.
            return None

        # Step 2: which dangerous characters survive?
        token = "sf%s" % rand_token(7)
        r2 = ctx.http.get(with_param(url, param,
                                     build_probe(token, self.PROBE_CHARS)))
        if not r2.ok or token not in r2.body:
            return None

        survived = surviving(r2.body, token, self.PROBE_CHARS)
        contexts = classify(r2.body, token + "0")
        if not contexts:
            return None

        # Step 3: independent re-confirmation with a different token.
        token3 = "sf%s" % rand_token(7)
        r3 = ctx.http.get(with_param(url, param,
                                     build_probe(token3, self.PROBE_CHARS)))
        confirmed = r3.ok and surviving(r3.body, token3, self.PROBE_CHARS) == survived

        sev, headline, why = self._assess(contexts, survived)
        if sev is None:
            return None

        unlocks = ", ".join(BREAKOUT[c] for c in survived if c in BREAKOUT) or "none"
        return Finding(
            title=headline % param,
            target=url,
            severity=sev,
            confidence="firm" if confirmed else "tentative",
            category=owasp.A03,
            cwe="CWE-79",
            module=self.name,
            impact=why,
            detail="Context: %s. Unencoded: %s (%s)."
                   % (", ".join(contexts), survived or "none", unlocks),
            repro=r2.curl(),
            refs=["https://owasp.org/www-community/attacks/xss/",
                  "https://portswigger.net/web-security/cross-site-scripting"],
            tags=["reflection", "manual-followup"] +
                 (["verified"] if confirmed else []),
            chainable=True,
            evidence=[r2.evidence(label="Reflected with unencoded characters",
                                  matched=self._excerpt(r2.body, token + "0"))],
            dedupe_key="reflect|%s|%s" % (urlsplit(url).path, param),
        )

    @staticmethod
    def _assess(contexts: List[str], survived: str) -> Tuple[Optional[str], str, str]:
        """Severity comes from context plus surviving characters, not reflection."""
        has_tag = "<" in survived and ">" in survived
        has_quote = '"' in survived or "'" in survived

        if Context_.SCRIPT in contexts and (has_quote or "`" in survived):
            return ("high",
                    "Input reflected into inline script with quotes unencoded ('%s')",
                    "Input lands inside a <script> block and the quote characters "
                    "needed to break out of the surrounding string survive encoding. "
                    "This is the strongest XSS candidate a scanner can identify "
                    "without a browser - build the breakout payload by hand and "
                    "confirm execution before reporting.")

        if has_tag and Context_.HTML in contexts:
            return ("high",
                    "Input reflected into HTML with tag characters unencoded ('%s')",
                    "Both < and > survive into HTML body context, so a new element "
                    "can be introduced. Confirm in a browser that it parses and "
                    "executes - if the page carries a CSP, check whether it blocks "
                    "inline script before writing the report.")

        if has_quote and Context_.URL_ATTR in contexts:
            return ("medium",
                    "Input reflected into a URL attribute with quotes unencoded ('%s')",
                    "Reflection into an href/src/action attribute with quote "
                    "characters intact allows attribute breakout, and the sink may "
                    "also accept a javascript: URI directly. Test both.")

        if has_quote and Context_.ATTR in contexts:
            return ("medium",
                    "Input reflected into an HTML attribute with quotes unencoded ('%s')",
                    "The quote that terminates the attribute value survives, so an "
                    "event-handler attribute can likely be injected. Confirm by hand.")

        if survived:
            return ("low",
                    "Input reflected with some special characters unencoded ('%s')",
                    "Reflection is present and encoding is incomplete, but the "
                    "characters needed for a straightforward breakout in this "
                    "context did not survive. Worth ten minutes with a context-"
                    "specific payload set; not reportable as-is.")

        # Reflection with full encoding is not a finding.
        return (None, "", "")

    @staticmethod
    def _excerpt(body: str, token: str, width: int = 110) -> str:
        m = re.search(re.escape(token), body)
        if not m:
            return ""
        return body[max(0, m.start() - width):m.end() + width].replace("\n", " ")
