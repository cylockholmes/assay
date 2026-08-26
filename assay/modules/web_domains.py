"""Unregistered-domain dependencies: references to names nobody owns.

An application that loads a script, frames a widget, or allow-lists an origin
on an unregistered domain has an open door. Register the name and you inherit
whatever the reference grants - and for a script source that is arbitrary
JavaScript executing in the application's own origin.

Severity is driven entirely by what the reference grants, not by the fact that
the domain is free. A dead <a href> is a broken link; a dead <script src> is
stored XSS waiting for someone to pay ten dollars.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set
from urllib.parse import urlsplit

from assay import domains, owasp
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register

# What each reference kind hands to whoever registers the domain.
CONSEQUENCE = {
    "script": ("critical",
               "The application loads executable JavaScript from this domain. "
               "Registering it yields arbitrary script execution in the "
               "application's origin for every visitor - session theft, request "
               "forgery on behalf of users, and full DOM control. This is "
               "equivalent to stored XSS with no injection required."),
    "frame": ("high",
              "The application frames content from this domain. Registering it "
              "allows serving arbitrary content inside the application's UI - a "
              "convincing credential-harvesting surface on the legitimate origin, "
              "and postMessage access to the parent if the page listens."),
    "csp": ("high",
            "The Content-Security-Policy allow-lists this domain as a permitted "
            "source. Registering it defeats the CSP: any injection elsewhere in "
            "the application can now load its payload from an allow-listed "
            "origin, converting an otherwise-blocked XSS into a working one."),
    "cors": ("high",
             "The application's CORS policy trusts this origin. Registering it "
             "grants cross-origin read access to authenticated responses."),
    "cert": ("medium",
             "The TLS certificate asserts this name. Registering it lets an "
             "attacker obtain a valid certificate for a name the target's own "
             "certificate vouches for, which matters wherever that SAN list is "
             "treated as an allow-list."),
    "css": ("medium",
            "The application loads a stylesheet from this domain. Registering it "
            "allows UI redressing and, through CSS selectors, exfiltration of "
            "attribute values such as CSRF tokens."),
    "form": ("high",
             "A form submits to this domain. Registering it means receiving "
             "whatever users type into that form, in plaintext."),
    "preconnect": ("low",
                   "The page hints a connection to this domain. No content is "
                   "loaded from it, so impact is limited unless the reference is "
                   "upgraded elsewhere in the application."),
    "js": ("medium",
           "Client-side JavaScript references this domain, typically as an API "
           "or asset host. Registering it captures whatever requests the script "
           "makes - review the calling code to determine whether credentials or "
           "user data travel with them."),
    "link": ("info",
             "Referenced only as a hyperlink. Registering it enables convincing "
             "phishing from a trusted page, but nothing is loaded into the "
             "application itself."),
}

ORDER = ["script", "form", "csp", "cors", "frame", "css", "cert", "js",
         "preconnect", "link"]


@register
class UnregisteredDomainModule(Module):
    name = "deaddomain"
    stage = "analyze"
    scope = "web"
    impact_class = "read"
    desc = "References to unregistered domains (script, CSP, CORS, cert SANs)"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        base = wt.final_url or wt.url
        refs: Dict[str, Set[str]] = {}

        r = ctx.http.get(base)
        body = r.body if r.ok else (wt.body_sample or "")
        headers = dict(r.headers) if r.ok else dict(wt.headers)

        self._merge(refs, domains.refs_from_html(body, wt.host))

        for key, val in headers.items():
            kl = key.lower()
            if kl in ("content-security-policy",
                      "content-security-policy-report-only"):
                self._merge(refs, domains.refs_from_csp(val, wt.host))
            elif kl == "access-control-allow-origin" and val.strip() not in ("*", ""):
                self._merge(refs, domains.refs_from_hosts(
                    [urlsplit(val.strip()).hostname or val.strip()], wt.host, "cors"))

        # Certificate SANs, and foreign hosts already extracted from JS bundles.
        for san in (wt.cert.get("sans") or []):
            self._merge(refs, domains.refs_from_hosts([san], wt.host, "cert"))
        origin = re.sub(r"(https?://[^/]+).*", r"\1", base)
        js_hosts = [urlsplit(u).hostname for u in ctx.urls.get(origin, [])
                    if u.startswith("http")]
        self._merge(refs, domains.refs_from_hosts(
            [h for h in js_hosts if h], wt.host, "js"))

        if not refs:
            return []

        budget = 12 if ctx.cfg.profile == "quick" else (
            40 if ctx.cfg.profile == "standard" else 120)
        checked = getattr(ctx, "_domain_cache", None)
        if checked is None:
            checked = {}
            setattr(ctx, "_domain_cache", checked)

        out: List[Finding] = []
        for apex in sorted(refs)[:budget]:
            status = checked.get(apex)
            if status is None:
                status = domains.check(apex, ctx.http)
                checked[apex] = status
            if not status.takeoverable:
                continue
            out.append(self._finding(apex, sorted(refs[apex]), status, base))
        return out

    @staticmethod
    def _merge(into: Dict[str, Set[str]], new: Dict[str, Set[str]]) -> None:
        for k, v in new.items():
            into.setdefault(k, set()).update(v)

    @staticmethod
    def _finding(apex: str, kinds: List[str], status, base: str) -> Finding:
        primary = next((k for k in ORDER if k in kinds), kinds[0])
        sev, impact = CONSEQUENCE.get(primary, ("low", "Referenced by the application."))
        return Finding(
            title="Unregistered domain referenced by the application: %s" % apex,
            target=apex,
            severity=sev,
            confidence="confirmed",
            category=owasp.A08,
            cwe="CWE-1104",
            module="deaddomain",
            impact=(
                "%s The domain is currently unregistered, so this requires no "
                "exploitation - only a registration. Confirm availability at a "
                "registrar before reporting, and never register it yourself unless "
                "the program explicitly permits it." % impact
            ),
            detail="Referenced as: %s. Registration check: %s"
                   % (", ".join(kinds), status.reason),
            repro="dig NS %s ; curl -s https://rdap.org/domain/%s -o /dev/null -w '%%{http_code}\\n'"
                  % (apex, apex),
            refs=["https://cwe.mitre.org/data/definitions/1104.html",
                  "https://owasp.org/www-project-top-ten/2021/A08"],
            tags=["deaddomain", "verified", "supply-chain"],
            chainable=True,
            evidence=[Evidence(
                kind="dns",
                label="Registration verification",
                request="dig NS %s  +  RDAP https://rdap.org/domain/%s" % (apex, apex),
                output="referenced from: %s\nreference kinds: %s\nNS records: %s\n"
                       "RDAP status: %s\nverdict: %s"
                       % (base, ", ".join(kinds), status.ns or "(none)",
                          status.rdap_code, status.reason),
                matched=apex)],
            dedupe_key="deaddomain|%s" % apex,
        )
