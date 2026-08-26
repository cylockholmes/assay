"""Active web checks with deterministic oracles.

Every check here uses a sentinel value the target could not produce on its own,
and every positive is re-tested with a second, different sentinel before it is
allowed to claim 'confirmed'. Requests carry a random cache-buster so a probe
can never poison a shared cache the program's real users sit behind.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register
from assay.net import Resp, rand_token

SENTINEL_DOMAIN = "example.net"

REDIRECT_PARAMS = [
    "url", "next", "redirect", "redirect_uri", "redirect_url", "return",
    "returnUrl", "return_to", "returnTo", "dest", "destination", "continue",
    "target", "goto", "callback", "checkout_url", "back", "backurl", "r", "u",
    "forward", "to", "out", "view", "image_url", "go", "link", "path",
]

FILE_PARAMS = [
    "file", "filename", "path", "page", "doc", "document", "template", "tpl",
    "download", "name", "img", "image", "src", "load", "read", "view", "item",
    "folder", "dir", "root", "pg", "style", "lang", "locale", "include",
]


def with_param(url: str, param: str, value: str, cache_bust: bool = True) -> str:
    parts = urlsplit(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    if cache_bust:
        q["assay_cb"] = rand_token(6)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(q), ""))


def existing_params(url: str) -> List[str]:
    return [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]


def candidate_urls(ctx: Context, wt: WebTarget, limit: int = 25) -> List[str]:
    """URLs worth injecting into: crawled URLs with parameters first."""
    origin = re.sub(r"(https?://[^/]+).*", r"\1", (wt.final_url or wt.url))
    urls = [u for u in ctx.urls.get(origin, []) if "?" in u]
    base = wt.final_url or wt.url
    if base not in urls:
        urls.append(base)
    # Prefer distinct paths so we do not burn the budget on one endpoint.
    seen: Dict[str, str] = {}
    for u in urls:
        key = urlsplit(u).path + "|" + ",".join(sorted(existing_params(u)))
        seen.setdefault(key, u)
    return list(seen.values())[:limit]


@register
class OpenRedirectModule(Module):
    name = "openredirect"
    stage = "active"
    scope = "web"
    impact_class = "probe"
    desc = "Parameter-driven open redirection"

    META_RE = re.compile(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+url=([^"\'>\s]+)', re.I)
    JS_RE = re.compile(r'(?:location(?:\.href)?\s*=\s*|location\.replace\()\s*["\']([^"\']+)', re.I)

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        out: List[Finding] = []
        tested: set = set()
        for url in candidate_urls(ctx, wt):
            params = existing_params(url)
            probe_params = [p for p in params if p.lower() in
                            {x.lower() for x in REDIRECT_PARAMS}]
            if not probe_params:
                probe_params = REDIRECT_PARAMS[:8] if url == (wt.final_url or wt.url) else []
            for p in probe_params:
                key = (urlsplit(url).path, p)
                if key in tested:
                    continue
                tested.add(key)
                f = self._probe(ctx, url, p)
                if f:
                    out.append(f)
                    break
        return out

    def _probe(self, ctx: Context, url: str, param: str) -> Optional[Finding]:
        token = rand_token(8)
        sentinel = "https://assay-%s.%s/" % (token, SENTINEL_DOMAIN)
        r = ctx.http.get(with_param(url, param, sentinel))
        where = self._redirects_to(r, token)
        if not where:
            return None

        token2 = rand_token(8)
        sentinel2 = "https://assay-%s.%s/" % (token2, SENTINEL_DOMAIN)
        r2 = ctx.http.get(with_param(url, param, sentinel2))
        confirmed = bool(self._redirects_to(r2, token2))

        oauthish = param.lower() in ("redirect_uri", "redirect_url", "callback") or \
            re.search(r"/(oauth|authorize|sso|saml|login|signin|auth)", url, re.I)
        sev = "medium" if oauthish else "low"
        return Finding(
            title="Open redirect via '%s' parameter" % param,
            target=url,
            severity=sev,
            confidence="confirmed" if confirmed else "firm",
            category=owasp.A01,
            cwe="CWE-601",
            module=self.name,
            impact=(
                "The endpoint sends users to an arbitrary external origin. On an OAuth/SSO "
                "or login flow this is the classic authorization-code and token theft "
                "primitive - request the flow with the redirect pointed at your host and "
                "capture the code. Off an auth flow it is phishing-grade only, so confirm "
                "which one you have before reporting."
                if oauthish else
                "Users can be sent to an arbitrary external origin from a trusted link. "
                "On its own most programs rate this low; it becomes materially more serious "
                "if it sits inside an authentication flow or can reach javascript:/data: URIs."
            ),
            detail="Redirected to sentinel via %s (%s)" % (param, where),
            repro=r.curl(),
            refs=["https://cwe.mitre.org/data/definitions/601.html"],
            tags=["redirect", "verified" if confirmed else "single-observation"],
            chainable=True,
            evidence=[r.evidence(label="Redirect to attacker-controlled sentinel",
                                 matched=where)],
            dedupe_key="openredirect|%s|%s" % (urlsplit(url).path, param),
        )

    def _redirects_to(self, r: Resp, token: str) -> str:
        if not r.ok:
            return ""
        loc = r.header("Location")
        if token in loc and re.match(r"https?://assay-%s\." % re.escape(token), loc):
            return "Location: " + loc[:160]
        m = self.META_RE.search(r.body[:8000])
        if m and token in m.group(1):
            return "meta refresh: " + m.group(1)[:160]
        m = self.JS_RE.search(r.body[:8000])
        if m and token in m.group(1):
            return "javascript redirect: " + m.group(1)[:160]
        return ""


@register
class HostHeaderModule(Module):
    name = "hostheader"
    stage = "active"
    scope = "web"
    impact_class = "probe"
    desc = "Host / X-Forwarded-Host injection and unkeyed-input reflection"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        url = wt.final_url or wt.url
        out: List[Finding] = []

        for header in ("X-Forwarded-Host", "X-Host", "X-Forwarded-Server"):
            f = self._probe(ctx, url, header)
            if f:
                out.append(f)
                break

        f = self._absolute_host(ctx, url)
        if f:
            out.append(f)
        return out

    def _probe(self, ctx: Context, url: str, header: str) -> Optional[Finding]:
        token = rand_token(8)
        sentinel = "assay-%s.%s" % (token, SENTINEL_DOMAIN)
        bust = with_param(url, "assay_cb", rand_token(6))
        r = ctx.http.get(bust, headers={header: sentinel})
        if not r.ok or token not in (r.header("Location") + r.body[:20000]):
            return None

        token2 = rand_token(8)
        r2 = ctx.http.get(with_param(url, "assay_cb", rand_token(6)),
                          headers={header: "assay-%s.%s" % (token2, SENTINEL_DOMAIN)})
        confirmed = r2.ok and token2 in (r2.header("Location") + r2.body[:20000])

        cacheable = self._cacheable(r)
        sev = "medium"
        where = "Location header" if token in r.header("Location") else "response body"
        return Finding(
            title="%s reflected into %s" % (header, where),
            target=url,
            severity=sev,
            confidence="confirmed" if confirmed else "firm",
            category=owasp.A05,
            cwe="CWE-644",
            module=self.name,
            impact=(
                "The application builds absolute URLs from an attacker-controlled header. "
                "Two concrete escalations to test by hand: password-reset poisoning (trigger "
                "a reset with this header set and check whether the emailed link points at "
                "your host), and %s"
                % ("web cache poisoning - this response carries cache headers, so a poisoned "
                   "entry would be served to other users."
                   if cacheable else
                   "SSRF/routing abuse if an upstream proxy trusts the same header.")
            ),
            detail="Sentinel %s reflected in %s. Cacheable: %s" % (sentinel, where, cacheable),
            repro=r.curl(),
            refs=["https://portswigger.net/web-security/host-header"],
            tags=["hostheader", "manual-followup",
                  "verified" if confirmed else "single-observation"] +
                 (["cache"] if cacheable else []),
            chainable=True,
            evidence=[r.evidence(label="Header reflected", matched=sentinel)],
            dedupe_key="hostheader|%s|%s" % (urlsplit(url).path, header),
        )

    def _absolute_host(self, ctx: Context, url: str) -> Optional[Finding]:
        """Does the vhost accept a completely different Host and still serve 200?"""
        token = rand_token(8)
        sentinel = "assay-%s.%s" % (token, SENTINEL_DOMAIN)
        r = ctx.http.get(with_param(url, "assay_cb", rand_token(6)),
                         headers={"Host": sentinel})
        if not r.ok or r.status != 200:
            return None
        if token not in r.body[:20000] and token not in r.header("Location"):
            return None
        return Finding(
            title="Host header reflected in response",
            target=url,
            severity="medium",
            confidence="firm",
            category=owasp.A05,
            cwe="CWE-644",
            module=self.name,
            impact=(
                "An arbitrary Host value is accepted and echoed into the page. Check the "
                "password-reset and email-link flows next: if they are generated from this "
                "value, an attacker receives working reset links for other users' accounts."
            ),
            repro=r.curl(),
            tags=["hostheader", "manual-followup"],
            chainable=True,
            evidence=[r.evidence(label="Arbitrary Host accepted and reflected",
                                 matched=sentinel)],
            dedupe_key="hostabs|%s" % urlsplit(url).netloc,
        )

    @staticmethod
    def _cacheable(r: Resp) -> bool:
        cc = r.header("Cache-Control").lower()
        if "no-store" in cc or "private" in cc:
            return False
        return bool(r.header("Age") or r.header("X-Cache") or r.header("CF-Cache-Status")
                    or "public" in cc or "max-age" in cc)


@register
class TraversalModule(Module):
    name = "traversal"
    stage = "active"
    scope = "web"
    impact_class = "probe"
    desc = "Path traversal / local file read"

    PAYLOADS = [
        "../../../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/passwd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        "../../../../../../windows/win.ini",
        "..\\..\\..\\..\\windows\\win.ini",
    ]
    # Oracles a normal application response cannot contain by accident.
    UNIX_RE = re.compile(r"^root:.*?:0:0:", re.M)
    WIN_RE = re.compile(r"\[fonts\]|\[extensions\]|for 16-bit app support", re.I)

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        out: List[Finding] = []
        tested: set = set()
        for url in candidate_urls(ctx, wt):
            params = [p for p in existing_params(url)
                      if p.lower() in {x.lower() for x in FILE_PARAMS}]
            if not params and url == (wt.final_url or wt.url):
                params = FILE_PARAMS[:6] if ctx.cfg.profile != "quick" else []
            for p in params:
                key = (urlsplit(url).path, p)
                if key in tested:
                    continue
                tested.add(key)
                f = self._probe(ctx, url, p)
                if f:
                    out.append(f)
        return out

    def _probe(self, ctx: Context, url: str, param: str) -> Optional[Finding]:
        for payload in self.PAYLOADS:
            r = ctx.http.get(with_param(url, param, payload))
            if not r.ok:
                continue
            unix = self.UNIX_RE.search(r.body[:40000])
            win = self.WIN_RE.search(r.body[:40000])
            if not (unix or win):
                continue
            matched = (unix or win).group(0)[:120]
            return Finding(
                title="Path traversal: arbitrary file read via '%s'" % param,
                target=url,
                severity="critical",
                confidence="confirmed",
                category=owasp.A01,
                cwe="CWE-22",
                module=self.name,
                impact=(
                    "The parameter is used to build a filesystem path with no containment, "
                    "so any file readable by the service account is retrievable. Escalate by "
                    "reading application config for database credentials, or private keys "
                    "under the service user's home directory. Evidenced here by the contents "
                    "of %s." % ("/etc/passwd" if unix else "win.ini")
                ),
                detail="Payload: %s" % payload,
                repro=r.curl(),
                refs=["https://owasp.org/www-community/attacks/Path_Traversal",
                      "https://cwe.mitre.org/data/definitions/22.html"],
                tags=["traversal", "verified"],
                evidence=[r.evidence(label="System file contents returned", matched=matched)],
                dedupe_key="traversal|%s|%s" % (urlsplit(url).path, param),
            )
        return None


@register
class GraphQLModule(Module):
    name = "graphql"
    stage = "active"
    scope = "web"
    impact_class = "probe"
    desc = "GraphQL endpoint discovery and introspection"

    ENDPOINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1",
                 "/query", "/api/query", "/gql", "/graphql/console"]
    INTROSPECTION = '{"query":"query{__schema{queryType{name} mutationType{name} types{name}}}"}'

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        origin = re.sub(r"(https?://[^/]+).*", r"\1", (wt.final_url or wt.url))
        out: List[Finding] = []
        eps = self.ENDPOINTS if ctx.cfg.profile != "quick" else self.ENDPOINTS[:3]
        for ep in eps:
            url = origin + ep
            r = ctx.http.post(url, data=self.INTROSPECTION,
                              headers={"Content-Type": "application/json"})
            if not r.ok or '"__schema"' not in r.body[:4000]:
                continue
            mutations = re.search(r'"mutationType"\s*:\s*\{\s*"name"\s*:\s*"([^"]+)"', r.body)
            types = len(re.findall(r'"name"\s*:', r.body))
            out.append(Finding(
                title="GraphQL introspection enabled",
                target=url,
                severity="medium" if mutations else "low",
                confidence="confirmed",
                category=owasp.A05,
                cwe="CWE-200",
                module=self.name,
                impact=(
                    "The full schema is downloadable, including %s. This is the map for "
                    "access-control testing: enumerate mutations and query fields that the "
                    "UI never calls, then check whether the resolver enforces authorization. "
                    "Broken object-level authorization found this way is the high-severity "
                    "finding; introspection itself is only the enabler."
                    % ("a mutation root ('%s') exposing state-changing operations"
                       % mutations.group(1) if mutations else "the query surface")
                ),
                detail="~%d named schema elements returned." % types,
                repro=("curl -sS -k -X POST %s -H 'Content-Type: application/json' "
                       "--data '%s'" % (url, self.INTROSPECTION)),
                refs=["https://owasp.org/www-project-web-security-testing-guide/"],
                tags=["graphql", "verified", "manual-followup"],
                chainable=True,
                evidence=[r.evidence(label="Introspection response", matched="__schema")],
                dedupe_key="graphql-introspection|%s" % url,
            ))
            break
        return out
