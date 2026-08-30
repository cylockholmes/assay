"""Post-scan reasoning over the whole finding set.

Two things can only be decided once everything is in.

**Prevalence.** A finding present on almost every host is a property of the
estate, not a discovery. Two hundred hosts each missing a security header is
one configuration decision reported two hundred times, and it buries the one
host that differs. Findings above a prevalence threshold are collapsed and
downranked - not deleted, because the fact remains true and occasionally the
estate-wide default *is* the finding.

**Chains.** Individually unremarkable findings that together demonstrate real
impact. These rules are deterministic and computed locally; they need no model
and they run whether or not AI triage is enabled. Each rule states why the
combination is worth more than its parts.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

from assay.models import Finding


def _host_of(target: str) -> str:
    t = target.strip()
    if "://" in t:
        return (urlsplit(t).hostname or t).lower()
    return t.split(":")[0].lower()


def _apex(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# --------------------------------------------------------------------------
# Prevalence
# --------------------------------------------------------------------------


@dataclass
class Prevalence:
    title: str
    hosts: List[str] = field(default_factory=list)
    share: float = 0.0

    @property
    def count(self) -> int:
        return len(self.hosts)


def environmental(findings: Sequence[Finding], min_hosts: int = 5,
                  min_share: float = 0.6) -> Dict[str, Prevalence]:
    """Findings so widespread they describe the estate rather than a host.

    Requires both an absolute count and a share: three hosts out of four is a
    small sample, not a policy, and collapsing it would hide real findings on a
    small scope.
    """
    all_hosts = {_host_of(f.target) for f in findings if f.target}
    if len(all_hosts) < min_hosts:
        return {}

    by_title: Dict[str, Set[str]] = defaultdict(set)
    for f in findings:
        if f.target:
            by_title[f.title].add(_host_of(f.target))

    out: Dict[str, Prevalence] = {}
    for title, hosts in by_title.items():
        share = len(hosts) / float(len(all_hosts))
        if len(hosts) >= min_hosts and share >= min_share:
            out[title] = Prevalence(title=title, hosts=sorted(hosts), share=share)
    return out


def apply_prevalence(findings: Sequence[Finding],
                     prevalent: Dict[str, Prevalence]) -> int:
    """Downrank the widespread, and say why on the finding itself."""
    touched = 0
    for f in findings:
        p = prevalent.get(f.title)
        if not p:
            continue
        if "environmental" not in f.tags:
            f.tags.append("environmental")
        f.notes = (f.notes + "\n" if f.notes else "") + (
            "Present on %d of the hosts scanned (%.0f%%), so this describes the "
            "environment rather than this host. Ranked down accordingly; the "
            "finding is still true, and an estate-wide default is occasionally "
            "worth reporting on its own." % (p.count, p.share * 100))
        f.compute_score()
        f.score = round(f.score * 0.35, 2)
        f.triage = ("CHASE" if f.score >= 55 else
                    "LOOK" if f.score >= 22 else "NOTE")
        touched += 1
    return touched


# --------------------------------------------------------------------------
# Chains
# --------------------------------------------------------------------------


@dataclass
class Chain:
    name: str
    severity: str
    finding_ids: List[str]
    impact: str
    steps: List[str]

    def as_dict(self) -> Dict:
        return {"name": self.name, "combined_severity": self.severity,
                "finding_ids": self.finding_ids, "combined_impact": self.impact,
                "steps": self.steps, "source": "assay"}


class _Index:
    """Lookup helpers so each rule reads as the question it is asking."""

    def __init__(self, findings: Sequence[Finding]) -> None:
        self.findings = list(findings)
        self.by_module: Dict[str, List[Finding]] = defaultdict(list)
        for f in self.findings:
            self.by_module[f.module].append(f)

    def module(self, name: str) -> List[Finding]:
        return self.by_module.get(name, [])

    def titled(self, pattern: str) -> List[Finding]:
        rx = re.compile(pattern, re.I)
        return [f for f in self.findings if rx.search(f.title)]

    def tagged(self, tag: str) -> List[Finding]:
        return [f for f in self.findings if tag in f.tags]


def _rule_cors_sibling_takeover(ix: _Index) -> Optional[Chain]:
    cors = ix.titled(r"CORS trusts any subdomain")
    takeover = ix.module("takeover")
    if not (cors and takeover):
        return None
    pairs = [(c, t) for c in cors for t in takeover
             if _apex(_host_of(c.target)) == _apex(_host_of(t.target))]
    if not pairs:
        return None
    c, t = pairs[0]
    return Chain(
        name="Subdomain takeover into authenticated cross-origin read",
        severity="critical",
        finding_ids=[c.fingerprint(), t.fingerprint()],
        impact=(
            "The application trusts any subdomain of its parent domain for "
            "credentialed cross-origin requests, and %s is a subdomain that can "
            "be claimed. Claiming it turns a medium CORS misconfiguration into "
            "full authenticated read access to %s for every logged-in user - "
            "neither finding reaches that severity alone."
            % (t.target, c.target)),
        steps=[
            "Claim %s at the third-party provider (only if the program permits it)."
            % t.target,
            "Serve a page from it that issues a credentialed fetch to %s." % c.target,
            "Show the authenticated response body being read cross-origin.",
        ])


def _rule_credentials_to_login(ix: _Index) -> Optional[Chain]:
    creds = [f for f in ix.module("exposure")
             if re.search(r"\.env|\.git|appsettings|web\.config|actuator/env|"
                          r"heapdump|\.aws", f.title, re.I)]
    surface = ix.titled(r"admin|login|unlinked administrative|Actuator|"
                        r"introspection|panel")
    if not creds:
        return None
    c = creds[0]
    ids = [c.fingerprint()] + [s.fingerprint() for s in surface[:2]]
    return Chain(
        name="Disclosed credentials into authenticated access",
        severity="critical",
        finding_ids=ids,
        impact=(
            "%s is readable without authentication and contains live "
            "credentials. The value is not the disclosure - it is what the "
            "credentials open. %s Confirm one credential is live against an "
            "identity endpoint, then report; do not use it to reach data."
            % (c.target,
               "An administrative surface was also found on this estate (%s), "
               "which is where to try them." % surface[0].target
               if surface else
               "Identify the service the credential belongs to and confirm it "
               "is accepted.")),
        steps=[
            "Retrieve %s and extract the credential." % c.target,
            "Identify the service it authenticates to.",
            "Confirm it is live with a single identity call and stop.",
        ])


def _rule_redirect_in_auth_flow(ix: _Index) -> Optional[Chain]:
    redirects = [f for f in ix.module("openredirect")
                 if re.search(r"/(oauth|authorize|sso|saml|login|signin|auth)",
                              f.target, re.I)]
    if not redirects:
        return None
    r = redirects[0]
    return Chain(
        name="Open redirect inside an authentication flow",
        severity="high",
        finding_ids=[r.fingerprint()],
        impact=(
            "The redirect sits on an authentication path, which is the "
            "difference between a phishing nuisance and token theft. If the "
            "flow returns an authorization code or token to the redirect "
            "target, it can be delivered to an attacker-controlled origin - "
            "and most programs treat open redirect as out of scope until "
            "exactly that is shown."),
        steps=[
            "Begin the authentication flow with the redirect pointed at your host.",
            "Complete it as a logged-in user.",
            "Capture the code or token arriving at your listener.",
        ])


def _rule_reflection_without_csp(ix: _Index) -> Optional[Chain]:
    refl = [f for f in ix.module("reflection") if f.severity in ("high", "medium")]
    hdrs = ix.module("headers")
    if not refl:
        return None
    no_csp = [h for h in hdrs if "Content-Security-Policy" in (h.detail or "")]
    if not no_csp:
        return None
    pairs = [(r, h) for r in refl for h in no_csp
             if _host_of(r.target) == _host_of(h.target)]
    if not pairs:
        return None
    r, h = pairs[0]
    return Chain(
        name="Reflected input on an origin with no Content-Security-Policy",
        severity="high",
        finding_ids=[r.fingerprint(), h.fingerprint()],
        impact=(
            "Input is reflected with dangerous characters intact, and the "
            "origin sets no CSP. The mitigation that would normally stop a "
            "working payload is absent, so this reflection is considerably "
            "more likely to be exploitable than the reflection finding alone "
            "suggests."),
        steps=[
            "Build a context-appropriate payload for %s." % r.target,
            "Confirm execution in a browser.",
            "Note the absence of CSP as the reason no mitigation applies.",
        ])


def _rule_cookie_theft(ix: _Index) -> Optional[Chain]:
    refl = [f for f in ix.module("reflection") if f.severity == "high"]
    cookies = [f for f in ix.module("cookies") if "HttpOnly" in (f.detail or "")]
    pairs = [(r, c) for r in refl for c in cookies
             if _host_of(r.target) == _host_of(c.target)]
    if not pairs:
        return None
    r, c = pairs[0]
    return Chain(
        name="Script-readable session cookie on an origin with reflected input",
        severity="high",
        finding_ids=[r.fingerprint(), c.fingerprint()],
        impact=(
            "The session cookie is readable from JavaScript and the same origin "
            "reflects input unencoded. Together these turn any working payload "
            "into session theft rather than a scoped action - the cookie flag "
            "is what decides whether an XSS is account takeover."),
        steps=[
            "Confirm the reflection executes on %s." % r.target,
            "Read document.cookie from the payload.",
            "Show the session identifier being exfiltrated.",
        ])


def _rule_ssrf_to_internal(ix: _Index) -> Optional[Chain]:
    ssrf = ix.module("ssrf")
    internal = ix.titled(r"Internal hosts referenced")
    if not (ssrf and internal):
        return None
    s, i = ssrf[0], internal[0]
    return Chain(
        name="Server-side request forgery with named internal targets",
        severity="critical",
        finding_ids=[s.fingerprint(), i.fingerprint()],
        impact=(
            "The application can be made to issue requests of the tester's "
            "choosing, and client-side assets name the internal hosts it "
            "normally talks to. That removes the guesswork from the SSRF: "
            "there is a list of reachable internal services to aim it at, "
            "which is what turns a callback into demonstrated internal access."),
        steps=[
            "Take the internal hostnames from %s." % i.target,
            "Point the SSRF parameter at each in turn.",
            "Record which respond, and how the response differs, to establish "
            "internal reachability. Do not retrieve cloud credentials.",
        ])


def _rule_ai_data_exposure(ix: _Index) -> Optional[Chain]:
    ai = ix.module("aisurface") + ix.module("mcp")
    if len(ai) < 2:
        return None
    return Chain(
        name="Unauthenticated AI stack: inference plus its data layer",
        severity="critical",
        finding_ids=[f.fingerprint() for f in ai[:4]],
        impact=(
            "More than one part of the AI stack is reachable without "
            "authentication (%s). Where an inference endpoint and its vector "
            "store are both open, the indexed corpus is retrievable directly "
            "from the store and extractable through the model, and either can "
            "be poisoned to change what the application tells users."
            % ", ".join(sorted({f.title.split(" exposed")[0] for f in ai})[:4])),
        steps=[
            "List the collections or models on each exposed service.",
            "Show that one document or model name is retrievable without auth.",
            "Stop there - do not read the corpus or run inference at volume.",
        ])


def _rule_listing_to_source(ix: _Index) -> Optional[Chain]:
    listing = ix.module("dirlisting")
    backups = ix.module("backups") + [f for f in ix.module("exposure")
                                      if "backup" in f.title.lower()]
    pairs = [(l, b) for l in listing for b in backups
             if _host_of(l.target) == _host_of(b.target)]
    if not pairs:
        return None
    l, b = pairs[0]
    return Chain(
        name="Directory listing leading to server-side source",
        severity="high",
        finding_ids=[l.fingerprint(), b.fingerprint()],
        impact=(
            "A browsable index on the same origin as a retrievable source file. "
            "The listing is how the rest of the unlinked content is found, and "
            "source disclosure usually carries the database credentials with "
            "it - report the source, citing the listing as the route to it."),
        steps=["Enumerate the listing at %s." % l.target,
               "Retrieve each source-like file it names.",
               "Extract any credentials and confirm one is live."])


RULES: List[Callable[[_Index], Optional[Chain]]] = [
    _rule_cors_sibling_takeover,
    _rule_credentials_to_login,
    _rule_ssrf_to_internal,
    _rule_ai_data_exposure,
    _rule_cookie_theft,
    _rule_reflection_without_csp,
    _rule_redirect_in_auth_flow,
    _rule_listing_to_source,
]


def chains(findings: Sequence[Finding]) -> List[Chain]:
    """Every chain the finding set supports, strongest first."""
    ix = _Index(findings)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    out: List[Chain] = []
    for rule in RULES:
        try:
            chain = rule(ix)
        except Exception:
            continue
        if chain:
            out.append(chain)
    return sorted(out, key=lambda c: order.get(c.severity, 9))
