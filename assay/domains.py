"""Are the domains this application depends on actually registered?

An application that loads a script, frames a page, or allow-lists an origin on
a domain nobody owns is handing an attacker a way in: register the name and you
control whatever the reference grants. Script sources are the worst case -
that is arbitrary JavaScript in the application's own origin.

Registration is checked with two independent signals, because either alone
produces false positives:

  DNS   the apex has no NS records. Necessary but not sufficient - a registered
        domain can be parked with its delegation removed.
  RDAP  the registry itself returns 404 for the object. Authoritative, free,
        and needs no API key or account (RDAP is the IANA-mandated WHOIS
        replacement; rdap.org bootstraps to the right registry automatically).

Only when both agree does assay call a domain unregistered.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit

# Suffixes where the registrable name is one label deeper than the last dot.
# Not the full Public Suffix List - just the ones that actually turn up.
MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.za", "org.za", "net.za", "gov.za",
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "com.ar", "com.co", "com.pe", "com.ve",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.sg", "com.hk", "com.tw", "com.my", "com.ph", "co.th", "co.id",
    "co.kr", "or.kr", "go.kr",
    "com.tr", "com.ua", "com.pl", "com.ru", "com.eg", "com.sa", "com.ng",
    "co.il", "org.il", "gov.il",
}

# Hosts that are never worth checking: infrastructure, standards bodies, and
# the placeholder domains reserved by RFC 2606.
IGNORE_APEXES = {
    "example.com", "example.net", "example.org", "example.edu",
    "localhost", "invalid", "test", "local",
    "w3.org", "schema.org", "ietf.org", "iana.org", "rfc-editor.org",
    "owasp.org", "mitre.org", "nist.gov", "portswigger.net",
}

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def registrable(host: str) -> str:
    """Reduce a hostname to the name someone would register."""
    host = (host or "").strip().lower().rstrip(".").lstrip("*.")
    if not host or _IPV4.match(host) or ":" in host:
        return ""
    parts = host.split(".")
    if len(parts) < 2:
        return ""
    last_two = ".".join(parts[-2:])
    if last_two in MULTI_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


@dataclass
class DomainStatus:
    domain: str
    registered: Optional[bool] = None      # None == could not determine
    ns: List[str] = field(default_factory=list)
    rdap_code: int = 0
    reason: str = ""
    referenced_by: List[str] = field(default_factory=list)
    how: Set[str] = field(default_factory=set)   # script / css / frame / csp / cors / cert / link

    @property
    def takeoverable(self) -> bool:
        return self.registered is False


# --------------------------------------------------------------------------
# Signal 1: DNS delegation
# --------------------------------------------------------------------------


def ns_records(domain: str, timeout: float = 8.0) -> Tuple[List[str], str]:
    """Returns (nameservers, raw status). Empty list means no delegation."""
    for cmd in (["dig", "+short", "+time=3", "+tries=1", "NS", domain],
                ["host", "-t", "NS", domain]):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError):
            continue
        out = (p.stdout or "").strip()
        if p.returncode != 0 and not out:
            continue
        if "NXDOMAIN" in out or "not found" in out.lower():
            return [], "NXDOMAIN"
        servers = [l.strip().rstrip(".") for l in out.splitlines()
                   if l.strip() and not l.startswith(";")
                   and "name server" not in l.lower() or "name server" in l.lower()]
        # `host` prints "domain name server ns1.x."; `dig +short` prints bare names.
        cleaned = []
        for line in out.splitlines():
            line = line.strip().rstrip(".")
            if not line or line.startswith(";"):
                continue
            m = re.search(r"name server\s+(\S+)", line, re.I)
            cleaned.append((m.group(1).rstrip(".") if m else line))
        cleaned = [c for c in cleaned if "." in c and " " not in c]
        return cleaned, "ok" if cleaned else "no-ns"
    return [], "lookup-failed"


# --------------------------------------------------------------------------
# Signal 2: RDAP (free, keyless, authoritative)
# --------------------------------------------------------------------------


def rdap_lookup(domain: str, http) -> Tuple[int, str]:
    """Query the registry via rdap.org's bootstrap. Returns (status, detail)."""
    r = http.get("https://rdap.org/domain/%s" % domain,
                 through_burp=False, timeout=15.0, infra=True)
    if not r.ok:
        return 0, r.error or "no response"
    if r.status == 404:
        return 404, "registry reports no such domain"
    if r.status == 200:
        try:
            doc = json.loads(r.body)
        except ValueError:
            return 200, "registered"
        events = doc.get("events") or []
        when = next((e.get("eventDate", "") for e in events
                     if e.get("eventAction") == "registration"), "")
        status = ", ".join(doc.get("status") or [])
        return 200, "registered%s%s" % (
            " since %s" % when[:10] if when else "",
            " (%s)" % status if status else "")
    return r.status, "RDAP HTTP %d" % r.status


# --------------------------------------------------------------------------
# Combined verdict
# --------------------------------------------------------------------------


def check(domain: str, http) -> DomainStatus:
    st = DomainStatus(domain=domain)
    st.ns, dns_state = ns_records(domain)

    if st.ns:
        st.registered = True
        st.reason = "delegated to %s" % ", ".join(st.ns[:2])
        return st

    # No delegation. That alone is not proof, so ask the registry.
    st.rdap_code, detail = rdap_lookup(domain, http)
    if st.rdap_code == 404:
        st.registered = False
        st.reason = "no NS records and %s" % detail
    elif st.rdap_code == 200:
        st.registered = True
        st.reason = "no NS records but %s - registered and parked" % detail
    else:
        st.registered = None
        st.reason = "no NS records (%s); RDAP inconclusive: %s" % (dns_state, detail)
    return st


# --------------------------------------------------------------------------
# Reference harvesting
# --------------------------------------------------------------------------

REF_PATTERNS: List[Tuple[str, "re.Pattern"]] = [
    ("script", re.compile(r"""<script[^>]+src\s*=\s*["']?([^"'\s>]+)""", re.I)),
    ("css", re.compile(r"""<link[^>]+href\s*=\s*["']?([^"'\s>]+)""", re.I)),
    ("frame", re.compile(r"""<i?frame[^>]+src\s*=\s*["']?([^"'\s>]+)""", re.I)),
    ("form", re.compile(r"""<form[^>]+action\s*=\s*["']?([^"'\s>]+)""", re.I)),
    ("link", re.compile(r"""<a[^>]+href\s*=\s*["']?(https?://[^"'\s>]+)""", re.I)),
    ("preconnect", re.compile(r"""<link[^>]+rel=["']?(?:dns-prefetch|preconnect)["']?[^>]+href=["']?([^"'\s>]+)""", re.I)),
]

CSP_HOST_RE = re.compile(r"(?:https?://)?(\*\.)?([A-Za-z0-9][A-Za-z0-9.-]{2,}\.[A-Za-z]{2,24})")


def refs_from_html(body: str, base_host: str) -> Dict[str, Set[str]]:
    """Map apex domain -> set of reference kinds, for a page's markup."""
    out: Dict[str, Set[str]] = {}
    for kind, rx in REF_PATTERNS:
        for raw in rx.findall(body[:400000]):
            host = urlsplit(raw if raw.startswith("http") else "//" + raw).hostname
            apex = registrable(host or "")
            if not apex or apex == registrable(base_host) or apex in IGNORE_APEXES:
                continue
            out.setdefault(apex, set()).add(kind)
    return out


def refs_from_csp(header_value: str, base_host: str) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for _, host in CSP_HOST_RE.findall(header_value or ""):
        apex = registrable(host)
        if not apex or apex == registrable(base_host) or apex in IGNORE_APEXES:
            continue
        out.setdefault(apex, set()).add("csp")
    return out


def refs_from_hosts(hosts: Iterable[str], base_host: str,
                    kind: str) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for h in hosts:
        apex = registrable(h)
        if not apex or apex == registrable(base_host) or apex in IGNORE_APEXES:
            continue
        out.setdefault(apex, set()).add(kind)
    return out
