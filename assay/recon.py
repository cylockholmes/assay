"""Attack-surface expansion: subdomains, virtual hosts, and origin exposure.

Split by what each technique touches, because that decides whether it may run
on an engagement by default:

  passive     third-party archives and CT logs. Never touches the target, but
              does tell a third party what you are looking at. --passive only.
  permutation generated candidate names resolved against DNS. Touches the
              target's resolvers only.
  vhost       Host-header probing against IPs already in scope. Touches the
              target, finds surface no DNS name ever pointed at.
  origin      direct-to-IP requests that bypass a CDN or WAF. The highest-value
              of the four: an exposed origin is unfiltered access to the app.
"""

from __future__ import annotations

import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Set, Tuple

from assay import tools
from assay.net import HttpClient, Resp, similarity, rand_token

# Environment prefixes/suffixes that reliably exist when the apex does.
PERMUTATIONS = [
    "dev", "development", "staging", "stage", "stg", "test", "testing", "qa",
    "uat", "preprod", "pre", "demo", "sandbox", "internal", "int", "corp",
    "admin", "api", "api-dev", "api-staging", "app", "portal", "beta",
    "old", "new", "legacy", "backup", "vpn", "mail", "git", "jenkins",
    "grafana", "kibana", "jira", "confluence", "status", "monitor",
]

# Headers that identify a CDN/WAF sitting in front of the real origin.
CDN_MARKERS = [
    ("cloudflare", re.compile(r"cloudflare|cf-ray|__cfduid", re.I)),
    ("akamai", re.compile(r"akamai|x-akamai|akamaighost", re.I)),
    ("fastly", re.compile(r"fastly|x-served-by.*cache", re.I)),
    ("cloudfront", re.compile(r"cloudfront|x-amz-cf-id", re.I)),
    ("incapsula", re.compile(r"incap_ses|visid_incap|x-iinfo", re.I)),
    ("sucuri", re.compile(r"sucuri|x-sucuri", re.I)),
]


def detect_cdn(resp: Resp) -> str:
    blob = "\n".join("%s: %s" % kv for kv in resp.headers.items())
    for name, rx in CDN_MARKERS:
        if rx.search(blob):
            return name
    return ""


# --------------------------------------------------------------------------
# Passive sources
# --------------------------------------------------------------------------


def crtsh_subdomains(domain: str, http: HttpClient,
                     limit: int = 500) -> List[str]:
    """Certificate transparency logs. Third-party lookup - passive mode only."""
    url = "https://crt.sh/?q=%%25.%s&output=json" % domain
    r = http.get(url, through_burp=False, timeout=30.0, infra=True)
    if not r.ok or r.status != 200:
        return []
    try:
        rows = json.loads(r.body)
    except ValueError:
        return []
    found: Set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for name in str(row.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain) and "@" not in name:
                found.add(name)
        if len(found) >= limit:
            break
    return sorted(found)


def passive_subdomains(domain: str, http: HttpClient, limit: int = 500) -> Tuple[List[str], str]:
    if tools.have("subfinder"):
        got = tools.subfinder_enum(domain)
        if got:
            return sorted({g.strip().lower() for g in got})[:limit], "subfinder"
    got = crtsh_subdomains(domain, http, limit)
    return got, "crt.sh" if got else ""


# --------------------------------------------------------------------------
# Permutation + resolution
# --------------------------------------------------------------------------


def permute(known: Iterable[str], apex: str, cap: int = 400) -> List[str]:
    """Generate plausible sibling names from an apex and any known hosts."""
    out: Set[str] = set()
    for word in PERMUTATIONS:
        out.add("%s.%s" % (word, apex))
    for host in list(known)[:40]:
        if not host.endswith(apex) or host == apex:
            continue
        label = host[: -(len(apex) + 1)]
        if not label or "." in label:
            continue
        for word in PERMUTATIONS[:16]:
            out.add("%s-%s.%s" % (label, word, apex))
            out.add("%s-%s.%s" % (word, label, apex))
    return sorted(out)[:cap]


def resolve_bulk(hosts: List[str], workers: int = 16) -> Dict[str, str]:
    """Resolve many names. Uses dnsx when available, else threaded getaddrinfo."""
    if not hosts:
        return {}
    if tools.have("dnsx"):
        out: Dict[str, str] = {}
        for obj in tools.dnsx_resolve(hosts):
            host = obj.get("host")
            a = obj.get("a") or []
            if host and a:
                out[host] = a[0]
        if out:
            return out

    def one(h: str) -> Tuple[str, str]:
        try:
            return h, socket.gethostbyname(h)
        except (socket.gaierror, OSError):
            return h, ""

    found: Dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in as_completed([pool.submit(one, h) for h in hosts]):
            h, ip = fut.result()
            if ip:
                found[h] = ip
    return found


def wildcard_ips(apex: str) -> Set[str]:
    """IPs a wildcard record resolves to, so we can discard them."""
    ips: Set[str] = set()
    for _ in range(2):
        probe = "assay%s.%s" % (rand_token(10), apex)
        try:
            ips.add(socket.gethostbyname(probe))
        except (socket.gaierror, OSError):
            pass
    return ips


# --------------------------------------------------------------------------
# Virtual hosts
# --------------------------------------------------------------------------


def vhost_probe(http: HttpClient, base_url: str, candidates: List[str],
                workers: int = 8) -> List[Tuple[str, Resp]]:
    """Find hostnames this IP serves differently from its default response.

    A vhost only counts when its response diverges from BOTH the default
    response and the response to a random nonexistent hostname. Comparing
    against one baseline alone reports every host on a catch-all server.
    """
    default = http.get(base_url)
    junk = http.get(base_url, headers={"Host": "assay%s.invalid" % rand_token(8)})
    if not default.ok:
        return []

    def check(name: str) -> Optional[Tuple[str, Resp]]:
        r = http.get(base_url, headers={"Host": name})
        if not r.ok or r.status in (0, 429) or r.status >= 500:
            return None
        if similarity(r.body, default.body) > 0.90:
            return None
        if junk.ok and similarity(r.body, junk.body) > 0.90:
            return None
        return name, r

    hits: List[Tuple[str, Resp]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in as_completed([pool.submit(check, n) for n in candidates]):
            got = fut.result()
            if got:
                hits.append(got)
    return hits


# --------------------------------------------------------------------------
# Origin exposure behind a CDN
# --------------------------------------------------------------------------


def origin_exposed(http: HttpClient, hostname: str, ip: str,
                   scheme: str = "https") -> Optional[Tuple[Resp, Resp]]:
    """Does connecting straight to the IP serve the same application?

    If it does, the CDN/WAF in front of the hostname is bypassable, which
    removes rate limiting, IP allow-listing and every WAF rule at once.
    """
    via_cdn = http.get("%s://%s/" % (scheme, hostname))
    if not via_cdn.ok:
        return None
    if not detect_cdn(via_cdn):
        return None
    direct = http.get("%s://%s/" % (scheme, ip), headers={"Host": hostname})
    if not direct.ok or direct.status >= 500:
        return None
    # Same application, but no CDN markers on the direct response.
    if similarity(direct.body, via_cdn.body) < 0.80:
        return None
    if detect_cdn(direct):
        return None
    return via_cdn, direct


# --------------------------------------------------------------------------
# CDN bypass: finding the origin behind the edge
# --------------------------------------------------------------------------

# Published edge ranges. A candidate inside one of these is the CDN itself,
# not the origin, so testing it is wasted effort.
CDN_RANGES = [
    # Cloudflare IPv4
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    # Fastly
    "151.101.0.0/16", "199.232.0.0/16", "23.235.32.0/20", "43.249.72.0/22",
    # Akamai (partial, the commonly seen blocks)
    "23.32.0.0/11", "23.64.0.0/14", "104.64.0.0/10", "184.24.0.0/13",
    "2.16.0.0/13", "95.100.0.0/15",
    # AWS CloudFront (partial)
    "13.32.0.0/15", "13.35.0.0/16", "52.84.0.0/15", "54.192.0.0/16",
    "99.86.0.0/16", "205.251.192.0/19",
    # Incapsula / Imperva
    "199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21", "45.64.64.0/22",
]

_CDN_NETS = []
for _c in CDN_RANGES:
    try:
        import ipaddress as _ip
        _CDN_NETS.append(_ip.ip_network(_c))
    except ValueError:
        pass

# Hostnames that commonly resolve straight to the origin because nobody
# remembered to proxy them.
ORIGIN_LABELS = [
    "origin", "origin-www", "direct", "direct-connect", "real", "backend",
    "server", "host", "cpanel", "webmail", "mail", "smtp", "ftp", "ssh",
    "vpn", "remote", "portal-origin", "www-origin", "old", "legacy",
    "staging", "dev", "test", "api-origin", "internal", "corp",
]


def is_cdn_ip(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _CDN_NETS)


def _dig(record: str, name: str, timeout: float = 8.0) -> List[str]:
    import subprocess
    try:
        p = subprocess.run(["dig", "+short", "+time=3", "+tries=1", record, name],
                           capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return []
    return [l.strip().rstrip(".") for l in (p.stdout or "").splitlines()
            if l.strip() and not l.startswith(";")]


def spf_ips(domain: str) -> List[str]:
    """IPs authorised to send mail. Mail usually leaves from the real origin."""
    out: List[str] = []
    for txt in _dig("TXT", domain):
        if "v=spf1" not in txt.lower():
            continue
        for m in re.finditer(r"ip4:(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?", txt):
            ip, prefix = m.group(1), m.group(2)
            # A /32 or bare address is a specific host; wider blocks are ranges
            # we do not want to enumerate here.
            if not prefix or prefix == "32":
                out.append(ip)
    return out


def mx_ips(domain: str) -> List[str]:
    import socket
    out: List[str] = []
    for line in _dig("MX", domain):
        parts = line.split()
        host = parts[-1] if parts else ""
        if not host:
            continue
        try:
            out.append(socket.gethostbyname(host))
        except (socket.gaierror, OSError):
            continue
    return out


def origin_candidates(hostname: str, known_hosts: Iterable[str],
                      workers: int = 12) -> Dict[str, str]:
    """Gather plausible origin IPs and say where each came from.

    Sources, in rough order of how often they pay off: sibling hostnames that
    were never put behind the edge, the mail infrastructure, and the SPF
    record. All of these read the target's own DNS - no third party involved.
    """
    import socket
    parts = hostname.split(".")
    if len(parts) < 2:
        return {}
    apex = ".".join(parts[-2:])

    candidates: Dict[str, str] = {}

    def add(ip: str, source: str) -> None:
        if ip and not is_cdn_ip(ip) and ip not in candidates:
            candidates[ip] = source

    names = ["%s.%s" % (label, apex) for label in ORIGIN_LABELS]
    names += [h for h in known_hosts if h.endswith(apex)]

    def resolve(n: str) -> Tuple[str, str]:
        try:
            return n, socket.gethostbyname(n)
        except (socket.gaierror, OSError):
            return n, ""

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for fut in as_completed([pool.submit(resolve, n) for n in set(names)]):
            name, ip = fut.result()
            if ip:
                add(ip, "DNS: %s" % name)

    for ip in mx_ips(apex):
        add(ip, "MX record for %s" % apex)
    for ip in spf_ips(apex):
        add(ip, "SPF record for %s" % apex)
    return candidates


def confirm_origin(http, hostname: str, ip: str, scheme: str,
                   edge: Resp) -> Optional[Resp]:
    """Does this IP serve the same application without the edge in front?"""
    direct = http.get("%s://%s/" % (scheme, ip), headers={"Host": hostname},
                      timeout=8.0)
    if not direct.ok or direct.status >= 500:
        return None
    if detect_cdn(direct):
        return None
    if similarity(direct.body, edge.body) < 0.80:
        return None
    return direct
