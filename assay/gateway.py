"""Detecting a proxy that answers for every address.

Some testing gateways transparently proxy all port 80 and 443 traffic, so every
address in scope answers a TCP connect and returns something - whether or not a
service exists behind it. Left alone that turns a /24 into "250 web endpoints",
and every content check then runs against the proxy's own error page.

The fix does not need a known-dead host to compare against. If a large share of
the probed addresses return effectively the same response, that response is the
gateway's, not two hundred identical applications. The modal response is the
signature, and hosts matching it are dropped.

This is the soft-404 idea moved up a layer: learn what "nothing here" looks
like on this network, then stop reporting it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from assay.models import WebTarget
from assay.net import similarity


# A proxy with nothing behind it says so. These need no clustering and carry
# no risk of mistaking a real server for the gateway.
NO_BACKEND_STATUSES = (502, 503, 504)

# Below this, a body carries no application content worth calling a service.
MIN_BODY_BYTES = 24


def looks_live(status: int, body: str, proxied_port: bool) -> Tuple[bool, str]:
    """Is there actually a service here, or just a proxy answering?

    On a network that proxies every address, a completed TCP connect and even
    an HTTP response prove nothing. What still distinguishes a real service is
    the content: a proxy with no backend returns a gateway error or an empty
    body, while a backend returns its own page.
    """
    if status == 0:
        return False, "no response"
    if status in NO_BACKEND_STATUSES:
        return False, "HTTP %d - proxy has no backend" % status
    body = (body or "").strip()
    if not body:
        return False, "empty response body"
    # A near-empty 200 through a proxy is the proxy. The size rule applies only
    # to 200s: a short 401 or 403 page is a real service protecting itself, and
    # those are precisely the endpoints worth testing for an access-control
    # bypass - filtering them would hide the best leads on the network.
    if status == 200 and len(body) < MIN_BODY_BYTES:
        return False, "200 with no meaningful content"
    return True, ""


@dataclass
class GatewayVerdict:
    detected: bool = False
    signature: str = ""              # short description for the log
    members: List[str] = field(default_factory=list)   # origins that matched
    sample: Optional[WebTarget] = None
    share: float = 0.0

    @property
    def count(self) -> int:
        return len(self.members)


def _fingerprint(wt: WebTarget) -> Tuple:
    """Coarse key: identical status, server, type and near-identical size."""
    return (wt.status, (wt.server or "").split("/")[0].strip().lower(),
            wt.content_type or "", wt.title.strip().lower(),
            len(wt.body_sample or "") // 64)


def detect(web: Sequence[WebTarget], min_hosts: int = 5,
           min_share: float = 0.55, body_threshold: float = 0.93,
           asserted: bool = False) -> GatewayVerdict:
    """Find the response the gateway gives for addresses with nothing behind it.

    Inferred mode requires both a meaningful count and a majority share: five
    identical responses out of six is a proxy, five out of two hundred is a
    load-balanced application pool and must not be touched.

    `asserted` means the operator has told us the ports are proxied, so the
    threshold drops to "more than one host answers identically" - we are no
    longer guessing whether a proxy exists, only which response is its default.
    """
    if asserted:
        # Lower than inferred, but not to the point where two genuinely
        # identical load-balanced nodes would be mistaken for the gateway.
        # Knowing a proxy exists does not tell us which response is its
        # default, so a majority is still required - just a smaller one.
        min_hosts, min_share = 3, 0.5
    verdict = GatewayVerdict()
    # Only compare across distinct hosts; several ports on one host are not
    # evidence of anything.
    by_host: Dict[str, WebTarget] = {}
    for wt in web:
        by_host.setdefault(wt.host, wt)
    if len(by_host) < min_hosts:
        return verdict

    groups: Dict[Tuple, List[WebTarget]] = {}
    for wt in by_host.values():
        groups.setdefault(_fingerprint(wt), []).append(wt)

    key, members = max(groups.items(), key=lambda kv: len(kv[1]))
    share = len(members) / float(len(by_host))
    if len(members) < min_hosts or share < min_share:
        return verdict

    # Confirm the bodies really are the same, not just similarly shaped.
    sample = members[0]
    matching = [m for m in members
                if similarity(m.body_sample or "", sample.body_sample or "")
                >= body_threshold]
    if len(matching) < min_hosts:
        return verdict

    verdict.detected = True
    verdict.sample = sample
    verdict.members = sorted(m.host for m in matching)
    verdict.share = len(matching) / float(len(by_host))
    verdict.signature = "HTTP %d%s%s, %d bytes" % (
        sample.status,
        ", server %s" % sample.server if sample.server else "",
        ", title %r" % sample.title[:40] if sample.title else "",
        len(sample.body_sample or ""))
    return verdict


def filter_web(web: List[WebTarget], verdict: GatewayVerdict) -> List[WebTarget]:
    """Drop endpoints that are only the gateway answering."""
    if not verdict.detected:
        return web
    drop = set(verdict.members)
    return [wt for wt in web if wt.host not in drop]
