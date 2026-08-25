"""Core data model: targets, evidence, findings, and the priority score."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

# --------------------------------------------------------------------------
# Severity / confidence
# --------------------------------------------------------------------------

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Base weight of a finding class, before confidence and context modifiers.
SEVERITY_WEIGHT = {
    "critical": 100.0,
    "high": 70.0,
    "medium": 40.0,
    "low": 15.0,
    "info": 4.0,
}

# How much we trust the detection. Anything below "firm" gets heavily damped so
# tentative pattern matches never outrank a verified issue.
CONFIDENCE_WEIGHT = {
    "confirmed": 1.0,   # independently re-verified with a second, distinct request
    "firm": 0.75,       # deterministic signature, single observation
    "tentative": 0.35,  # heuristic match, needs a human
}

# Buckets shown in the UI. Everything is sorted by score inside its bucket.
TRIAGE_CHASE = "CHASE"    # drop what you are doing
TRIAGE_LOOK = "LOOK"      # worth manual time this session
TRIAGE_NOTE = "NOTE"      # context, chain material, or report padding


def _now() -> float:
    return time.time()


# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------


@dataclass
class Target:
    """A host-level target: an IP or a hostname, plus what we learn about it."""

    raw: str
    host: str
    kind: str = "host"                      # host | url
    ip: Optional[str] = None
    resolved: List[str] = field(default_factory=list)
    ports: List["Port"] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False


@dataclass
class Port:
    port: int
    proto: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""                        # "ssl" when nmap sees TLS
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_tls(self) -> bool:
        return self.tunnel == "ssl" or self.service in ("https", "https-alt", "ssl")


@dataclass
class WebTarget:
    """A live HTTP(S) endpoint worth pointing web modules at."""

    url: str
    host: str
    port: int
    scheme: str
    status: int = 0
    title: str = ""
    server: str = ""
    content_type: str = ""
    length: int = 0
    words: int = 0
    tech: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    body_sample: str = ""
    cert: Dict[str, Any] = field(default_factory=dict)
    redirect_chain: List[str] = field(default_factory=list)
    final_url: str = ""
    # Soft-404 / wildcard fingerprint, filled by net.Baseline.
    baseline: Dict[str, Any] = field(default_factory=dict)
    favicon_hash: Optional[int] = None

    @property
    def origin(self) -> str:
        return "%s://%s:%d" % (self.scheme, self.host, self.port)

    def key(self) -> str:
        return self.origin


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------


@dataclass
class Evidence:
    """Proof attached to a finding. A finding with no evidence is dropped."""

    kind: str                               # http | command | tls | dns | note
    label: str = ""
    request: str = ""
    response: str = ""
    output: str = ""
    matched: str = ""

    def compact(self, limit: int = 1400) -> str:
        parts = []
        if self.request:
            parts.append(self.request.strip())
        if self.response:
            parts.append(self.response.strip())
        if self.output:
            parts.append(self.output.strip())
        blob = "\n\n".join(parts)
        if len(blob) > limit:
            blob = blob[:limit] + "\n... [truncated]"
        return blob


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------


@dataclass
class Finding:
    title: str
    target: str
    severity: str = "info"
    confidence: str = "tentative"
    category: str = ""                      # OWASP bucket, e.g. "A01 Broken Access Control"
    cwe: str = ""
    module: str = ""
    # One sentence on what an attacker actually gets. This is the field that
    # decides whether a finding is worth a report, so modules must fill it.
    impact: str = ""
    detail: str = ""
    repro: str = ""                         # copy-pasteable curl / command
    refs: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    # Extra multipliers applied by scoring(); set by modules when they know more.
    unauth: bool = True                     # reachable with no credentials
    chainable: bool = False                 # useful as a step in a larger chain
    dedupe_key: Optional[str] = None
    created: float = field(default_factory=_now)
    score: float = 0.0
    triage: str = TRIAGE_NOTE
    notes: str = ""

    # -- identity ----------------------------------------------------------
    def fingerprint(self) -> str:
        base = self.dedupe_key or "%s|%s|%s" % (self.module, self.title, self.target)
        return hashlib.sha1(base.encode("utf-8", "replace")).hexdigest()[:16]

    # -- scoring -----------------------------------------------------------
    def compute_score(self) -> float:
        """Priority = how likely this is real x how much it is worth.

        The intent is a single sortable number that puts 'confirmed thing with
        real impact' above 'maybe-something with a scary name'.
        """
        base = SEVERITY_WEIGHT.get(self.severity, 4.0)
        conf = CONFIDENCE_WEIGHT.get(self.confidence, 0.35)
        score = base * conf

        if self.unauth:
            score *= 1.15
        if self.chainable:
            score *= 1.05
        if not self.evidence:
            score *= 0.4
        if not self.impact:
            score *= 0.7
        if "verified" in self.tags:
            score *= 1.2
        if "noise-prone" in self.tags:
            score *= 0.6

        self.score = round(min(score, 150.0), 2)
        self.triage = (
            TRIAGE_CHASE if self.score >= 55
            else TRIAGE_LOOK if self.score >= 22
            else TRIAGE_NOTE
        )
        return self.score

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["id"] = self.fingerprint()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def normalize_url(url: str) -> str:
    if not _SCHEME_RE.match(url):
        url = "https://" + url
    parts = urlsplit(url)
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def host_port_from_url(url: str) -> "tuple":
    parts = urlsplit(url if _SCHEME_RE.match(url) else "https://" + url)
    scheme = parts.scheme or "https"
    port = parts.port or (443 if scheme == "https" else 80)
    return parts.hostname or "", port, scheme
