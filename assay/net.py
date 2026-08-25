"""HTTP engine: rate limiting, scope enforcement, evidence capture, soft-404 baselines.

Every request the tool makes goes through HttpClient so that three things are
guaranteed: the host is in scope, the global rate ceiling is respected, and the
exact bytes are available as evidence for any finding built from the response.
"""

from __future__ import annotations

import hashlib
import random
import re
import string
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import requests
import urllib3

from assay.config import Config
from assay.models import Evidence

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_BODY = 512 * 1024

# Public recon infrastructure. These are not the target, so the scope guard
# must not block them - but they are also the ONLY hosts allowed to bypass it,
# and only when a caller explicitly asks. Everything else goes through scope.
INFRA_HOSTS = {
    "crt.sh", "web.archive.org", "archive.org", "rdap.org", "rdap.iana.org",
    "data.iana.org", "otx.alienvault.com", "urlscan.io", "index.commoncrawl.org",
    "dns.google", "cloudflare-dns.com",
}


def is_infra(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    return host in INFRA_HOSTS or any(
        host.endswith("." + h) for h in INFRA_HOSTS)


class RateLimiter:
    """Simple thread-safe token bucket, requests per second."""

    def __init__(self, rate: float) -> None:
        self.rate = max(rate, 0.1)
        self.capacity = max(rate, 1.0)
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def take(self, n: float = 1.0) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= n:
                    self._tokens -= n
                    return
                deficit = (n - self._tokens) / self.rate
            time.sleep(min(deficit, 1.0))


@dataclass
class Resp:
    """A normalized response plus the raw text needed to prove a finding."""

    url: str
    status: int
    headers: Dict[str, str]
    body: str
    elapsed: float
    method: str = "GET"
    request_line: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    history: List[str] = field(default_factory=list)
    error: str = ""
    raw_len: int = 0

    @property
    def ok(self) -> bool:
        return self.status > 0 and not self.error

    def header(self, name: str, default: str = "") -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    @property
    def title(self) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", self.body, re.I | re.S)
        return re.sub(r"\s+", " ", m.group(1)).strip()[:120] if m else ""

    @property
    def content_type(self) -> str:
        return self.header("Content-Type").split(";")[0].strip().lower()

    def request_text(self) -> str:
        lines = [self.request_line or "%s %s HTTP/1.1" % (self.method, self.url)]
        for k, v in self.request_headers.items():
            lines.append("%s: %s" % (k, v))
        if self.request_body:
            lines.append("")
            lines.append(self.request_body[:800])
        return "\n".join(lines)

    def response_text(self, body_limit: int = 900) -> str:
        lines = ["HTTP/1.1 %d" % self.status]
        for k, v in self.headers.items():
            lines.append("%s: %s" % (k, v))
        if self.body:
            lines.append("")
            lines.append(self.body[:body_limit])
        return "\n".join(lines)

    def evidence(self, label: str = "", matched: str = "", body_limit: int = 900) -> Evidence:
        return Evidence(
            kind="http",
            label=label or "%s %s -> %d" % (self.method, self.url, self.status),
            request=self.request_text(),
            response=self.response_text(body_limit),
            matched=matched,
        )

    def curl(self, insecure: bool = True) -> str:
        parts = ["curl -sSi"]
        if insecure:
            parts.append("-k")
        if self.method != "GET":
            parts.append("-X %s" % self.method)
        skip = {"accept-encoding", "connection", "content-length", "host"}
        for k, v in self.request_headers.items():
            if k.lower() in skip:
                continue
            parts.append("-H %s" % _shq("%s: %s" % (k, v)))
        if self.request_body:
            parts.append("--data-raw %s" % _shq(self.request_body[:300]))
        parts.append(_shq(self.url))
        return " ".join(parts)


def _shq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


class HttpClient:
    """Thread-safe-ish HTTP client. One requests.Session per worker thread."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.limiter = RateLimiter(cfg.rate)
        self._local = threading.local()
        self._blocked: set = set()
        self._lock = threading.Lock()
        self.count = 0

    # -- session ----------------------------------------------------------
    def _session(self) -> requests.Session:
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session()
            s.trust_env = False
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=8, pool_maxsize=8, max_retries=0
            )
            s.mount("http://", adapter)
            s.mount("https://", adapter)
            self._local.session = s
        return s

    # -- core -------------------------------------------------------------
    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data=None,
        allow_redirects: bool = False,
        timeout: Optional[float] = None,
        through_burp: bool = True,
        stream_limit: int = MAX_BODY,
        infra: bool = False,
    ) -> Resp:
        """`infra=True` marks a lookup against public recon infrastructure.

        It still has to be on the INFRA_HOSTS allowlist; the flag only means
        the caller knows this is not a target host. Nothing else can bypass
        the scope guard.
        """
        host = urlsplit(url).hostname or ""
        allowed = self.cfg.scope.allows(host) or (infra and is_infra(host))
        if not allowed:
            with self._lock:
                self._blocked.add(host)
            return Resp(url=url, status=0, headers={}, body="", elapsed=0.0,
                        method=method, error="out-of-scope")

        hdrs = self.cfg.request_headers()
        if headers:
            hdrs.update(headers)

        proxies = self.cfg.burp.proxies() if (through_burp and self.cfg.burp.proxy) else None
        tmo = timeout or self.cfg.timeout
        attempts = self.cfg.retries + 1
        last_err = ""

        for attempt in range(attempts):
            self.limiter.take()
            start = time.monotonic()
            try:
                r = self._session().request(
                    method,
                    url,
                    headers=hdrs,
                    data=data,
                    allow_redirects=allow_redirects,
                    timeout=tmo,
                    verify=not self.cfg.insecure,
                    proxies=proxies,
                    stream=True,
                )
                raw = r.raw.read(stream_limit, decode_content=True) or b""
                body = raw.decode(r.encoding or "utf-8", "replace")
                elapsed = time.monotonic() - start
                r.close()
                with self._lock:
                    self.count += 1
                return Resp(
                    url=r.url,
                    status=r.status_code,
                    headers=dict(r.headers),
                    body=body,
                    elapsed=elapsed,
                    method=method.upper(),
                    request_line="%s %s HTTP/1.1" % (method.upper(), url),
                    request_headers=dict(hdrs),
                    request_body=data if isinstance(data, str) else "",
                    history=[h.headers.get("Location", h.url) for h in r.history],
                    raw_len=len(raw),
                )
            except requests.RequestException as exc:
                last_err = type(exc).__name__ + ": " + str(exc)[:160]
                if attempt + 1 < attempts:
                    time.sleep(0.4 * (attempt + 1))

        return Resp(url=url, status=0, headers={}, body="", elapsed=0.0,
                    method=method.upper(), error=last_err,
                    request_headers=dict(hdrs),
                    request_line="%s %s HTTP/1.1" % (method.upper(), url))

    def get(self, url: str, **kw) -> Resp:
        return self.request("GET", url, **kw)

    def head(self, url: str, **kw) -> Resp:
        return self.request("HEAD", url, **kw)

    def post(self, url: str, data=None, **kw) -> Resp:
        return self.request("POST", url, data=data, **kw)

    def blocked_hosts(self) -> List[str]:
        with self._lock:
            return sorted(self._blocked)


# --------------------------------------------------------------------------
# Soft-404 / wildcard baselines -- the single biggest false-positive killer
# --------------------------------------------------------------------------

_NOISE = re.compile(
    r"(?:[0-9a-f]{16,}|\d{4,}|csrf[^\"'<>]{0,40}|nonce[^\"'<>]{0,40}|"
    r"\d{2}:\d{2}:\d{2}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    re.I,
)


def normalize_body(body: str) -> str:
    body = _NOISE.sub("", body or "")
    return re.sub(r"\s+", " ", body).strip().lower()


def shingles(text: str, k: int = 5) -> set:
    toks = text.split()
    if len(toks) < k:
        return set(toks)
    return {" ".join(toks[i:i + k]) for i in range(0, len(toks) - k + 1, 2)}


def similarity(a: str, b: str) -> float:
    """Jaccard similarity over word shingles. 1.0 == effectively identical."""
    sa, sb = shingles(normalize_body(a)), shingles(normalize_body(b))
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / float(len(sa | sb))


@dataclass
class Baseline:
    """Fingerprint of how an origin answers requests for things that do not exist."""

    origin: str
    statuses: List[int] = field(default_factory=list)
    lengths: List[int] = field(default_factory=list)
    bodies: List[str] = field(default_factory=list)
    titles: List[str] = field(default_factory=list)
    soft404: bool = False                  # returns 200 for nonsense paths
    dynamic: bool = False                  # two nonsense paths differ -> length checks unreliable

    def is_noise(self, resp: Resp, threshold: float = 0.92) -> bool:
        """True when a response looks like the origin's catch-all page."""
        if not resp.ok:
            return True
        if resp.status in (429, 503) or resp.status >= 500:
            return True
        if self.soft404 and resp.status == 200:
            for body in self.bodies:
                if similarity(resp.body, body) >= threshold:
                    return True
            # Same status and near-identical size as the catch-all.
            for ln in self.lengths:
                if ln and abs(len(resp.body) - ln) <= max(24, ln * 0.02):
                    return True
        if resp.status in self.statuses and resp.status in (401, 403):
            # Blanket auth wall: every path answers the same, so a 403 here
            # tells us nothing about whether the path exists.
            for body in self.bodies:
                if similarity(resp.body, body) >= threshold:
                    return True
        return False


def build_baseline(http: HttpClient, origin: str, probes: int = 3) -> Baseline:
    bl = Baseline(origin=origin)
    for _ in range(probes):
        junk = "".join(random.choice(string.ascii_lowercase) for _ in range(14))
        r = http.get("%s/%s.html" % (origin.rstrip("/"), junk))
        if not r.ok:
            continue
        bl.statuses.append(r.status)
        bl.lengths.append(len(r.body))
        bl.bodies.append(r.body[:20000])
        bl.titles.append(r.title)
    if bl.statuses:
        bl.soft404 = any(s == 200 for s in bl.statuses)
        if len(bl.bodies) >= 2:
            bl.dynamic = similarity(bl.bodies[0], bl.bodies[1]) < 0.9
    return bl


def body_hash(body: str) -> str:
    return hashlib.sha1(normalize_body(body).encode("utf-8", "replace")).hexdigest()[:12]


def rand_token(n: int = 10) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))
