"""HTTP engine: rate limiting, scope enforcement, evidence capture, soft-404 baselines.

Every request the tool makes goes through HttpClient so that three things are
guaranteed: the host is in scope, the global rate ceiling is respected, and the
exact bytes are available as evidence for any finding built from the response.
"""

from __future__ import annotations

import random
import re
import string
import threading
import time
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

from assay import tools
from assay.config import Config
from assay.models import Evidence

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_BODY = 512 * 1024
MAX_REDIRECTS = 10
_REDIRECT_CODES = (301, 302, 303, 307, 308)

# Public recon infrastructure. These are not the target, so the scope guard
# must not block them - but they are also the ONLY hosts allowed to bypass it,
# and only when a caller explicitly asks. Everything else goes through scope.
INFRA_HOSTS = {
    "crt.sh", "web.archive.org", "archive.org", "rdap.org", "rdap.iana.org",
    "data.iana.org", "otx.alienvault.com", "urlscan.io", "index.commoncrawl.org",
    "dns.google", "cloudflare-dns.com", "services.nvd.nist.gov",
    # Google API endpoints, exact hosts only (never the bare googleapis.com).
    # Used solely to ask Google whether a key found on the target is accepted;
    # the request goes to Google, not the target. See assay/gmaps.py.
    "maps.googleapis.com", "roads.googleapis.com", "www.googleapis.com",
    "addressvalidation.googleapis.com", "airquality.googleapis.com",
    "aerialview.googleapis.com", "routes.googleapis.com",
    "fcm.googleapis.com", "generativelanguage.googleapis.com",
}


def is_infra(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    return host in INFRA_HOSTS or any(
        host.endswith("." + h) for h in INFRA_HOSTS)


class RateLimiter:
    """Thread-safe token bucket, requests per second.

    The rate can be lowered at runtime: when a target starts returning 429 or
    503 it is telling us we are too fast, and continuing at the configured rate
    risks degrading a production service. Recovery is gradual.
    """

    def __init__(self, rate: float) -> None:
        self.base_rate = max(rate, 0.1)
        self.rate = self.base_rate
        self.capacity = max(rate, 1.0)
        self._tokens = self.capacity
        self._last = time.monotonic()
        self._lock = threading.Lock()
        self.throttled = 0

    def back_off(self, factor: float = 0.5, floor: float = 0.5) -> float:
        """Halve the rate. Returns the new rate."""
        with self._lock:
            self.rate = max(floor, self.rate * factor)
            self.capacity = max(1.0, self.rate)
            self.throttled += 1
            return self.rate

    def recover(self, step: float = 1.15) -> None:
        """Creep back toward the configured rate after a quiet period."""
        with self._lock:
            if self.rate < self.base_rate:
                self.rate = min(self.base_rate, self.rate * step)
                self.capacity = max(1.0, self.rate)

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
    headers: dict[str, str]
    body: str
    elapsed: float
    method: str = "GET"
    request_line: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    history: list[str] = field(default_factory=list)
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


def _infra_headers(cfg: Config) -> dict[str, str]:
    """Headers for a request to recon infrastructure: identification only."""
    return {"User-Agent": cfg.user_agent, "Accept": "*/*",
            "Connection": "close"}


class HttpClient:
    """Thread-safe-ish HTTP client. One requests.Session per worker thread."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.limiter = RateLimiter(cfg.rate)
        # A global ceiling still allows every worker to pile onto one host.
        # The per-host limiter is what actually protects an individual service.
        self._host_limiters: dict[str, RateLimiter] = {}
        self._local = threading.local()
        self._blocked: set = set()
        self._lock = threading.Lock()
        self.count = 0                      # responses received
        self.attempts = 0                   # requests sent, including failures
        self.failures = 0
        self.journal = None                 # set by the engine
        self.throttle_events = 0
        self._last_throttle = 0.0
        self.avoided = 0                    # requests the avoid list dropped
        # Target traffic goes through cfg.proxy; recon infrastructure never
        # does (Burp has no business holding a session for crt.sh).
        self._proxies = ({"http": cfg.proxy, "https": cfg.proxy}
                         if cfg.proxy else {})

    def _host_limiter(self, host: str) -> RateLimiter | None:
        if self.cfg.rate_per_host <= 0:
            return None
        with self._lock:
            lim = self._host_limiters.get(host)
            if lim is None:
                lim = RateLimiter(self.cfg.rate_per_host)
                self._host_limiters[host] = lim
            return lim

    def _note_throttle(self, host: str, resp: Resp) -> float:
        """Target pushed back. Slow down and honour Retry-After if given."""
        with self._lock:
            self.throttle_events += 1
            self._last_throttle = time.monotonic()
        self.limiter.back_off()
        lim = self._host_limiter(host)
        if lim is not None:
            lim.back_off()
        wait = 0.0
        header = resp.header("Retry-After").strip()
        if header:
            try:
                wait = min(float(header), 30.0)
            except ValueError:
                wait = 5.0
        return wait or 2.0

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
        headers: dict[str, str] | None = None,
        data=None,
        allow_redirects: bool = False,
        timeout: float | None = None,
        stream_limit: int = MAX_BODY,
        infra: bool = False,
        canary: bool = False,
    ) -> Resp:
        """`infra=True` marks a lookup against public recon infrastructure.

        It still has to be on the INFRA_HOSTS allowlist; the flag only means
        the caller knows this is not a target host. Nothing else can bypass
        the scope guard.

        `canary=True` is the session canary's own probe: it must get through
        while the scan is paused, since it is what decides to resume it.
        """
        if allow_redirects:
            return self._follow(method, url, headers=headers, data=data,
                                timeout=timeout, stream_limit=stream_limit,
                                infra=infra, canary=canary)
        host = urlsplit(url).hostname or ""
        in_scope = self.cfg.scope.allows(host)
        direct = not in_scope and infra and is_infra(host)
        if not (in_scope or direct):
            with self._lock:
                self._blocked.add(host)
            return Resp(url=url, status=0, headers={}, body="", elapsed=0.0,
                        method=method, error="out-of-scope")
        if not direct and not canary and self.cfg.avoids(url):
            with self._lock:
                self.avoided += 1
            return Resp(url=url, status=0, headers={}, body="", elapsed=0.0,
                        method=method, error="avoided")
        # A paused scan (operator 'p', or the session canary) holds target
        # traffic here too, not only at the next tool launch: a module halfway
        # through a list of URLs would otherwise keep testing a dead session.
        if not direct and not canary:
            tools.wait_while_paused()

        # A direct request goes to public recon infrastructure (NVD, RDAP,
        # the Wayback Machine, Google's key check), not the target, so it
        # carries none of the engagement's session: no cookies, no basic
        # auth, no custom headers, no traffic tag. Only what the caller
        # passed for that service (an NVD API key, say) goes with it.
        hdrs = _infra_headers(self.cfg) if direct else self.cfg.request_headers()
        if headers:
            hdrs.update(headers)

        tmo = timeout or self.cfg.timeout
        attempts = self.cfg.retries + 1
        last_err = ""

        if self.journal is not None:
            self.journal.request(method.upper(), url, hdrs,
                                 data if isinstance(data, str) else "")
        with self._lock:
            self.attempts += 1
        host_limiter = self._host_limiter(host)
        for attempt in range(attempts):
            self.limiter.take()
            if host_limiter is not None:
                host_limiter.take()
            if self.cfg.delay > 0:
                time.sleep(self.cfg.delay * (0.5 + random.random()))
            start = time.monotonic()
            try:
                r = self._session().request(
                    method,
                    url,
                    headers=hdrs,
                    data=data,
                    allow_redirects=False,      # hops go through _follow()
                    timeout=tmo,
                    # --insecure exists for targets' broken certificates.
                    # Third-party services have real ones, and a request to
                    # them may carry an API key, so they are always verified.
                    verify=True if direct else not self.cfg.insecure,
                    stream=True,
                    proxies={} if direct else self._proxies,
                )
                # Reading the raw stream ourselves (rather than r.content /
                # r.iter_content) is what lets stream_limit cap the bytes we
                # ever pull off a slow or enormous body -- but it also means
                # we bypass the exception translation requests normally does
                # inside those helpers, so a body that stops answering mid-read
                # raises urllib3's own ReadTimeoutError/ProtocolError, not
                # requests.exceptions.ReadTimeout. Closed in a finally either
                # way: on hundreds of hosts, a response leaked on every timeout
                # empties this pool of 8 connections fast.
                try:
                    raw = r.raw.read(stream_limit, decode_content=True) or b""
                    body = raw.decode(r.encoding or "utf-8", "replace")
                    elapsed = time.monotonic() - start
                finally:
                    r.close()
                with self._lock:
                    self.count += 1
                    since = time.monotonic() - (self._last_throttle or 0)
                if since > 20:
                    self.limiter.recover()
                    if host_limiter is not None:
                        host_limiter.recover()
                built = Resp(
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
                if built.status in (429, 503):
                    wait = self._note_throttle(host, built)
                    if attempt + 1 < attempts:
                        time.sleep(wait)
                        continue
                return built
            # urllib3.exceptions.HTTPError alongside requests.RequestException:
            # a body read that stops answering mid-stream raises the former
            # (ReadTimeoutError, ProtocolError), not the latter, and it is not
            # a subclass of it -- confirmed against this exact call shape. Left
            # uncaught it skipped every retry and this attempt's backoff,
            # surfaced several layers up as a bare "ReadTimeoutError" with no
            # context, and on a scan with many black-holing hosts read as the
            # whole probe stage stalling rather than one slow candidate.
            except (requests.RequestException, urllib3.exceptions.HTTPError) as exc:
                last_err = type(exc).__name__ + ": " + str(exc)[:160]
                if attempt + 1 < attempts:
                    time.sleep(0.4 * (attempt + 1))

        with self._lock:
            self.failures += 1
        return Resp(url=url, status=0, headers={}, body="", elapsed=0.0,
                    method=method.upper(), error=last_err,
                    request_headers=dict(hdrs),
                    request_line="%s %s HTTP/1.1" % (method.upper(), url))

    def _follow(self, method: str, url: str, **kw) -> Resp:
        """Follow redirects one hop at a time, each through request().

        requests' own redirect handling sends every hop wherever Location
        points, with the engagement's custom headers, and the scope guard
        only ever saw the first URL. Here each hop is a fresh request(), so
        it is scope-checked, rate-limited and journaled like any other. A
        hop that would leave scope is not taken: the redirect itself is the
        answer, which is still a live endpoint.
        """
        hops: list[str] = []
        current, data = url, kw.pop("data", None)
        r = self.request(method, current, data=data, **kw)
        for _ in range(MAX_REDIRECTS):
            location = r.header("Location") if r.ok else ""
            if r.status not in _REDIRECT_CODES or not location:
                break
            nxt = urljoin(current, location)
            if urlsplit(nxt).scheme not in ("http", "https"):
                break
            nxt_host = urlsplit(nxt).hostname or ""
            if not self.cfg.scope.allows(nxt_host) and not (
                    kw.get("infra") and is_infra(nxt_host)):
                with self._lock:
                    self._blocked.add(nxt_host)
                if self.journal is not None:
                    self.journal.note("redirect not followed, out of scope: %s -> %s"
                                      % (current, nxt))
                break
            hops.append(location)
            # 303, and 301/302 after a POST, become a GET without a body,
            # which is what browsers and requests both do.
            if r.status == 303 or (r.status in (301, 302) and method.upper() == "POST"):
                method, data = "GET", None
            current = nxt
            r = self.request(method, current, data=data, **kw)
        r.history = hops + list(r.history)
        return r

    def get(self, url: str, **kw) -> Resp:
        return self.request("GET", url, **kw)

    def head(self, url: str, **kw) -> Resp:
        return self.request("HEAD", url, **kw)

    def post(self, url: str, data=None, **kw) -> Resp:
        return self.request("POST", url, data=data, **kw)

    def close(self) -> None:
        """Release the per-thread connection pools."""
        s = getattr(self._local, "session", None)
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
            self._local.session = None

    def blocked_hosts(self) -> list[str]:
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


@lru_cache(maxsize=128)
def _shingled(body: str) -> frozenset:
    # Baselines are compared against every probed path; normalise each body once.
    return frozenset(shingles(normalize_body(body)))


def similarity(a: str, b: str) -> float:
    """Jaccard similarity over word shingles. 1.0 == effectively identical."""
    sa, sb = _shingled(a), _shingled(b)
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / float(len(sa | sb))


@dataclass
class Baseline:
    """Fingerprint of how an origin answers requests for things that do not exist."""

    origin: str
    statuses: list[int] = field(default_factory=list)
    lengths: list[int] = field(default_factory=list)
    bodies: list[str] = field(default_factory=list)
    titles: list[str] = field(default_factory=list)
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


def rand_token(n: int = 10) -> str:
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))
