"""Keeping an authenticated scan honest about whether it is still logged in.

assay never logs in itself. The session belongs to Burp: a session handling
rule scoped to Proxy checks each request, runs a login macro when the session
has expired, and puts fresh cookies on the request before it leaves. assay
only sends its traffic through Burp (--proxy) and watches the result.

Watching is the part that matters. When Burp's macro stops working - the
password rotated, the login form gained a CAPTCHA, the rule was never scoped
to Proxy - nothing errors. Every request still gets a 200, it is just the
login page, and a scan that does not notice spends hours testing it and
reports whatever the login page happens to do as findings about the app.

The canary is one page only a logged-in user sees, fetched on a timer. While
it looks logged out the scan is paused (tools.PAUSE, the same pause the
operator's 'p' key sets) and the operator is pinged. When it recovers -
someone fixed the macro, or logged in again in the browser - the scan resumes
by itself, but only if it was the canary that paused it.
"""

from __future__ import annotations

import os
import re
import socket
import threading
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from assay import tools
from assay.burpimport import looks_unauthenticated, seed_urls

# A logged-out canary is checked once more after this long before the scan is
# paused, so one request that raced Burp's re-login does not stop anything.
RECHECK_SECONDS = 5.0
# While paused, how often to look for the session coming back.
PAUSED_POLL_SECONDS = 15.0


def logged_in(resp, expect: str = "") -> tuple[bool, str]:
    """Does this canary response look like a logged-in page? (ok, reason)"""
    if resp.status == 0:
        if resp.error == "avoided":
            return False, "the canary URL is on the avoid list - pick another page"
        return False, "no response (%s) - is the proxy still running?" % (
            resp.error or "connection failed")
    if resp.status in (401, 403, 407):
        return False, "HTTP %d" % resp.status
    if 300 <= resp.status < 400:
        return False, "HTTP %d redirect to %s" % (
            resp.status, resp.header("Location") or "?")
    if expect:
        if re.search(expect, resp.body or ""):
            return True, "HTTP %d, expected content present" % resp.status
        return False, "HTTP %d but the expected content is missing" % resp.status
    if looks_unauthenticated(resp.body or "", resp.status):
        return False, "HTTP %d looks like a login page" % resp.status
    return True, "HTTP %d" % resp.status


def proxy_reachable(proxy: str, timeout: float = 5.0) -> str | None:
    """None when something is listening at the proxy address, else why not."""
    parts = urlsplit(proxy if "://" in proxy else "http://" + proxy)
    host = parts.hostname
    if not host:
        return "cannot read a host out of %r" % proxy
    try:
        port = parts.port or (443 if parts.scheme == "https" else 8080)
    except ValueError:
        return "bad port in %r" % proxy
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return None
    except OSError as exc:
        return "%s:%d is not accepting connections (%s)" % (
            host, port, exc.strerror or type(exc).__name__)


def preflight(cfg, http=None) -> list[str]:
    """Problems that make an authenticated scan pointless, found before it starts.

    Each is something that would otherwise surface hours in as a scan of the
    login page: Burp not listening, a canary that is not actually logged in,
    a seed file with nothing in it.
    """
    problems: list[str] = []
    if cfg.proxy:
        err = proxy_reachable(cfg.proxy)
        if err:
            problems.append(
                "proxy %s: %s. Is Burp running, and is its listener bound to "
                "all interfaces (Proxy > Proxy settings > Listeners)? From WSL "
                "in NAT mode the Windows firewall must also allow the port."
                % (cfg.proxy, err))
    if cfg.session_expect:
        try:
            re.compile(cfg.session_expect)
        except re.error as exc:
            problems.append("--session-expect is not a valid regex: %s" % exc)
    if cfg.session_check:
        host = urlsplit(cfg.session_check).hostname or ""
        if not host:
            problems.append("--session-check needs a full URL, got %r"
                            % cfg.session_check)
        elif not cfg.scope.allows(host):
            problems.append("--session-check host %s is not in scope" % host)
    for path in cfg.seeds:
        if not os.path.isfile(path):
            problems.append("--seed %s: no such file" % path)
            continue
        found, _ = seed_urls(path)
        if not found:
            problems.append("--seed %s: no GET URLs found (expected a Burp XML "
                            "export or a HAR file)" % path)
    if problems or not cfg.session_check:
        return problems
    if http is None:
        from assay.net import HttpClient
        http = HttpClient(cfg)
    r = http.request("GET", cfg.session_check, allow_redirects=False, canary=True)
    ok, why = logged_in(r, cfg.session_expect)
    if not ok:
        hint = ("Check that Burp's session handling rule has Proxy ticked in its "
                "tool scope and that its login macro succeeds (Settings > "
                "Sessions > Macros > Test macro)." if cfg.proxy else
                "Is the --cookie value current?")
        problems.append("not logged in at %s before the scan started: %s. %s"
                        % (cfg.session_check, why, hint))
    return problems


class SessionCanary:
    """Background watcher that pauses the scan while the session is gone."""

    def __init__(self, http, url: str, expect: str = "",
                 interval: float = 60.0,
                 say: Callable[[str, str], None] | None = None,
                 notify: Callable[[str], object] | None = None,
                 note: Callable[[str], None] | None = None) -> None:
        self.http = http
        self.url = url
        self.expect = expect
        self.interval = max(5.0, float(interval or 60.0))
        self._say = say or (lambda stage, msg: None)
        self._notify = notify or (lambda text: None)
        self._note = note or (lambda text: None)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.paused_by_us = False
        self.checks = 0
        # (started, ended) wall-clock pairs; ended is None while still out.
        self.outages: list[list[float | None]] = []

    def check(self) -> tuple[bool, str]:
        self.checks += 1
        r = self.http.request("GET", self.url, allow_redirects=False, canary=True)
        return logged_in(r, self.expect)

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="assay-canary",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        self._release()
        if self.outages and self.outages[-1][1] is None:
            self.outages[-1][1] = time.time()

    def _loop(self) -> None:
        while not self._stop.wait(PAUSED_POLL_SECONDS if self.paused_by_us
                                  else self.interval):
            self.tick()

    # -- one step, separate from the thread so it can be driven directly -------
    def tick(self, recheck_wait: float = RECHECK_SECONDS) -> bool:
        """Check once and pause or resume accordingly. Returns logged-in."""
        ok, why = self.check()
        if not ok and not self.paused_by_us:
            # One retry before acting: Burp may have been mid re-login.
            if self._stop.wait(recheck_wait):
                return ok
            ok, why = self.check()
        if ok:
            if self.paused_by_us:
                self._release()
                self.outages[-1][1] = time.time()
                mins = (self.outages[-1][1] - self.outages[-1][0]) / 60.0
                self._say("session", "session is back (%s) - resuming after "
                                     "%.1f min paused" % (why, mins))
                self._note("session canary: session restored, scan resumed")
            return True
        if not self.paused_by_us:
            # Already paused by the operator: hold it for them too, so their
            # 'r' does not resume into a dead session without a word.
            tools.PAUSE.set()
            self.paused_by_us = True
            self.outages.append([time.time(), None])
            msg = ("logged out at %s: %s. Scan PAUSED - fix the Burp session "
                   "macro or log in again; it resumes when the canary passes"
                   % (self.url, why))
            self._say("session", msg)
            self._note("session canary: " + msg)
            self._notify(msg)
        elif not tools.PAUSE.is_set():
            # The operator pressed 'r' while still logged out. Hold the pause.
            tools.PAUSE.set()
            self._say("session", "still logged out (%s) - staying paused" % why)
        return False

    def _release(self) -> None:
        if self.paused_by_us:
            tools.PAUSE.clear()
            self.paused_by_us = False

    def summary(self) -> str:
        if not self.outages:
            return "session held for the whole scan (%d check(s))" % self.checks
        total = sum((end or time.time()) - start for start, end in self.outages)
        return ("session lost %d time(s), %.1f min paused in total - findings "
                "from just before each pause deserve a second look"
                % (len(self.outages), total / 60.0))
