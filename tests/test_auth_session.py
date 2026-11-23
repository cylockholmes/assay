"""Authenticated scanning through Burp: proxy, session canary, seeds, avoid list.

Offline only. The proxy is never contacted - requests.Session is replaced with
a recorder, socket.create_connection with a stub, and every external tool's
spawn with a function that captures the argv it would have run.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, __file__.rsplit("/tests/", 1)[0])

from assay import env, session, tools
from assay.config import Config, Scope
from assay.net import HttpClient, Resp
from tests.stub import StubHttp, web_target

LOGIN_PAGE = ('<html><form action="/login" method=post>'
              '<input name=password type=password></form></html>')
ACCOUNT_PAGE = "<html><h1>My account</h1><a href=/logout>Sign out</a></html>"


def _authed_cfg(**kw) -> Config:
    kw.setdefault("cookies", "sid=abc")
    kw.setdefault("out_dir", tempfile.mkdtemp())
    return Config(**kw)


class _Globals(unittest.TestCase):
    """Reset the run-wide tool globals and the pause around every test."""

    def setUp(self):
        self._saved = (tools.PROXY, tools.AVOID)
        tools.PAUSE.clear()
        tools.SKIP.clear()

    def tearDown(self):
        tools.PROXY, tools.AVOID = self._saved
        tools.PAUSE.clear()
        tools.SKIP.clear()


# --------------------------------------------------------------------------
# avoid list
# --------------------------------------------------------------------------


class AvoidListTests(unittest.TestCase):
    def test_defaults_catch_session_and_state_changing_paths(self):
        cfg = _authed_cfg()
        for url in ("https://app.test/logout",
                    "https://app.test/auth/log-off?next=/",
                    "https://app.test/Account/SignOut",
                    "https://app.test/delete",
                    "https://app.test/api/users/42/delete",
                    "https://app.test/item?action=delete&id=4",
                    "https://app.test/user_remove",
                    "https://app.test/settings/change-password",
                    "https://app.test/password/reset",
                    "https://app.test/oauth/revoke"):
            self.assertTrue(cfg.avoids(url), url)

    def test_lookalikes_are_not_avoided(self):
        cfg = _authed_cfg()
        for url in ("https://app.test/",
                    "https://app.test/deleted-items",
                    "https://app.test/blog/removed",
                    "https://catalog-offers.app.test/products",
                    "https://app.test/account",
                    "https://app.test/disabled-features"):
            self.assertFalse(cfg.avoids(url), url)

    def test_not_applied_without_a_session(self):
        cfg = Config(out_dir=tempfile.mkdtemp())
        self.assertFalse(cfg.authenticated)
        self.assertFalse(cfg.avoids("https://app.test/logout"))

    def test_proxy_alone_counts_as_authenticated(self):
        cfg = Config(out_dir=tempfile.mkdtemp(), proxy="http://127.0.0.1:8080")
        self.assertTrue(cfg.avoids("https://app.test/logout"))

    def test_custom_and_disabled_defaults(self):
        cfg = _authed_cfg(avoid=[r"/billing/"], avoid_defaults=False)
        self.assertTrue(cfg.avoids("https://app.test/billing/pay"))
        self.assertFalse(cfg.avoids("https://app.test/logout"))

    def test_katana_regex_is_anchored_past_the_host(self):
        from assay.engine import Engine
        eng = types.SimpleNamespace(cfg=_authed_cfg())
        rx = re.compile(Engine._katana_avoid(eng))
        self.assertTrue(rx.search("https://app.test/delete"))
        self.assertTrue(rx.search("https://app.test/a/LOGOUT?x=1"))
        self.assertTrue(rx.search("http://app.test:8080/?do=delete"))
        self.assertFalse(rx.search("https://catalog-offers.app.test/"))
        self.assertFalse(rx.search("https://delete.app.test/home"))
        self.assertFalse(rx.search("https://app.test/deleted"))

    def test_katana_regex_absent_when_not_authenticated(self):
        from assay.engine import Engine
        eng = types.SimpleNamespace(cfg=Config(out_dir=tempfile.mkdtemp()))
        self.assertIsNone(Engine._katana_avoid(eng))


# --------------------------------------------------------------------------
# HttpClient: proxy routing, avoid list, pause
# --------------------------------------------------------------------------


class _FakeRaw:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, n, decode_content=True):
        return self._body[:n]


class _FakeResponse:
    def __init__(self, url, status=200, body=b"ok"):
        self.url = url
        self.status_code = status
        self.headers = {"Content-Type": "text/html"}
        self.raw = _FakeRaw(body)
        self.encoding = "utf-8"
        self.history = []

    def close(self):
        pass


class _RecordingSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return _FakeResponse(url)


def _client(cfg) -> (HttpClient, _RecordingSession):
    http = HttpClient(cfg)
    rec = _RecordingSession()
    http._session = lambda: rec
    return http, rec


class HttpClientProxyTests(_Globals):
    def test_target_traffic_goes_through_the_proxy(self):
        http, rec = _client(_authed_cfg(proxy="http://10.9.9.9:8080"))
        r = http.get("https://app.test/account")
        self.assertEqual(r.status, 200)
        self.assertEqual(rec.calls[0][2]["proxies"],
                         {"http": "http://10.9.9.9:8080",
                          "https": "http://10.9.9.9:8080"})

    def test_recon_infrastructure_goes_direct(self):
        cfg = _authed_cfg(proxy="http://10.9.9.9:8080",
                          scope=Scope(allow=["app.test"]))
        http, rec = _client(cfg)
        http.request("GET", "https://crt.sh/?q=app.test", infra=True)
        self.assertEqual(rec.calls[0][2]["proxies"], {})

    def test_no_proxy_configured_means_no_proxies(self):
        http, rec = _client(_authed_cfg())
        http.get("https://app.test/")
        self.assertEqual(rec.calls[0][2]["proxies"], {})

    def test_avoided_url_is_never_sent(self):
        http, rec = _client(_authed_cfg())
        r = http.get("https://app.test/logout")
        self.assertEqual((r.status, r.error), (0, "avoided"))
        self.assertEqual(rec.calls, [])
        self.assertEqual(http.avoided, 1)

    def test_avoid_list_is_off_for_unauthenticated_scans(self):
        http, rec = _client(Config(out_dir=tempfile.mkdtemp()))
        http.get("https://app.test/logout")
        self.assertEqual(len(rec.calls), 1)

    def test_pause_holds_target_requests_but_not_the_canary(self):
        http, rec = _client(_authed_cfg())
        tools.PAUSE.set()
        done = threading.Event()
        t = threading.Thread(target=lambda: (http.get("https://app.test/a"), done.set()))
        t.start()
        time.sleep(0.4)
        self.assertFalse(done.is_set(), "a paused scan sent a target request")
        http.request("GET", "https://app.test/account", canary=True)
        self.assertEqual([c[1] for c in rec.calls], ["https://app.test/account"])
        tools.PAUSE.clear()
        t.join(2)
        self.assertTrue(done.is_set())
        self.assertEqual(len(rec.calls), 2)


# --------------------------------------------------------------------------
# external tools
# --------------------------------------------------------------------------


class ToolProxyTests(_Globals):
    def _capture_stream(self):
        seen = []

        def fake(cmd, timeout=0, **kw):
            seen.append(list(cmd))
            return iter(())
        return seen, mock.patch.object(tools, "stream_json", fake)

    def test_httpx_nuclei_katana_get_proxy_flags(self):
        tools.PROXY = "http://10.9.9.9:8080"
        seen, patch = self._capture_stream()
        with patch:
            list(tools.httpx_probe(["https://app.test"], {"rate": 5}))
            list(tools.nuclei_scan(["https://app.test"], "high", {}))
            tools.katana_crawl(["https://app.test"], 2, {"rate": 5}, 10,
                               avoid="(?i)logout")
        httpx, nuclei, katana = seen
        self.assertIn("http://10.9.9.9:8080", httpx[httpx.index("-http-proxy") + 1])
        self.assertEqual(nuclei[nuclei.index("-proxy") + 1], "http://10.9.9.9:8080")
        self.assertEqual(katana[katana.index("-proxy") + 1], "http://10.9.9.9:8080")
        self.assertEqual(katana[katana.index("-cos") + 1], "(?i)logout")

    def test_no_proxy_no_flags(self):
        tools.PROXY = ""
        seen, patch = self._capture_stream()
        with patch:
            tools.katana_crawl(["https://app.test"], 2, {}, 10)
        self.assertNotIn("-proxy", seen[0])
        self.assertNotIn("-cos", seen[0])

    def test_ffuf_gets_proxy_and_headers(self):
        tools.PROXY = "http://10.9.9.9:8080"
        seen = []

        def fake_run(cmd, timeout=0, **kw):
            seen.append(list(cmd))
            return types.SimpleNamespace(ok=True, timed_out=False)
        wl = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        wl.write("admin\n")
        wl.close()
        self.addCleanup(os.unlink, wl.name)
        with mock.patch.object(tools, "run", fake_run):
            tools.ffuf_discover("https://app.test", wl.name, {},
                                headers={"Cookie": "sid=abc"})
        cmd = seen[0]
        self.assertEqual(cmd[cmd.index("-x") + 1], "http://10.9.9.9:8080")
        self.assertIn("Cookie: sid=abc", cmd)

    def test_ffuf_argv_parses_to_the_end(self):
        """Go's flag package stops at the first bare word; nothing after it applies.

        A valueless -acc once ate "-mc" and stranded the status list, so ffuf
        ignored every later flag - including -x, -H and -o.
        """
        tools.PROXY = "http://10.9.9.9:8080"
        seen = []

        def fake_run(cmd, timeout=0, **kw):
            seen.append(list(cmd))
            return types.SimpleNamespace(ok=True, timed_out=False)
        wl = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        wl.write("admin\n")
        wl.close()
        self.addCleanup(os.unlink, wl.name)
        with mock.patch.object(tools, "run", fake_run):
            tools.ffuf_discover("https://app.test", wl.name, {},
                                extensions="php", headers={"Cookie": "sid=abc"})
        argv = seen[0][1:]
        # ffuf flags assay passes that take no value; every other flag takes one.
        boolean = {"-ac", "-s", "-noninteractive"}
        i = 0
        while i < len(argv):
            tok = argv[i]
            self.assertTrue(tok.startswith("-"),
                            "ffuf stops parsing at %r; ignored: %s" % (tok, argv[i:]))
            i += 1 if tok in boolean else 2
        self.assertIn("-x", argv)

    def test_arjun_gets_proxy_through_environment(self):
        tools.PROXY = "http://10.9.9.9:8080"
        got = {}

        def fake_run(cmd, timeout=0, env_extra=None, **kw):
            got["env"] = env_extra
            return types.SimpleNamespace(ok=True)
        with mock.patch.object(tools, "run", fake_run):
            tools.arjun_params("https://app.test/x", {})
        self.assertEqual(got["env"]["HTTPS_PROXY"], "http://10.9.9.9:8080")

    def test_arjun_no_proxy_no_environment(self):
        tools.PROXY = ""
        got = {}

        def fake_run(cmd, timeout=0, env_extra=None, **kw):
            got["env"] = env_extra
            return types.SimpleNamespace(ok=True)
        with mock.patch.object(tools, "run", fake_run):
            tools.arjun_params("https://app.test/x", {})
        self.assertIsNone(got["env"])

    def test_ffuf_sweep_drops_avoided_words_without_shifting_the_resume_index(self):
        tools.AVOID = _authed_cfg().avoid_regex()
        words = ["admin", "logout", "backup", "delete", "config"]
        wl = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        wl.write("\n".join(words) + "\n")
        wl.close()
        self.addCleanup(os.unlink, wl.name)
        sent = []

        def fake_discover(url, wordlist, tune, extensions="", timeout=0, headers=None):
            with open(wordlist) as fh:
                sent.extend(w.strip() for w in fh if w.strip())
            return tools.FfufRun(planned=0, elapsed=2.0, wordlist=wordlist,
                                 attempted=0, killed=False, errored=False,
                                 completed=True)
        with mock.patch.object(tools, "ffuf_discover", fake_discover):
            sweep = tools.ffuf_sweep("https://app.test", wl.name, {"rate": 30},
                                     timeout=600)
        self.assertEqual(sent, ["admin", "backup", "config"])
        self.assertEqual(sweep.reached, len(words))


class ToolHeaderTests(unittest.TestCase):
    def test_tool_headers_carry_cookie_auth_and_tag(self):
        cfg = _authed_cfg(basic_auth="u:p", traffic_tag="t1",
                          headers={"X-Extra": "1"})
        h = cfg.tool_headers()
        self.assertEqual(h["Cookie"], "sid=abc")
        self.assertTrue(h["Authorization"].startswith("Basic "))
        self.assertEqual(h["X-Scan-Tag"], "t1")
        self.assertEqual(h["X-Extra"], "1")

    def test_nuclei_module_sends_the_cookie(self):
        from assay.modules import web_nuclei
        captured = {}

        def fake_scan(urls, sev, tune, headers=None, **kw):
            captured["headers"] = headers
            return iter(())
        mod = web_nuclei.NucleiModule()
        ctx = types.SimpleNamespace(cfg=_authed_cfg(), web=[web_target("https://app.test/")],
                                    tune={}, say=lambda *a, **k: None,
                                    emit=lambda f: True)
        with mock.patch.object(tools, "nuclei_scan", fake_scan):
            mod.run_global(ctx)
        self.assertEqual(captured["headers"]["Cookie"], "sid=abc")


# --------------------------------------------------------------------------
# session canary
# --------------------------------------------------------------------------


class _Switch:
    """A canary page whose logged-in state the test flips."""

    def __init__(self):
        self.logged_in = True

    def route(self, m, url, h, b):
        if url.endswith("/account"):
            if self.logged_in:
                return 200, {"Content-Type": "text/html"}, ACCOUNT_PAGE
            return 302, {"Location": "/login"}, ""
        return None


class LoggedInTests(unittest.TestCase):
    def _r(self, status, body="", headers=None, error=""):
        return Resp(url="https://app.test/account", status=status,
                    headers=headers or {}, body=body, elapsed=0.0, error=error)

    def test_verdicts(self):
        self.assertTrue(session.logged_in(self._r(200, ACCOUNT_PAGE))[0])
        self.assertFalse(session.logged_in(self._r(200, LOGIN_PAGE))[0])
        self.assertFalse(session.logged_in(self._r(302, "", {"Location": "/login"}))[0])
        self.assertFalse(session.logged_in(self._r(401))[0])
        ok, why = session.logged_in(self._r(0, error="ConnectionError"))
        self.assertFalse(ok)
        self.assertIn("proxy", why)

    def test_expect_regex_is_authoritative(self):
        self.assertTrue(session.logged_in(self._r(200, ACCOUNT_PAGE), "Sign out")[0])
        # A 200 that lacks the marker is logged out, even with no login form.
        self.assertFalse(session.logged_in(self._r(200, "<h1>Welcome</h1>"),
                                           "Sign out")[0])


class CanaryTests(_Globals):
    def _canary(self):
        sw = _Switch()
        http = StubHttp([sw.route])
        notes, pings = [], []
        c = session.SessionCanary(http, "https://app.test/account",
                                  expect="Sign out", interval=60,
                                  notify=pings.append, note=notes.append)
        return c, sw, pings

    def test_logged_in_does_nothing(self):
        c, sw, pings = self._canary()
        self.assertTrue(c.tick(recheck_wait=0))
        self.assertFalse(tools.PAUSE.is_set())
        self.assertEqual(pings, [])

    def test_logout_pauses_once_and_recovery_resumes(self):
        c, sw, pings = self._canary()
        sw.logged_in = False
        self.assertFalse(c.tick(recheck_wait=0))
        self.assertTrue(tools.PAUSE.is_set())
        self.assertEqual(len(pings), 1)
        # Still out: no second ping.
        c.tick(recheck_wait=0)
        self.assertEqual(len(pings), 1)
        # Operator presses 'r' while still logged out: the canary re-holds.
        tools.PAUSE.clear()
        c.tick(recheck_wait=0)
        self.assertTrue(tools.PAUSE.is_set())
        sw.logged_in = True
        self.assertTrue(c.tick(recheck_wait=0))
        self.assertFalse(tools.PAUSE.is_set())
        self.assertEqual(len(c.outages), 1)
        self.assertIsNotNone(c.outages[0][1])
        self.assertIn("lost 1 time", c.summary())

    def test_transient_logout_is_rechecked_before_pausing(self):
        c, sw, pings = self._canary()
        calls = {"n": 0}

        def flaky(m, url, h, b):
            calls["n"] += 1
            if calls["n"] == 1:
                return 302, {"Location": "/login"}, ""
            return 200, {}, ACCOUNT_PAGE
        c.http = StubHttp([flaky])
        self.assertTrue(c.tick(recheck_wait=0))
        self.assertFalse(tools.PAUSE.is_set())
        self.assertEqual(pings, [])

    def test_operator_pause_is_not_lifted_by_a_healthy_canary(self):
        c, sw, pings = self._canary()
        tools.PAUSE.set()
        c.tick(recheck_wait=0)
        self.assertTrue(tools.PAUSE.is_set())

    def test_stop_releases_its_own_pause(self):
        c, sw, pings = self._canary()
        sw.logged_in = False
        c.tick(recheck_wait=0)
        c.stop()
        self.assertFalse(tools.PAUSE.is_set())

    def test_canary_requests_bypass_the_pause_and_avoid_list(self):
        c, sw, pings = self._canary()
        kw_seen = []
        orig = c.http.request

        def spy(method, url, **kw):
            kw_seen.append(kw)
            return orig(method, url, **kw)
        c.http.request = spy
        c.check()
        self.assertTrue(kw_seen[0].get("canary"))
        self.assertFalse(kw_seen[0].get("allow_redirects"))


# --------------------------------------------------------------------------
# preflight
# --------------------------------------------------------------------------


class PreflightTests(_Globals):
    def test_unreachable_proxy_is_reported_with_the_listener_hint(self):
        cfg = _authed_cfg(proxy="http://10.9.9.9:8080")
        with mock.patch("socket.create_connection",
                        side_effect=ConnectionRefusedError(61, "Connection refused")):
            problems = session.preflight(cfg)
        self.assertEqual(len(problems), 1)
        self.assertIn("all interfaces", problems[0])

    def test_reachable_proxy_passes(self):
        cfg = _authed_cfg(proxy="http://10.9.9.9:8080")
        with mock.patch("socket.create_connection", return_value=mock.MagicMock()):
            self.assertEqual(session.preflight(cfg), [])

    def test_canary_out_of_scope(self):
        cfg = _authed_cfg(scope=Scope(allow=["app.test"]),
                          session_check="https://other.test/account")
        self.assertIn("not in scope", session.preflight(cfg)[0])

    def test_bad_expect_regex(self):
        cfg = _authed_cfg(session_check="https://app.test/account",
                          session_expect="(")
        self.assertIn("not a valid regex", session.preflight(cfg)[0])

    def test_not_logged_in_at_start_blocks_the_scan(self):
        sw = _Switch()
        sw.logged_in = False
        cfg = _authed_cfg(session_check="https://app.test/account",
                          session_expect="Sign out")
        problems = session.preflight(cfg, http=StubHttp([sw.route]))
        self.assertEqual(len(problems), 1)
        self.assertIn("not logged in", problems[0])

    def test_logged_in_at_start_passes(self):
        cfg = _authed_cfg(session_check="https://app.test/account",
                          session_expect="Sign out")
        self.assertEqual(session.preflight(cfg, http=StubHttp([_Switch().route])), [])

    def test_missing_and_empty_seed_files(self):
        empty = tempfile.NamedTemporaryFile("w", suffix=".har", delete=False)
        json.dump({"log": {"entries": []}}, empty)
        empty.close()
        self.addCleanup(os.unlink, empty.name)
        cfg = _authed_cfg(seeds=["/nonexistent/x.har", empty.name])
        problems = session.preflight(cfg)
        self.assertEqual(len(problems), 2)
        self.assertIn("no such file", problems[0])
        self.assertIn("no GET URLs", problems[1])


# --------------------------------------------------------------------------
# seeds
# --------------------------------------------------------------------------


def _har(entries):
    f = tempfile.NamedTemporaryFile("w", suffix=".har", delete=False)
    json.dump({"log": {"entries": [
        {"request": {"method": m, "url": u, "headers": []},
         "response": {"status": s, "content": {"text": "x"}}}
        for m, u, s in entries]}}, f)
    f.close()
    return f.name


class SeedTests(_Globals):
    ENTRIES = [
        ("GET", "https://app.test/dashboard", 200),
        ("GET", "https://app.test/dashboard", 200),           # duplicate
        ("GET", "https://app.test/reports?id=7#top", 200),
        ("POST", "https://app.test/reports/save", 200),        # may change state
        ("GET", "https://app.test/static/app.js", 200),        # static
        ("GET", "https://app.test/missing", 404),              # error
        ("GET", "https://app.test/logout", 302),               # avoid list
        ("GET", "https://app.test:443/settings", 200),         # explicit default port
        ("GET", "https://analytics.vendor.test/collect", 200), # third party
        ("GET", "https://admin.app.test/users", 200),          # in scope, not scanned
    ]

    def test_seed_urls_filters_the_capture(self):
        path = _har(self.ENTRIES)
        self.addCleanup(os.unlink, path)
        from assay.burpimport import seed_urls
        urls, dropped = seed_urls(path)
        self.assertEqual(urls[:2], ["https://app.test/dashboard",
                                    "https://app.test/reports?id=7"])
        self.assertNotIn("https://app.test/reports/save", urls)
        self.assertEqual(dropped, {"method": 1, "static": 1, "error": 1})

    def _engine(self, seeds):
        from assay.engine import Engine
        out = tempfile.mkdtemp()
        cfg = _authed_cfg(targets=["app.test"], out_dir=out, journal=False,
                          seeds=seeds, scope=Scope(allow=["*.app.test", "app.test"]))
        eng = Engine(cfg)
        self.addCleanup(eng.store.close)
        eng.ctx.web = [web_target("https://app.test/")]
        said = []
        eng.ctx.say = lambda stage, msg, **kw: said.append(msg)
        return eng, said

    def test_engine_groups_seeds_under_live_web_targets(self):
        path = _har(self.ENTRIES)
        self.addCleanup(os.unlink, path)
        eng, said = self._engine([path])
        got = eng._seed_urls()
        self.assertEqual(list(got), ["https://app.test"])
        self.assertEqual(got["https://app.test"],
                         ["https://app.test/dashboard",
                          "https://app.test/reports?id=7",
                          "https://app.test:443/settings"])
        self.assertTrue(any("admin.app.test" in m for m in said), said)
        self.assertFalse(any("vendor" in m for m in said), said)

    def test_seeds_are_crawl_start_points_and_survive_the_cap(self):
        path = _har(self.ENTRIES)
        self.addCleanup(os.unlink, path)
        eng, said = self._engine([path])
        starts = {}

        def fake_katana(urls, depth, tune, max_urls, headers=None, avoid=None, **kw):
            starts["urls"] = list(urls)
            starts["avoid"] = avoid
            # A crawl that finds the logout link and far more pages than
            # the per-host cap.
            return ([{"request": {"endpoint": "https://app.test/logout"}}]
                    + [{"request": {"endpoint": "https://app.test/p%d" % i}}
                       for i in range(200)])
        eng.ctx.tools["katana"] = "/usr/bin/katana"
        eng.cfg.passive = False
        with mock.patch.object(tools, "katana_crawl", fake_katana), \
                mock.patch.object(tools, "have", lambda n: False):
            eng._stage_urls()
        self.assertIn("https://app.test/dashboard", starts["urls"])
        self.assertTrue(starts["avoid"].startswith("(?i)^"))
        pool = eng.ctx.urls["https://app.test"]
        self.assertIn("https://app.test/dashboard", pool)
        self.assertNotIn("https://app.test/logout", pool)


# --------------------------------------------------------------------------
# --proxy resolution
# --------------------------------------------------------------------------


class ProxyResolutionTests(unittest.TestCase):
    def test_burp_keyword_uses_windows_host_under_wsl_nat(self):
        from assay.cli import _proxy_url
        with mock.patch.object(env, "is_wsl", return_value=True), \
                mock.patch.object(env, "wsl_networking_mode", return_value="nat"), \
                mock.patch.object(env, "windows_host_ip", return_value="172.20.0.1"):
            self.assertEqual(_proxy_url("burp"), "http://172.20.0.1:8080")
            self.assertEqual(_proxy_url("burp:8081"), "http://172.20.0.1:8081")

    def test_burp_keyword_is_localhost_when_mirrored_or_native(self):
        from assay.cli import _proxy_url
        with mock.patch.object(env, "is_wsl", return_value=True), \
                mock.patch.object(env, "wsl_networking_mode", return_value="mirrored"):
            self.assertEqual(_proxy_url("burp"), "http://127.0.0.1:8080")
        with mock.patch.object(env, "is_wsl", return_value=False):
            self.assertEqual(_proxy_url("BURP"), "http://127.0.0.1:8080")

    def test_bare_host_port_gets_a_scheme(self):
        from assay.cli import _proxy_url
        self.assertEqual(_proxy_url("10.0.0.2:8080"), "http://10.0.0.2:8080")
        self.assertEqual(_proxy_url("socks5://h:1080"), "socks5://h:1080")
        self.assertEqual(_proxy_url(""), "")

    def test_tools_under_the_wsl_bridge_reach_burp_on_the_windows_host(self):
        with mock.patch.object(env, "use_wsl_bridge", return_value=True), \
                mock.patch.object(env, "_wslconfig_mirrored", return_value=False), \
                mock.patch.object(env, "wsl_gateway_ip", return_value="172.20.0.1"):
            self.assertEqual(env.proxy_for_tools("http://127.0.0.1:8080"),
                             "http://172.20.0.1:8080")
            self.assertEqual(env.proxy_for_tools("http://10.0.0.2:8080"),
                             "http://10.0.0.2:8080")
        with mock.patch.object(env, "use_wsl_bridge", return_value=True), \
                mock.patch.object(env, "_wslconfig_mirrored", return_value=True):
            self.assertEqual(env.proxy_for_tools("http://127.0.0.1:8080"),
                             "http://127.0.0.1:8080")
        with mock.patch.object(env, "use_wsl_bridge", return_value=False):
            self.assertEqual(env.proxy_for_tools("http://127.0.0.1:8080"),
                             "http://127.0.0.1:8080")


if __name__ == "__main__":
    unittest.main()
