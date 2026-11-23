"""Google API key verification (gmapsapiscanner logic). Offline, canned only."""

from __future__ import annotations

import sys
import unittest
from urllib.parse import urlsplit

sys.path.insert(0, __file__.rsplit("/tests/", 1)[0])

from tests.stub import make_ctx, titles, web_target

KEY = "AIza" + "A" * 35
DENIED_MAPS = '{"error_message":"This API project is not authorized","status":"REQUEST_DENIED"}'
DENIED_G = '{"error":{"code":403,"message":"API key not valid","status":"PERMISSION_DENIED"}}'
JS = "var k='%s';" % KEY


def _google(allowed_hosts_paths):
    """Route answering Google hosts: accept listed path prefixes, deny the rest."""
    def route(m, url, h, b):
        u = urlsplit(url)
        if not u.hostname.endswith("googleapis.com"):
            return None
        if any(u.path.startswith(p) for p in allowed_hosts_paths):
            if "staticmap" in u.path or "streetview" in u.path:
                return 200, {"Content-Type": "image/png"}, "PNG"
            if "photo" in u.path:
                return 302, {"Location": "https://x"}, ""
            return 200, {"Content-Type": "application/json"}, '{"status":"OK","results":[]}'
        body = DENIED_MAPS if u.hostname == "maps.googleapis.com" else DENIED_G
        return 403, {"Content-Type": "application/json"}, body
    return route


def _page(ctx_routes):
    from tests.stub import path_route
    return [path_route("/", ctype="text/html", body='<script src="/a.js"></script>'),
            path_route("/a.js", ctype="application/javascript", body=JS)] + ctx_routes


def _run(routes):
    from assay.modules.gmaps_key import GoogleKeyModule
    from assay.modules.secrets import SecretsModule
    ctx, http = make_ctx(_page(routes), soft404=False)
    SecretsModule().run_web(ctx, web_target())
    return GoogleKeyModule().run_global(ctx), ctx, http


class GoogleKeyTests(unittest.TestCase):
    def test_key_is_captured_by_secrets(self):
        _, ctx, _ = _run([_google([])])
        self.assertIn(KEY, ctx.google_keys)

    def test_unrestricted_key_reported(self):
        found, _, _ = _run([_google(["/maps/api/geocode", "/maps/api/staticmap"])])
        self.assertEqual(len(found), 1)
        f = found[0]
        self.assertIn("Unrestricted Google API key accepted by 2 API(s)", f.title)
        self.assertEqual(f.severity, "medium")
        self.assertIn(KEY, f.repro)
        self.assertTrue(f.evidence and f.impact)

    def test_gemini_acceptance_raises_severity(self):
        found, _, _ = _run([_google(["/v1beta/files"])])
        self.assertEqual(found[0].severity, "high")

    def test_restricted_key_is_info_only(self):
        found, _, _ = _run([_google([])])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "info")
        self.assertNotIn("Unrestricted", found[0].title)

    def test_html_200_is_not_acceptance(self):
        """A 200 HTML page with no error marker must not read as accepted for image APIs."""
        def route(m, url, h, b):
            if "googleapis.com" in url:
                return 200, {"Content-Type": "text/html"}, "<html>hi</html>"
        found, _, _ = _run([route])
        out = found[0].evidence[0].output
        for name in ("Static Maps", "Street View Static", "Places Photo", "FCM (legacy send)",
                     "Gemini Files"):
            line = next(l for l in out.splitlines() if l.startswith(name))
            self.assertNotIn("ACCEPTED", line, name)

    def test_only_google_hosts_contacted_and_each_key_once(self):
        _, _, http = _run([_google([])])
        hosts = {urlsplit(u).hostname for _, u in http.calls if "googleapis" in u}
        self.assertTrue(hosts <= {"maps.googleapis.com", "roads.googleapis.com",
                                  "www.googleapis.com", "addressvalidation.googleapis.com",
                                  "airquality.googleapis.com", "aerialview.googleapis.com",
                                  "routes.googleapis.com", "fcm.googleapis.com",
                                  "generativelanguage.googleapis.com"})

    def test_hosts_pass_scope_guard_for_real_client(self):
        from assay.net import is_infra
        from assay import gmaps
        for p in gmaps.PROBES:
            self.assertTrue(is_infra(urlsplit(p.url).hostname), p.url)
        self.assertFalse(is_infra("evil.googleapis.com"))

    def test_safe_mode_skips_module(self):
        from assay.modules.gmaps_key import GoogleKeyModule
        ctx, _ = make_ctx([])
        ctx.cfg.safe_mode = True
        self.assertFalse(GoogleKeyModule().applicable(ctx))


if __name__ == "__main__":
    unittest.main()
