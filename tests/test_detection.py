"""Detection tests. Offline only - canned responses, no sockets, no live targets.

Each test asserts both directions: the check fires on the real condition, and
stays silent on the benign lookalike. The negative half is the one that keeps
the tool usable.
"""

from __future__ import annotations

import sys
import unittest
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, __file__.rsplit("/tests/", 1)[0])

from tests.stub import (SOFT404_BODY, make_ctx, path_route, titles, web_target)

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


class ExposureTests(unittest.TestCase):
    def test_git_head_detected(self):
        from assay.modules.web_exposure import ExposureModule
        ctx, _ = make_ctx([
            path_route("/.git/HEAD", body="ref: refs/heads/main\n"),
            path_route("/.git/config", body="[core]\n\trepositoryformatversion = 0\n"),
        ])
        found = ExposureModule().run_web(ctx, web_target())
        self.assertIn("Exposed .git repository", titles(found))
        git = next(f for f in found if f.title == "Exposed .git repository")
        # The follow-up fetch of .git/config must promote it to confirmed.
        self.assertEqual(git.confidence, "confirmed")
        self.assertTrue(git.evidence, "a finding must carry evidence")
        self.assertTrue(git.impact, "a finding must state attacker impact")

    def test_soft404_shell_produces_nothing(self):
        """An SPA answering 200 HTML for every path must not yield findings."""
        from assay.modules.web_exposure import ExposureModule
        ctx, _ = make_ctx([])          # every path hits the 200 HTML catch-all
        found = ExposureModule().run_web(ctx, web_target())
        self.assertEqual(found, [], "soft-404 shell produced false positives: %s"
                         % titles(found))

    def test_env_html_error_page_not_reported(self):
        """A themed 'not found' HTML page containing the word DB_PASSWORD."""
        from assay.modules.web_exposure import ExposureModule
        body = ("<html><title>404 Not Found</title><body>No such file: "
                "DB_PASSWORD=example</body></html>")
        ctx, _ = make_ctx([path_route("/.env", ctype="text/html", body=body)])
        found = ExposureModule().run_web(ctx, web_target())
        self.assertNotIn("Exposed .env file", titles(found))

    def test_env_detected_as_plaintext(self):
        from assay.modules.web_exposure import ExposureModule
        ctx, _ = make_ctx([path_route(
            "/.env", body="APP_KEY=base64:x\nDB_PASSWORD=hunter2\n")])
        found = ExposureModule().run_web(ctx, web_target())
        self.assertIn("Exposed .env file", titles(found))
        self.assertEqual(found[0].severity, "critical")


class DirListingTests(unittest.TestCase):
    def test_index_of_detected(self):
        from assay.modules.web_exposure import DirListingModule
        listing = ("<html><head><title>Index of /backup</title></head><body>"
                   "<h1>Index of /backup</h1><a href='../'>Parent Directory</a>"
                   "<a href='db.sql'>db.sql</a></body></html>")
        ctx, _ = make_ctx([path_route("/backup/", ctype="text/html", body=listing)])
        found = DirListingModule().run_web(ctx, web_target())
        self.assertEqual(len(found), 1)
        # /backup is on the sensitive list, so it must outrank a plain /assets hit.
        self.assertEqual(found[0].severity, "medium")

    def test_no_listing_no_finding(self):
        from assay.modules.web_exposure import DirListingModule
        ctx, _ = make_ctx([])
        self.assertEqual(DirListingModule().run_web(ctx, web_target()), [])


class CorsTests(unittest.TestCase):
    @staticmethod
    def _reflecting(creds: bool):
        def route(m, url, h, b):
            origin = h.get("Origin")
            hdrs = {"Content-Type": "application/json"}
            if origin:
                hdrs["Access-Control-Allow-Origin"] = origin
                if creds:
                    hdrs["Access-Control-Allow-Credentials"] = "true"
            return 200, hdrs, '{"email":"a@b.c","token":"x"}'
        return route

    def test_reflected_origin_with_credentials(self):
        from assay.modules.web_headers import CorsModule
        ctx, _ = make_ctx([self._reflecting(True)])
        found = CorsModule().run_web(ctx, web_target())
        t = titles(found)
        self.assertIn("CORS reflects arbitrary Origin with credentials allowed", t)
        f = found[0]
        self.assertEqual(f.confidence, "confirmed")
        self.assertEqual(f.severity, "high")
        # Two distinct sentinel origins must both have been reflected.
        self.assertGreaterEqual(len(f.evidence), 2)

    def test_static_acao_is_not_reflection(self):
        """A fixed ACAO for a partner origin must not be called reflection."""
        from assay.modules.web_headers import CorsModule

        def route(m, url, h, b):
            return 200, {"Content-Type": "application/json",
                         "Access-Control-Allow-Origin": "https://partner.example.org",
                         "Access-Control-Allow-Credentials": "true"}, "{}"
        ctx, _ = make_ctx([route])
        found = CorsModule().run_web(ctx, web_target())
        self.assertEqual(found, [], "static ACAO misreported: %s" % titles(found))

    def test_wildcard_without_sensitive_data_is_quiet(self):
        from assay.modules.web_headers import CorsModule

        def route(m, url, h, b):
            return 200, {"Content-Type": "application/json",
                         "Access-Control-Allow-Origin": "*"}, '{"status":"ok"}'
        ctx, _ = make_ctx([route])
        self.assertEqual(CorsModule().run_web(ctx, web_target()), [])


class OpenRedirectTests(unittest.TestCase):
    @staticmethod
    def _redirector(param="next"):
        def route(m, url, h, b):
            parts = urlsplit(url)
            if parts.path != "/login":
                return None
            q = parse_qs(parts.query)
            if param not in q:
                return None
            return 302, {"Location": q[param][0]}, ""
        return route

    def test_open_redirect_from_crawled_url(self):
        from assay.modules.web_active import OpenRedirectModule
        origin = "http://target.test:8080"
        ctx, _ = make_ctx([self._redirector()],
                          urls={origin: [origin + "/login?next=/dashboard"]})
        found = OpenRedirectModule().run_web(ctx, web_target())
        self.assertTrue(found, "open redirect on a crawled URL was missed")
        self.assertEqual(found[0].confidence, "confirmed")
        self.assertIn("next", found[0].title)

    def test_relative_redirect_is_not_open(self):
        """Redirecting to a fixed internal path must never be reported."""
        from assay.modules.web_active import OpenRedirectModule

        def route(m, url, h, b):
            if urlsplit(url).path != "/login":
                return None
            return 302, {"Location": "/dashboard"}, ""
        origin = "http://target.test:8080"
        ctx, _ = make_ctx([route], urls={origin: [origin + "/login?next=/dashboard"]})
        self.assertEqual(OpenRedirectModule().run_web(ctx, web_target()), [])


class TraversalTests(unittest.TestCase):
    def test_passwd_oracle(self):
        from assay.modules.web_active import TraversalModule

        def route(m, url, h, b):
            parts = urlsplit(url)
            if parts.path != "/download":
                return None
            q = parse_qs(parts.query)
            if "etc/passwd" in (q.get("file", [""])[0]):
                return 200, {"Content-Type": "text/plain"}, PASSWD
            return None
        origin = "http://target.test:8080"
        ctx, _ = make_ctx([route], urls={origin: [origin + "/download?file=report.pdf"]})
        found = TraversalModule().run_web(ctx, web_target())
        self.assertTrue(found, "path traversal with a /etc/passwd oracle was missed")
        self.assertEqual(found[0].severity, "critical")
        self.assertEqual(found[0].confidence, "confirmed")

    def test_reflected_payload_without_file_contents(self):
        """Echoing the payload back is not a file read."""
        from assay.modules.web_active import TraversalModule

        def route(m, url, h, b):
            q = parse_qs(urlsplit(url).query)
            return 200, {"Content-Type": "text/html"}, \
                "<p>No such file: %s</p>" % q.get("file", [""])[0]
        origin = "http://target.test:8080"
        ctx, _ = make_ctx([route], urls={origin: [origin + "/download?file=x"]})
        self.assertEqual(TraversalModule().run_web(ctx, web_target()), [])


class HostHeaderTests(unittest.TestCase):
    def test_xfh_reflection(self):
        from assay.modules.web_active import HostHeaderModule

        def route(m, url, h, b):
            xfh = h.get("X-Forwarded-Host")
            if not xfh:
                return None
            return 200, {"Content-Type": "text/html",
                         "Cache-Control": "public, max-age=60"}, \
                "<a href='https://%s/reset'>reset</a>" % xfh
        ctx, _ = make_ctx([route])
        found = HostHeaderModule().run_web(ctx, web_target())
        self.assertTrue(found)
        self.assertEqual(found[0].confidence, "confirmed")
        self.assertIn("cache", found[0].tags)

    def test_no_reflection_no_finding(self):
        from assay.modules.web_active import HostHeaderModule
        ctx, _ = make_ctx([])
        self.assertEqual(HostHeaderModule().run_web(ctx, web_target()), [])


class GraphQLTests(unittest.TestCase):
    def test_introspection(self):
        from assay.modules.web_active import GraphQLModule
        schema = ('{"data":{"__schema":{"queryType":{"name":"Query"},'
                  '"mutationType":{"name":"Mutation"},"types":[{"name":"User"}]}}}')
        ctx, _ = make_ctx([path_route("/graphql", ctype="application/json",
                                      body=schema, method="POST")])
        found = GraphQLModule().run_web(ctx, web_target())
        self.assertTrue(found)
        # A mutation root means state-changing operations are enumerable.
        self.assertEqual(found[0].severity, "medium")

    def test_introspection_disabled(self):
        from assay.modules.web_active import GraphQLModule
        ctx, _ = make_ctx([path_route(
            "/graphql", ctype="application/json", method="POST",
            body='{"errors":[{"message":"introspection is disabled"}]}')])
        self.assertEqual(GraphQLModule().run_web(ctx, web_target()), [])


class SecretsTests(unittest.TestCase):
    def test_aws_key_and_sourcemap(self):
        from assay.modules.secrets import SecretsModule
        js = ('var API="https://billing.internal:8443/api";\n'
              'var k="AKIAIOSFODNN7EXAMPLE";\n'
              '//# sourceMappingURL=app.js.map\n')
        smap = '{"version":3,"sources":["src/admin/Secret.tsx"],"sourcesContent":["x"]}'
        ctx, _ = make_ctx([
            path_route("/", ctype="text/html",
                       body='<html><script src="/static/app.js"></script></html>'),
            path_route("/static/app.js", ctype="application/javascript", body=js),
            path_route("/static/app.js.map", ctype="application/json", body=smap),
        ])
        found = SecretsModule().run_web(ctx, web_target())
        t = titles(found)
        self.assertIn("AWS access key id exposed in client-side asset", t)
        self.assertIn("JavaScript source map published in production", t)
        self.assertIn("Internal hosts referenced from client-side JavaScript", t)

    def test_clean_bundle_is_quiet(self):
        from assay.modules.secrets import SecretsModule
        ctx, _ = make_ctx([
            path_route("/", ctype="text/html",
                       body='<html><script src="/static/app.js"></script></html>'),
            path_route("/static/app.js", ctype="application/javascript",
                       body='function f(){return 1}'),
        ])
        self.assertEqual(SecretsModule().run_web(ctx, web_target()), [])


class ScoringTests(unittest.TestCase):
    def test_confirmed_critical_outranks_tentative_critical(self):
        from assay.models import Evidence, Finding
        confirmed = Finding(title="a", target="t", severity="critical",
                            confidence="confirmed", impact="x",
                            evidence=[Evidence(kind="http")])
        tentative = Finding(title="b", target="t", severity="critical",
                            confidence="tentative", impact="x",
                            evidence=[Evidence(kind="http")])
        self.assertGreater(confirmed.compute_score(), tentative.compute_score())
        self.assertEqual(confirmed.triage, "CHASE")

    def test_evidence_free_finding_is_damped(self):
        from assay.models import Evidence, Finding
        with_ev = Finding(title="a", target="t", severity="high", confidence="firm",
                          impact="x", evidence=[Evidence(kind="http")])
        without = Finding(title="a", target="t", severity="high", confidence="firm",
                          impact="x")
        self.assertGreater(with_ev.compute_score(), without.compute_score() * 2)

    def test_hygiene_finding_never_reaches_chase(self):
        from assay.models import Evidence, Finding
        f = Finding(title="Security headers absent", target="t", severity="info",
                    confidence="firm", impact="x", tags=["noise-prone"],
                    evidence=[Evidence(kind="http")])
        f.compute_score()
        self.assertEqual(f.triage, "NOTE")


class ScopeTests(unittest.TestCase):
    def test_wildcard_cidr_and_deny(self):
        from assay.config import Scope
        s = Scope(allow=["*.target.tld", "10.0.0.0/8"], deny=["nope.target.tld"])
        self.assertTrue(s.allows("api.target.tld"))
        self.assertTrue(s.allows("10.1.2.3"))
        self.assertFalse(s.allows("nope.target.tld"))
        self.assertFalse(s.allows("evil.tld"))
        self.assertFalse(s.allows("target.tld.evil.tld"))

    def test_out_of_scope_request_is_blocked(self):
        from assay.config import Config, Scope
        from assay.net import HttpClient
        cfg = Config(scope=Scope(allow=["target.tld"]))
        r = HttpClient(cfg).get("https://evil.tld/")
        self.assertEqual(r.error, "out-of-scope")
        self.assertEqual(r.status, 0)


class RedactionTests(unittest.TestCase):
    SAMPLE = (
        "https://admin.acmebank.com:8443/x (10.42.7.13)\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\n"
        "DB_PASSWORD=Sup3rS3cret\naws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"
        "jane.doe@acmebank.com  415-555-0199\n"
        "root:x:0:0:root:/root:/bin/bash\n/home/jsmith/app\n"
        "https://owasp.org/ref\n"
    )

    def _redactor(self):
        from assay.redact import Redactor, terms_from_context
        return Redactor(extra_terms=terms_from_context(
            ["https://admin.acmebank.com"], ["*.acmebank.com"], ["10.42.7.13"]))

    def test_no_residual_leaks(self):
        r = self._redactor()
        self.assertEqual(r.verify(r.text(self.SAMPLE)), [])

    def test_reference_domains_survive(self):
        r = self._redactor()
        self.assertIn("owasp.org", r.text(self.SAMPLE))

    def test_pseudonyms_are_stable_and_reversible(self):
        r = self._redactor()
        out = r.text(self.SAMPLE)
        self.assertEqual(out, r.text(self.SAMPLE))
        self.assertIn("acmebank.com", r.map.rehydrate(out))
        self.assertNotIn("acmebank", out)

    def test_payload_gate_blocks_on_leak(self):
        """A term the redactor does not know must be caught by verify()."""
        from assay.redact import Redactor
        r = Redactor(extra_terms=[])
        leaked = "contact ops at internal-jump.corpnet.example-client.tld"
        self.assertTrue(r.verify(leaked), "verify() failed to flag a bare hostname")

    def test_ai_payload_refuses_to_build_with_leaks(self):
        from assay.ai import AIConfig, build_payload
        from assay.models import Evidence, Finding
        from assay.redact import Redactor
        f = [Finding(title="x", target="https://a.acmebank.com/", severity="high",
                     impact="y", evidence=[Evidence(kind="http", output="10.9.9.9")])]
        payload, leaks = build_payload(f, {}, AIConfig(include_evidence=True), Redactor())
        blob = str(payload)
        self.assertNotIn("acmebank.com", blob)
        self.assertNotIn("10.9.9.9", blob)
        self.assertEqual(leaks, [])


class NucleiFilterTests(unittest.TestCase):
    def test_fingerprint_templates_dropped(self):
        from assay.modules.web_nuclei import NucleiModule
        m = NucleiModule()
        for tid in ("tech-detect", "waf-detect", "http-missing-security-headers"):
            self.assertIsNone(m._convert({"template-id": tid,
                                          "info": {"severity": "info"}}), tid)

    def test_real_finding_converted(self):
        from assay.modules.web_nuclei import NucleiModule
        f = NucleiModule()._convert({
            "template-id": "git-config-exposure",
            "matched-at": "https://t/.git/config",
            "response": "[core]",
            "info": {"name": "Git Config", "severity": "high",
                     "tags": ["exposure", "config"],
                     "classification": {"cwe-id": ["cwe-200"]}}})
        self.assertIsNotNone(f)
        self.assertEqual(f.severity, "high")
        self.assertTrue(f.evidence[0].response)




class InstallerTests(unittest.TestCase):
    """The planner is exercised against a simulated Kali box.

    The real target environment (apt + go present) cannot be reproduced on the
    development machine, so _has() and the tool inventory are stubbed to prove
    the plan is correct for the environment assay actually ships to.
    """

    def _plan(self, have_apt=True, have_go=True, present=(), constrained=False,
              only=None):
        from assay import installer
        from assay.env import Resources

        binaries = {"apt-get": have_apt, "go": have_go}
        orig_has, orig_avail, orig_res, orig_gopath = (
            installer._has, installer.tools.available,
            installer.env.resources, installer.gopath_bin)
        installer._has = lambda b: binaries.get(b, b in present)
        installer.tools.available = lambda: {
            n: ("/usr/bin/" + n if n in present else None)
            for n in installer.tools.REGISTRY}
        # constrained is (cpus <= 2 or mem_avail < 2048), so both must move.
        installer.env.resources = lambda: Resources(
            cpus=2 if constrained else 8,
            mem_total_mb=2048 if constrained else 16384,
            mem_avail_mb=900 if constrained else 8000)
        installer.gopath_bin = lambda: "/root/go/bin"
        try:
            return installer.build_plan(only=only)
        finally:
            (installer._has, installer.tools.available,
             installer.env.resources, installer.gopath_bin) = (
                orig_has, orig_avail, orig_res, orig_gopath)

    def test_kali_plan_covers_apt_and_go(self):
        plan = self._plan()
        cmds = [s.display() for s in plan.steps]
        self.assertTrue(any("apt-get update" in c for c in cmds))
        install = next(c for c in cmds if "apt-get install" in c)
        for pkg in ("nmap", "ffuf", "seclists", "testssl.sh"):
            self.assertIn(pkg, install)
        self.assertTrue(any("nuclei" in c and "go install" in c for c in cmds))
        self.assertEqual(plan.unsupported, [])
        self.assertEqual(plan.path_hint, "/root/go/bin")

    def test_already_installed_tools_are_skipped(self):
        plan = self._plan(present=("nmap", "nuclei", "ffuf"))
        self.assertNotIn("nmap", plan.missing)
        self.assertIn("nmap", plan.already)
        cmds = " ".join(s.display() for s in plan.steps)
        self.assertNotIn("nuclei@latest", cmds)
        self.assertNotIn("nuclei -update-templates", cmds)

    def test_nothing_to_do_yields_empty_plan(self):
        plan = self._plan(present=tuple(
            __import__("assay.tools", fromlist=["REGISTRY"]).REGISTRY))
        self.assertTrue(plan.empty)

    def test_post_install_only_for_queued_tools(self):
        """nuclei's template update must not run when go is unavailable."""
        plan = self._plan(have_apt=False, have_go=False)
        cmds = " ".join(s.display() for s in plan.steps)
        self.assertNotIn("update-templates", cmds)
        self.assertTrue(plan.empty)

    def test_nuclei_templates_queued_when_installable(self):
        plan = self._plan(only=["nuclei"])
        cmds = [s.display() for s in plan.steps]
        self.assertTrue(any("update-templates" in c for c in cmds))

    def test_constrained_vm_pins_single_compiler_process(self):
        plan = self._plan(constrained=True, only=["httpx"])
        build = next(s for s in plan.steps if "build" in s.label)
        self.assertEqual(build.env_extra.get("GOFLAGS"), "-p=1")
        self.assertTrue(any("single" in n for n in plan.notes))

    def test_unconstrained_host_does_not_pin_goflags(self):
        plan = self._plan(constrained=False, only=["httpx"])
        build = next(s for s in plan.steps if "build" in s.label)
        self.assertEqual(build.env_extra, {})

    def test_go_toolchain_installed_first_when_absent(self):
        plan = self._plan(have_go=False, only=["httpx"])
        labels = [s.label for s in plan.steps]
        self.assertIn("install the Go toolchain", labels)
        self.assertLess(labels.index("install the Go toolchain"),
                        labels.index("build httpx"))

    def test_root_needs_no_sudo(self):
        from assay import installer
        orig = installer._sudo_needed
        installer._sudo_needed = lambda: False
        try:
            plan = self._plan(only=["nmap"])
            self.assertFalse(any(s.needs_sudo for s in plan.steps))
        finally:
            installer._sudo_needed = orig

    def test_non_debian_is_reported_not_attempted(self):
        plan = self._plan(have_apt=False, have_go=True, only=["nmap"])
        self.assertIn("nmap", plan.unsupported)
        self.assertEqual(plan.steps, [])
        self.assertTrue(any("non-Debian" in n for n in plan.notes))


class ReflectionTests(unittest.TestCase):
    ORIGIN = "http://target.test:8080"

    def _ctx(self, transform):
        """transform(reflected_value) -> what the page renders."""
        def route(m, url, h, b):
            q = parse_qs(urlsplit(url).query)
            val = q.get("q", [""])[0]
            return 200, {"Content-Type": "text/html"}, transform(val)
        return make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/s?q=x"]})

    def test_raw_html_reflection_is_high(self):
        from assay.modules.web_reflect import ReflectionModule
        ctx, _ = self._ctx(lambda v: "<html><body><p>%s</p></body></html>" % v)
        found = ReflectionModule().run_web(ctx, web_target())
        self.assertTrue(found)
        self.assertEqual(found[0].severity, "high")
        self.assertIn("HTML body text", found[0].detail)

    def test_fully_encoded_reflection_is_not_reported(self):
        from assay.modules.web_reflect import ReflectionModule
        import html as _h
        ctx, _ = self._ctx(lambda v: "<p>%s</p>" % _h.escape(v, quote=True)
                           .replace("`", "&#96;").replace("(", "&#40;")
                           .replace(")", "&#41;").replace("{", "&#123;")
                           .replace("}", "&#125;").replace(";", "&#59;"))
        self.assertEqual(ReflectionModule().run_web(ctx, web_target()), [])

    def test_no_reflection_no_finding(self):
        from assay.modules.web_reflect import ReflectionModule
        ctx, _ = self._ctx(lambda v: "<p>static page</p>")
        self.assertEqual(ReflectionModule().run_web(ctx, web_target()), [])

    def test_json_response_is_not_a_browser_sink(self):
        """Reflection into an application/json body is not XSS."""
        from assay.modules.web_reflect import ReflectionModule

        def route(m, url, h, b):
            q = parse_qs(urlsplit(url).query)
            return 200, {"Content-Type": "application/json"}, \
                '{"q":"%s"}' % q.get("q", [""])[0]
        ctx, _ = make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/s?q=x"]})
        self.assertEqual(ReflectionModule().run_web(ctx, web_target()), [])

    def test_script_context_with_quotes_is_high(self):
        from assay.modules.web_reflect import ReflectionModule
        ctx, _ = self._ctx(
            lambda v: "<html><script>var a=\"%s\";</script></html>"
            % v.replace("<", "&lt;").replace(">", "&gt;"))
        found = ReflectionModule().run_web(ctx, web_target())
        self.assertTrue(found)
        self.assertEqual(found[0].severity, "high")
        self.assertIn("script", found[0].detail.lower())


class SqliTests(unittest.TestCase):
    ORIGIN = "http://target.test:8080"
    MYSQL_ERR = ("You have an error in your SQL syntax; check the manual that "
                 "corresponds to your MySQL server version")

    def test_error_differential_fires(self):
        from assay.modules.web_sqli import SqliModule

        def route(m, url, h, b):
            v = parse_qs(urlsplit(url).query).get("id", [""])[0]
            broken = v.count("'") % 2 == 1
            body = self.MYSQL_ERR if broken else "<p>Product 1</p>"
            return 200, {"Content-Type": "text/html"}, body
        ctx, _ = make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/p?id=1"]})
        found = SqliModule().run_web(ctx, web_target())
        self.assertTrue(found, "error differential missed")
        self.assertEqual(found[0].severity, "critical")
        self.assertEqual(len(found[0].evidence), 2)

    def test_page_that_always_errors_is_not_reported(self):
        """A permanently broken page is not an injection point."""
        from assay.modules.web_sqli import SqliModule

        def route(m, url, h, b):
            return 200, {"Content-Type": "text/html"}, self.MYSQL_ERR
        ctx, _ = make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/p?id=1"]})
        self.assertEqual(SqliModule().run_web(ctx, web_target()), [])

    def test_error_text_without_differential_is_not_reported(self):
        """Error appears for both broken and balanced quotes -> not injection."""
        from assay.modules.web_sqli import SqliModule

        def route(m, url, h, b):
            v = parse_qs(urlsplit(url).query).get("id", [""])[0]
            body = self.MYSQL_ERR if "'" in v else "<p>ok</p>"
            return 200, {"Content-Type": "text/html"}, body
        ctx, _ = make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/p?id=1"]})
        self.assertEqual(SqliModule().run_web(ctx, web_target()), [])

    def test_boolean_inference_requires_stable_baseline(self):
        """An endpoint whose output changes every request must be skipped."""
        from assay.modules.web_sqli import SqliModule
        counter = {"n": 0}

        def route(m, url, h, b):
            counter["n"] += 1
            return 200, {"Content-Type": "text/html"}, \
                "<p>random %d %s</p>" % (counter["n"], "x" * counter["n"])
        ctx, _ = make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/p?id=1"]})
        self.assertEqual(SqliModule().run_web(ctx, web_target()), [])


class SsrfTests(unittest.TestCase):
    ORIGIN = "http://target.test:8080"

    def test_inband_fetch_error_is_tentative(self):
        from assay.modules.web_ssrf import SsrfModule
        from assay.oob import OOBSession
        import tempfile

        def route(m, url, h, b):
            if "url=" in url:
                return 200, {"Content-Type": "text/html"}, \
                    "cURL error 6: Could not resolve host"
            return None
        ctx, _ = make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/f?url=x"]})
        ctx.oob = OOBSession(tempfile.mkdtemp(), domain="c.oastify.com")
        ctx.oob.start()
        found = SsrfModule().run_web(ctx, web_target())
        self.assertTrue(found)
        self.assertEqual(found[0].confidence, "tentative")
        self.assertEqual(found[0].category[:3], "A10")

    def test_no_oob_backend_means_no_probe(self):
        from assay.modules.web_ssrf import SsrfModule
        ctx, http = make_ctx([], urls={self.ORIGIN: [self.ORIGIN + "/f?url=x"]})
        ctx.oob = None
        self.assertEqual(SsrfModule().run_web(ctx, web_target()), [])

    def test_ledger_records_every_payload_fired(self):
        from assay.oob import OOBSession
        import tempfile, os
        s = OOBSession(tempfile.mkdtemp(), domain="c.oastify.com")
        s.start()
        pid, host = s.payload("https://t/x param=url")
        self.assertIn(pid, host)
        path = s.flush_ledger()
        self.assertTrue(os.path.exists(path))
        self.assertIn(pid, open(path).read())
        self.assertIsNone(s.seen(pid), "ledger mode must never claim a callback")


class HostDeepTests(unittest.TestCase):
    def test_rules_fire_only_on_the_true_condition(self):
        from assay.modules.host_deep import load_rules
        rules = {r["script"]: r for r in load_rules()}
        cases = [
            ("ftp-anon", "Anonymous FTP login allowed (FTP code 230)", True),
            ("ftp-anon", "530 login incorrect", False),
            ("smb2-security-mode", "Message signing enabled but not required", True),
            ("smb2-security-mode", "Message signing enabled and required", False),
            ("smb-enum-shares", "Anonymous access: READ/WRITE", True),
            ("smb-enum-shares", "Anonymous access: <none>", False),
            ("rdp-enum-encryption", "CredSSP (NLA): FAILED", True),
            ("rdp-enum-encryption", "CredSSP (NLA): SUCCESS", False),
            ("smtp-open-relay", "Server is an open relay (16/16 tests)", True),
            ("smtp-open-relay", "Server doesn't seem to be an open relay", False),
            ("mysql-empty-password", "root account has empty password", True),
            ("mysql-empty-password", "All accounts require a password", False),
        ]
        for script, output, expected in cases:
            fired = bool(rules[script]["_re"].search(output))
            self.assertEqual(fired, expected, "%s on %r" % (script, output))

    def test_finding_carries_evidence_and_a_next_step(self):
        from assay.modules.host_deep import HostDeepModule, load_rules
        rule = next(r for r in load_rules() if r["script"] == "ftp-anon")
        f = HostDeepModule()._finding(rule, "10.0.0.9", 21,
                                      "Anonymous FTP login allowed", "Anonymous FTP")
        self.assertEqual(f.confidence, "confirmed")
        self.assertTrue(f.evidence and f.evidence[0].output)
        self.assertIn("10.0.0.9", f.repro)
        self.assertTrue(f.impact)


class SurfaceTests(unittest.TestCase):
    def test_vhost_requires_divergence_from_both_baselines(self):
        """A catch-all server that answers everything identically yields nothing."""
        from assay import recon
        ctx, http = make_ctx([])       # every request returns the same shell
        hits = recon.vhost_probe(http, "http://target.test:8080/",
                                 ["dev.target.test", "api.target.test"])
        self.assertEqual(hits, [])

    def test_vhost_detected_when_response_differs(self):
        from assay import recon

        def route(m, url, h, b):
            if h.get("Host", "").startswith("dev."):
                return 200, {"Content-Type": "text/html"}, \
                    "<html><h1>Staging control panel</h1>" + ("filler " * 60) + "</html>"
            return None
        ctx, http = make_ctx([route])
        hits = recon.vhost_probe(http, "http://target.test:8080/",
                                 ["dev.target.test", "api.target.test"])
        self.assertEqual([n for n, _ in hits], ["dev.target.test"])

    def test_origin_requires_a_cdn_in_front(self):
        """No CDN means there is nothing to bypass."""
        from assay import recon
        ctx, http = make_ctx([])
        self.assertIsNone(recon.origin_exposed(http, "target.test", "1.2.3.4"))

    def test_cdn_detection(self):
        from assay.recon import detect_cdn
        from assay.net import Resp
        r = Resp(url="x", status=200, headers={"CF-Ray": "abc"}, body="", elapsed=0)
        self.assertEqual(detect_cdn(r), "cloudflare")
        self.assertEqual(detect_cdn(Resp(url="x", status=200,
                                         headers={"Server": "nginx"},
                                         body="", elapsed=0)), "")


class UrlSourcingTests(unittest.TestCase):
    def test_js_extraction_separates_local_from_foreign(self):
        from assay.urls import extract_from_js
        js = ('fetch("/api/v2/me");var C="https://cdn.other.tld/x.js";'
              'var A="https://target.test/v1/orders";var m="application/json";'
              'var i="/logo.png";')
        local, foreign = extract_from_js(js, "https://target.test/a.js", "target.test")
        self.assertIn("https://target.test/api/v2/me", local)
        self.assertIn("https://target.test/v1/orders", local)
        self.assertEqual(foreign, ["https://cdn.other.tld/x.js"])
        joined = " ".join(local)
        self.assertNotIn("application/json", joined)
        self.assertNotIn("logo.png", joined)

    def test_dedupe_collapses_id_variants(self):
        from assay.urls import dedupe_by_shape
        urls = ["https://t/x?id=%d" % i for i in range(50)] + ["https://t/y?a=1&b=2"]
        self.assertEqual(len(dedupe_by_shape(urls, 100)), 2)

    def test_assets_are_not_injection_points(self):
        from assay.urls import dedupe_by_shape
        self.assertEqual(dedupe_by_shape(
            ["https://t/a.png", "https://t/b.css", "https://t/c.woff2"], 10), [])

    def test_hidden_params_are_appended(self):
        from assay.urls import with_params
        got = with_params("https://t/x?id=1", ["debug", "id", "admin"])
        self.assertIn("debug=1", got)
        self.assertIn("admin=1", got)
        self.assertEqual(got.count("id="), 1, "existing param must not duplicate")


class BasicAuthTests(unittest.TestCase):
    def test_header_is_set_and_shared_with_tools(self):
        from assay.config import Config
        from assay import tools
        cfg = Config(basic_auth="admin:s3cret")
        self.assertEqual(cfg.request_headers()["Authorization"],
                         "Basic YWRtaW46czNjcmV0")
        self.assertEqual(tools.header_args("nuclei",
                                           {"Authorization": cfg.auth_header()}),
                         ["-H", "Authorization: Basic YWRtaW46czNjcmV0"])

    def test_absent_by_default(self):
        from assay.config import Config
        self.assertIsNone(Config().auth_header())
        self.assertNotIn("Authorization", Config().request_headers())


class WindowsWslBridgeTests(unittest.TestCase):
    """assay hosted on Windows, external scanners executed inside WSL."""

    def setUp(self):
        from assay import env
        self._name = env.os.name
        self._state = dict(env._WSL_STATE)
        self._paths = dict(env._PATH_CACHE)

    def tearDown(self):
        from assay import env
        env.os.name = self._name
        env._WSL_STATE.clear(); env._WSL_STATE.update(self._state)
        env._PATH_CACHE.clear(); env._PATH_CACHE.update(self._paths)

    def _windows(self, gateway=None):
        from assay import env
        env.os.name = "nt"
        env._WSL_STATE.update(checked=True, ok=True, distro="kali-linux",
                              **({"gateway": gateway} if gateway else {}))
        env._PATH_CACHE.clear()
        return env

    def test_native_host_is_untouched(self):
        from assay import tools
        self.assertEqual(tools.bridge(["nmap", "-sV"]), ["nmap", "-sV"])

    def test_commands_are_wrapped_for_wsl(self):
        self._windows()
        from assay import tools
        self.assertEqual(tools.bridge(["nuclei", "-silent"]),
                         ["wsl.exe", "-d", "kali-linux", "--", "nuclei", "-silent"])

    def test_windows_paths_translate_to_wsl_mounts(self):
        env = self._windows()
        self.assertEqual(env.to_wsl_path(r"C:\Users\me\out\raw\nmap.xml"),
                         "/mnt/c/Users/me/out/raw/nmap.xml")

    def test_loopback_proxy_is_rewritten_to_the_windows_host(self):
        """A WSL-side tool proxying to 127.0.0.1 would miss Burp entirely."""
        self._windows(gateway="172.28.16.1")
        from assay import tools
        self.assertEqual(tools.proxy_args("nuclei", "http://127.0.0.1:8080"),
                         ["-proxy", "http://172.28.16.1:8080"])
        self.assertEqual(tools.proxy_args("ffuf", "http://localhost:8080"),
                         ["-x", "http://172.28.16.1:8080"])

    def test_explicit_proxy_address_is_left_alone(self):
        self._windows(gateway="172.28.16.1")
        from assay import tools
        self.assertEqual(tools.proxy_args("nuclei", "http://192.168.1.50:8080"),
                         ["-proxy", "http://192.168.1.50:8080"])

    def test_no_proxy_stays_no_proxy(self):
        self._windows(gateway="172.28.16.1")
        from assay import tools
        self.assertEqual(tools.proxy_args("nuclei", None), [])

    def test_sudo_check_does_not_crash_without_geteuid(self):
        """os.geteuid does not exist on Windows."""
        from assay import installer
        real = getattr(installer.os, "geteuid", None)
        try:
            if real is not None:
                del installer.os.geteuid
            self.assertTrue(installer._sudo_needed())
        finally:
            if real is not None:
                installer.os.geteuid = real

    def test_no_subprocess_uses_a_shell(self):
        """shell=True plus attacker-influenced argv is how tools get owned.

        Parsed rather than grepped: the string also appears in prose explaining
        why it is avoided, and a test that cannot tell code from a comment is
        not a test.
        """
        import ast
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent / "assay"
        offenders = []
        for f in sorted(root.rglob("*.py")):
            tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for kw in node.keywords:
                    if kw.arg != "shell":
                        continue
                    if isinstance(kw.value, ast.Constant) and kw.value.value:
                        offenders.append("%s:%d" % (f.name, node.lineno))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
