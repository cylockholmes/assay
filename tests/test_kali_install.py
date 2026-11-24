"""Install and tool-resolution behaviour seen on a fresh Kali box.

Offline: tools are fake files in a temp dir and the installer only plans.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, __file__.rsplit("/tests/", 1)[0])

from assay import env, installer, tools

ROOT = __file__.rsplit("/tests/", 1)[0]


def _exe(path: str, body: str) -> str:
    with open(path, "w") as fh:
        fh.write(body)
    os.chmod(path, 0o755)
    return path


class ToolResolutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path_dir = os.path.join(self.tmp.name, "usr-bin")
        self.go_dir = os.path.join(self.tmp.name, "go-bin")
        os.makedirs(self.path_dir)
        os.makedirs(self.go_dir)
        self.patches = [
            mock.patch.dict(os.environ, {"PATH": self.path_dir}),
            mock.patch.object(env, "EXTRA_BIN_DIRS", [self.go_dir]),
            mock.patch.object(env, "use_wsl_bridge", return_value=False),
        ]
        for p in self.patches:
            p.start()
        tools._RESOLVED.clear()
        tools._SHADOWED.clear()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        tools._RESOLVED.clear()
        tools._SHADOWED.clear()
        self.tmp.cleanup()

    def test_python_httpx_on_path_is_not_projectdiscovery_httpx(self):
        _exe(os.path.join(self.path_dir, "httpx"),
             "#!/usr/bin/python3\nfrom httpx import main\nmain()\n")
        self.assertIsNone(tools.resolve("httpx"))
        self.assertIn("httpx", tools.shadowed())

    def test_go_bin_httpx_wins_over_python_httpx(self):
        _exe(os.path.join(self.path_dir, "httpx"), "#!/usr/bin/python3\n")
        real = _exe(os.path.join(self.go_dir, "httpx"), "\x7fELF fake")
        self.assertEqual(tools.resolve("httpx"), real)
        self.assertEqual(tools._real_argv(["httpx", "-silent"]), [real, "-silent"])

    def test_kali_httpx_toolkit_is_accepted(self):
        _exe(os.path.join(self.path_dir, "httpx"), "#!/usr/bin/python3\n")
        kit = _exe(os.path.join(self.path_dir, "httpx-toolkit"), "\x7fELF fake")
        self.assertEqual(tools.resolve("httpx"), kit)
        self.assertEqual(tools._real_argv(["httpx", "-json"])[0], kit)

    def test_genuine_tool_on_path_is_left_alone(self):
        real = _exe(os.path.join(self.path_dir, "httpx"), "\x7fELF fake")
        self.assertEqual(tools.resolve("httpx"), real)
        self.assertEqual(tools._real_argv(["httpx"]), ["httpx"])
        self.assertEqual(tools.shadowed(), {})

    def test_run_executes_the_resolved_binary(self):
        _exe(os.path.join(self.path_dir, "httpx"), "#!/usr/bin/python3\nexit 9\n")
        _exe(os.path.join(self.go_dir, "httpx"), "#!/bin/sh\necho projectdiscovery\n")
        tools.resolve("httpx")
        proc = tools.run(["httpx", "-version"], timeout=10)
        self.assertEqual(proc.out.strip(), "projectdiscovery")


class KaliAptWhenPinnedTests(unittest.TestCase):
    """Owner's call (2026-11-24): on Kali take a Go tool from apt only when
    the package is exactly the pinned release; otherwise go install."""

    POLICY = {"nuclei": "3.11.1-0kali1", "naabu": "2.7.0-0kali1",
              "katana": "1.7.9-0kali1", "subfinder": "1:2.17.0-0kali1"}

    def _plan(self, only, kali=True):
        missing = {n: None for n in tools.REGISTRY}
        res = mock.Mock(constrained=False, mem_avail_mb=8000)

        def fake_run(cmd, **kw):
            if cmd[:2] == ["apt-cache", "policy"]:
                ver = self.POLICY.get(cmd[2])
                out = ("%s:\n  Installed: (none)\n  Candidate: %s\n"
                       % (cmd[2], ver or "(none)"))
                return tools.Proc(rc=0, out=out, err="", cmd=list(cmd))
            return tools.Proc(rc=0, out="/home/k/go\n", err="", cmd=list(cmd))

        with mock.patch.object(tools, "available", return_value=missing), \
             mock.patch.object(env, "resources", return_value=res), \
             mock.patch.object(env, "is_kali", return_value=kali), \
             mock.patch.object(tools, "run", side_effect=fake_run), \
             mock.patch.object(installer, "_has", side_effect=lambda b: b in ("apt-get", "go")):
            return installer.build_plan(only=only)

    def _cmds(self, plan):
        return [" ".join(st.cmd) for st in plan.steps]

    def test_exact_pin_comes_from_apt(self):
        cmds = self._cmds(self._plan(["nuclei", "naabu", "subfinder"]))
        apt = next(c for c in cmds if c.startswith("apt-get install"))
        for pkg in ("nuclei", "naabu", "subfinder"):
            self.assertIn(pkg, apt.split())
        self.assertFalse(any(c.startswith("go install") for c in cmds), cmds)
        self.assertTrue(any("update-templates" in c for c in cmds))

    def test_version_mismatch_or_no_package_keeps_go_install(self):
        cmds = self._cmds(self._plan(["katana", "dnsx"]))
        self.assertTrue(any("go install" in c and "katana@v1.8.0" in c for c in cmds))
        self.assertTrue(any("go install" in c and "dnsx@v1.3.1" in c for c in cmds))
        self.assertFalse(any(c.startswith("apt-get install") for c in cmds), cmds)

    def test_not_kali_never_uses_apt_for_go_tools(self):
        cmds = self._cmds(self._plan(["nuclei"], kali=False))
        self.assertTrue(any("go install" in c and "nuclei" in c for c in cmds))

    def test_is_kali_reads_os_release(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write('PRETTY_NAME="Kali GNU/Linux Rolling"\nID=kali\nID_LIKE=debian\n')
        try:
            with mock.patch.object(env, "use_wsl_bridge", return_value=False):
                self.assertTrue(env.is_kali(fh.name))
                self.assertFalse(env.is_kali("/nonexistent"))
        finally:
            os.unlink(fh.name)


class InstallScriptTests(unittest.TestCase):
    def test_flags_parse_and_help_lists_them(self):
        out = subprocess.run(["bash", os.path.join(ROOT, "install.sh"), "--help"],
                             capture_output=True, text=True, timeout=10).stdout
        self.assertIn("--no-ai", out)
        self.assertIn("--ai", out)

    def test_ai_prompt_only_reads_from_a_terminal(self):
        with open(os.path.join(ROOT, "install.sh")) as fh:
            src = fh.read()
        self.assertIn('[ "$AI" = ask ] && [ -t 0 ]', src)


if __name__ == "__main__":
    unittest.main()


class ExplicitScopeNeverWidensTests(unittest.TestCase):
    """A Kali lab run, `assay scan http://127.0.0.1:3000 --scope 127.0.0.1`,
    once parsed the scope to nothing, which meant "allow every host", and the
    scan followed Juice Shop's links to third-party APIs with payloads.
    Loopback is never in scope; a scope that allows nothing is refused."""

    def _cfg(self, *argv):
        from assay import cli
        args = cli.build_parser().parse_args(["scan", *argv, "--no-open"])
        with tempfile.TemporaryDirectory() as out:
            args.out = out
            return cli.make_config(args)

    def _refused(self, *argv):
        with self.assertRaises(SystemExit) as cm:
            self._cfg(*argv)
        self.assertEqual(cm.exception.code, 2)

    def test_the_kali_lab_command_is_refused(self):
        self._refused("http://127.0.0.1:3000", "--scope", "127.0.0.1")

    def test_loopback_scope_cannot_widen_a_real_target(self):
        self._refused("http://172.17.0.2:3000", "--scope", "127.0.0.1")

    def test_scope_that_allows_nothing_is_refused(self):
        self._refused("http://172.17.0.2:3000", "--scope", "0.0.0.0/0")

    def test_scope_file_with_no_allow_rules_is_refused(self):
        for body in ("# nothing allowed\n!evil.example.com\n",
                     "localhost\n127.0.0.1\n::1\n127.0.0.0/8\n"):
            with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
                fh.write(body)
            try:
                self._refused("app.example.com", "--scope", fh.name)
            finally:
                os.unlink(fh.name)

    def test_loopback_targets_are_never_scanned(self):
        for t in ("127.0.0.1", "localhost", "http://127.0.0.1:3000",
                  "http://localhost:3000/", "127.0.0.5", "app.localhost"):
            self._refused(t)

    def test_private_lab_ip_scope_is_enforced(self):
        cfg = self._cfg("http://172.17.0.2:3000", "--scope", "172.17.0.2")
        self.assertFalse(cfg.scope.permissive)
        self.assertTrue(cfg.scope.allows("172.17.0.2"))
        self.assertFalse(cfg.scope.allows("api.ipinfodb.com"))
        self.assertFalse(cfg.scope.allows("127.0.0.1"))

    def test_loopback_is_stripped_from_a_mixed_scope(self):
        from assay.config import Scope
        scope = Scope(allow=["10.0.0.0/8", "localhost", "127.0.0.1"])
        self.assertFalse(scope.allows("127.0.0.1"))
        self.assertFalse(scope.allows("localhost"))
        self.assertTrue(scope.allows("10.1.2.3"))
        wide = Scope(allow=["*"])
        self.assertFalse(wide.allows("localhost"))
        self.assertFalse(wide.allows("127.0.0.1"))
        self.assertFalse(wide.allows("::1"))


_FAKE_NMAP = r'''#!/usr/bin/env python3
import sys
args = sys.argv[1:]
out = args[args.index("-oX") + 1]
ok = "--unprivileged" in args or MODE == "ok"
host = '<host><address addr="172.17.0.2" addrtype="ipv4"/><ports>' \
       '<port protocol="tcp" portid="3000"><state state="open"/>' \
       '<service name="http"/></port></ports></host>'
fin = '<finished exit="success"/>' if ok else \
      '<finished exit="error" errormsg="Couldn\'t open a raw socket or eth handle."/>'
with open(out, "w") as fh:
    fh.write('<?xml version="1.0"?><nmaprun>%s<runstats>%s</runstats></nmaprun>'
             % (host if ok else "", fin))
'''


class NmapFailureIsNotACleanScanTests(unittest.TestCase):
    """On minimal Kali, nmap's --privileged wrapper fails without file
    capabilities and writes exit="error"; that used to read as 'no open
    ports' and the host was reported clean."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.bin = os.path.join(self.tmp.name, "bin")
        os.makedirs(self.bin)
        self.p = mock.patch.dict(os.environ, {"PATH": self.bin + os.pathsep
                                              + os.environ.get("PATH", "")})
        self.p.start()
        tools.NMAP_UNPRIVILEGED.clear()

    def tearDown(self):
        self.p.stop()
        tools.NMAP_UNPRIVILEGED.clear()
        self.tmp.cleanup()

    def _nmap(self, mode):
        _exe(os.path.join(self.bin, "nmap"),
             _FAKE_NMAP.replace("MODE", repr(mode), 1))

    def test_raw_socket_error_retries_unprivileged(self):
        self._nmap("needs-unprivileged")
        res = tools.nmap_scan(["172.17.0.2"], "3000", {}, out_dir=self.tmp.name)
        self.assertEqual([p.port for p in res["172.17.0.2"].ports], [3000])
        self.assertTrue(tools.NMAP_UNPRIVILEGED.is_set())

    def test_persistent_error_raises_instead_of_reporting_clean(self):
        _exe(os.path.join(self.bin, "nmap"), _FAKE_NMAP.replace(
            'ok = "--unprivileged" in args or MODE == "ok"', "ok = False"))
        with self.assertRaises(tools.NmapFailed):
            tools.nmap_scan(["172.17.0.2"], "3000", {}, out_dir=self.tmp.name)

    def test_successful_run_is_unchanged(self):
        self._nmap("ok")
        res = tools.nmap_scan(["172.17.0.2"], "3000", {}, out_dir=self.tmp.name)
        self.assertIn("172.17.0.2", res)
        self.assertFalse(tools.NMAP_UNPRIVILEGED.is_set())


class PersistPathTests(unittest.TestCase):
    def test_go_bin_goes_first_and_reaches_login_shells(self):
        with tempfile.TemporaryDirectory() as home:
            for rc in (".profile", ".bashrc", ".zshrc"):
                open(os.path.join(home, rc), "w").write("# stock\n")
            with mock.patch.dict(os.environ, {"HOME": home}):
                changed = installer.persist_path("/home/kali/go/bin")
                again = installer.persist_path("/home/kali/go/bin")
            names = sorted(os.path.basename(c) for c in changed)
            self.assertEqual(names, [".bashrc", ".profile", ".zshrc"])
            self.assertEqual(again, [])
            body = open(os.path.join(home, ".profile")).read()
            self.assertIn('export PATH="/home/kali/go/bin:$PATH"', body)
            self.assertFalse(os.path.exists(os.path.join(home, ".zprofile")))
