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


class InstallerPlanTests(unittest.TestCase):
    def _plan(self, only, have_go=True):
        missing = {n: None for n in tools.REGISTRY}
        res = mock.Mock(constrained=False, mem_avail_mb=8000)
        with mock.patch.object(tools, "available", return_value=missing), \
             mock.patch.object(env, "resources", return_value=res), \
             mock.patch.object(installer, "_has",
                               side_effect=lambda b: b == "apt-get" or (have_go and b == "go")), \
             mock.patch.object(installer, "gopath_bin", return_value="/home/k/go/bin"):
            return installer.build_plan(only=only)

    def test_naabu_build_pulls_in_libpcap_headers_and_a_compiler(self):
        plan = self._plan(["naabu"])
        cmds = [" ".join(s.cmd) for s in plan.steps]
        self.assertTrue(any("libpcap-dev" in c and "gcc" in c for c in cmds), cmds)
        dep = next(i for i, c in enumerate(cmds) if "libpcap-dev" in c)
        build = next(i for i, c in enumerate(cmds) if "naabu" in c and "go install" in c)
        self.assertLess(dep, build)
        self.assertIn("apt-get update -qq", cmds[0])

    def test_go_toolchain_and_deps_share_one_apt_step(self):
        plan = self._plan(["naabu"], have_go=False)
        cmds = [" ".join(s.cmd) for s in plan.steps]
        self.assertEqual(sum("apt-get install" in c for c in cmds), 1, cmds)
        self.assertTrue(any("golang-go" in c and "libpcap-dev" in c for c in cmds))

    def test_pure_go_tool_needs_no_extra_packages(self):
        plan = self._plan(["katana"])
        self.assertFalse(any("apt-get" in " ".join(s.cmd) for s in plan.steps))


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
