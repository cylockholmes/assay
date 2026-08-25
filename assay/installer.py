"""Automatic installation of the external tools assay orchestrates.

Everything here is explicit by design. Installing software is not something to
do silently, so the planner builds the complete command list first, prints it,
and asks before running anything. `--dry-run` stops after printing.

On a constrained VM the Go builds are the dangerous part: `go build` will
happily spawn one compiler per core and OOM a 2 GB box. The plan pins
GOFLAGS=-p=1 and runs modules sequentially when memory is tight.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from assay import env, tools


@dataclass
class Step:
    label: str
    cmd: List[str]
    needs_sudo: bool = False
    optional: bool = False          # failure is survivable, keep going
    env_extra: Dict[str, str] = field(default_factory=dict)

    def display(self) -> str:
        prefix = "sudo " if self.needs_sudo else ""
        extra = " ".join("%s=%s" % kv for kv in sorted(self.env_extra.items()))
        return (extra + " " if extra else "") + prefix + " ".join(self.cmd)


@dataclass
class Plan:
    steps: List[Step] = field(default_factory=list)
    missing: List[str] = field(default_factory=list)
    already: List[str] = field(default_factory=list)
    unsupported: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    path_hint: str = ""

    @property
    def empty(self) -> bool:
        return not self.steps


def _has(binary: str) -> bool:
    return shutil.which(binary) is not None or env.which(binary) is not None


def _sudo_needed() -> bool:
    return os.geteuid() != 0


def gopath_bin() -> str:
    try:
        out = subprocess.run(["go", "env", "GOPATH"], capture_output=True,
                             text=True, timeout=10).stdout.strip()
        if out:
            return os.path.join(out, "bin")
    except (OSError, subprocess.SubprocessError):
        pass
    return os.path.expanduser("~/go/bin")


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


def build_plan(only: Optional[List[str]] = None,
               include_optional: bool = True) -> Plan:
    """Work out what is missing and exactly what would be run to fix it."""
    plan = Plan()
    env.augment_path()
    have = tools.available()
    res = env.resources()

    wanted: List[Tuple[str, tools.ToolSpec]] = []
    for name, spec in tools.REGISTRY.items():
        if only and name not in only:
            continue
        if not include_optional and spec.optional:
            continue
        if have.get(name):
            plan.already.append(name)
            continue
        wanted.append((name, spec))
        plan.missing.append(name)

    if not wanted:
        return plan

    apt_pkgs = [s.apt for _, s in wanted if s.method == "apt"]
    go_mods = [(n, s) for n, s in wanted if s.method == "go"]
    manual = [n for n, s in wanted if s.method == "manual"]
    plan.unsupported = manual

    have_apt = _has("apt-get")
    sudo = _sudo_needed()
    queued: List[Tuple[str, tools.ToolSpec]] = []

    # -- apt ---------------------------------------------------------------
    if apt_pkgs:
        if not have_apt:
            plan.unsupported += [n for n, s in wanted if s.method == "apt"]
            plan.notes.append(
                "apt-get not found - this looks like a non-Debian system. "
                "Install these with your own package manager: " + ", ".join(apt_pkgs)
            )
        else:
            plan.steps.append(Step("refresh package lists",
                                   ["apt-get", "update", "-qq"], needs_sudo=sudo))
            plan.steps.append(Step("install %d package(s)" % len(apt_pkgs),
                                   ["apt-get", "install", "-y", "-qq"] + apt_pkgs,
                                   needs_sudo=sudo))
            queued += [(n, sp) for n, sp in wanted if sp.method == "apt"]

    # -- go toolchain ------------------------------------------------------
    if go_mods:
        if not _has("go"):
            if have_apt:
                plan.steps.append(Step("install the Go toolchain",
                                       ["apt-get", "install", "-y", "-qq", "golang-go"],
                                       needs_sudo=sudo))
            else:
                plan.unsupported += [n for n, _ in go_mods]
                plan.notes.append(
                    "Go is not installed and apt is unavailable; install Go from "
                    "https://go.dev/dl/ and re-run 'assay install'."
                )
                go_mods = []

    if go_mods:
        # One compiler process at a time: parallel Go builds OOM a small VM.
        build_env = {"GOFLAGS": "-p=1"} if res.constrained else {}
        if res.constrained:
            plan.notes.append(
                "Only %d MB RAM available - Go builds are pinned to a single "
                "compiler process. Expect this to be slow but not to swap."
                % res.mem_avail_mb
            )
        for name, spec in go_mods:
            plan.steps.append(Step("build %s" % name,
                                   ["go", "install", "-v", spec.go],
                                   optional=True, env_extra=build_env))
        queued += go_mods

    # -- post-install ------------------------------------------------------
    for name, spec in queued:
        for cmd in spec.post:
            plan.steps.append(Step("%s: %s" % (name, cmd.split()[1] if len(cmd.split()) > 1
                                               else "post-install"),
                                   cmd.split(), optional=True))

    if any(n for n, _ in queued if tools.REGISTRY[n].method == "go"):
        plan.path_hint = gopath_bin()
    seen: set = set()
    plan.unsupported = [n for n in plan.unsupported
                        if not (n in seen or seen.add(n))]
    return plan


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


def run_plan(plan: Plan, on_step: Optional[Callable[[str, str], None]] = None,
             timeout: float = 900.0) -> Tuple[int, int]:
    """Execute the plan. Returns (succeeded, failed)."""
    def say(kind: str, msg: str) -> None:
        if on_step:
            on_step(kind, msg)

    ok = fail = 0
    for i, step in enumerate(plan.steps, 1):
        say("start", "[%d/%d] %s" % (i, len(plan.steps), step.label))
        cmd = (["sudo", "-n"] + step.cmd) if step.needs_sudo else list(step.cmd)
        proc_env = dict(os.environ)
        proc_env.update(step.env_extra)
        proc_env["PATH"] = proc_env.get("PATH", "") + os.pathsep + gopath_bin()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, env=proc_env)
        except subprocess.TimeoutExpired:
            fail += 1
            say("fail", "%s timed out after %ds" % (step.label, int(timeout)))
            continue
        except OSError as exc:
            fail += 1
            say("fail", "%s: %s" % (step.label, exc))
            continue

        if proc.returncode == 0:
            ok += 1
            say("ok", step.label)
            continue

        # sudo -n fails when a password is required rather than prompting.
        stderr = (proc.stderr or "").strip().splitlines()
        hint = stderr[-1][:160] if stderr else "exit %d" % proc.returncode
        if step.needs_sudo and "password" in (proc.stderr or "").lower():
            hint = ("sudo needs a password. Run 'sudo -v' first, then re-run "
                    "'assay install'.")
        fail += 1
        say("fail" if not step.optional else "skip", "%s - %s" % (step.label, hint))
    return ok, fail


def persist_path(bin_dir: str) -> List[str]:
    """Add a directory to the user's shell rc files. Returns files changed."""
    line = 'export PATH="$PATH:%s"' % bin_dir
    changed: List[str] = []
    for rc in ("~/.bashrc", "~/.zshrc"):
        path = os.path.expanduser(rc)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                if bin_dir in fh.read():
                    continue
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("\n# added by assay install\n%s\n" % line)
            changed.append(path)
        except OSError:
            continue
    return changed


def verify(names: Optional[List[str]] = None) -> Dict[str, Optional[str]]:
    """Re-resolve tools after an install, ignoring any cached PATH."""
    env.augment_path()
    have = tools.available()
    if names:
        return {n: have.get(n) for n in names}
    return have
