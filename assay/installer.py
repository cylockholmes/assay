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
from dataclasses import dataclass, field
from collections.abc import Callable

from assay import env, tools


@dataclass
class Step:
    label: str
    cmd: list[str]
    needs_sudo: bool = False
    optional: bool = False          # failure is survivable, keep going
    env_extra: dict[str, str] = field(default_factory=dict)

    def display(self) -> str:
        prefix = "sudo " if self.needs_sudo else ""
        extra = " ".join("%s=%s" % kv for kv in sorted(self.env_extra.items()))
        return (extra + " " if extra else "") + prefix + " ".join(self.cmd)


@dataclass
class Plan:
    steps: list[Step] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    already: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    path_hint: str = ""

    @property
    def empty(self) -> bool:
        return not self.steps


def _has(binary: str) -> bool:
    return shutil.which(binary) is not None or env.which(binary) is not None


def _sudo_needed() -> bool:
    """Is sudo required to install? os.geteuid does not exist on Windows."""
    getuid = getattr(os, "geteuid", None)
    if getuid is None:
        # Windows host: the install happens inside WSL, where the shell's own
        # user decides. Assume a normal user and let sudo prompt if needed.
        return True
    return getuid() != 0


def gopath_bin() -> str:
    # Through tools.run so that under the bridge this asks the distribution's
    # go, not a Windows one - the binaries go install produces live where the
    # command ran, and that is the path the rest of the install needs.
    out = (tools.run(["go", "env", "GOPATH"], timeout=10).out or "").strip()
    if out:
        return out.rstrip("/") + "/bin"
    return os.path.expanduser("~/go/bin")


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------


def build_plan(only: list[str] | None = None,
               include_optional: bool = True) -> Plan:
    """Work out what is missing and exactly what would be run to fix it."""
    plan = Plan()
    env.augment_path()
    have = tools.available()
    res = env.resources()

    wanted: list[tuple[str, tools.ToolSpec]] = []
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
    queued: list[tuple[str, tools.ToolSpec]] = []

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
        # Memory, not core count: a 2-vCPU VM with 8 GB builds fine in
        # parallel, and -p=1 there nearly doubled the install time.
        low_mem = res.mem_avail_mb < 3000
        build_env = {"GOFLAGS": "-p=1"} if low_mem else {}
        if low_mem:
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


def run_plan(plan: Plan, on_step: Callable[[str, str], None] | None = None,
             timeout: float = 900.0) -> tuple[int, int]:
    """Execute the plan. Returns (succeeded, failed)."""
    def say(kind: str, msg: str) -> None:
        if on_step:
            on_step(kind, msg)

    ok = fail = 0
    for i, step in enumerate(plan.steps, 1):
        say("start", "[%d/%d] %s" % (i, len(plan.steps), step.label))
        cmd = (["sudo", "-n"] + step.cmd) if step.needs_sudo else list(step.cmd)
        extra = dict(step.env_extra)
        if not env.use_wsl_bridge():
            extra["PATH"] = os.environ.get("PATH", "") + os.pathsep + gopath_bin()
        # else: inside the distribution its own PATH already carries
        # $GOPATH/bin (persist_path adds it to the shell startup files). Pushing a
        # Windows PATH across the bridge would replace it with directories
        # the distribution cannot see.
        proc = tools.run(cmd, timeout=timeout, env_extra=extra)
        if proc.timed_out:
            fail += 1
            say("fail", "%s timed out after %ds" % (step.label, int(timeout)))
            continue

        if proc.rc == 0:
            ok += 1
            say("ok", step.label)
            continue

        # sudo -n fails when a password is required rather than prompting.
        stderr = (proc.err or "").strip().splitlines()
        hint = stderr[-1][:160] if stderr else "exit %d" % proc.rc
        if step.needs_sudo and "password" in (proc.err or "").lower():
            hint = ("sudo needs a password. Run 'sudo -v' first, then re-run "
                    "'assay install'.")
        fail += 1
        say("fail" if not step.optional else "skip", "%s - %s" % (step.label, hint))
    return ok, fail


def persist_path(bin_dir: str) -> list[str]:
    """Add a directory to the user's shell startup files. Returns files changed.

    ~/.profile and ~/.zprofile cover login shells, including non-interactive
    ones (ssh host cmd, cron, scripts): Debian's ~/.bashrc returns early for
    those, so a line appended there never runs. The directory goes first, so
    the Go tools win over same-named system binaries (Kali's /usr/bin/httpx
    is the Python client).
    """
    line = 'export PATH="%s:$PATH"' % bin_dir
    changed: list[str] = []
    for rc in ("~/.profile", "~/.zprofile", "~/.bashrc", "~/.zshrc"):
        path = os.path.expanduser(rc)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                if bin_dir in fh.read():
                    continue
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("\n# added by assay install\n%s\n" % line)
            changed.append(path)
        except OSError:
            continue
    return changed


def verify(names: list[str] | None = None) -> dict[str, str | None]:
    """Re-resolve tools after an install, ignoring any cached PATH."""
    env.augment_path()
    have = tools.available()
    if names:
        return {n: have.get(n) for n in names}
    return have
