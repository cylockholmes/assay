"""Wrappers around the external scanners assay orchestrates.

Everything here is optional: assay degrades to its own pure-Python checks when a
binary is missing, and tells the user exactly what they are losing. Output is
streamed line by line rather than buffered, which matters on a small VM where
a nuclei run against a /24 can otherwise produce hundreds of MB.
"""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import shutil
import re
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

from assay import env
from assay.models import Port


@dataclass
class ToolSpec:
    """One external tool: what it buys us, and how to obtain it.

    `apt` and `go` are the machine-readable install methods used by
    assay.installer; `install` is the human-readable string shown by doctor.
    Keeping all three on the same object means there is exactly one place to
    edit when a tool moves or is renamed.
    """

    name: str
    purpose: str
    install: str
    binary: str = ""
    optional: bool = True
    apt: str = ""                       # apt package name
    go: str = ""                        # go module path for `go install`
    post: List[str] = field(default_factory=list)   # commands to run after install

    def __post_init__(self) -> None:
        self.binary = self.binary or self.name

    @property
    def method(self) -> str:
        if self.apt:
            return "apt"
        if self.go:
            return "go"
        return "manual"


REGISTRY: Dict[str, ToolSpec] = {
    "nmap": ToolSpec("nmap", "port + service/version detection on host targets",
                     "sudo apt install -y nmap", apt="nmap", optional=False),
    "naabu": ToolSpec("naabu", "fast SYN/CONNECT port sweep (faster than nmap for discovery)",
                      "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
                      go="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "httpx": ToolSpec("httpx", "HTTP probing, titles, tech detection, favicon hashes",
                      "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
                      go="github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "nuclei": ToolSpec("nuclei", "community CVE/misconfig templates - the volume driver",
                       "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                       go="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                       post=["nuclei -update-templates -silent"]),
    "katana": ToolSpec("katana", "crawler that feeds URLs/params to the active checks",
                       "go install github.com/projectdiscovery/katana/cmd/katana@latest",
                       go="github.com/projectdiscovery/katana/cmd/katana@latest"),
    "subfinder": ToolSpec("subfinder", "passive subdomain enumeration (opt-in, third-party APIs)",
                          "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                          go="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "dnsx": ToolSpec("dnsx", "DNS resolution and CNAME chains for takeover checks",
                     "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
                     go="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    "ffuf": ToolSpec("ffuf", "content discovery with automatic soft-404 calibration",
                     "sudo apt install -y ffuf", apt="ffuf"),
    "seclists": ToolSpec("seclists", "wordlists ffuf and dnsx need for content "
                         "discovery and subdomain brute-forcing",
                         "sudo apt install -y seclists", apt="seclists",
                         binary="__wordlist__"),
    "gau": ToolSpec("gau", "historical URLs from Wayback/CommonCrawl/OTX (passive)",
                    "go install github.com/lc/gau/v2/cmd/gau@latest",
                    go="github.com/lc/gau/v2/cmd/gau@latest"),
    "waybackurls": ToolSpec("waybackurls", "historical URLs from the Wayback Machine (passive)",
                            "go install github.com/tomnomnom/waybackurls@latest",
                            go="github.com/tomnomnom/waybackurls@latest"),
    "arjun": ToolSpec("arjun", "discovers hidden GET/POST parameters the crawl never sees",
                      "sudo apt install -y arjun", apt="arjun"),
    "xsltproc": ToolSpec("xsltproc",
                         "renders nmap XML into NmapView's standalone HTML dashboard",
                         "sudo apt install -y xsltproc", apt="xsltproc"),
}


@dataclass
class Proc:
    rc: int
    out: str
    err: str
    cmd: List[str] = field(default_factory=list)
    timed_out: bool = False
    # Cut short by the operator's skip key, not a deadline. A separate flag
    # from timed_out rather than reusing it: a caller that wants to tell "the
    # tool was slow" apart from "we chose to move on" - for its own logging,
    # say - needs the distinction preserved, not collapsed into one bit.
    skipped: bool = False

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out and not self.skipped

    def cmdline(self) -> str:
        return " ".join(self.cmd)


def human_duration(seconds: float) -> str:
    """Compact elapsed time. "763s" is hard to read at a glance; "12m43s" is not."""
    total = int(max(0, seconds))
    if total < 60:
        return "%ds" % total
    if total < 3600:
        return "%dm%02ds" % divmod(total, 60)
    h, rem = divmod(total, 3600)
    return "%dh%02dm" % (h, rem // 60)


# Set by the engine so external commands land in the run journal too.
JOURNAL = None

# Set by the engine so every external command's outcome (command, exit, a
# capped slice of output) lands in the verifiable tool-run ledger. Ambient
# like JOURNAL and for the same reason: run() and stream_lines() are the two
# spawn primitives the whole tool layer funnels through, so recording here
# catches every invocation without threading a handle through every caller.
LEDGER = None

# How much of a streamed tool's stdout the ledger keeps (the head; the full output
# is consumed by the caller and not retained).
_LEDGER_OUT_CAP = 8192


def _ledger(tool: str, argv: List[str], rc: int, state: str,
            duration: float, output: str) -> None:
    """Record one tool invocation in the ledger, if one is attached. Never
    raises - the ledger must not be able to take a scan down with it."""
    if LEDGER is None:
        return
    try:
        LEDGER.record(tool=tool, argv=" ".join(shlex.quote(a) for a in argv),
                      rc=rc, state=state, duration=duration, output=output)
    except Exception:
        pass


def _ledger_proc(p: "Proc", t0: float) -> "Proc":
    """Ledger a finished run() Proc and return it unchanged, so each return
    site in run() stays a one-liner."""
    state = ("skipped" if p.skipped else "timeout" if p.timed_out
             else "ok" if p.rc == 0 else "broke")
    out = (p.out or "") + (("\n" + p.err) if p.err else "")
    _ledger(p.cmd[0].split("/")[-1] if p.cmd else "?", p.cmd, p.rc, state,
            time.time() - t0, out)
    return p

# Set by the engine so a command that takes minutes can say it is still alive.
# Ambient like JOURNAL, and for the same reason: every subprocess assay spawns
# goes through run() or stream_lines(), so setting it once covers the whole
# toolchain and no wrapper has to thread a callback down to its subprocess.
PROGRESS = None

# How long a command may say nothing before it is indistinguishable from a hang.
HEARTBEAT = 5.0

# Set by the engine's key listener when the operator asks to move past
# whatever the current stage is doing (assay.ui.KeyListener). Left set
# across multiple calls deliberately: a stage that is many tool invocations
# deep - content discovery running ffuf once per web target, say - should
# have all of its remaining invocations wave through immediately rather
# than needing one skip press per target. Cleared once, at the start of the
# next stage (see Engine._run_stage), so a skip never leaks into later work
# the operator never asked to cut.
SKIP = threading.Event()

# Set by the key listener when the operator pauses the scan ('p'), cleared on
# resume ('r'). Unlike SKIP it is NOT cleared between stages: a pause holds
# until the operator lifts it. Checkpoints call wait_while_paused() to block
# before starting new work - a tool already running is left to finish, so the
# pause takes effect at the next launch, not mid-request.
PAUSE = threading.Event()


def wait_while_paused() -> None:
    """Block at a checkpoint for as long as the operator has the scan paused.

    Returns at once if a skip is in effect, so 's' and teardown still work
    while paused and nothing can wedge: the engine sets SKIP to drain paused
    worker threads when the run is interrupted. Polls rather than Event.wait()
    so a resume (or a skip) is picked up within a quarter second, and so a
    pause on the main thread stays interruptible by Ctrl-C.
    """
    while PAUSE.is_set() and not SKIP.is_set():
        time.sleep(0.25)


# Binary -> a parser turning one of its stdout lines into a status phrase.
# Only for tools whose stdout is progress rather than results; everything else
# gets the generic count below, which is what its lines actually are.
_LINE_STATUS: Dict[str, Callable[[str], Optional[str]]] = {}


def _say(msg: str, tick: bool = True) -> None:
    """Report to the ambient progress sink, if the engine installed one.

    tick=True is a heartbeat: it updates the status line without earning a
    line in the scroll log. tick=False is an event worth keeping.
    """
    if PROGRESS is None:
        return
    try:
        PROGRESS(msg, tick)
    except Exception:  # the UI must never kill a scan
        pass


class _Heartbeat:
    """Reports that a command is still running, on its own clock.

    Reporting per line of output is not enough: nuclei can go minutes between
    matches and ffuf says nothing at all until it exits, and that silence is
    exactly what makes a working tool look wedged. A timer thread reports on a
    fixed cadence whether or not the tool has spoken; the reader loop, when
    there is one, feeds it the newest detail to report along the way.
    """

    def __init__(self, cmd: Sequence[str], every: Optional[float] = None) -> None:
        self.name = cmd[0] if cmd else "?"
        # Read at construction rather than bound as a default, so the cadence
        # stays a knob and not a value frozen at import.
        self.every = HEARTBEAT if every is None else every
        self.started = time.time()
        # Both written by the reader thread, read by the timer thread. Plain
        # assignment of an int or a str, so no lock is needed for either.
        self.count = 0
        self.detail = ""
        # Set by this thread, read by the caller once its blocking call
        # returns - same reasoning as count/detail above, just the other
        # direction. Distinguishes "the operator moved us on" from a normal
        # finish or a deadline cutoff, which look identical from the
        # caller's side otherwise (both are just "the process ended").
        self.was_skipped = False
        self._proc: Optional["subprocess.Popen"] = None
        self._done = threading.Event()

    def bind(self, proc: "subprocess.Popen") -> "_Heartbeat":
        """Give this heartbeat the process it is watching.

        Without this, only the caller's own read loop - if it has one - can
        ever notice a cutoff, and run()'s single blocking subprocess call has
        no such loop at all: nothing would read stdout line by line to give
        it a chance to check anything mid-flight. With it, this thread's own
        timer can act on a deadline or a skip request directly, which is what
        makes a fully-blocking call like run()'s interruptible in the first
        place, not just refuse the *next* one.
        """
        self._proc = proc
        return self

    def start(self) -> "_Heartbeat":
        if PROGRESS is not None:
            threading.Thread(target=self._loop, daemon=True).start()
        return self

    def stop(self) -> None:
        self._done.set()

    def timed_out(self, timeout: float) -> None:
        """A cut-off tool is an event, not a tick: partial results are news."""
        _say("%s: hit its %s limit - results are partial"
             % (self.name, human_duration(timeout)), tick=False)

    def _text(self) -> str:
        if self.detail:
            return self.detail
        return "%d result(s) so far" % self.count if self.count else ""

    def _loop(self) -> None:
        while not self._done.wait(self.every):
            if SKIP.is_set() and self._proc is not None:
                self.was_skipped = True
                _say("%s: skipped - moving on to the next stage" % self.name,
                     tick=False)
                _stop(self._proc)
                return
            text = self._text()
            _say("%s: running %s%s" % (self.name,
                                       human_duration(time.time() - self.started),
                                       " - %s" % text if text else ""))


def _stop(proc: "subprocess.Popen", grace: float = 10.0) -> None:
    """Ask a process to stop before insisting.

    SIGKILL cannot be caught, so a tool killed outright never gets to finish
    the file it was writing - nmap loses the closing tag on its XML and with
    it, to a strict parser, every host it had already scanned. SIGTERM gives
    it the chance to land its output; the kill is still there for anything
    that ignores the request.
    """
    try:
        proc.terminate()
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        proc.kill()
    except OSError:
        pass


def _record(cmd: Sequence[str]) -> None:
    if JOURNAL is not None:
        try:
            JOURNAL.command(list(cmd))
        except Exception:
            pass


def _record_failure(cmd: Sequence[str], detail: str) -> None:
    """Surface a nonzero exit or launch failure in activity.log.

    A tool that exits nonzero (wrong flag for its installed version, missing
    binary, etc.) previously vanished as a silent empty result -- the caller
    saw "found nothing" with no way to tell that from "actually found
    nothing". This makes that distinguishable without having to run the
    command by hand.
    """
    if JOURNAL is None:
        return
    lines = [ln for ln in (detail or "").strip().splitlines() if ln.strip()]
    tail = " | ".join(lines[-2:]) if lines else "(no output)"
    try:
        JOURNAL.note("FAILED  %s -- %s" % (cmd[0] if cmd else "?", tail[:300]))
    except Exception:
        pass


def _note(msg: str) -> None:
    """Something the operator needs to know, in the journal and on screen.

    Not a failure - the run carries on - but not a heartbeat either: these
    are the things that quietly change what a result means.
    """
    if JOURNAL is not None:
        try:
            JOURNAL.note(msg)
        except Exception:
            pass
    _say(msg, tick=False)


def dns_lookup(record: str, name: str, timeout: float = 8.0) -> str:
    """Raw stdout of a DNS lookup, via dig and falling back to host.

    Goes through run(), so unlike the three hand-rolled wrappers this replaced
    it is bridged into WSL (where the resolver tools actually live on a
    Windows host) and lands in the journal like every other command.

    Returns the first command's output that was not empty, even on a non-zero
    exit: `host` exits non-zero on NXDOMAIN but prints the reason, and callers
    need to tell that apart from "the lookup did not run".
    """
    for cmd in (["dig", "+short", "+time=3", "+tries=1", record, name],
                ["host", "-t", record, name]):
        p = run(cmd, timeout=timeout)
        if (p.out or "").strip():
            return p.out
    return ""


def bridge(cmd: Sequence[str]) -> List[str]:
    """Prepend the WSL prefix when assay is hosted on Windows.

    Every subprocess call in assay funnels through run() or stream_lines(),
    so wrapping here is enough to move the entire external toolchain into WSL.
    """
    cmd = list(cmd)
    if env.use_wsl_bridge():
        return env.wsl_prefix() + cmd
    return cmd


def available() -> Dict[str, Optional[str]]:
    env.augment_path()
    out: Dict[str, Optional[str]] = {}
    binaries = [s.binary for s in REGISTRY.values() if s.binary != "__wordlist__"]
    resolved = env.wsl_which_many(binaries) if env.use_wsl_bridge() else {}
    for name, spec in REGISTRY.items():
        if spec.binary == "__wordlist__":
            out[name] = default_wordlist()
        elif resolved:
            out[name] = resolved.get(spec.binary)
        else:
            out[name] = env.which(spec.binary)
    return out


def have(name: str) -> bool:
    return env.which(REGISTRY[name].binary if name in REGISTRY else name) is not None


def run(cmd: Sequence[str], timeout: float = 300.0, stdin: str = "",
        cwd: Optional[str] = None,
        env_extra: Optional[Dict[str, str]] = None) -> Proc:
    """Run an external command. The only spawn primitive besides stream_lines.

    `env_extra` sets variables for the child. Under the WSL bridge the host's
    environment does not cross into the distribution, so the assignments are
    carried as an `env K=V` prefix inside the bridged command instead of being
    set on the Windows-side process, where the tool would never see them.
    """
    env.augment_path()
    _record(cmd)
    t0 = time.time()
    argv = list(cmd)
    proc_env = None
    if env_extra:
        if env.use_wsl_bridge():
            argv = (["env"] + ["%s=%s" % kv for kv in sorted(env_extra.items())]
                    + argv)
        else:
            proc_env = dict(os.environ)
            proc_env.update(env_extra)
    argv = bridge(argv)
    wait_while_paused()
    if SKIP.is_set():
        # The operator already asked to move past this stage before this
        # call even started - honour it immediately rather than spawning
        # something only to kill it moments later.
        _say("%s: skipped - moving on to the next stage" % (cmd[0] if cmd else "?"),
             tick=False)
        return _ledger_proc(
            Proc(rc=-1, out="", err="skipped by operator", cmd=list(cmd), skipped=True), t0)
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, cwd=cwd, env=proc_env,
        )
    except OSError as exc:
        _record_failure(cmd, str(exc))
        return _ledger_proc(Proc(rc=-1, out="", err=str(exc), cmd=list(cmd)), t0)
    # Bound to a real Popen (unlike the subprocess.run() this replaced), so
    # this thread's own timer can act on a deadline or a skip directly - the
    # only way a single fully-blocking call like this one can be interrupted
    # mid-flight at all, since nothing here reads output line by line to
    # give a check-in point of its own the way stream_lines() has.
    hb = _Heartbeat(cmd).bind(proc).start()
    try:
        out, err = proc.communicate(input=stdin, timeout=timeout)
        if hb.was_skipped:
            return _ledger_proc(
                Proc(rc=proc.returncode, out=out or "", err=err or "skipped by operator",
                     cmd=list(cmd), skipped=True), t0)
        if proc.returncode != 0:
            _record_failure(cmd, err)
        return _ledger_proc(
            Proc(rc=proc.returncode, out=out or "", err=err or "", cmd=list(cmd)), t0)
    except subprocess.TimeoutExpired:
        # Terminate, not kill: matches stream_lines() - a tool writing a
        # result file needs the chance to close it.
        _stop(proc)
        out, err = proc.communicate()
        hb.timed_out(timeout)
        return _ledger_proc(
            Proc(rc=-1, out=out or "", err="timeout after %ss" % timeout,
                 cmd=list(cmd), timed_out=True), t0)
    except (OSError, ValueError) as exc:
        _record_failure(cmd, str(exc))
        return _ledger_proc(Proc(rc=-1, out="", err=str(exc), cmd=list(cmd)), t0)
    finally:
        hb.stop()


def stream_lines(cmd: Sequence[str], timeout: float = 900.0,
                 stdin: str = "", ledger: bool = True) -> Iterator[str]:
    """Yield stdout lines as they arrive. Keeps peak memory flat.

    Every invocation is written to the tool-runs ledger, as run() does -
    httpx, nuclei, katana and the rest stream, so without this they never
    appeared there. Callers that record a richer summary of their own (nmap,
    naabu) pass ledger=False so the run is not listed twice.
    """
    env.augment_path()
    t0 = time.time()
    wait_while_paused()
    if SKIP.is_set():
        # See run()'s identical check: honour a skip already in effect
        # before spawning anything, rather than starting only to kill it.
        _say("%s: skipped - moving on to the next stage" % (cmd[0] if cmd else "?"),
             tick=False)
        if ledger:
            _ledger(cmd[0].split("/")[-1] if cmd else "?", list(cmd), -1,
                    "skipped", 0.0, "skipped by operator")
        return
    _record(cmd)
    # A real file rather than a pipe for stderr: a chatty tool could otherwise
    # fill a pipe's OS buffer and deadlock while we're only draining stdout.
    stderr_buf = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
    timed_out = False
    try:
        proc = subprocess.Popen(
            bridge(cmd), stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=stderr_buf, text=True, bufsize=1,
        )
    except OSError as exc:
        _record_failure(cmd, str(exc))
        stderr_buf.close()
        if ledger:
            _ledger(cmd[0].split("/")[-1] if cmd else "?", list(cmd), -1,
                    "broke", time.time() - t0, str(exc))
        return
    if stdin and proc.stdin:
        try:
            proc.stdin.write(stdin)
            proc.stdin.close()
        except OSError:
            pass
    # Bound to the real process: a tool that says nothing at all only ever
    # gets noticed by this thread's own timer, not by the per-line checks
    # below, which never run if there is no line to run them on.
    hb = _Heartbeat(cmd).bind(proc)
    status = _LINE_STATUS.get(hb.name)
    n_lines = 0
    head: List[str] = []
    head_len = 0
    completed = False
    try:
        assert proc.stdout is not None
        # `timeout` was accepted and never enforced: only the finally's
        # proc.wait(10) bounded anything, so a tool that ran long ran forever.
        # Checked per line, so it bounds a tool that is still talking - a
        # process that goes completely silent still blocks on the read below,
        # which needs a watchdog thread rather than a deadline.
        deadline = time.time() + timeout
        hb.start()
        for line in proc.stdout:
            line = line.strip()
            if line:
                # Counting rather than formatting: a tool that streams a
                # hundred thousand URLs would otherwise pay for a message
                # nobody reads. The heartbeat thread formats when it fires.
                hb.count += 1
                n_lines += 1
                if head_len < _LEDGER_OUT_CAP:
                    head.append(line)
                    head_len += len(line) + 1
                if status is not None:
                    hb.detail = status(line) or hb.detail
                yield line
            if hb.was_skipped:
                # The heartbeat thread already stopped the process; just stop
                # reading from it. Checked here too, not only relying on that
                # thread's own timer, so a chatty tool notices between two
                # lines rather than waiting up to a whole heartbeat interval.
                break
            if time.time() > deadline:
                # The caller has already consumed everything up to here and
                # cannot otherwise tell a finished tool from a cut-off one, so
                # say so rather than letting partial output pass as complete.
                timed_out = True
                _record_failure(cmd, "timed out after %.0fs" % timeout)
                # Terminate, not kill: a tool writing a result file needs the
                # chance to close it, or the whole run is thrown away for the
                # sake of a few closing bytes.
                _stop(proc)
                hb.timed_out(timeout)
                break
        else:
            completed = True
    finally:
        hb.stop()
        if proc.stdout:
            # Closing the pipe both releases the descriptor and tells a tool
            # we abandoned early (a caller that hit its own cap and stopped
            # reading) to stop, instead of leaving it writing into the void.
            proc.stdout.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _stop(proc, grace=5.0)
        # A kill of our own - by the deadline above or by a skip - is
        # recorded there; the returncode it produces is the same event, not
        # a second failure.
        stderr_buf.seek(0)
        err_text = stderr_buf.read()
        if proc.returncode and not timed_out and not hb.was_skipped:
            _record_failure(cmd, err_text)
        stderr_buf.close()
        if ledger:
            # A caller that stopped reading (hit its own cap) closes the pipe,
            # which makes the tool exit nonzero - that is not a failure.
            if hb.was_skipped:
                state = "skipped"
            elif timed_out:
                state = "timeout"
            elif completed and proc.returncode:
                state = "broke"
            else:
                state = "ok"
            summary = "%d line(s) of output%s" % (
                n_lines, "" if completed or timed_out else " (caller stopped reading early)")
            body = "\n".join(head)
            if head_len >= _LEDGER_OUT_CAP:
                body += "\n... [first %d bytes shown]" % _LEDGER_OUT_CAP
            _ledger(cmd[0].split("/")[-1] if cmd else "?", list(cmd),
                    proc.returncode if proc.returncode is not None else -1,
                    state, time.time() - t0,
                    "\n".join(x for x in (summary, body,
                                          ("stderr: " + err_text.strip()[-1500:])
                                          if err_text.strip() else "") if x))


def stream_json(cmd: Sequence[str], timeout: float = 900.0,
                stdin: str = "", ledger: bool = True) -> Iterator[dict]:
    for line in stream_lines(cmd, timeout=timeout, stdin=stdin, ledger=ledger):
        if not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except ValueError:
            continue


# --------------------------------------------------------------------------
# Header plumbing for external tools
# --------------------------------------------------------------------------


def header_args(tool: str, headers: Optional[Dict[str, str]] = None) -> List[str]:
    """Render extra request headers in each tool's own flag syntax."""
    if not headers:
        return []
    out: List[str] = []
    flag = {"httpx": "-H", "nuclei": "-H", "katana": "-H", "ffuf": "-H"}.get(tool)
    if not flag:
        return []
    for k, v in headers.items():
        out += [flag, "%s: %s" % (k, v)]
    return out


# --------------------------------------------------------------------------
# nmap
# --------------------------------------------------------------------------


def nmap_port_args(spec: str) -> List[str]:
    """Translate the base of a port spec ('top-N+extra,ports' forms included).

    Only ever returns one port-selection method. nmap treats --top-ports and
    -p given together as an INTERSECTION, not a union (nmap/nmap#447), so any
    extra ports outside the top-N list would silently vanish if appended here.
    Extra ports are scanned separately -- see nmap_extra_port_args().
    """
    if spec == "all":
        return ["-p-"]
    base = spec.partition("+")[0]
    if base == "top-100":
        return ["--top-ports", "100"]
    if base == "top-1000":
        return ["--top-ports", "1000"]
    return ["-p", base]


def nmap_extra_port_args(spec: str) -> Optional[List[str]]:
    """Ports appended after '+' in a 'top-N+extra,ports' spec, as -p args."""
    if "+" not in spec or spec == "all":
        return None
    extra = spec.partition("+")[2]
    return ["-p", extra] if extra else None


@dataclass
class NmapHost:
    """One scanned address's open ports and the hostname(s) nmap's own
    reverse-DNS lookup found for it while scanning."""
    ports: List[Port] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)


def _merge_nmap_hosts(dest: Dict[str, NmapHost], src: Dict[str, NmapHost]) -> None:
    for addr, nh in src.items():
        existing = dest.setdefault(addr, NmapHost())
        seen = {(p.port, p.proto) for p in existing.ports}
        for p in nh.ports:
            if (p.port, p.proto) not in seen:
                existing.ports.append(p)
                seen.add((p.port, p.proto))
        for name in nh.hostnames:
            if name not in existing.hostnames:
                existing.hostnames.append(name)


_NMAP_PCT = re.compile(r"About ([\d.]+)% done(?:.*?\(([\d:]+) remaining\))?")
_NMAP_HOSTS = re.compile(r"(\d+) hosts? completed")


def nmap_stat_line(line: str) -> Optional[str]:
    """Turn one nmap --stats-every line into a status, or None if it is not one.

    nmap prints these to stdout on its own timer. They are the only progress
    an -sV sweep gives: without them a scan of several hundred hosts is a
    single blocking call that says nothing for however long it takes.
    """
    m = _NMAP_PCT.search(line)
    if m:
        return "%s%% done%s" % (m.group(1),
                                ", %s remaining" % m.group(2) if m.group(2) else "")
    m = _NMAP_HOSTS.search(line)
    if m:
        return "%s host(s) completed" % m.group(1)
    return None


# nmap is the one tool here whose stdout is progress rather than results, so
# it is the one that needs the heartbeat to read its lines instead of counting
# them. Registered rather than special-cased inside stream_lines so the next
# such tool is a line of data, not another branch.
_LINE_STATUS["nmap"] = nmap_stat_line


# A wall-clock backstop for nmap, not a work budget: --host-timeout already
# bounds each host, so this only has to sit above what the host count can
# honestly need. A flat half hour did not - it cut a 55-host -sV sweep off
# mid-scan and, before the XML salvage below, took every result with it.
NMAP_BASE_TIMEOUT = 1800.0
NMAP_PER_HOST_TIMEOUT = 60.0
NMAP_TIMEOUT_CAP = 6 * 3600.0

# nmap scans in groups and writes a host's XML only once its whole group is
# finished, so the group size is also the checkpoint interval. One group means
# a scan stopped at 99% writes nothing whatsoever - which is what a 55-host
# sweep did after being cut off 130 seconds from the end. Aiming for a few
# groups rather than the smallest possible bounds both the work at risk and
# the cross-host parallelism given up to protect it.
NMAP_CHECKPOINTS = 4
NMAP_MIN_HOSTGROUP = 16


_SPEC_RANK = {"top-100": 1, "top-1000": 2, "all": 3}


def _csv_ports(spec: str):
    """A spec written as explicit ports -> the set of ints, else None."""
    if not spec or spec in _SPEC_RANK:
        return None
    out = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, _, b = part.partition("-")
            if a.isdigit() and b.isdigit():
                out.update(range(int(a), int(b) + 1))
            else:
                return None
        elif part.isdigit():
            out.add(int(part))
        else:
            return None
    return out


def spec_covers(recorded: str, requested: str) -> bool:
    """Is a sweep at `recorded` at least as thorough as one at `requested`?

    Used to decide whether a host already scanned needs scanning again. It is
    deliberately conservative: when coverage cannot be proven (two specs that
    are not comparable), it returns False so the host is re-scanned rather
    than silently skipped. "Don't miss anything" beats "save a little time".
    """
    if recorded == requested:
        return True
    if recorded == "all":
        return True
    if requested == "all":
        return False
    r, q = _SPEC_RANK.get(recorded), _SPEC_RANK.get(requested)
    if r and q:
        return r >= q
    rs, qs = _csv_ports(recorded), _csv_ports(requested)
    if rs is not None and qs is not None:
        return qs <= rs
    return False


def port_count(spec: str) -> int:
    """How many ports a spec asks for. For budgeting time, not for scanning."""
    if spec == "all":
        return 65535
    total = 0
    base, _, extra = spec.partition("+")
    for part in (base, extra):
        if not part:
            continue
        if part in ("top-100", "top-1000"):
            total += int(part.partition("-")[2])
            continue
        for item in part.split(","):
            item = item.strip()
            if not item:
                continue
            lo, dash, hi = item.partition("-")
            try:
                total += (int(hi) - int(lo) + 1) if dash else 1
            except ValueError:
                total += 1
    return max(1, total)


def nmap_timeout(hosts: Sequence[str], port_spec: str = "") -> float:
    """A wall-clock backstop, sized by what the caller actually asked for.

    Driven by the host count: -sV spends its time interrogating the ports it
    finds open, so a thousand-port sweep costs far less than a thousand times
    a one-port sweep. Not nothing, though - it has more to find - hence the
    small per-port term.
    """
    per_host = NMAP_PER_HOST_TIMEOUT + 0.02 * port_count(port_spec or "top-1000")
    return min(NMAP_TIMEOUT_CAP,
               NMAP_BASE_TIMEOUT + per_host * max(1, len(hosts)))


def nmap_hostgroup(hosts: Sequence[str]) -> Optional[int]:
    """Cap nmap's host group so a cut-off scan keeps most of its work.

    None when the scan is too small to be worth splitting: the whole thing is
    one batch either way, and fragmenting it would only cost parallelism.
    """
    if len(hosts) <= NMAP_MIN_HOSTGROUP:
        return None
    return max(NMAP_MIN_HOSTGROUP, -(-len(hosts) // NMAP_CHECKPOINTS))


def nmap_scan(hosts: List[str], port_spec: str, tune: Dict,
              timeout: Optional[float] = None,
              out_dir: str = ".", xml_prefix: str = "nmap") -> Dict[str, NmapHost]:
    """Service/version scan. Returns scanned address -> NmapHost.

    Always keyed by the address nmap actually scanned, never by a
    reverse-DNS name alone: a target given as a bare IP whose reverse DNS
    resolves to some hostname must still be found by that IP by whoever
    matches these results back to a Target, or its entire port list
    silently disappears. Any hostname nmap did resolve is carried on
    NmapHost.hostnames instead, for the caller to act on deliberately.

    xml_prefix names the raw XML file(s) this call writes (<prefix>.xml,
    <prefix>-extra.xml for the AI-ports follow-up). A caller that invokes
    this more than once per run (e.g. a follow-up scan of hostnames
    discovered via reverse DNS) must pass a distinct prefix each time, or a
    later call silently overwrites an earlier one's raw XML on disk.
    """
    # Scaled by default: how long an -sV sweep needs is a function of how many
    # hosts the caller handed it, and a constant is only ever right for one
    # size of scan.
    if timeout is None:
        timeout = nmap_timeout(hosts, port_spec)
    base_args = [
        "nmap", "-Pn", "-sV", "--version-intensity", "5",
        "-T3" if tune.get("constrained") else "-T4",
        "--max-retries", "2", "--host-timeout", "20m",
        "--min-rate", str(tune.get("nmap_min_rate", 300)),
    ]
    # Checkpointing, not throttling: this is what makes a partial scan
    # recoverable at all, since nothing reaches the XML until a group ends.
    group = nmap_hostgroup(hosts)
    if group:
        base_args += ["--max-hostgroup", str(group)]

    def _run(port_args: List[str], xml_name: str) -> Dict[str, NmapHost]:
        xml_path = os.path.join(out_dir, "raw", xml_name)
        os.makedirs(os.path.dirname(xml_path), exist_ok=True)
        cmd = ([base_args[0], "--stats-every", "10s"] + base_args[1:]
               + ["-oX", xml_path] + port_args + hosts)
        # nmap runs inside WSL under the bridge, so -oX must name a path it can see.
        cmd[cmd.index("-oX") + 1] = env.to_wsl_path(xml_path)
        # Always streamed: the results come from the XML either way, so the
        # only question is whether the wait is spent silently. --stats-every
        # makes nmap narrate it, stream_lines turns that into progress, and
        # nothing downstream cares if no one is reading.
        t0 = time.time()
        for _ in stream_lines(cmd, timeout=timeout, ledger=False):
            pass
        parsed = parse_nmap_xml(xml_path) if os.path.exists(xml_path) else {}
        # Ledger the sweep's outcome. The full XML is on disk; this is the
        # at-a-glance "nmap ran, found N open port(s) across M host(s)" (or
        # none, or no XML at all) that makes the port scan verifiable.
        ports = sum(len(h.ports) for h in parsed.values())
        if not os.path.exists(xml_path):
            summary, state = "nmap produced no XML (nothing scanned or scan cut short)", "broke"
        elif ports:
            summary = "\n".join(
                "%s: %s" % (addr, ", ".join(
                    "%d/%s%s" % (p.port, p.proto, " " + p.service if p.service else "")
                    for p in h.ports))
                for addr, h in sorted(parsed.items()))
            state = "findings"
        else:
            summary, state = "no open ports across %d host(s)" % len(hosts), "no-findings"
        _ledger("nmap", cmd, 0, state, time.time() - t0, summary)
        return parsed

    results = _run(nmap_port_args(port_spec), "%s.xml" % xml_prefix)
    extra_args = nmap_extra_port_args(port_spec)
    if extra_args:
        _merge_nmap_hosts(results, _run(extra_args, "%s-extra.xml" % xml_prefix))
    return results


# Curated high-value UDP ports. Deliberately NOT --top-ports: a full UDP sweep
# is punishingly slow (closed ports rely on rate-limited ICMP unreachables), so
# this is a hand-picked set where each port maps to a real, reportable finding -
# DNS, SNMP, NTP amplification, TFTP, IKE, NetBIOS, SSDP, mDNS, rpcbind, IPMI,
# memcached, XDMCP, chargen, RIP, MSSQL browser.
UDP_PORTS = [19, 53, 69, 111, 123, 137, 138, 161, 162, 177, 500, 520,
             623, 1434, 1900, 4500, 5353, 11211]


def nmap_udp_scan(hosts: List[str], tune: Dict, out_dir: str = ".",
                  xml_prefix: str = "nmap-udp",
                  timeout: Optional[float] = None) -> Dict[str, NmapHost]:
    """Curated-port UDP service scan. Returns scanned address -> NmapHost, with
    ports carrying their honest `open` / `open|filtered` state (UDP usually
    cannot tell the two apart).

    Separate from nmap_scan() on purpose: UDP needs its own, much more
    forgiving timing (a wide sweep would otherwise never finish) and its own
    XML file so it does not clobber the TCP scan's - the same per-prefix
    hazard nmap_scan() documents.
    """
    if not hosts:
        return {}
    ports = ",".join(str(p) for p in UDP_PORTS)
    # Low version-intensity and a tight per-host budget: UDP is slow and
    # lossy by nature, so bound it hard rather than chase certainty.
    base = ["nmap", "-Pn", "-sU", "-sV", "--version-intensity", "0",
            "-T3" if tune.get("constrained") else "-T4",
            "--max-retries", "1", "--host-timeout", "5m",
            "-p", ports]
    xml_path = os.path.join(out_dir, "raw", "%s.xml" % xml_prefix)
    os.makedirs(os.path.dirname(xml_path), exist_ok=True)
    cmd = base + ["-oX", env.to_wsl_path(xml_path)] + hosts
    deadline = timeout if timeout is not None else max(300.0, 180.0 * len(hosts))
    t0 = time.time()
    for _ in stream_lines(["nmap", "--stats-every", "10s"] + cmd[1:], timeout=deadline,
                          ledger=False):
        pass
    parsed = parse_nmap_xml(xml_path, include_open_filtered=True) if os.path.exists(xml_path) else {}
    n = sum(len(h.ports) for h in parsed.values())
    if not os.path.exists(xml_path):
        summary, state = "nmap produced no UDP XML (nothing scanned or cut short)", "broke"
    elif n:
        summary = "\n".join(
            "%s: %s" % (addr, ", ".join(
                "%d/udp %s%s" % (p.port, p.state, " " + p.service if p.service else "")
                for p in h.ports))
            for addr, h in sorted(parsed.items()))
        state = "findings"
    else:
        summary, state = "no UDP ports responded across %d host(s)" % len(hosts), "no-findings"
    _ledger("nmap", cmd, 0, state, time.time() - t0, summary)
    return parsed


# --------------------------------------------------------------------------
# NmapView (https://nmapview.github.io) -- an XSLT stylesheet that renders
# nmap's own XML into a standalone HTML dashboard via xsltproc.
# --------------------------------------------------------------------------

NMAPVIEW_XSL_URL = "https://github.com/dreizehnutters/NmapView/releases/latest/download/NmapView.xsl"
_VENDORED_NMAPVIEW_XSL = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "NmapView.xsl")


def fetch_nmapview_xsl(dest_path: str, timeout: float = 15.0) -> str:
    """Get a working copy of NmapView.xsl at dest_path.

    Tries a fresh download from the NmapView release first, so a fix or
    feature upstream is picked up without waiting for assay's own vendored
    copy to be updated by hand. Falls back to the copy vendored with assay
    (for an engagement with no network path to GitHub) when the download
    fails, times out, or the download tool is not installed.

    Returns dest_path on success from either source, or "" if neither
    produced a usable file.
    """
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    proc = run(["curl", "-fsSL", "-o", dest_path, NMAPVIEW_XSL_URL], timeout=timeout)
    if proc.ok and os.path.exists(dest_path) and os.path.getsize(dest_path) > 1000:
        return dest_path
    if os.path.exists(_VENDORED_NMAPVIEW_XSL):
        try:
            shutil.copyfile(_VENDORED_NMAPVIEW_XSL, dest_path)
            return dest_path
        except OSError:
            pass
    return ""


def merge_nmap_xml_files(paths: List[str], out_path: str) -> bool:
    """Combine one or more nmap XML runs into a single <nmaprun> document,
    joining on each <host>'s address.

    A run can produce several XML files (a base scan, an AI/ML-ports
    follow-up, a separate follow-up scan of hostnames discovered via
    reverse DNS) - a beautifier that expects one scan should see the union
    of all of them, not just whichever file happens to be first.
    """
    paths = [p for p in paths if os.path.exists(p)]
    if not paths:
        return False
    if len(paths) == 1:
        try:
            shutil.copyfile(paths[0], out_path)
            return True
        except OSError:
            return False
    try:
        base_tree = ET.parse(paths[0])
    except (ET.ParseError, OSError):
        return False
    base_root = base_tree.getroot()

    def _addr(host_el) -> Optional[str]:
        for a in host_el.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                return a.get("addr")
        return None

    by_addr = {_addr(h): h for h in base_root.findall("host") if _addr(h)}
    for p in paths[1:]:
        try:
            extra_root = ET.parse(p).getroot()
        except (ET.ParseError, OSError):
            continue
        for h in extra_root.findall("host"):
            addr = _addr(h)
            existing = by_addr.get(addr) if addr else None
            if existing is None:
                base_root.append(h)
                if addr:
                    by_addr[addr] = h
                continue
            src_ports = h.find("ports")
            if src_ports is None:
                continue
            dst_ports = existing.find("ports")
            if dst_ports is None:
                existing.append(src_ports)
                continue
            for port_el in src_ports.findall("port"):
                dst_ports.append(port_el)
    try:
        base_tree.write(out_path, encoding="utf-8", xml_declaration=True)
        return True
    except OSError:
        return False


def nmapview_render(xml_path: str, xsl_path: str, out_path: str,
                    timeout: float = 90.0) -> bool:
    """Render nmap XML into NmapView's standalone HTML dashboard."""
    proc = run(["xsltproc", "-o", out_path, xsl_path, xml_path], timeout=timeout)
    return proc.ok and os.path.exists(out_path) and os.path.getsize(out_path) > 1000


def build_nmapview_report(xml_paths: List[str], out_dir: str,
                          timeout: float = 90.0) -> str:
    """One-shot pipeline: fetch NmapView.xsl, merge the given XML files, and
    render the result. Returns the rendered HTML's path on success, or "".

    Meant to be called once per run, after the last nmap invocation has
    written its XML - not from the report renderer, which can be invoked
    repeatedly while a live scan is still going and should not repeat this
    every time it is.
    """
    raw_dir = os.path.join(out_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    xsl_path = fetch_nmapview_xsl(os.path.join(raw_dir, "NmapView.xsl"))
    if not xsl_path:
        return ""
    merged_path = os.path.join(raw_dir, "nmap-merged.xml")
    if not merge_nmap_xml_files(xml_paths, merged_path):
        return ""
    out_path = os.path.join(raw_dir, "nmapview.html")
    return out_path if nmapview_render(merged_path, xsl_path, out_path,
                                       timeout=timeout) else ""


def nmap_script_scan(host: str, ports: List[int], scripts: List[str],
                     out_dir: str, udp: bool = False,
                     timeout: float = 600.0) -> Dict[int, Dict[str, str]]:
    """Run targeted NSE scripts. Returns {port: {script_id: output}}."""
    if not ports or not scripts:
        return {}
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    xml_path = os.path.join(out_dir, "raw", "nse-%s%s.xml"
                            % (safe_host, "-udp" if udp else ""))
    os.makedirs(os.path.dirname(xml_path), exist_ok=True)
    cmd = ["nmap", "-Pn", "-sU" if udp else "-sT",
           "-p", ",".join(str(p) for p in sorted(set(ports))),
           "--script", ",".join(sorted(set(scripts))),
           "--script-timeout", "90s", "--host-timeout", "10m",
           "-oX", env.to_wsl_path(xml_path), host]
    run(cmd, timeout=timeout)
    return parse_nse_xml(xml_path)


def parse_nse_xml(path: str) -> Dict[int, Dict[str, str]]:
    out: Dict[int, Dict[str, str]] = {}
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError):
        return out
    for port_el in tree.getroot().iter("port"):
        try:
            portid = int(port_el.get("portid", "0"))
        except ValueError:
            continue
        for script in port_el.findall("script"):
            sid = script.get("id", "")
            output = script.get("output", "") or ""
            if sid:
                out.setdefault(portid, {})[sid] = output
    # host-level scripts (e.g. smb-os-discovery) attach to hostscript
    for script in tree.getroot().iter("hostscript"):
        for sc in script.findall("script"):
            sid = sc.get("id", "")
            if sid:
                out.setdefault(0, {})[sid] = sc.get("output", "") or ""
    return out


def _salvage_nmap_xml(path: str):
    """Recover the finished hosts from an nmap XML with no closing tag.

    nmap writes each <host> the moment it finishes with it, but the closing
    </nmaprun> only when it exits of its own accord. A scan stopped by its
    timeout therefore leaves a file that is a perfectly good list of every
    host nmap DID complete and, to a strict parser, not a document at all.
    Treating that ParseError as "no results" discarded the entire scan -- on
    a subnet sweep, half an hour of work and every port it had found.

    Cuts at the last complete </host> and closes the root. Everything else
    nmap writes at that level (scaninfo, verbose, taskbegin, taskprogress)
    is self-closing, so the result parses.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = fh.read()
    except OSError:
        return None
    end = data.rfind("</host>")
    if end == -1:
        return None
    try:
        return ET.fromstring(data[:end + len("</host>")] + "\n</nmaprun>")
    except ET.ParseError:
        return None


def parse_nmap_xml(path: str, include_open_filtered: bool = False) -> Dict[str, NmapHost]:
    """Parse nmap's XML into scanned address -> NmapHost.

    Keyed by the numeric address nmap scanned (always present - nmap resolves
    a hostname target to an address before it ever probes a port), not by a
    reverse-DNS name. See nmap_scan()'s docstring for why that distinction
    matters.

    `include_open_filtered` keeps ports in the `open|filtered` state, which is
    UDP's dominant result (no reply means nmap cannot tell open from filtered).
    TCP parsing leaves it False so only genuinely open ports count; the UDP
    scan passes True and the state is carried through honestly rather than
    being relabelled "open".
    """
    keep_states = {"open", "open|filtered"} if include_open_filtered else {"open"}
    out: Dict[str, NmapHost] = {}
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError) as exc:
        root = _salvage_nmap_xml(path)
        if root is None:
            _record_failure(["nmap"], "unreadable XML at %s: %s" % (path, exc))
            return out
        # Worth a line of its own: the run continues with real results, but
        # they are the results of a scan that did not finish.
        _note("nmap XML was truncated - recovered %d completed host(s) from %s"
              % (len(root.findall("host")), os.path.basename(path)))
    for host_el in root.findall("host"):
        addr = ""
        for a in host_el.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        names = [h.get("name", "") for h in host_el.findall("hostnames/hostname")
                 if h.get("name")]
        key = addr or (names[0] if names else "")
        if not key:
            continue
        ports: List[Port] = []
        for p in host_el.findall("ports/port"):
            state_el = p.find("state")
            pstate = state_el.get("state") if state_el is not None else ""
            if pstate not in keep_states:
                continue
            svc = p.find("service")
            ports.append(Port(
                port=int(p.get("portid", "0")),
                proto=p.get("protocol", "tcp"),
                state=pstate,
                service=(svc.get("name", "") if svc is not None else ""),
                product=(svc.get("product", "") if svc is not None else ""),
                version=(svc.get("version", "") if svc is not None else ""),
                tunnel=(svc.get("tunnel", "") if svc is not None else ""),
                extra={"extrainfo": (svc.get("extrainfo", "") if svc is not None else ""),
                       "ip": addr},
            ))
        if ports or names:
            existing = out.setdefault(key, NmapHost())
            existing.ports.extend(ports)
            for n in names:
                if n not in existing.hostnames:
                    existing.hostnames.append(n)
    return out


def nmap_xml_path(out_dir: str, xml_prefix: str = "nmap") -> str:
    return os.path.join(out_dir, "raw", "%s.xml" % xml_prefix)


def _nmap_xml_variants() -> List[Tuple[str, str]]:
    base = [
        ("nmap.xml", "base scan"),
        ("nmap-extra.xml", "AI/ML port scan"),
        ("nmap-discovered.xml", "reverse-DNS-discovered hosts"),
        ("nmap-discovered-extra.xml", "reverse-DNS-discovered hosts, AI/ML ports"),
    ]
    out: List[Tuple[str, str]] = []
    for name, label in base:
        out.append((name, label))
        out.append((name.replace(".xml", "-previous.xml"), label + ", pre-resume"))
    return out


# Every raw XML file a full run's nmap phase can produce, name paired with a
# human label. --resume adds a "-previous" sibling of a file it preserves
# instead of overwriting (see Engine._preserve_previous_xml) - one place to
# name it, so the report's raw-XML section and NmapView's own render pick it
# up without either maintaining its own copy of this list.
NMAP_XML_FILES: List[Tuple[str, str]] = _nmap_xml_variants()


def resumable_nmap_hosts(out_dir: str, xml_prefix: str = "nmap") -> Dict[str, NmapHost]:
    """Whatever an earlier nmap_scan() call already wrote under this prefix.

    --resume's whole mechanism: parse_nmap_xml already salvages a killed
    scan's completed hosts (see _salvage_nmap_xml), so a scan cut off by its
    own timeout is exactly the case this recovers, not a special case of it.

    A host nmap fully scanned and found completely closed is NOT a key in the
    returned dict -- parse_nmap_xml only records a host with something to
    report, by design (see its docstring). Resume treats "absent" as "not yet
    covered" and scans it again. That is wasted work on a clean host, never
    wrong: nothing is skipped on the strength of a guess, which is the
    property that matters when the caller is deciding what to trust.
    """
    return parse_nmap_xml(nmap_xml_path(out_dir, xml_prefix))


# --------------------------------------------------------------------------
# naabu
# --------------------------------------------------------------------------


NAABU_BASE_TIMEOUT = 300.0
NAABU_TIMEOUT_CAP = 3 * 3600.0
# Probes are sent at a fixed rate, so the wait is arithmetic; the multiplier
# is slack for retries and for hosts that answer slowly.
NAABU_SLACK = 3.0


def naabu_timeout(hosts: Sequence[str], port_spec: str, tune: Dict,
                  cap: float = NAABU_TIMEOUT_CAP) -> float:
    """How long hosts x ports probes take at the configured rate, plus slack.

    A flat cap was wrong here for the same reason it was wrong for nmap: the
    work is the caller's choice. Unlike nmap's, naabu's runtime is almost
    entirely predictable - it is a rate-limited sweep, and both the probe
    count and the rate are known right here.
    """
    rate = max(1.0, float(tune.get("nmap_min_rate", 300)))
    probes = max(1, len(hosts)) * port_count(port_spec)
    return min(cap, NAABU_BASE_TIMEOUT + NAABU_SLACK * probes / rate)


@contextlib.contextmanager
def _target_list_file(items: Sequence[str]):
    """A real file listing one target per line, cleaned up on exit.

    Every tool below used to get its targets piped over stdin instead - cheap
    when it works, but it relies on the tool auto-detecting a non-interactive
    stdin the instant its -list/-u flag is omitted entirely. naabu and katana
    follow that convention; nuclei has shipped bugs where stdin piped in via
    subprocess.Popen specifically (not a real shell |, which is all "it works
    when I test it by hand" ever proves) was not read at all
    (projectdiscovery/nuclei#2032) - exactly how every one of these is
    invoked here. A real file sidesteps whether stdin auto-detection holds
    for a given tool and Python's own subprocess plumbing: every one of them
    already supports "-list <path>" as its first-class, most-tested input
    method, so this is one mechanism to trust instead of five.

    Used as `with _target_list_file(hosts) as path: cmd = [..., "-list", path]`.
    A generator function that stays suspended at a yield inside this `with`
    keeps the file alive for as long as its caller is still reading results,
    and still cleans up on an early break (the `for` loop's implicit
    .close() raises GeneratorExit at that yield, which unwinds through this
    `finally` the same as normal exhaustion would).
    """
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="assay-targets-", text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write("\n".join(items) + "\n")
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def naabu_scan(hosts: List[str], port_spec: str, tune: Dict,
               timeout: Optional[float] = None,
               status: Optional[Dict] = None) -> Dict[str, List[int]]:
    """`status`, when given, gets "timed_out"/"skipped" set to True if a pass
    was cut off. naabu only emits lines for open ports, so the result alone
    cannot say whether every host was actually swept."""
    # Kept as two separate passes (base + extra), mirroring nmap_scan: relying
    # on naabu to union -top-ports with a -p list in one invocation is
    # unverified, and nmap's equivalent combination turned out to be an
    # intersection (nmap/nmap#447), silently dropping the extra ports.
    base, _, extra = port_spec.partition("+")
    spec = {"top-100": ["-top-ports", "100"],
            "top-1000": ["-top-ports", "1000"],
            "all": ["-p", "-"]}.get(base, ["-p", base])

    def _run(port_args: List[str], ports: str) -> Dict[str, List[int]]:
        # Budgeted per pass, not per call: the extra-ports pass is a handful
        # of ports and has no business inheriting the base sweep's allowance.
        deadline = timeout if timeout is not None else naabu_timeout(hosts, ports, tune)
        # "-list -" does NOT mean "read stdin" -- naabu 2.4.0 takes it
        # literally and tries to open a file named "-", failing with "[FTL]
        # Could not run enumeration: open -: no such file or directory" on
        # stderr, which stream_json() never surfaces since it only looks for
        # JSON on stdout. That silently turned every naabu scan into a
        # no-op, and _stage_portscan() then trusted the empty result and
        # returned without ever falling back to nmap. A real file for
        # "-list" sidesteps the whole question of whether stdin auto-detects
        # correctly when piped in via subprocess rather than a shell |; see
        # _target_list_file.
        cmd = ["naabu", "-silent", "-json", "-rate", str(tune.get("nmap_min_rate", 300)),
               "-c", str(tune.get("concurrency", 10))] + port_args
        found: Dict[str, List[int]] = {}
        t0 = time.time()
        # naabu only ever emits a line for a port it found open, so there is no
        # honest "N of 384 swept" to report - what stream_lines counts as it
        # streams is exactly the open ports found so far, which is enough to
        # tell a working sweep from a wedged one.
        with _target_list_file(hosts) as path:
            for obj in stream_json(cmd + ["-list", path], timeout=deadline,
                               ledger=False):
                h = obj.get("host") or obj.get("ip")
                p = obj.get("port")
                if h and p:
                    found.setdefault(str(h), []).append(int(p))
        # Ledger the sweep so a zero-port result is a visible, verifiable
        # outcome rather than silence - this is the case that made a scan's
        # report impossible to trust ("did naabu find nothing, or break?").
        if status is not None:
            if SKIP.is_set():
                status["skipped"] = True
            elif time.time() - t0 >= deadline - 1.0:
                status["timed_out"] = True
        total = sum(len(v) for v in found.values())
        # Candidates only: naabu is a fast SYN sweep with false positives
        # against firewalls and tarpits. nmap -sV decides what is really open
        # (see Engine._reconcile_naabu for what it dropped). Long lists are
        # clipped so one noisy host cannot bury the rest of the ledger.
        def _fmt(h, v):
            ps = sorted(set(v))
            shown = ",".join(str(x) for x in ps[:40])
            return "%s: %d candidate(s): %s%s" % (
                h, len(ps), shown, " ... (+%d more)" % (len(ps) - 40) if len(ps) > 40 else "")
        summary = (("CANDIDATES - not confirmed open until nmap -sV runs\n"
                    + "\n".join(_fmt(h, v) for h, v in sorted(found.items())))
                   if found else "no open ports found across %d host(s)" % len(hosts))
        _ledger("naabu", cmd + ["-list", "%d host(s)" % len(hosts)], 0,
                "findings" if found else "no-findings", time.time() - t0, summary)
        return found

    found = _run(spec, base)
    if extra:
        for h, ports in _run(["-p", extra], extra).items():
            existing = found.setdefault(h, [])
            for p in ports:
                if p not in existing:
                    existing.append(p)
    return found


# Aim each batch at no more than this much probing, so a timeout loses a
# slice of the work rather than the whole sweep.
NAABU_BATCH_TARGET_SECONDS = 2 * 3600.0
NAABU_MAX_BATCHES = 50


def plan_batches(hosts: Sequence[str], port_spec: str, tune: Dict,
                 requested: int = 0) -> List[List[str]]:
    """Split hosts into sweep batches. `requested` 0 means size them from the
    estimated probe time; otherwise exactly that many (never more than hosts)."""
    hosts = list(hosts)
    if not hosts:
        return []
    if requested and requested > 0:
        n = requested
    else:
        rate = max(1.0, float(tune.get("nmap_min_rate", 300)))
        est = len(hosts) * port_count(port_spec) / rate
        n = int(-(-est // NAABU_BATCH_TARGET_SECONDS))
    n = max(1, min(n, NAABU_MAX_BATCHES, len(hosts)))
    size = -(-len(hosts) // n)
    return [hosts[i:i + size] for i in range(0, len(hosts), size)]


def naabu_sweep(hosts: List[str], port_spec: str, tune: Dict, batches: int = 0,
                max_splits: int = 3, batch_cap: float = NAABU_TIMEOUT_CAP,
                say=None, progress_path: Optional[str] = None,
                resume: bool = False, scan=None) -> Tuple[Dict[str, List[int]], List[str]]:
    """Sweep in batches so a time limit never silently drops hosts.

    A batch that times out is split in half and both halves are queued again,
    up to `max_splits` levels deep, so work that did not finish is redone in
    smaller pieces instead of being lost. Ports found before a cutoff are
    kept. A batch the user skipped is not retried. Whatever still has not
    been swept at the end is returned, so the caller can say exactly what was
    missed. `progress_path` records finished hosts and their ports; with `resume`
    a later run reads it back and skips them.

    Returns (open ports by host, hosts that were not fully swept).
    """
    scan = scan or naabu_scan
    say = say or (lambda msg: None)
    found: Dict[str, List[int]] = {}
    done: set = set()

    if resume and progress_path and os.path.isfile(progress_path):
        try:
            with open(progress_path, "r", encoding="utf-8") as fh:
                prev = json.load(fh)
            if prev.get("spec") == port_spec:
                done = set(prev.get("done") or [])
                for h, ports in (prev.get("found") or {}).items():
                    found[h] = list(ports)
        except (OSError, ValueError):
            done = set()
    pending = [h for h in hosts if h not in done]
    if done:
        say("naabu: %d host(s) already swept in an earlier run, skipping"
            % (len(hosts) - len(pending)))

    def save() -> None:
        if not progress_path:
            return
        try:
            with open(progress_path, "w", encoding="utf-8") as fh:
                json.dump({"spec": port_spec, "done": sorted(done),
                           "found": found}, fh)
        except OSError:
            pass

    queue: List[Tuple[List[str], int]] = [
        (b, 0) for b in plan_batches(pending, port_spec, tune, batches)]
    total = len(queue)
    unscanned: List[str] = []
    n = 0
    while queue:
        batch, depth = queue.pop(0)
        n += 1
        label = "batch %d/%d" % (min(n, total), total) if depth == 0 \
            else "retry (split x%d)" % depth
        say("naabu %s: %d host(s)" % (label, len(batch)))
        st: Dict = {}
        deadline = naabu_timeout(batch, port_spec, tune, cap=batch_cap)
        part = scan(batch, port_spec, tune, timeout=deadline, status=st)
        for h, ports in part.items():
            have = found.setdefault(h, [])
            for p in ports:
                if p not in have:
                    have.append(p)
        if st.get("skipped"):
            say("naabu: skipped by request - %d host(s) not swept" % len(batch))
            unscanned.extend(batch)
            continue
        if st.get("timed_out"):
            if depth >= max_splits or len(batch) < 2:
                say("naabu: %d host(s) still timed out after retries" % len(batch))
                unscanned.extend(batch)
                continue
            mid = len(batch) // 2
            say("naabu: batch hit its limit - splitting and re-running")
            queue[0:0] = [(batch[:mid], depth + 1), (batch[mid:], depth + 1)]
            continue
        done.update(batch)
        save()
    return found, unscanned


# --------------------------------------------------------------------------
# httpx
# --------------------------------------------------------------------------


HTTPX_BASE_TIMEOUT = 60.0
HTTPX_TIMEOUT_CAP = 3 * 3600.0
# httpx's own per-request timeout (-timeout 10) doubled for -retries 1's one
# retry: the worst case for a candidate that never answers at all, which on
# a speculative probe of every open TCP port - not just ones already known
# to speak HTTP - is common, not the exception. A run of 2187 candidates hit
# a flat 600s cap at 155 confirmed live endpoints; worked-out worst case at
# the default 10 threads is closer to 74 minutes.
HTTPX_PER_REQUEST_WORST_CASE = 10.0 * 2


def httpx_timeout(candidates: Sequence[str], tune: Dict) -> float:
    threads = max(1, int(tune.get("concurrency", 10)))
    worst_case = len(candidates) * HTTPX_PER_REQUEST_WORST_CASE / threads
    return min(HTTPX_TIMEOUT_CAP, HTTPX_BASE_TIMEOUT + worst_case)


def httpx_probe(targets: List[str], tune: Dict,
                timeout: Optional[float] = None,
                headers: Optional[Dict[str, str]] = None) -> Iterator[dict]:
    # "-list -" doesn't mean stdin here either -- see _target_list_file. The
    # near-silent version of this failure is worse than naabu's: httpx
    # exiting immediately just looks like zero live endpoints, and
    # _stage_probe falls back to the native per-candidate probe without ever
    # printing that httpx failed, since a nonzero exit isn't an exception.
    if timeout is None:
        timeout = httpx_timeout(targets, tune)
    cmd = [
        "httpx", "-silent", "-json", "-no-color",
        "-status-code", "-title", "-tech-detect", "-web-server",
        "-content-length", "-favicon", "-tls-grab", "-location", "-word-count",
        "-timeout", "10", "-retries", "1",
        "-threads", str(tune.get("concurrency", 10)),
        "-rate-limit", str(int(tune.get("rate", 30))),
    ] + header_args("httpx", headers)
    with _target_list_file(targets) as path:
        yield from stream_json(cmd + ["-list", path], timeout=timeout)


# --------------------------------------------------------------------------
# nuclei
# --------------------------------------------------------------------------


def nuclei_scan(urls: List[str], severity: str, tune: Dict,
                extra_tags: str = "",
                timeout: float = 3600.0,
                headers: Optional[Dict[str, str]] = None) -> Iterator[dict]:
    # A real file, not stdin -- nuclei has shipped bugs where stdin piped in
    # via subprocess.Popen specifically was never read at all
    # (projectdiscovery/nuclei#2032), on top of the same "-list -" literal-
    # file mistake naabu and httpx had. See _target_list_file.
    cmd = [
        "nuclei", "-silent", "-jsonl", "-no-color", "-disable-update-check",
        "-severity", severity,
        "-c", str(tune.get("nuclei_concurrency", 10)),
        "-bulk-size", str(tune.get("nuclei_bulk", 8)),
        "-rate-limit", str(tune.get("nuclei_rate", 60)),
        "-timeout", "8", "-retries", "1",
        # -irr attaches the matched request/response so findings carry evidence.
        "-irr",
        # Templates that fire on generic pages produce most of nuclei's noise.
        "-exclude-tags", "dos,fuzz,intrusive,honeypot",
    ]
    if extra_tags:
        cmd += ["-tags", extra_tags]
    cmd += header_args("nuclei", headers)
    with _target_list_file(urls) as path:
        yield from stream_json(cmd + ["-list", path], timeout=timeout)


# --------------------------------------------------------------------------
# katana
# --------------------------------------------------------------------------


KATANA_BASE_TIMEOUT = 60.0
KATANA_TIMEOUT_CAP = 3 * 3600.0
# katana's own -timeout 10 is the worst-case cost of one request that never
# answers. A crawl visits more than one request per seed candidate, unlike
# httpx's one-shot probe - depth is the parameter that says how much more,
# so it is a linear factor here rather than an attempt to model branching
# that nothing in this codebase measures.
KATANA_PER_REQUEST_WORST_CASE = 10.0


def katana_timeout(candidates: Sequence[str], depth: int, tune: Dict) -> float:
    # Must match -c's own cap below, or the budget and the concurrency it is
    # sized for would silently disagree.
    threads = max(1, min(int(tune.get("concurrency", 10)), 10))
    worst_case = len(candidates) * max(1, depth) * KATANA_PER_REQUEST_WORST_CASE / threads
    return min(KATANA_TIMEOUT_CAP, KATANA_BASE_TIMEOUT + worst_case)


def katana_crawl(urls: List[str], depth: int, tune: Dict, max_urls: int,
                 timeout: Optional[float] = None,
                 headers: Optional[Dict[str, str]] = None) -> List[dict]:
    # Flat 600s was the same bug already fixed for nmap, naabu and httpx
    # today: a crawl of 359 endpoints hit it and cut short at 317 URLs.
    # katana_timeout scales with candidates and depth instead.
    if timeout is None:
        timeout = katana_timeout(urls, depth, tune)
    # A real file, not stdin -- "-list -" doesn't mean stdin here (confirmed
    # against katana's own docs: -list takes a path, and katana reads stdin
    # only when -u/-list is omitted entirely). This is what silently
    # produced zero URLs from a crawl of hundreds of live endpoints - katana
    # exits immediately trying to open a file literally named "-", and a
    # nonzero exit isn't an exception, so nothing surfaced beyond
    # activity.log. See _target_list_file.
    #
    # -jc was also removed: it is katana's alias for -js-crawl (crawl
    # JavaScript files for endpoints), not a "give me the complete JSON
    # object" flag as its presence here implied - -jsonl already includes
    # request.endpoint/response by default, which is the field this
    # function reads.
    cmd = [
        "katana", "-silent", "-jsonl", "-no-color",
        "-d", str(depth), "-c", str(min(tune.get("concurrency", 10), 10)),
        "-rate-limit", str(int(tune.get("rate", 30))),
        # -kf is a single choice, not a comma-list like -ef below: reproduced
        # against a real installed katana, "-kf robotstxt,sitemapxml" is
        # rejected outright ("invalid value ... allowed values are , all,
        # robotstxt, sitemapxml"), exit code 2, in well under a second. That
        # is what actually produced "crawl: 0 URL(s)" from a real crawl of
        # 155 live endpoints - not an empty crawl, a crawl that never ran.
        # "all" is the choice that covers both robots.txt and sitemap.xml.
        "-timeout", "10", "-kf", "all",
        "-ef", "png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,mp4,pdf",
    ] + header_args("katana", headers)
    out: List[dict] = []
    with _target_list_file(urls) as path:
        for obj in stream_json(cmd + ["-list", path], timeout=timeout):
            out.append(obj)
            if len(out) >= max_urls:
                break
    return out


# --------------------------------------------------------------------------
# dnsx / subfinder
# --------------------------------------------------------------------------



def dnsx_resolve(hosts: List[str], timeout: float = 300.0) -> Iterator[dict]:
    # A real file, not stdin -- same "-list -" mistake as naabu/httpx/nuclei/
    # katana above. See _target_list_file.
    cmd = ["dnsx", "-silent", "-json", "-a", "-cname", "-resp"]
    with _target_list_file(hosts) as path:
        yield from stream_json(cmd + ["-list", path], timeout=timeout)


def subfinder_enum(domain: str, timeout: float = 300.0) -> List[str]:
    cmd = ["subfinder", "-silent", "-all", "-d", domain]
    return [l for l in stream_lines(cmd, timeout=timeout) if l]


# --------------------------------------------------------------------------
# ffuf
# --------------------------------------------------------------------------


@dataclass
class FfufRun:
    """Outcome of one ffuf pass, with enough context to say how far through the
    wordlist it got. A deep pass almost never finishes the list inside its
    budget, so "47 hits" means something very different after 3% of the words
    than after the whole file - and a run that stopped early with nothing looks
    identical to one that swept everything and found nothing unless we say which
    it was. The caller reports `coverage` so a partial pass is never mistaken
    for an exhaustive one.
    """
    results: List[dict] = field(default_factory=list)
    planned: int = 0          # words x (1 + extensions): a full pass's requests
    attempted: int = 0        # estimate (rate x elapsed), capped at planned
    elapsed: float = 0.0
    completed: bool = False    # finished the list, vs stopped on the time budget
    killed: bool = False       # hard-killed by run() before it could write hits
    errored: bool = False      # exited nonzero (bad flag, connect refused, ...)
    wordlist: str = ""

    @property
    def coverage(self) -> str:
        """One line a human can read without knowing ffuf's flags."""
        name = os.path.basename(self.wordlist) or "wordlist"
        took = human_duration(self.elapsed)
        if self.killed:
            return ("%s: hard-killed at the time limit after %s before it "
                    "could write results - hits lost" % (name, took))
        if self.errored:
            return "%s: ffuf exited with an error after %s (see ledger)" % (name, took)
        if self.completed:
            return "%s: completed, ~%d requests in %s" % (name, self.planned, took)
        if self.planned:
            pct = 100 * self.attempted // self.planned
            scope = "~%d%% (est.) of ~%d planned requests" % (pct, self.planned)
        else:
            scope = "partial"
        return ("%s: stopped at the %s time budget - %s; wordlist is "
                "frequency-ordered so these are the likeliest paths"
                % (name, took, scope))


_WORDLIST_LINES: Dict[str, int] = {}


def _wordlist_len(path: str) -> int:
    """Line count of a wordlist, cached: deep reuses the same file for every
    host in a run and the big lists are ~350k lines, so count each one once."""
    if path not in _WORDLIST_LINES:
        try:
            with open(path, "rb") as fh:
                _WORDLIST_LINES[path] = sum(1 for _ in fh)
        except OSError:
            _WORDLIST_LINES[path] = 0
    return _WORDLIST_LINES[path]


def ffuf_discover(url: str, wordlist: str, tune: Dict,
                  extensions: str = "", timeout: float = 600.0) -> "FfufRun":
    """Content discovery with ffuf's own auto-calibration to suppress soft-404s.

    A wordlist times the extension list is hundreds of thousands of requests,
    which at a polite rate never fits `timeout`. ffuf only writes its -o file
    when it exits on its own, so the hard kill from run() threw away every hit
    found so far. -maxtime makes ffuf stop itself shortly before that deadline
    and write what it has; wordlists are frequency-ordered, so the partial
    result is the most likely paths. The returned FfufRun carries how far
    through the list that budget actually got, so the caller can say so.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    base = url.rstrip("/")
    # ffuf writes its -o file only on a clean exit, never on the SIGTERM that
    # run() sends at `timeout`, so -maxtime MUST fire first with room to spare.
    # A flat 30s gap was not enough: ffuf overruns -maxtime while its -rate
    # limiter is sleeping and while in-flight requests drain, so it was
    # reaching the hard kill and losing every hit. Scale the cushion
    # with the budget - a long deep/finalize pass has many more in-flight and
    # far more clock to overrun - with a floor that still doubles the old gap
    # on the short profiles.
    grace = max(60.0, timeout * 0.1)
    maxtime = max(30.0, timeout - grace)
    rate = int(tune.get("rate", 30))
    n_ext = len([e for e in extensions.split(",") if e]) if extensions else 0
    planned = _wordlist_len(wordlist) * (1 + n_ext)
    cmd = [
        "ffuf", "-u", base + "/FUZZ", "-w", wordlist,
        "-ac", "-acc", "-mc", "200,201,204,301,302,307,401,403,405,500",
        "-fs", "0", "-t", str(tune.get("ffuf_threads", 10)),
        "-rate", str(rate),
        "-maxtime", str(int(maxtime)),
        "-timeout", "8", "-s", "-of", "json",
        "-o", env.to_wsl_path(tmp.name), "-noninteractive",
    ]
    if extensions:
        cmd += ["-e", extensions]
    t0 = time.time()
    proc = run(cmd, timeout=timeout)
    elapsed = time.time() - t0
    out = FfufRun(
        planned=planned, elapsed=elapsed, wordlist=wordlist,
        attempted=min(planned, int(elapsed * rate)) if planned else 0,
        killed=proc.timed_out,
        errored=not proc.ok and not proc.timed_out,
        # ffuf exits rc 0 both when it finishes the list and when it hits
        # -maxtime, so rc alone can't tell them apart; the clock does. Leaving
        # a few seconds' slack below maxtime keeps a run that stopped on the
        # budget from being reported as a completed sweep.
        completed=proc.ok and elapsed < maxtime - 5,
    )
    try:
        with open(tmp.name, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        out.results = data.get("results", [])
    except (OSError, ValueError):
        out.results = []
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    return out


@dataclass
class FfufSweep:
    """Outcome of fuzzing a wordlist in ordered shards. `reached` is the exact
    word index to resume from - banked across every shard that finished, so a
    later pass continues from there instead of redoing the front of the list."""
    results: List[dict] = field(default_factory=list)
    reached: int = 0           # word index to resume from next time
    total: int = 0             # words in the wordlist
    elapsed: float = 0.0
    done: bool = False         # the whole wordlist was swept
    killed: bool = False       # a shard was hard-killed before it could flush
    wordlist: str = ""

    @property
    def coverage(self) -> str:
        name = os.path.basename(self.wordlist) or "wordlist"
        took = human_duration(self.elapsed)
        if self.done:
            return "%s: swept all %d words in %s" % (name, self.total, took)
        pct = (" (%d%%)" % (100 * self.reached // self.total)) if self.total else ""
        tail = " - a shard was hard-killed, some of its hits lost" if self.killed else ""
        return ("%s: %d/%d words%s in %s - stopped on the time budget; resume "
                "picks up from word %d%s"
                % (name, self.reached, self.total, pct, took, self.reached, tail))


# Each shard aims at roughly this many seconds of requests at the rate cap, so
# a shard is about the same wall-clock slice whatever the extension multiplier
# does to the request count - small enough that a cut loses at most one shard's
# worth of progress, large enough that per-shard ffuf startup and -ac
# calibration stay negligible.
_SHARD_SECONDS = 300.0


def ffuf_sweep(url: str, wordlist: str, tune: Dict,
               extensions: str = "", timeout: float = 600.0,
               start: int = 0) -> "FfufSweep":
    """Fuzz `wordlist` in ordered shards, from word index `start`, until the
    list is exhausted or `timeout` is spent.

    ffuf has no resume of its own and only writes hits when it exits cleanly, so
    one long pass that gets cut loses everything after its last flush, and a
    retry would redo the whole front of the (frequency-ordered) list. Fuzzing
    fixed-size shards instead banks every finished shard's hits and records the
    exact word index reached, so a later pass - a `finalize` - continues from
    there rather than from the top.
    """
    try:
        with open(wordlist, "r", encoding="utf-8", errors="replace") as fh:
            words = [w.rstrip("\n") for w in fh if w.strip()]
    except OSError:
        return FfufSweep(wordlist=wordlist)
    total = len(words)
    rate = max(1, int(tune.get("rate", 30)))
    n_ext = len([e for e in extensions.split(",") if e]) if extensions else 0
    shard_words = max(200, int(rate * _SHARD_SECONDS / (1 + n_ext)))

    sweep = FfufSweep(total=total, wordlist=wordlist,
                      reached=min(max(0, start), total))
    t0 = time.time()
    deadline = t0 + timeout
    i = sweep.reached
    while i < total:
        remaining = deadline - time.time()
        # Too little left to spawn another shard and have it make real
        # progress; stop here and leave the rest for a resume.
        if remaining < 45:
            break
        chunk = words[i:i + shard_words]
        tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                          encoding="utf-8")
        try:
            tmp.write("\n".join(chunk) + "\n")
            tmp.close()
            fr = ffuf_discover(url, env.to_wsl_path(tmp.name), tune,
                               extensions=extensions, timeout=remaining)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass
        sweep.results.extend(fr.results)
        if fr.completed:
            i += len(chunk)
            sweep.reached = min(i, total)
            continue
        # The shard did not finish inside the budget (stopped on its own
        # -maxtime, was hard-killed, or errored): leave `reached` at this
        # shard's start so a resume redoes only this shard, not the ones
        # already banked before it.
        sweep.reached = i
        sweep.killed = fr.killed
        break
    sweep.elapsed = time.time() - t0
    sweep.done = sweep.reached >= total
    return sweep


# Bigger costs time, not just hit rate - ffuf still has to send one request
# per word - so the wordlist scales with the profile's own time budget
# instead of always reaching for the largest list installed.
_CONTENT_WORDLIST_TIERS = {
    "quick": (
        "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ),
    "standard": (
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    ),
    "deep": (
        # raft-large-words.txt (~350k) before directory-list-2.3-big.txt
        # (~1.27M): the latter is real but turns "deep = an overnight pass"
        # into multiple days per host at any sane rate limit, so it is a
        # fallback here, not the preferred deep-tier list.
        "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    ),
}
_CONTENT_WORDLIST_FALLBACK = (
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
)


def default_wordlist(profile: str = "standard") -> Optional[str]:
    tiers = _CONTENT_WORDLIST_TIERS.get(profile, _CONTENT_WORDLIST_TIERS["standard"])
    for path in tiers + _CONTENT_WORDLIST_FALLBACK:
        if os.path.exists(path):
            return path
    return None


# Subdomain brute-forcing: gobuster's dns mode / Sublist3r's brute-force pass,
# handed to dnsx for resolution rather than reimplementing a resolver. 'quick'
# gets no entry here at all - the passive sources and the small permutation
# list in recon.PERMUTATIONS stay fast on their own, and wordlist
# brute-forcing is what --expand buys on standard/deep.
_DNS_WORDLIST_TIERS = {
    "deep": (
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    ),
    "standard": (
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    ),
}


def dns_wordlist(profile: str = "standard") -> Optional[str]:
    for path in _DNS_WORDLIST_TIERS.get(profile, ()):
        if os.path.exists(path):
            return path
    return None


# --------------------------------------------------------------------------
# Historical URL sources (passive - these query third-party archives)
# --------------------------------------------------------------------------


def gau_urls(domain: str, limit: int, timeout: float = 300.0) -> List[str]:
    cmd = ["gau", "--subs", "--threads", "3", "--timeout", "20", domain]
    out: List[str] = []
    for line in stream_lines(cmd, timeout=timeout):
        if line.startswith("http"):
            out.append(line)
            if len(out) >= limit:
                break
    return out


def waybackurls_urls(domain: str, limit: int, timeout: float = 300.0) -> List[str]:
    out: List[str] = []
    for line in stream_lines(["waybackurls", domain], timeout=timeout, stdin=""):
        if line.startswith("http"):
            out.append(line)
            if len(out) >= limit:
                break
    return out


def arjun_params(url: str, tune: Dict, timeout: float = 300.0) -> List[str]:
    """Discover parameters a crawl cannot see. Returns parameter names."""
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    # No --stable: as I recall it forces one thread and a multi-second delay
    # between requests, which cannot finish inside `timeout` (verify with
    # `arjun --help` on the Kali box). Politeness comes from the thread cap
    # instead: the engine runs up to 6 of these at once, so 4 threads each
    # bounds it at about 24 concurrent requests.
    cmd = ["arjun", "-u", url, "-oJ", tmp.name, "-q",
           "-t", str(min(tune.get("ffuf_threads", 4), 4))]
    run(cmd, timeout=timeout)
    try:
        with open(tmp.name, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        names: List[str] = []
        for entry in (data.values() if isinstance(data, dict) else []):
            if isinstance(entry, dict):
                names += list(entry.get("params") or [])
        return sorted(set(names))
    except (OSError, ValueError, AttributeError):
        return []
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
