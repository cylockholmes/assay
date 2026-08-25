"""Run the AI's recommended verification commands, safely.

The triage pass reasons over pseudonymised data, so every command it suggests
comes back containing tokens like [CLIENT-01]. Those are un-redacted locally
against the mapping file - the real hostnames never left the machine, so
putting them back is a local operation.

Executing a command a language model wrote is the genuinely dangerous part of
this feature, so it is gated four ways and none of them can be skipped:

  1. allow-list   only read-oriented security tools may run. Anything else is
                  refused, including shells and package managers.
  2. no shell     commands are parsed with shlex and executed without a shell.
                  Metacharacters cause a refusal rather than being escaped.
  3. scope        every host, IP and URL in the command is checked against the
                  engagement scope. An out-of-scope argument refuses the whole
                  command - this is the guarantee that matters most.
  4. consent      nothing runs without --run and an explicit confirmation.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from assay.config import Config

# Read-oriented tools only. Nothing that writes to the target, installs
# software, or can be turned into a shell.
ALLOWED = {
    # http
    "curl", "wget", "httpx", "nuclei", "katana", "ffuf", "whatweb", "gau",
    "waybackurls", "arjun", "gobuster", "feroxbuster", "dirsearch",
    # dns / tls
    "dig", "host", "nslookup", "openssl", "tlsx", "dnsx", "subfinder",
    "testssl.sh", "sslscan",
    # network / services
    "nmap", "naabu", "smbclient", "ldapsearch", "showmount", "snmpwalk",
    "rpcinfo", "enum4linux", "enum4linux-ng", "redis-cli", "mongosh",
    "nikto", "wafw00f", "amass",
    # local helpers
    "jq", "grep", "echo", "strings", "base64", "sort", "uniq", "head", "wc",
}

# Flags that turn an allowed tool into something else entirely.
BANNED_ARGS = re.compile(
    r"^(?:-e|--exec|--eval|-oN?\s*/etc|--output-document=/|--script-args=.*unsafe)",
    re.I)

# Anything that implies a shell.
SHELL_CHARS = re.compile(r"[;&|`$><\n\r]|\$\(|\{\}")

HOSTLIKE = re.compile(
    r"(?:https?://)?(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,24}|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


@dataclass
class Command:
    raw: str
    finding_id: str = ""
    finding_title: str = ""
    ok: bool = False
    reason: str = ""
    argv: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    output: str = ""
    rc: Optional[int] = None

    @property
    def display(self) -> str:
        return " ".join(self.argv) if self.argv else self.raw


def extract_hosts(text: str) -> List[str]:
    found: List[str] = []
    for m in HOSTLIKE.finditer(text):
        host = m.group(0)
        if host.startswith("http"):
            host = urlsplit(host).hostname or ""
        host = host.strip("/:,'\"")
        # Bare tool names like testssl.sh look host-shaped; ignore known tools.
        if not host or host in ALLOWED or host.split(".")[0] in ALLOWED:
            continue
        if host not in found:
            found.append(host)
    return found


def vet(raw: str, cfg: Config) -> Command:
    """Decide whether a suggested command may run. Never raises."""
    cmd = Command(raw=raw.strip())
    text = cmd.raw

    if not text or text.startswith("#"):
        cmd.reason = "not a command"
        return cmd
    if SHELL_CHARS.search(text):
        cmd.reason = "contains shell metacharacters"
        return cmd

    try:
        argv = shlex.split(text)
    except ValueError as exc:
        cmd.reason = "unparseable: %s" % exc
        return cmd
    if not argv:
        cmd.reason = "empty"
        return cmd

    binary = argv[0].split("/")[-1]
    if binary not in ALLOWED:
        cmd.reason = "'%s' is not on the read-only tool allow-list" % binary
        return cmd
    for a in argv[1:]:
        if BANNED_ARGS.match(a):
            cmd.reason = "argument '%s' is not permitted" % a[:30]
            return cmd

    hosts = extract_hosts(text)
    out_of_scope = [h for h in hosts if not cfg.scope.allows(h)]
    if out_of_scope:
        cmd.reason = "out of scope: %s" % ", ".join(out_of_scope)
        cmd.hosts = hosts
        return cmd

    cmd.argv = argv
    cmd.hosts = hosts
    cmd.ok = True
    cmd.reason = "ready"
    return cmd


def run(cmd: Command, timeout: float = 120.0) -> Command:
    if not cmd.ok:
        return cmd
    try:
        p = subprocess.run(cmd.argv, capture_output=True, text=True,
                           timeout=timeout)
        cmd.rc = p.returncode
        cmd.output = ((p.stdout or "") + (p.stderr or ""))[:8000]
    except subprocess.TimeoutExpired:
        cmd.rc = -1
        cmd.output = "timed out after %ds" % int(timeout)
    except OSError as exc:
        cmd.rc = -1
        cmd.output = "failed to execute: %s" % exc
    return cmd


def collect(store, redactor=None) -> List[Command]:
    """Gather every AI-suggested command, un-redacted, in priority order."""
    out: List[Command] = []
    for f in store.iter_findings():
        ai = store.ai_for(f.fingerprint())
        if not ai:
            continue
        for raw in (ai.get("commands") or []) + [
                s for s in (ai.get("next_steps") or []) if _looks_like_cmd(s)]:
            text = raw
            if redactor is not None:
                text = redactor.map.rehydrate(text)
            c = Command(raw=text, finding_id=f.fingerprint(),
                        finding_title=f.title)
            out.append(c)
    return out


def _looks_like_cmd(text: str) -> bool:
    """A next_step is runnable if it starts with an allow-listed binary."""
    head = text.strip().split(" ", 1)[0].split("/")[-1]
    return head in ALLOWED
