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
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlsplit

from assay import tools
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

# Risk tiering (PLAN-LOOP §1), by the TWO independent axes that matter:
#
#   tier  = may this invocation AUTO-RUN without the operator saying yes?
#   send  = may this tool's OUTPUT be sent back to the AI (when resend is on)?
#
# They are orthogonal: curl is cheap to auto-run but its raw body is the
# highest-risk thing to send, so it is passive-to-run yet never send-eligible.
#
# PASSIVE_BINS: no packets to the target, or a single benign request. Default
# is DENY - a binary not listed here is ACTIVE and needs consent, and even a
# listed one is ACTIVE if its arguments look active (see _tier).
PASSIVE_BINS = {
    "dig", "host", "nslookup", "dnsx", "tlsx", "openssl", "whatweb", "wafw00f",
    "gau", "waybackurls", "curl", "wget",
    "jq", "grep", "echo", "strings", "base64", "sort", "uniq", "head", "wc",
}

# curl/wget flags that make an otherwise-passive fetch active (writes a body,
# uploads, posts a form, or forces a non-GET method).
_CURL_ACTIVE = {"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode",
                "-F", "--form", "-T", "--upload-file", "-X", "--request"}

# SEND_ELIGIBLE: tools whose output is bounded, infra-level metadata rather
# than raw target/attacker-controlled content, so it MAY be re-redacted and
# sent back to the AI when output-resend is enabled. Everything else is
# local-only (proof page / ledger), never sent. Default is DENY.
SEND_ELIGIBLE = {
    "dig", "host", "nslookup", "dnsx",          # DNS answers
    "whatweb", "wafw00f", "tlsx", "nmap", "naabu",  # infra fingerprint
    "wc", "sort", "uniq",                        # pure counts/ordering
}


def tier_of(argv: List[str]) -> str:
    """'passive' (auto-run eligible) or 'active' (needs consent). Default-deny:
    anything not provably passive is active."""
    if not argv:
        return "active"
    b = argv[0].split("/")[-1]
    if b not in PASSIVE_BINS:
        return "active"
    if b in ("curl", "wget"):
        for a in argv[1:]:
            if a in _CURL_ACTIVE or a.startswith("--data"):
                return "active"
    return "passive"


def send_eligible(tool: str) -> bool:
    """Whether this tool's output may ever be sent back to the AI (§3)."""
    return (tool or "").split("/")[-1] in SEND_ELIGIBLE


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
    tier: str = "active"   # 'passive' (auto-run eligible) or 'active' (consent)

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
    cmd.tier = tier_of(argv)
    cmd.ok = True
    cmd.reason = "ready"
    return cmd


def rescrub(output: str, tool: str, redactor, cap: int = 8192) -> Tuple[Optional[str], List[str]]:
    """Decide whether a command's output may go back to the AI (PLAN-LOOP §3).

    Returns (sendable_text, leaks). sendable_text is None when the output must
    stay local - because the tool is not send-eligible, or because redaction
    left residual client identifiers (leaks non-empty). Only a send-eligible
    tool whose redacted output passes verify() comes back as text to send.

    `verify()` catches only KNOWN entities (seeded terms + minted tokens), so
    this reduces but cannot eliminate residual risk; that is exactly why
    resend is opt-in and high-risk tools are excluded by send_eligible().
    """
    if not output or not send_eligible(tool):
        return None, []
    redacted = redactor.text(output)[:cap]
    leaks = redactor.verify(redacted)
    if leaks:
        return None, leaks
    return redacted, []


_HTTP_STATUS = re.compile(r"^HTTP/[\d.]+\s+(\d{3})", re.M)


def digest(output: str, rc: Optional[int]) -> str:
    """Content-free summary of output that may not be sent verbatim.

    Tools outside SEND_ELIGIBLE (curl, openssl, ...) can return arbitrary
    target-controlled text, so their bodies stay local. The model still needs
    to know the command ran and roughly what happened, so it gets the exit
    code, size and - where present - the HTTP status, never the content.
    """
    out = output or ""
    parts = ["exit %s" % (rc if rc is not None else "?"),
             "%d bytes" % len(out.encode("utf-8", "replace")),
             "%d lines" % (out.count("\n") + (1 if out and not out.endswith("\n") else 0))]
    codes = _HTTP_STATUS.findall(out)
    if codes:
        parts.append("HTTP status %s" % ", ".join(codes[:4]))
    return "output withheld (not send-eligible): " + "; ".join(parts)


def plan_followups(vetted: List[Command], auto_mode: str = "passive",
                   rate_cap_per_host: int = 5) -> Tuple[List[Command], List[Command], List[Command]]:
    """Partition vetted commands into (auto_run, queued, refused) for one round.

    Default-deny all the way down:
      * a command that did not pass vet() is refused (allow-list / shell / scope);
      * an active-tier command is queued for consent, never auto-run;
      * a passive command auto-runs only when auto_mode == 'passive' and it is
        within the per-host rate cap - anything over the cap is queued, so
        'passive' can never become a slow scan by sheer volume.
    """
    auto: List[Command] = []
    queued: List[Command] = []
    refused: List[Command] = []
    per_host: Dict[str, int] = {}
    for c in vetted:
        if not c.ok:
            refused.append(c)
            continue
        if c.tier != "passive" or auto_mode != "passive":
            queued.append(c)
            continue
        host_key = c.hosts[0] if c.hosts else ""
        if per_host.get(host_key, 0) >= rate_cap_per_host:
            queued.append(c)          # over the per-host cap this round
            continue
        per_host[host_key] = per_host.get(host_key, 0) + 1
        auto.append(c)
    return auto, queued, refused


def run(cmd: Command, timeout: float = 120.0) -> Command:
    """Execute a vetted command through tools.run().

    Not bare subprocess: every binary on ALLOWED lives inside the distribution
    on a Windows host, so an unbridged call fails for exactly the commands the
    engine runs successfully. Going through run() also puts them in the
    journal, which for commands a model wrote is the point.
    """
    if not cmd.ok:
        return cmd
    p = tools.run(cmd.argv, timeout=timeout)
    cmd.rc = -1 if p.timed_out else p.rc
    cmd.output = (("timed out after %ds" % int(timeout)) if p.timed_out
                  else ((p.out or "") + (p.err or ""))[:8000])
    return cmd


def collect(store, redaction_map=None) -> List[Command]:
    """Gather every AI-suggested command, un-redacted, in priority order.

    `redaction_map` is the run's RedactionMap. The model wrote these commands
    against pseudonyms, so without it they still carry [HOST-02] and will not
    resolve; putting the real values back is a purely local operation.
    """
    out: List[Command] = []
    ai_by_fid = store.ai_map()          # one query, not one per finding
    for f in store.iter_findings():
        ai = ai_by_fid.get(f.fingerprint())
        if not ai:
            continue
        for raw in (ai.get("commands") or []) + [
                s for s in (ai.get("next_steps") or []) if _looks_like_cmd(s)]:
            text = raw
            if redaction_map is not None:
                text = redaction_map.rehydrate(text)
            c = Command(raw=text, finding_id=f.fingerprint(),
                        finding_title=f.title)
            out.append(c)
    return out


def _looks_like_cmd(text: str) -> bool:
    """A next_step is runnable if it starts with an allow-listed binary."""
    head = text.strip().split(" ", 1)[0].split("/")[-1]
    return head in ALLOWED
