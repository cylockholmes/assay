"""Run the AI's recommended verification commands, safely.

The triage pass reasons over pseudonymised data, so every command it suggests
comes back containing tokens like [CLIENT-01]. Those are un-redacted locally
against the mapping file - the real hostnames never left the machine, so
putting them back is a local operation.

Executing a command a language model wrote is the genuinely dangerous part of
this feature, so it is gated four ways and none of them can be skipped:

  1. allow-list   only read-oriented network tools may run, by bare name.
                  Anything else is refused, including shells, package
                  managers and local file helpers. Flags that write or load a
                  local file, and arguments that name one, are refused too
                  (system wordlists are the one exception).
  2. no shell     commands are parsed with shlex and executed without a shell.
                  Metacharacters cause a refusal rather than being escaped.
  3. scope        every host, IP and URL in the command is checked against the
                  engagement scope, only http(s) URLs are accepted, this
                  machine is never a target, and a network tool that names no
                  host is refused. An out-of-scope argument refuses the whole
                  command - this is the guarantee that matters most.
  4. consent      nothing runs without --run and an explicit confirmation,
                  except the passive tier under --ai-loop (see tier_of).

The model reads target-controlled text, so its suggestions must be treated as
attacker-influenced: every gate assumes a hostile command, not a careless one.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from assay import tools
from assay.config import Config

# Read-oriented network tools only. Nothing that writes to the target,
# installs software, or can be turned into a shell.
#
# There are deliberately no local file helpers here (grep, head, sort, wc,
# base64, jq, ...). Commands run without a shell, so there is no pipe to feed
# them: the only thing they can ever read is a file on this machine, which is
# exactly what a prompt-injected suggestion would want. wget is out for the
# same family of reasons - it writes every download to disk by default.
ALLOWED = {
    # http
    "curl", "httpx", "nuclei", "katana", "ffuf", "whatweb", "gau",
    "waybackurls", "arjun", "gobuster", "feroxbuster", "dirsearch",
    # dns / tls
    "dig", "host", "nslookup", "openssl", "tlsx", "dnsx", "subfinder",
    "testssl.sh", "sslscan",
    # network / services
    "nmap", "naabu", "smbclient", "ldapsearch", "showmount", "snmpwalk",
    "rpcinfo", "enum4linux", "enum4linux-ng", "redis-cli", "mongosh",
    "nikto", "wafw00f", "amass",
    # harmless
    "echo",
}

# Tools that need no target at all. Every other tool must name at least one
# host, and every host it names must be in scope.
_NO_TARGET = {"echo"}

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
    "gau", "waybackurls", "curl", "echo",
}

# curl flags that make an otherwise-passive fetch active (sends a body,
# uploads, posts a form, or forces a non-GET method). Short forms are also
# matched with their value attached ("-dx=1", "-XPOST").
_CURL_ACTIVE = {"-d", "--data", "--data-binary", "--data-raw", "--data-urlencode",
                "--data-ascii", "--json", "-F", "--form", "--form-string",
                "-T", "--upload-file", "-X", "--request"}
_CURL_ACTIVE_SHORT = ("-d", "-F", "-T", "-X")

# SEND_ELIGIBLE: tools whose output is bounded, infra-level metadata rather
# than raw target/attacker-controlled content, so it MAY be re-redacted and
# sent back to the AI when output-resend is enabled. Everything else is
# local-only (proof page / ledger), never sent. Default is DENY.
SEND_ELIGIBLE = {
    "dig", "host", "nslookup", "dnsx",          # DNS answers
    "whatweb", "wafw00f", "tlsx", "nmap", "naabu",  # infra fingerprint
}


def tier_of(argv: list[str]) -> str:
    """'passive' (auto-run eligible) or 'active' (needs consent). Default-deny:
    anything not provably passive is active."""
    if not argv:
        return "active"
    b = argv[0].split("/")[-1]
    if b not in PASSIVE_BINS:
        return "active"
    if b == "curl":
        for a in argv[1:]:
            flag = a.split("=", 1)[0]
            if (flag in _CURL_ACTIVE or a.startswith("--data")
                    or a.startswith("--form")
                    or (not a.startswith("--") and a.startswith(_CURL_ACTIVE_SHORT))):
                return "active"
    return "passive"


def send_eligible(tool: str) -> bool:
    """Whether this tool's output may ever be sent back to the AI (§3)."""
    return (tool or "").split("/")[-1] in SEND_ELIGIBLE


# Flags that turn an allowed tool into something else entirely.
BANNED_ARGS = re.compile(
    r"^(?:-e|--exec|--eval|--script-args=.*unsafe)",
    re.I)

# Flags that write to, or read configuration from, this machine. A model's
# suggestion never needs either: output is captured from stdout, and the
# command line is the whole configuration. Matched on the flag name, before
# any "=value".
_WRITE_FLAGS: dict[str, set[str]] = {
    "curl": {"-o", "--output", "-O", "--remote-name", "--remote-name-all",
             "--output-dir", "--create-dirs", "-D", "--dump-header", "-c",
             "--cookie-jar", "-K", "--config", "--trace", "--trace-ascii",
             "--libcurl", "--stderr", "--etag-save", "--hsts", "--alt-svc",
             "-q", "--disable", "--netrc", "-n", "--netrc-file", "--unix-socket",
             "--abstract-unix-socket", "--key", "--cert", "--cacert",
             "--capath", "--crlfile", "--pinnedpubkey", "--proto-default"},
    "nmap": {"-iL", "-iR", "--resume", "--datadir", "--stylesheet",
             "--servicedb", "--versiondb", "--excludefile", "--script-args-file",
             "--script-updatedb"},
    "smbclient": {"-c", "--command", "-D", "--directory", "-T", "--tar",
                  "-A", "--authentication-file", "-s", "--configfile"},
    "openssl": set(),        # vetted by its own allow-list below
}
# curl's single-letter write/config options, also caught inside a bundle.
_CURL_WRITE_SHORT = "oODcKqn"
# Long flags whose name says they write or load a file, for any tool.
_WRITE_FLAG_RX = re.compile(
    r"^--?(?:[a-z0-9-]*-)?(?:o|out|output|outfile|output-file|output-dir|"
    r"log|logfile|log-file|save|store|write|dump|config|resume|"
    r"json-?file|html-?file|csv-?file|xml-?file|report|export)"
    r"(?:-[a-z0-9-]+)?$")
# nmap's output family: -oN -oX -oG -oA -oS -oM, value attached or not.
_NMAP_OUT = re.compile(r"^-o[NXGASM]?")

# Flags whose value is a wordlist. The only local path a command may name,
# and only under the system wordlist directories.
_WORDLIST_FLAGS = {"-w", "--wordlist", "-wordlist", "--wordlists"}
_WORDLIST_ROOTS = ("/usr/share/seclists/", "/usr/share/wordlists/",
                   "/usr/share/dirb/", "/usr/share/dirbuster/",
                   "/usr/share/nmap/", "/opt/seclists/")

# openssl can read and write any file. The only use a verification step has
# for it is s_client against a host, with these flags.
_OPENSSL_SUBCOMMANDS = {"s_client"}
_OPENSSL_FLAGS = {"-connect", "-servername", "-showcerts", "-brief", "-status",
                  "-alpn", "-starttls", "-tls1", "-tls1_1", "-tls1_2", "-tls1_3",
                  "-no_tls1_3", "-cipher", "-ciphersuites", "-verify_return_error",
                  "-prexit", "-state", "-msg", "-debug", "-ign_eof", "-nbio",
                  "-crlf", "-quiet", "-verify", "-host", "-port", "-reconnect",
                  "-sigalgs", "-groups", "-curves", "-ct", "-noservername"}

# curl flags that take a value. Every other bare word on a curl command line
# is a URL, and is checked as one.
_CURL_VALUE_FLAGS = {
    "-H", "--header", "-A", "--user-agent", "-e", "--referer", "-u", "--user",
    "-X", "--request", "-d", "--data", "--data-raw", "--data-binary",
    "--data-urlencode", "--data-ascii", "--json", "-F", "--form",
    "--form-string", "-m", "--max-time", "--connect-timeout", "-x", "--proxy",
    "--resolve", "--connect-to", "-w", "--write-out", "--max-redirs", "-r",
    "--range", "-b", "--cookie", "--retry", "--retry-delay", "--retry-max-time",
    "-z", "--time-cond", "--interface", "--local-port", "--limit-rate", "-Y",
    "--speed-limit", "-y", "--speed-time", "--ciphers", "--tls-max",
    "--tlsv1.2", "--proxy-user", "-U", "--noproxy", "--request-target",
    "--happy-eyeballs-timeout-ms", "--expect100-timeout", "--keepalive-time",
    "-C", "--continue-at", "--url-query", "--variable", "--aws-sigv4",
    "--oauth2-bearer", "--sasl-authzid", "--dns-servers", "--max-filesize",
}

# Anything that implies a shell.
SHELL_CHARS = re.compile(r"[;&|`$><\n\r]|\$\(|\{\}")

HOSTLIKE = re.compile(
    r"(?:https?://)?(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,24}|"
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# Any URL scheme. Only http(s) may appear: file:, gopher:, dict:, ftp: and
# the rest are how a fetch tool is talked into reading this machine or a
# service that the host-shaped scope check would never see.
_SCHEME = re.compile(r"\b([A-Za-z][A-Za-z0-9+.-]{1,15})://")
_FILE_SCHEME = re.compile(r"\bfile:", re.I)

# Names that always mean this machine, whatever the scope file says.
_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost",
                "ip6-loopback"}


@dataclass
class Command:
    raw: str
    finding_id: str = ""
    finding_title: str = ""
    ok: bool = False
    reason: str = ""
    argv: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    output: str = ""
    rc: int | None = None
    tier: str = "active"   # 'passive' (auto-run eligible) or 'active' (consent)

    @property
    def display(self) -> str:
        return " ".join(self.argv) if self.argv else self.raw


def extract_hosts(text: str) -> list[str]:
    found: list[str] = []
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


def _url_host(url: str) -> tuple[str | None, str]:
    """(host, problem) for one URL-shaped argument. A host of None means the
    argument must be refused, for the reason given."""
    m = _SCHEME.search(url)
    if m and m.group(1).lower() not in ("http", "https"):
        return None, "scheme '%s:' is not permitted" % m.group(1).lower()
    target = url if m else "http://" + url
    try:
        host = urlsplit(target).hostname or ""
    except ValueError:
        return None, "unparseable URL '%s'" % url[:40]
    if not host:
        return None, "URL '%s' has no host" % url[:40]
    return host.lower().rstrip("."), ""


def _is_local_path(value: str) -> bool:
    v = value.lstrip("@<")
    if v.startswith("//"):          # //host/share is a UNC target, not a path
        return False
    return v.startswith(("/", "~", "./", "../")) or v in (".", "..")


def _check_args(binary: str, argv: list[str]) -> tuple[str, list[str]]:
    """Per-argument refusals. Returns (reason, extra_hosts); reason is "" when
    every argument is acceptable. extra_hosts are hosts found in positions the
    generic host scan cannot see (bare curl URLs, UNC targets)."""
    extra: list[str] = []
    args = argv[1:]
    if binary == "openssl":
        if not args or args[0] not in _OPENSSL_SUBCOMMANDS:
            return "openssl may only run s_client", extra
    write_flags = _WRITE_FLAGS.get(binary, set())
    prev = ""
    for i, a in enumerate(args):
        flag, _, value = a.partition("=") if a.startswith("-") else ("", "", a)
        if BANNED_ARGS.match(a):
            return "argument '%s' is not permitted" % a[:30], extra
        if _FILE_SCHEME.search(a):
            return "file: URLs are not permitted", extra
        if a.startswith("-"):
            name = flag
            if name in write_flags or _WRITE_FLAG_RX.match(name) or (
                    binary == "nmap" and _NMAP_OUT.match(name)):
                return "'%s' writes or loads a local file" % name[:30], extra
            if binary == "openssl" and i > 0 and name not in _OPENSSL_FLAGS:
                return "openssl flag '%s' is not permitted" % name[:30], extra
            if binary == "curl" and not a.startswith("--"):
                if "@" in a or "<" in a:
                    return "curl '@file' arguments are not permitted", extra
                # Bundled short options: "-sSo out" writes a file as surely
                # as "-o out" does.
                # A letter that takes a value ends the bundle: "-XPOST" is
                # -X with "POST", not -X -P -O -S -T.
                for ch in a[1:]:
                    if ch in _CURL_WRITE_SHORT:
                        return ("curl '-%s' writes or loads a local file" % ch), extra
                    if "-" + ch in _CURL_VALUE_FLAGS:
                        break
            if value and _is_local_path(value) and not (
                    name in _WORDLIST_FLAGS and value.startswith(_WORDLIST_ROOTS)):
                return "argument '%s' names a local file" % a[:40], extra
            prev = a
            continue
        # A bare word: a flag's value, a target, or a subcommand.
        if binary == "curl" and (a.startswith("@") or "=@" in a or "=<" in a):
            return "curl '@file' arguments are not permitted", extra
        if _is_local_path(a) and not (
                prev in _WORDLIST_FLAGS and a.startswith(_WORDLIST_ROOTS)):
            return "argument '%s' names a local file" % a[:40], extra
        if a.startswith("//"):
            host = a[2:].split("/", 1)[0]
            if host:
                extra.append(host.lower())
        is_value = prev.startswith("-") and "=" not in prev
        if binary == "curl" and not (is_value and prev in _CURL_VALUE_FLAGS):
            host, problem = _url_host(a)
            if host is None:
                return problem, extra
            extra.append(host)
        elif "://" in a:
            host, problem = _url_host(a)
            if host is None:
                return problem, extra
            extra.append(host)
        prev = a if a.startswith("-") else ""
    return "", extra


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

    # A bare name, found on PATH. "/tmp/x/curl" is not curl.
    if "/" in argv[0] or "\\" in argv[0]:
        cmd.reason = "'%s' must be a bare tool name, not a path" % argv[0][:40]
        return cmd
    binary = argv[0]
    if binary not in ALLOWED:
        cmd.reason = "'%s' is not on the read-only tool allow-list" % binary
        return cmd

    problem, positional_hosts = _check_args(binary, argv)
    if problem:
        cmd.reason = problem
        return cmd

    # A wordlist path such as .../common.txt is host-shaped; it is a file
    # already vetted above, not a target.
    host_text = " ".join(
        a for i, a in enumerate(argv)
        if not (i and argv[i - 1] in _WORDLIST_FLAGS and a.startswith(_WORDLIST_ROOTS))
        and not (a.split("=", 1)[0] in _WORDLIST_FLAGS
                 and a.partition("=")[2].startswith(_WORDLIST_ROOTS)))
    hosts = extract_hosts(host_text)
    for h in positional_hosts:
        if h not in hosts:
            hosts.append(h)
    local = [h for h in hosts if h in _LOCAL_NAMES or h.endswith(".localhost")]
    if local:
        cmd.reason = "targets this machine: %s" % ", ".join(local)
        cmd.hosts = hosts
        return cmd
    out_of_scope = [h for h in hosts if not cfg.scope.allows(h)]
    if out_of_scope:
        cmd.reason = "out of scope: %s" % ", ".join(out_of_scope)
        cmd.hosts = hosts
        return cmd
    if not hosts and binary not in _NO_TARGET:
        # Nothing to check against scope means nothing proves it is in scope.
        cmd.reason = "names no in-scope host"
        return cmd

    cmd.argv = argv
    cmd.hosts = hosts
    cmd.tier = tier_of(argv)
    cmd.ok = True
    cmd.reason = "ready"
    return cmd


def rescrub(output: str, tool: str, redactor, cap: int = 8192) -> tuple[str | None, list[str]]:
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


def digest(output: str, rc: int | None) -> str:
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


def plan_followups(vetted: list[Command], auto_mode: str = "passive",
                   rate_cap_per_host: int = 5) -> tuple[list[Command], list[Command], list[Command]]:
    """Partition vetted commands into (auto_run, queued, refused) for one round.

    Default-deny all the way down:
      * a command that did not pass vet() is refused (allow-list / shell / scope);
      * an active-tier command is queued for consent, never auto-run;
      * a passive command auto-runs only when auto_mode == 'passive' and it is
        within the per-host rate cap - anything over the cap is queued, so
        'passive' can never become a slow scan by sheer volume.
    """
    auto: list[Command] = []
    queued: list[Command] = []
    refused: list[Command] = []
    per_host: dict[str, int] = {}
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


def collect(store, redaction_map=None) -> list[Command]:
    """Gather every AI-suggested command, un-redacted, in priority order.

    `redaction_map` is the run's RedactionMap. The model wrote these commands
    against pseudonyms, so without it they still carry [HOST-02] and will not
    resolve; putting the real values back is a purely local operation.
    """
    out: list[Command] = []
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
