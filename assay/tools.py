"""Wrappers around the external scanners assay orchestrates.

Everything here is optional: assay degrades to its own pure-Python checks when a
binary is missing, and tells the user exactly what they are losing. Output is
streamed line by line rather than buffered, which matters on a small VM where
a nuclei run against a /24 can otherwise produce hundreds of MB.
"""

from __future__ import annotations

import json
import os
import shutil
import re
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Sequence

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

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out

    def cmdline(self) -> str:
        return " ".join(self.cmd)


# Set by the engine so external commands land in the run journal too.
JOURNAL = None


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
    try:
        p = subprocess.run(
            argv, input=stdin, capture_output=True, text=True,
            timeout=timeout, cwd=cwd, env=proc_env,
        )
        if p.returncode != 0:
            _record_failure(cmd, p.stderr)
        return Proc(rc=p.returncode, out=p.stdout, err=p.stderr, cmd=list(cmd))
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return Proc(rc=-1, out=out, err="timeout after %ss" % timeout,
                    cmd=list(cmd), timed_out=True)
    except (OSError, ValueError) as exc:
        _record_failure(cmd, str(exc))
        return Proc(rc=-1, out="", err=str(exc), cmd=list(cmd))


def stream_lines(cmd: Sequence[str], timeout: float = 900.0,
                 stdin: str = "",
                 on_timeout: Optional[Callable[[float], None]] = None
                 ) -> Iterator[str]:
    """Yield stdout lines as they arrive. Keeps peak memory flat."""
    env.augment_path()
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
        return
    if stdin and proc.stdin:
        try:
            proc.stdin.write(stdin)
            proc.stdin.close()
        except OSError:
            pass
    try:
        assert proc.stdout is not None
        # `timeout` was accepted and never enforced: only the finally's
        # proc.wait(10) bounded anything, so a tool that ran long ran forever.
        # Checked per line, so it bounds a tool that is still talking - a
        # process that goes completely silent still blocks on the read below,
        # which needs a watchdog thread rather than a deadline.
        deadline = time.time() + timeout
        for line in proc.stdout:
            line = line.strip()
            if line:
                yield line
            if time.time() > deadline:
                # The caller has already consumed everything up to here and
                # cannot otherwise tell a finished tool from a cut-off one, so
                # say so rather than letting partial output pass as complete.
                timed_out = True
                _record_failure(cmd, "timed out after %.0fs" % timeout)
                proc.kill()
                if on_timeout:
                    on_timeout(timeout)
                break
    finally:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        # A kill of our own is recorded above; the returncode it produces is
        # the same event, not a second failure.
        if proc.returncode and not timed_out:
            stderr_buf.seek(0)
            _record_failure(cmd, stderr_buf.read())
        stderr_buf.close()


def stream_json(cmd: Sequence[str], timeout: float = 900.0,
                stdin: str = "",
                on_timeout: Optional[Callable[[float], None]] = None
                ) -> Iterator[dict]:
    for line in stream_lines(cmd, timeout=timeout, stdin=stdin,
                             on_timeout=on_timeout):
        if not line.startswith("{"):
            continue
        try:
            yield json.loads(line)
        except ValueError:
            continue


# --------------------------------------------------------------------------
# Proxy plumbing -- route external tools through Burp too
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


def proxy_args(tool: str, proxy: Optional[str]) -> List[str]:
    # Under the Windows->WSL bridge a loopback proxy has to be rewritten to the
    # Windows host address, or the tool proxies to the WSL VM and misses Burp.
    proxy = env.proxy_for_tools(proxy)
    if not proxy:
        return []
    if tool in ("httpx", "nuclei", "katana"):
        return ["-proxy", proxy]
    if tool == "ffuf":
        return ["-x", proxy]
    if tool == "gowitness":
        return ["--proxy", proxy]
    return []


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


def nmap_scan(hosts: List[str], port_spec: str, tune: Dict, timeout: float = 1800.0,
              out_dir: str = ".", xml_prefix: str = "nmap",
              on_progress: Optional[Callable[[str], None]] = None
              ) -> Dict[str, NmapHost]:
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
    base_args = [
        "nmap", "-Pn", "-sV", "--version-intensity", "5",
        "-T3" if tune.get("constrained") else "-T4",
        "--max-retries", "2", "--host-timeout", "20m",
        "--min-rate", str(tune.get("nmap_min_rate", 300)),
    ]

    def _run(port_args: List[str], xml_name: str) -> Dict[str, NmapHost]:
        xml_path = os.path.join(out_dir, "raw", xml_name)
        os.makedirs(os.path.dirname(xml_path), exist_ok=True)
        cmd = ([base_args[0], "--stats-every", "10s"] + base_args[1:]
               + ["-oX", xml_path] + port_args + hosts)
        # nmap runs inside WSL under the bridge, so -oX must name a path it can see.
        cmd[cmd.index("-oX") + 1] = env.to_wsl_path(xml_path)
        # Always streamed: the results come from the XML either way, so the
        # only question is whether the wait is spent silently. --stats-every
        # makes nmap narrate it, and nothing downstream cares if no one reads.
        cut = ((lambda t: on_progress("scan hit its %.0fs limit - results are "
                                      "partial" % t)) if on_progress else None)
        for line in stream_lines(cmd, timeout=timeout, on_timeout=cut):
            msg = nmap_stat_line(line) if on_progress else None
            if msg:
                on_progress(msg)
        if not os.path.exists(xml_path):
            return {}
        return parse_nmap_xml(xml_path)

    results = _run(nmap_port_args(port_spec), "%s.xml" % xml_prefix)
    extra_args = nmap_extra_port_args(port_spec)
    if extra_args:
        _merge_nmap_hosts(results, _run(extra_args, "%s-extra.xml" % xml_prefix))
    return results


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


def parse_nmap_xml(path: str) -> Dict[str, NmapHost]:
    """Parse nmap's XML into scanned address -> NmapHost.

    Keyed by the numeric address nmap scanned (always present - nmap resolves
    a hostname target to an address before it ever probes a port), not by a
    reverse-DNS name. See nmap_scan()'s docstring for why that distinction
    matters.
    """
    out: Dict[str, NmapHost] = {}
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError):
        return out
    for host_el in tree.getroot().findall("host"):
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
            if state_el is None or state_el.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append(Port(
                port=int(p.get("portid", "0")),
                proto=p.get("protocol", "tcp"),
                state="open",
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


# --------------------------------------------------------------------------
# naabu
# --------------------------------------------------------------------------


def naabu_scan(hosts: List[str], port_spec: str, tune: Dict,
               timeout: float = 900.0,
               on_progress: Optional[Callable[[str], None]] = None
               ) -> Dict[str, List[int]]:
    # Kept as two separate passes (base + extra), mirroring nmap_scan: relying
    # on naabu to union -top-ports with a -p list in one invocation is
    # unverified, and nmap's equivalent combination turned out to be an
    # intersection (nmap/nmap#447), silently dropping the extra ports.
    base, _, extra = port_spec.partition("+")
    spec = {"top-100": ["-top-ports", "100"],
            "top-1000": ["-top-ports", "1000"],
            "all": ["-p", "-"]}.get(base, ["-p", base])

    def _run(port_args: List[str]) -> Dict[str, List[int]]:
        # No -list/-host flag: naabu reads targets from stdin by default when
        # neither is given. "-list -" does NOT mean "read stdin" here -- naabu
        # 2.4.0 takes it literally and tries to open a file named "-", failing
        # with "[FTL] Could not run enumeration: open -: no such file or
        # directory" on stderr, which stream_json() never surfaces since it
        # only looks for JSON on stdout. That silently turned every naabu scan
        # into a no-op, and _stage_portscan() then trusted the empty result
        # and returned without ever falling back to nmap.
        cmd = ["naabu", "-silent", "-json", "-rate", str(tune.get("nmap_min_rate", 300)),
               "-c", str(tune.get("concurrency", 10))] + port_args
        found: Dict[str, List[int]] = {}
        # naabu only ever emits a line for a port it found open, so there is no
        # honest "N of 384 swept" to report - what it can say is what has turned
        # up so far, which is enough to tell a working sweep from a wedged one.
        last = 0.0
        cut = ((lambda t: on_progress("sweep hit its %.0fs limit - results are "
                                      "partial" % t)) if on_progress else None)
        for obj in stream_json(cmd, timeout=timeout,
                               stdin="\n".join(hosts) + "\n", on_timeout=cut):
            h = obj.get("host") or obj.get("ip")
            p = obj.get("port")
            if h and p:
                found.setdefault(str(h), []).append(int(p))
                if on_progress and time.time() - last >= 2.0:
                    last = time.time()
                    on_progress("%d open port(s) on %d host(s) so far"
                                % (sum(len(v) for v in found.values()), len(found)))
        return found

    found = _run(spec)
    if extra:
        for h, ports in _run(["-p", extra]).items():
            existing = found.setdefault(h, [])
            for p in ports:
                if p not in existing:
                    existing.append(p)
    return found


# --------------------------------------------------------------------------
# httpx
# --------------------------------------------------------------------------


def httpx_probe(targets: List[str], tune: Dict, proxy: Optional[str] = None,
                timeout: float = 600.0,
                headers: Optional[Dict[str, str]] = None) -> Iterator[dict]:
    cmd = [
        "httpx", "-silent", "-json", "-no-color",
        "-status-code", "-title", "-tech-detect", "-web-server",
        "-content-length", "-favicon", "-tls-grab", "-location", "-word-count",
        "-timeout", "10", "-retries", "1",
        "-threads", str(tune.get("concurrency", 10)),
        "-rate-limit", str(int(tune.get("rate", 30))),
        "-list", "-",
    ] + proxy_args("httpx", proxy) + header_args("httpx", headers)
    return stream_json(cmd, timeout=timeout, stdin="\n".join(targets) + "\n")


# --------------------------------------------------------------------------
# nuclei
# --------------------------------------------------------------------------


def nuclei_scan(urls: List[str], severity: str, tune: Dict,
                proxy: Optional[str] = None, extra_tags: str = "",
                timeout: float = 3600.0,
                headers: Optional[Dict[str, str]] = None) -> Iterator[dict]:
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
        "-list", "-",
    ]
    if extra_tags:
        cmd += ["-tags", extra_tags]
    cmd += proxy_args("nuclei", proxy) + header_args("nuclei", headers)
    return stream_json(cmd, timeout=timeout, stdin="\n".join(urls) + "\n")


def nuclei_templates_present() -> bool:
    return os.path.isdir(os.path.expanduser("~/.local/nuclei-templates")) or os.path.isdir(
        os.path.expanduser("~/nuclei-templates")
    )


# --------------------------------------------------------------------------
# katana
# --------------------------------------------------------------------------


def katana_crawl(urls: List[str], depth: int, tune: Dict, max_urls: int,
                 proxy: Optional[str] = None, timeout: float = 600.0,
                 headers: Optional[Dict[str, str]] = None) -> List[dict]:
    cmd = [
        "katana", "-silent", "-jsonl", "-no-color",
        "-d", str(depth), "-c", str(min(tune.get("concurrency", 10), 10)),
        "-rate-limit", str(int(tune.get("rate", 30))),
        "-timeout", "10", "-jc", "-kf", "robotstxt,sitemapxml",
        "-ef", "png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico,mp4,pdf",
        "-list", "-",
    ] + proxy_args("katana", proxy) + header_args("katana", headers)
    out: List[dict] = []
    for obj in stream_json(cmd, timeout=timeout, stdin="\n".join(urls) + "\n"):
        out.append(obj)
        if len(out) >= max_urls:
            break
    return out


# --------------------------------------------------------------------------
# dnsx / subfinder
# --------------------------------------------------------------------------



def dnsx_resolve(hosts: List[str], timeout: float = 300.0) -> Iterator[dict]:
    cmd = ["dnsx", "-silent", "-json", "-a", "-cname", "-resp", "-list", "-"]
    return stream_json(cmd, timeout=timeout, stdin="\n".join(hosts) + "\n")


def subfinder_enum(domain: str, timeout: float = 300.0) -> List[str]:
    cmd = ["subfinder", "-silent", "-all", "-d", domain]
    return [l for l in stream_lines(cmd, timeout=timeout) if l]


# --------------------------------------------------------------------------
# ffuf
# --------------------------------------------------------------------------


def ffuf_discover(url: str, wordlist: str, tune: Dict, proxy: Optional[str] = None,
                  extensions: str = "", timeout: float = 600.0) -> List[dict]:
    """Content discovery with ffuf's own auto-calibration to suppress soft-404s."""
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    base = url.rstrip("/")
    cmd = [
        "ffuf", "-u", base + "/FUZZ", "-w", wordlist,
        "-ac", "-acc", "-mc", "200,201,204,301,302,307,401,403,405,500",
        "-fs", "0", "-t", str(tune.get("ffuf_threads", 10)),
        "-rate", str(int(tune.get("rate", 30))),
        "-timeout", "8", "-s", "-of", "json",
        "-o", env.to_wsl_path(tmp.name), "-noninteractive",
    ]
    if extensions:
        cmd += ["-e", extensions]
    cmd += proxy_args("ffuf", proxy)
    run(cmd, timeout=timeout)
    try:
        with open(tmp.name, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data.get("results", [])
    except (OSError, ValueError):
        return []
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


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
    cmd = ["arjun", "-u", url, "-oJ", tmp.name, "-q",
           "-t", str(min(tune.get("ffuf_threads", 8), 12)),
           "--stable"]
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
