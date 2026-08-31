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
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Sequence

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
    "seclists": ToolSpec("seclists", "wordlists ffuf needs to find unlinked endpoints",
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
    "interactsh-client": ToolSpec("interactsh-client",
                                  "out-of-band callbacks for blind SSRF/RCE/XXE",
                                  "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
                                  go="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"),
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
        cwd: Optional[str] = None) -> Proc:
    env.augment_path()
    _record(cmd)
    argv = bridge(cmd)
    try:
        p = subprocess.run(
            argv, input=stdin, capture_output=True, text=True,
            timeout=timeout, cwd=cwd,
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
                 stdin: str = "") -> Iterator[str]:
    """Yield stdout lines as they arrive. Keeps peak memory flat."""
    env.augment_path()
    _record(cmd)
    # A real file rather than a pipe for stderr: a chatty tool could otherwise
    # fill a pipe's OS buffer and deadlock while we're only draining stdout.
    stderr_buf = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
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
        for line in proc.stdout:
            line = line.strip()
            if line:
                yield line
    finally:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if proc.returncode:
            stderr_buf.seek(0)
            _record_failure(cmd, stderr_buf.read())
        stderr_buf.close()


def stream_json(cmd: Sequence[str], timeout: float = 900.0,
                stdin: str = "") -> Iterator[dict]:
    for line in stream_lines(cmd, timeout=timeout, stdin=stdin):
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


def _merge_ports(dest: Dict[str, List[Port]], src: Dict[str, List[Port]]) -> None:
    for host, ports in src.items():
        existing = dest.setdefault(host, [])
        seen = {(p.port, p.proto) for p in existing}
        for p in ports:
            if (p.port, p.proto) not in seen:
                existing.append(p)
                seen.add((p.port, p.proto))


def nmap_scan(hosts: List[str], port_spec: str, tune: Dict, timeout: float = 1800.0,
              out_dir: str = ".") -> Dict[str, List[Port]]:
    """Service/version scan. Returns host -> open ports."""
    base_args = [
        "nmap", "-Pn", "-sV", "--version-intensity", "5",
        "-T3" if tune.get("constrained") else "-T4",
        "--max-retries", "2", "--host-timeout", "20m",
        "--min-rate", str(tune.get("nmap_min_rate", 300)),
    ]

    def _run(port_args: List[str], xml_name: str) -> Dict[str, List[Port]]:
        xml_path = os.path.join(out_dir, "raw", xml_name)
        os.makedirs(os.path.dirname(xml_path), exist_ok=True)
        cmd = list(base_args) + ["-oX", xml_path] + port_args + hosts
        # nmap runs inside WSL under the bridge, so -oX must name a path it can see.
        cmd[cmd.index("-oX") + 1] = env.to_wsl_path(xml_path)
        run(cmd, timeout=timeout)
        if not os.path.exists(xml_path):
            return {}
        return parse_nmap_xml(xml_path)

    results = _run(nmap_port_args(port_spec), "nmap.xml")
    extra_args = nmap_extra_port_args(port_spec)
    if extra_args:
        _merge_ports(results, _run(extra_args, "nmap-extra.xml"))
    return results


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


def parse_nmap_xml(path: str) -> Dict[str, List[Port]]:
    out: Dict[str, List[Port]] = {}
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
        names = [h.get("name", "") for h in host_el.findall("hostnames/hostname")]
        key = names[0] if names and names[0] else addr
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
        if ports:
            out[key] = ports
    return out


# --------------------------------------------------------------------------
# naabu
# --------------------------------------------------------------------------


def naabu_scan(hosts: List[str], port_spec: str, tune: Dict,
               timeout: float = 900.0) -> Dict[str, List[int]]:
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
        for obj in stream_json(cmd, timeout=timeout, stdin="\n".join(hosts) + "\n"):
            h = obj.get("host") or obj.get("ip")
            p = obj.get("port")
            if h and p:
                found.setdefault(str(h), []).append(int(p))
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


def default_wordlist() -> Optional[str]:
    for path in (
        "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
    ):
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
