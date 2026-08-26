"""Environment detection: WSL quirks, resource budget, Burp discovery, tool paths.

Built for a common engagement setup: Kali under WSL2 on Windows 11, with Burp
running on the Windows side and a CPU/RAM-constrained VM underneath.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Directories Kali / Go installs drop binaries into but which are not always on
# PATH for non-login shells.
EXTRA_BIN_DIRS = [
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.local/bin"),
    "/usr/local/go/bin",
    "/usr/local/bin",
    "/usr/share/testssl.sh",
    "/opt/tools/bin",
]


# --------------------------------------------------------------------------
# Platform
# --------------------------------------------------------------------------


def is_windows() -> bool:
    return os.name == "nt"


# --------------------------------------------------------------------------
# Windows host -> WSL bridge
#
# assay itself is pure Python and runs fine on Windows, but every scanner it
# orchestrates is a Linux binary. Rather than requiring a second install inside
# WSL, a Windows-hosted run routes each external command through `wsl.exe`,
# so the tools stay where they already are.
#
# Two things make this work without special-casing every call site: every
# subprocess invocation in assay is an argv list (never shell=True), so the
# bridge only has to prepend a prefix; and the handful of flags that pass a
# filesystem path get translated with `wslpath`.
# --------------------------------------------------------------------------

_WSL_STATE: Dict[str, object] = {"checked": False, "distro": None, "ok": False}


def wsl_available() -> bool:
    """Is there a usable WSL distribution we can hand commands to?"""
    if not is_windows():
        return False
    if _WSL_STATE["checked"]:
        return bool(_WSL_STATE["ok"])
    _WSL_STATE["checked"] = True
    exe = shutil.which("wsl.exe") or shutil.which("wsl")
    if not exe:
        return False
    try:
        # -l -q lists installed distributions, one per line. WSL emits UTF-16.
        p = subprocess.run([exe, "-l", "-q"], capture_output=True, timeout=20)
        raw = p.stdout or b""
        text = raw.decode("utf-16-le", "ignore") if b"\x00" in raw[:40] \
            else raw.decode("utf-8", "ignore")
        distros = [d.strip() for d in text.splitlines() if d.strip()]
    except (OSError, subprocess.SubprocessError):
        return False
    if not distros:
        return False
    # Prefer a Kali/Debian-family distro, which is where the tools will be.
    preferred = next((d for d in distros
                      if any(k in d.lower() for k in ("kali", "debian", "ubuntu"))),
                     distros[0])
    _WSL_STATE["distro"] = preferred
    _WSL_STATE["ok"] = True
    return True


def wsl_distro() -> Optional[str]:
    wsl_available()
    d = _WSL_STATE.get("distro")
    return d if isinstance(d, str) else None


def wsl_prefix() -> List[str]:
    """Argv prefix that runs the rest of the command inside WSL."""
    distro = wsl_distro()
    if not distro:
        return []
    return ["wsl.exe", "-d", distro, "--"]


def use_wsl_bridge() -> bool:
    """True when external tools must be run through WSL rather than directly."""
    return is_windows() and wsl_available()


_PATH_CACHE: Dict[str, str] = {}


def to_wsl_path(path: str) -> str:
    r"""Translate a Windows path to the path WSL sees.

    C:\Users\me\out  ->  /mnt/c/Users/me/out
    """
    if not is_windows() or not path:
        return path
    if path in _PATH_CACHE:
        return _PATH_CACHE[path]
    translated = path
    try:
        p = subprocess.run(wsl_prefix() + ["wslpath", "-u", path],
                           capture_output=True, text=True, timeout=15)
        out = (p.stdout or "").strip()
        if out:
            translated = out
    except (OSError, subprocess.SubprocessError):
        # Fall back to the standard drive mapping.
        m = re.match(r"^([A-Za-z]):[\\/](.*)$", path)
        if m:
            translated = "/mnt/%s/%s" % (m.group(1).lower(),
                                         m.group(2).replace("\\", "/"))
    _PATH_CACHE[path] = translated
    return translated


def is_wsl() -> bool:
    try:
        with open("/proc/version", "r", encoding="utf-8", errors="replace") as fh:
            v = fh.read().lower()
        return "microsoft" in v or "wsl" in v
    except OSError:
        return False


def wsl_networking_mode() -> str:
    """'mirrored' when Windows localhost is reachable as 127.0.0.1, else 'nat'."""
    if not is_wsl():
        return "n/a"
    # In mirrored mode the WSL interface carries the Windows host's own IP and
    # the default route has no separate gateway host.
    return "mirrored" if os.path.exists("/proc/sys/net/ipv4/conf/loopback0") else "nat"


def windows_host_ip() -> Optional[str]:
    """Best-effort IP of the Windows host as seen from inside WSL2 (NAT mode)."""
    if not is_wsl():
        return None
    # WSL2 NAT: the default gateway is the Windows host.
    try:
        out = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=5,
        ).stdout
        for tok in out.split():
            if tok.count(".") == 3 and tok != "0.0.0.0":
                return tok
    except (OSError, subprocess.SubprocessError):
        pass
    # Fallback: resolv.conf nameserver is the host in default WSL2 configs.
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    return line.split()[1].strip()
    except (OSError, IndexError):
        pass
    return None


def open_in_browser(path: str) -> bool:
    """Open a local report. Under WSL this must hand off to Windows."""
    abspath = os.path.abspath(path)
    candidates: List[List[str]] = []
    if is_wsl():
        candidates.append(["wslview", abspath])
        try:
            win = subprocess.run(
                ["wslpath", "-w", abspath], capture_output=True, text=True, timeout=5
            ).stdout.strip()
            if win:
                candidates.append(["explorer.exe", win])
        except (OSError, subprocess.SubprocessError):
            pass
    candidates.append(["xdg-open", abspath])
    for cmd in candidates:
        if shutil.which(cmd[0]):
            try:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
            except OSError:
                continue
    return False


# --------------------------------------------------------------------------
# Resource budget -- this VM is small, so pace ourselves
# --------------------------------------------------------------------------


@dataclass
class Resources:
    cpus: int = 2
    mem_total_mb: int = 2048
    mem_avail_mb: int = 1024
    wsl: bool = False

    @property
    def constrained(self) -> bool:
        return self.cpus <= 2 or self.mem_avail_mb < 2048


def resources() -> Resources:
    r = Resources(cpus=os.cpu_count() or 2, wsl=is_wsl())
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    r.mem_total_mb = int(line.split()[1]) // 1024
                elif line.startswith("MemAvailable:"):
                    r.mem_avail_mb = int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return r


def autotune(res: Optional[Resources] = None) -> Dict[str, object]:
    """Pick concurrency/rate that will not swap a 2-4 GB VM into the ground.

    Returns knobs consumed by Config and by the external tool wrappers. Every
    value here is a ceiling; the user can always override on the CLI.
    """
    res = res or resources()
    # Roughly 40 MB of headroom per in-flight worker once TLS buffers are counted.
    by_mem = max(2, int(res.mem_avail_mb / 60))
    by_cpu = max(2, res.cpus * 4)
    workers = max(2, min(by_mem, by_cpu, 24))
    return {
        "concurrency": workers,
        "rate": float(min(60, workers * 3)),
        # External scanners get their own, tighter budget because they fork.
        "nuclei_concurrency": max(4, min(workers, 12)),
        "nuclei_rate": max(20, min(120, workers * 8)),
        "nuclei_bulk": max(4, min(workers, 10)),
        "nmap_min_rate": 300 if res.constrained else 1000,
        "nmap_parallel": "--min-hostgroup 16" if res.constrained else "--min-hostgroup 64",
        "ffuf_threads": max(4, min(workers, 20)),
        "constrained": res.constrained,
        "cpus": res.cpus,
        "mem_avail_mb": res.mem_avail_mb,
    }


# --------------------------------------------------------------------------
# Burp discovery
# --------------------------------------------------------------------------


def _port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def burp_candidates() -> List[str]:
    hosts = ["127.0.0.1"]
    hip = windows_host_ip()
    if hip and hip not in hosts:
        hosts.append(hip)
    return hosts


def find_burp_proxy(port: int = 8080) -> Optional[str]:
    """Locate a reachable Burp proxy listener.

    Under WSL2 NAT, Burp on Windows listening on 127.0.0.1 is NOT reachable;
    it must bind all interfaces (or WSL must run in mirrored networking mode).
    """
    for host in burp_candidates():
        if _port_open(host, port):
            return "http://%s:%d" % (host, port)
    return None


def find_burp_api(port: int = 1337) -> Optional[str]:
    for host in burp_candidates():
        if _port_open(host, port):
            return "http://%s:%d" % (host, port)
    return None


def burp_hint() -> str:
    """Actionable guidance when Burp cannot be reached from WSL."""
    if not is_wsl():
        return "Start Burp and enable the Proxy listener on 127.0.0.1:8080."
    hip = windows_host_ip() or "<windows-ip>"
    return (
        "Burp appears to be on the Windows side. Either:\n"
        "  a) set WSL to mirrored networking - add to C:\\Users\\<you>\\.wslconfig:\n"
        "       [wsl2]\n       networkingMode=mirrored\n"
        "     then 'wsl --shutdown' and reopen; Burp on 127.0.0.1:8080 then just works; or\n"
        "  b) in Burp -> Proxy -> Proxy settings, bind the listener to 'All interfaces',\n"
        "     allow it through Windows Defender Firewall, and run:\n"
        "       assay scan --burp http://%s:8080 ..." % hip
    )


# --------------------------------------------------------------------------
# External tool discovery
# --------------------------------------------------------------------------


def wsl_gateway_ip() -> Optional[str]:
    """The address WSL uses to reach the Windows host (NAT mode default route)."""
    if not use_wsl_bridge():
        return None
    cached = _WSL_STATE.get("gateway")
    if isinstance(cached, str):
        return cached
    try:
        p = subprocess.run(wsl_prefix() + ["sh", "-lc",
                                           "ip route show default | awk '{print $3; exit}'"],
                           capture_output=True, text=True, timeout=20)
        ip = (p.stdout or "").strip()
    except (OSError, subprocess.SubprocessError):
        ip = ""
    if ip.count(".") == 3:
        _WSL_STATE["gateway"] = ip
        return ip
    return None


def proxy_for_tools(proxy: Optional[str]) -> Optional[str]:
    """Rewrite a loopback proxy so a tool running inside WSL can reach it.

    assay's own requests run on the Windows host, where Burp on 127.0.0.1 is
    directly reachable. The scanners run inside WSL, where 127.0.0.1 is the
    WSL VM itself - a different machine. Under mirrored networking the two
    coincide; under the default NAT they do not, and the tools would silently
    bypass the proxy. Point them at the Windows host explicitly.
    """
    if not proxy or not use_wsl_bridge():
        return proxy
    m = re.match(r"^(\w+://)(127\.0\.0\.1|localhost)(:\d+)?(.*)$", proxy, re.I)
    if not m:
        return proxy
    gateway = wsl_gateway_ip()
    if not gateway:
        return proxy
    return "%s%s%s%s" % (m.group(1), gateway, m.group(3) or "", m.group(4) or "")


_WSL_WHICH: Dict[str, Optional[str]] = {}


def wsl_which_many(names: List[str]) -> Dict[str, Optional[str]]:
    """Resolve several tools inside WSL in one call.

    One wsl.exe spawn costs ~200ms, so resolving seventeen tools individually
    would add several seconds to every startup. `which` accepts multiple
    arguments and prints a line per hit.
    """
    if not use_wsl_bridge() or not names:
        return {n: None for n in names}
    missing = [n for n in names if n not in _WSL_WHICH]
    if missing:
        found: Dict[str, Optional[str]] = {n: None for n in missing}
        try:
            # -lc so the login shell puts ~/go/bin and friends on PATH.
            script = "which " + " ".join(missing) + " 2>/dev/null"
            p = subprocess.run(wsl_prefix() + ["sh", "-lc", script],
                               capture_output=True, text=True, timeout=45)
            for line in (p.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                base = line.rsplit("/", 1)[-1]
                if base in found:
                    found[base] = line
        except (OSError, subprocess.SubprocessError):
            pass
        _WSL_WHICH.update(found)
    return {n: _WSL_WHICH.get(n) for n in names}


def which(name: str) -> Optional[str]:
    if use_wsl_bridge():
        return wsl_which_many([name]).get(name)
    path = shutil.which(name)
    if path:
        return path
    for d in EXTRA_BIN_DIRS:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def augment_path() -> None:
    """Make Go-installed tools visible to subprocesses."""
    parts = os.environ.get("PATH", "").split(os.pathsep)
    for d in EXTRA_BIN_DIRS:
        if os.path.isdir(d) and d not in parts:
            parts.append(d)
    os.environ["PATH"] = os.pathsep.join(parts)
