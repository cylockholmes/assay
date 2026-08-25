"""Environment detection: WSL quirks, resource budget, Burp discovery, tool paths.

Built for a common engagement setup: Kali under WSL2 on Windows 11, with Burp
running on the Windows side and a CPU/RAM-constrained VM underneath.
"""

from __future__ import annotations

import os
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


def which(name: str) -> Optional[str]:
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
