"""Out-of-band interaction capture for blind vulnerability classes.

Blind SSRF, blind XXE and blind command injection produce no change in the
response - the only evidence is a callback. Two backends:

  interactsh   spawns interactsh-client, reads its payload domain, and polls
               its JSON output for interactions. Fully automatic.
  ledger       when no client is available, assay still emits uniquely-labelled
               payloads and writes a ledger mapping each payload to the exact
               request that carried it. Point them at a Burp Collaborator
               domain with --oob-domain and correlate by hand.

The ledger mode matters: most researchers already have Collaborator open, and
a payload that was fired but never correlated is still far more useful than a
check that never ran.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from assay import env
from assay.net import rand_token


@dataclass
class Interaction:
    payload_id: str
    protocol: str
    remote_addr: str
    raw: str
    at: float = field(default_factory=time.time)


class OOBSession:
    """Issues correlatable payloads and, where possible, observes the callbacks."""

    def __init__(self, out_dir: str, domain: Optional[str] = None,
                 enabled: bool = True) -> None:
        self.out_dir = out_dir
        self.mode = "off"
        self.domain: Optional[str] = domain
        self.enabled = enabled
        self._proc: Optional[subprocess.Popen] = None
        self._interactions: Dict[str, Interaction] = {}
        self._ledger: Dict[str, str] = {}      # payload id -> what carried it
        self._lock = threading.Lock()
        self._reader: Optional[threading.Thread] = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> str:
        """Returns a human-readable description of the active mode."""
        if not self.enabled:
            return "disabled"
        if self.domain:
            self.mode = "ledger"
            return "ledger mode against %s (correlate manually)" % self.domain
        if not env.which("interactsh-client"):
            self.mode = "off"
            return ("no OOB backend - install interactsh-client, or pass "
                    "--oob-domain with a Burp Collaborator payload domain")
        try:
            self._proc = subprocess.Popen(
                ["interactsh-client", "-json", "-v"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except OSError as exc:
            self.mode = "off"
            return "interactsh-client failed to start: %s" % exc

        domain = self._await_domain(timeout=20.0)
        if not domain:
            self.stop()
            self.mode = "off"
            return "interactsh-client did not report a payload domain"
        self.domain = domain
        self.mode = "interactsh"
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        return "interactsh via %s" % domain

    def _await_domain(self, timeout: float) -> Optional[str]:
        """The client prints its assigned domain before any interactions."""
        if not self._proc or not self._proc.stdout:
            return None
        deadline = time.time() + timeout
        rx = re.compile(r"\b([a-z0-9]{20,}\.[a-z0-9.-]*oast\.[a-z]+|"
                        r"[a-z0-9]{20,}\.interact\.sh)\b", re.I)
        while time.time() < deadline:
            line = self._proc.stdout.readline()
            if not line:
                return None
            m = rx.search(line)
            if m:
                return m.group(1)
        return None

    def _read_loop(self) -> None:
        if not self._proc or not self._proc.stdout:
            return
        for line in self._proc.stdout:
            line = line.strip()
            if not line:
                continue
            obj = None
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except ValueError:
                    obj = None
            full = (obj or {}).get("full-id") or (obj or {}).get("unique-id") or ""
            protocol = (obj or {}).get("protocol", "") or "unknown"
            remote = (obj or {}).get("remote-address", "") or ""
            if not full:
                m = re.search(r"\b([a-z0-9]{6,})\." + re.escape(self.domain or ""),
                              line, re.I)
                full = m.group(1) if m else ""
                if not full:
                    continue
            with self._lock:
                for pid in list(self._ledger):
                    if pid.lower() in full.lower():
                        self._interactions[pid] = Interaction(
                            payload_id=pid, protocol=protocol,
                            remote_addr=remote, raw=line[:600])
                        break

    def stop(self) -> None:
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                try:
                    self._proc.kill()
                except OSError:
                    pass
            self._proc = None
        self.flush_ledger()

    # -- payloads ----------------------------------------------------------
    @property
    def active(self) -> bool:
        return self.mode in ("interactsh", "ledger")

    def payload(self, label: str) -> Tuple[str, str]:
        """Mint a correlatable hostname. Returns (payload_id, hostname)."""
        pid = "sf%s" % rand_token(8)
        host = "%s.%s" % (pid, self.domain) if self.domain else pid
        with self._lock:
            self._ledger[pid] = label
        return pid, host

    def seen(self, payload_id: str, wait: float = 0.0) -> Optional[Interaction]:
        """Was a callback observed? Only ever true in interactsh mode.

        In ledger mode nothing can ever arrive, so waiting is pure latency -
        at ~16 probes per host that would add a minute of dead time to a scan
        for no possible result.
        """
        if self.mode != "interactsh":
            return None
        deadline = time.time() + wait
        while True:
            with self._lock:
                hit = self._interactions.get(payload_id)
            if hit or time.time() >= deadline:
                return hit
            time.sleep(1.0)

    def flush_ledger(self) -> Optional[str]:
        """Write payload -> carrier so ledger-mode hits can be traced back."""
        with self._lock:
            if not self._ledger:
                return None
            rows = sorted(self._ledger.items())
            hits = dict(self._interactions)
        path = os.path.join(self.out_dir, "oob-payloads.txt")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# assay out-of-band payload ledger\n")
                fh.write("# mode: %s   domain: %s\n" % (self.mode, self.domain or "-"))
                fh.write("# Any of these appearing in your collaborator is a "
                         "confirmed callback for the request shown.\n\n")
                for pid, label in rows:
                    mark = "HIT " if pid in hits else "    "
                    fh.write("%s%s.%s\t%s\n" % (mark, pid, self.domain or "", label))
        except OSError:
            return None
        return path

    def stats(self) -> Tuple[int, int]:
        with self._lock:
            return len(self._ledger), len(self._interactions)
