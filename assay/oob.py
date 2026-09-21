"""Out-of-band payload correlation for blind vulnerability classes.

Blind SSRF, blind XXE and blind command injection produce no change in the
response - the only evidence is a callback, which arrives somewhere assay is
not. assay runs no listener of its own. It emits uniquely-labelled payloads
against a collaborator domain you supply with --oob-domain, and writes a
ledger mapping each payload to the exact request that carried it.

Correlation is yours to do: anything from the ledger showing up in your
collaborator is a confirmed callback for the request named beside it. That
trade is deliberate - most researchers already have Collaborator open, and a
payload that was fired but needs correlating by hand is still far more useful
than a check that never ran.
"""

from __future__ import annotations

import os
import threading
from typing import Dict, Optional, Tuple

from assay.net import rand_token


class OOBSession:
    """Issues correlatable payloads and records what carried each one."""

    def __init__(self, out_dir: str, domain: Optional[str] = None,
                 enabled: bool = True) -> None:
        self.out_dir = out_dir
        self.mode = "off"
        self.domain: Optional[str] = domain
        self.enabled = enabled
        self._ledger: Dict[str, str] = {}      # payload id -> what carried it
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> str:
        """Returns a human-readable description of the active mode."""
        if not self.enabled:
            return "disabled"
        if not self.domain:
            self.mode = "off"
            return ("no OOB domain - pass --oob-domain with a Burp Collaborator "
                    "payload domain to fire blind payloads")
        self.mode = "ledger"
        return "ledger mode against %s (correlate manually)" % self.domain

    def stop(self) -> None:
        self.flush_ledger()

    # -- payloads ----------------------------------------------------------
    @property
    def active(self) -> bool:
        return self.mode == "ledger"

    def payload(self, label: str) -> Tuple[str, str]:
        """Mint a correlatable hostname. Returns (payload_id, hostname)."""
        pid = "sf%s" % rand_token(8)
        host = "%s.%s" % (pid, self.domain) if self.domain else pid
        with self._lock:
            self._ledger[pid] = label
        return pid, host

    def flush_ledger(self) -> Optional[str]:
        """Write payload -> carrier so a callback can be traced back."""
        with self._lock:
            if not self._ledger:
                return None
            rows = sorted(self._ledger.items())
        path = os.path.join(self.out_dir, "oob-payloads.txt")
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# assay out-of-band payload ledger\n")
                fh.write("# mode: %s   domain: %s\n" % (self.mode, self.domain or "-"))
                fh.write("# Any of these appearing in your collaborator is a "
                         "confirmed callback for the request shown.\n\n")
                for pid, label in rows:
                    fh.write("%s.%s\t%s\n" % (pid, self.domain or "", label))
        except OSError:
            return None
        return path

    def fired(self) -> int:
        with self._lock:
            return len(self._ledger)
