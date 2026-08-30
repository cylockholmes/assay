"""A replayable record of everything assay did.

Two problems this solves. First, a finding is only useful if you can reproduce
it, and reproducing it by hand from a report is slower than re-running the
exact request. Second, on an engagement you may need to show precisely what you
sent and when - "the scanner did it" is not an answer.

Two files are written side by side:

  activity.log  every action with a timestamp, in the order it happened.
  replay.sh     the same actions as runnable commands, deduplicated.

The journal never records response bodies. It is a record of what was sent, not
what came back; the findings carry the evidence.
"""

from __future__ import annotations

import os
import shlex
import threading
import time
from typing import Dict, List, Optional, Set

# Header values that are secrets. They are replaced with a shell variable so
# the replay stays runnable without writing the credential to disk - an
# executable file full of engagement credentials is exactly the artefact you
# do not want sitting in an output folder.
SECRET_HEADERS = {
    "authorization": "ASSAY_AUTH",
    "proxy-authorization": "ASSAY_PROXY_AUTH",
    "cookie": "ASSAY_COOKIE",
    "x-api-key": "ASSAY_API_KEY",
    "x-auth-token": "ASSAY_AUTH_TOKEN",
}

HEADER = """#!/usr/bin/env bash
# Replay of an assay run - every request and command it issued, in order.
#
#   started : %s
#   targets : %s
#   profile : %s
#
# Review before running. These are the same requests assay already made, so
# re-running them repeats that traffic against the target.
#
# Credentials are NOT stored here. Where a request carried one, the value is
# referenced as a shell variable; export it before running if you need the
# authenticated replay:
#
#   export ASSAY_AUTH='Basic ...'      # or ASSAY_COOKIE, ASSAY_API_KEY
#
set -u
"""


class Journal:
    def __init__(self, out_dir: str, enabled: bool = True) -> None:
        self.enabled = enabled
        self.out_dir = out_dir
        self.log_path = os.path.join(out_dir, "activity.log")
        self.replay_path = os.path.join(out_dir, "replay.sh")
        self._lock = threading.Lock()
        self._log: Optional[object] = None
        self._seen: Set[str] = set()
        self._replay: List[str] = []
        self.requests = 0
        self.commands = 0
        self.started = time.time()

    # -- lifecycle ---------------------------------------------------------
    def open(self, targets: List[str], profile: str) -> None:
        if not self.enabled:
            return
        os.makedirs(self.out_dir, exist_ok=True)
        self._log = open(self.log_path, "w", encoding="utf-8", buffering=1)
        self._write("# assay activity log - started %s"
                    % time.strftime("%Y-%m-%d %H:%M:%S"))
        self._write("# targets: %s" % ", ".join(targets[:20]))
        self._write("# profile: %s" % profile)
        self._replay.append(HEADER % (time.strftime("%Y-%m-%d %H:%M:%S"),
                                      " ".join(targets[:20]), profile))

    def close(self) -> None:
        if not self.enabled:
            return
        try:
            if self._log:
                self._write("# finished %s - %d request(s), %d command(s)"
                            % (time.strftime("%Y-%m-%d %H:%M:%S"),
                               self.requests, self.commands))
                self._log.close()  # type: ignore[union-attr]
                self._log = None
            with open(self.replay_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(self._replay) + "\n")
            # Executable, but owner-only: it records every target URL touched.
            os.chmod(self.replay_path, 0o700)
            try:
                os.chmod(self.log_path, 0o600)
            except OSError:
                pass
        except OSError:
            pass

    # -- recording ---------------------------------------------------------
    def _write(self, line: str) -> None:
        if self._log is None:
            return
        try:
            self._log.write(line + "\n")  # type: ignore[union-attr]
        except (OSError, ValueError):
            pass

    def _stamp(self) -> str:
        return "%7.2fs" % (time.time() - self.started)

    def request(self, method: str, url: str, headers: Optional[Dict] = None,
                body: str = "", module: str = "") -> None:
        """Record one HTTP request as a curl command."""
        if not self.enabled:
            return
        with self._lock:
            self.requests += 1
            self._write("%s  %-6s %s%s"
                        % (self._stamp(), method, url,
                           "   [%s]" % module if module else ""))
            cmd = self._curl(method, url, headers or {}, body)
            if cmd not in self._seen:
                self._seen.add(cmd)
                self._replay.append(cmd)

    def command(self, argv: List[str], module: str = "") -> None:
        """Record one external tool invocation."""
        if not self.enabled:
            return
        with self._lock:
            self.commands += 1
            line = " ".join(shlex.quote(a) for a in argv)
            self._write("%s  EXEC   %s%s"
                        % (self._stamp(), line,
                           "   [%s]" % module if module else ""))
            if line not in self._seen:
                self._seen.add(line)
                self._replay.append(line)

    def note(self, text: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._write("%s  NOTE   %s" % (self._stamp(), text))

    @staticmethod
    def _curl(method: str, url: str, headers: Dict, body: str) -> str:
        parts = ["curl -sSik"]
        if method != "GET":
            parts.append("-X %s" % method)
        skip = {"accept-encoding", "connection", "content-length", "host",
                "accept", "accept-language", "user-agent"}
        for k, v in headers.items():
            kl = k.lower()
            if kl in skip:
                continue
            var = SECRET_HEADERS.get(kl)
            if var:
                # Reference, never the value.
                parts.append('-H "%s: ${%s:-}"' % (k, var))
                continue
            parts.append("-H %s" % shlex.quote("%s: %s" % (k, v)))
        if body:
            parts.append("--data-raw %s" % shlex.quote(body[:400]))
        parts.append(shlex.quote(url))
        return " ".join(parts)
