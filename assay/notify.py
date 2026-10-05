"""Slack notifications for long, unattended scans.

A deep scan can run for hours; the operator starts it and walks away. These
pings bring them back at the two moments that matter: the scan has finished, or
it has stopped to ask a question and cannot make progress until it is answered.

Opt-in and best-effort. Nothing is sent unless a Slack incoming-webhook URL is
configured (`--slack-webhook`, or the ASSAY_SLACK_WEBHOOK environment
variable). A webhook that is slow, wrong or down must never delay or break a
scan, so the POST has a short timeout and every failure is swallowed - the only
signal back to the caller is the bool return, for a caller that wants to log it.

An incoming webhook posts to one preconfigured channel and needs no token or
OAuth scopes, which suits a CLI run from a researcher's own machine. The
payload is the webhook's simplest form, `{"text": ...}`, with Slack mrkdwn.
"""

from __future__ import annotations

import os
from typing import Optional

import requests

ENV_WEBHOOK = "ASSAY_SLACK_WEBHOOK"


class Notifier:
    """Sends the two scan-lifecycle pings, or quietly does nothing when no
    webhook is configured."""

    def __init__(self, webhook: str = "", label: str = "assay",
                 timeout: float = 10.0):
        self.webhook = (webhook or os.environ.get(ENV_WEBHOOK) or "").strip()
        self.label = label or "assay"
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.webhook)

    def _post(self, text: str) -> bool:
        if not self.enabled:
            return False
        try:
            r = requests.post(self.webhook, json={"text": text},
                              timeout=self.timeout)
            return bool(getattr(r, "ok", False))
        except Exception:
            # A notification is never worth taking a scan down for.
            return False

    def scan_done(self, summary: str = "") -> bool:
        """The scan has finished. `summary` is a short human line of results."""
        text = ":white_check_mark: *%s* scan complete" % self.label
        if summary:
            text += "\n%s" % summary
        return self._post(text)

    def needs_input(self, question: str) -> bool:
        """The scan has paused on a prompt and cannot proceed until answered."""
        text = ":warning: *%s* is waiting for input" % self.label
        if question:
            text += "\n> %s" % question
        return self._post(text)


def from_cfg(cfg) -> Notifier:
    """Build a Notifier from a Config. The webhook may come from the config
    (set by --slack-webhook) or, failing that, the environment."""
    return Notifier(webhook=getattr(cfg, "slack_webhook", "") or "",
                    label=getattr(cfg, "codename", "") or "assay")
