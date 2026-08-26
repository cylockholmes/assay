"""Secrets in archived copies of assets.

A key committed into a bundle and quietly removed next sprint is still live if
nobody rotated it, and the Wayback Machine still serves the file. The current
site looks clean, which is exactly why this is worth checking.

Third-party traffic, so --passive only.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

from assay import archive, owasp
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register
from assay.modules.secrets import SECRET_PATTERNS


@register
class ArchivedSecretsModule(Module):
    name = "archive"
    stage = "analyze"
    scope = "web"
    impact_class = "passive"
    desc = "Credentials in archived copies of assets that were later removed"

    def applicable(self, ctx: Context) -> bool:
        if not Module.applicable(self, ctx):
            return False
        # Queries web.archive.org, so it is a passive third-party lookup.
        return ctx.cfg.passive

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        cache: Set[str] = getattr(ctx, "_archive_hosts", set())
        setattr(ctx, "_archive_hosts", cache)
        if wt.host in cache:
            return []
        cache.add(wt.host)

        budget = {"quick": 15, "standard": 40, "deep": 120}.get(ctx.cfg.profile, 40)
        snaps = archive.cdx_index(wt.host, ctx.http, limit=budget * 6)
        if not snaps:
            return []
        ctx.say("archive", "%s: %d archived artefact(s) to review"
                % (wt.host, min(len(snaps), budget)))

        out: List[Finding] = []
        seen: Set[str] = set()
        for snap in snaps[:budget]:
            body = archive.fetch(snap, ctx.http)
            if not body:
                continue
            for label, sev, rx, why in SECRET_PATTERNS:
                m = rx.search(body)
                if not m:
                    continue
                token = m.group(0)
                if token in seen:
                    continue
                seen.add(token)
                out.append(self._finding(ctx, snap, label, sev, token, why, m, body))
        return out

    def _finding(self, ctx: Context, snap, label: str, sev: str, token: str,
                 why: str, match, body: str) -> Finding:
        live = archive.still_live(snap.url, ctx.http, token)
        if live is True:
            headline = "%s exposed in a live asset (also in archive)" % label
            extra = ("The credential is still present in the version served today, "
                     "so this is exploitable right now.")
        elif live is False:
            headline = "%s exposed in an archived asset (removed from live site)" % label
            extra = ("The credential was removed from the current version, but "
                     "removal is not rotation - it remains valid until revoked, and "
                     "the archived copy is permanently public. Confirm the key is "
                     "still live before reporting; that is what makes this a finding "
                     "rather than a historical note.")
        else:
            headline = "%s exposed in an archived asset" % label
            extra = ("The current version of this URL did not respond, so it is "
                     "unclear whether the credential is still shipped. Check both.")

        return Finding(
            title=headline,
            target=snap.url,
            severity=sev if live is not False else self._downgrade(sev),
            confidence="firm",
            category=owasp.A05,
            cwe="CWE-798",
            module="archive",
            impact="%s %s" % (why, extra),
            detail="Snapshot from %s (%s)" % (snap.when, snap.mimetype or "unknown type"),
            repro="curl -sSk '%s'" % snap.fetch_url,
            refs=["https://cwe.mitre.org/data/definitions/798.html"],
            tags=["secrets", "archive", "manual-followup"],
            chainable=True,
            evidence=[Evidence(
                kind="http",
                label="Archived copy captured %s" % snap.when,
                request="GET %s" % snap.fetch_url,
                output=self._excerpt(body, match.start()),
                matched=token[:14] + "...")],
            dedupe_key="archive-secret|%s|%s" % (label, token[:24]),
        )

    @staticmethod
    def _downgrade(sev: str) -> str:
        return {"critical": "high", "high": "medium", "medium": "low"}.get(sev, sev)

    @staticmethod
    def _excerpt(body: str, pos: int, width: int = 100) -> str:
        return body[max(0, pos - width):pos + width].replace("\n", " ")
