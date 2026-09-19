"""Software and version inventory, with an optional CVE cross-reference.

Every product/version this run could identify - from nmap service detection
on the host side, and from HTTP headers, generator meta tags and bundled JS
libraries on the web side - collapses into one table, written to the report
regardless of whether anything looks vulnerable. That list is useful on its
own: it is the asset inventory a client's security team usually does not
have, and it costs nothing extra once the scan already ran.

The CVE cross-reference is additional and --passive-gated, same as the
Wayback Machine lookups in web_archive.py: for every (product, version) pair
it queries NVD's public keyword search (assay.cve) and turns a hit into a
Finding. Keyword search is a text match, not a CPE match, so every result is
"known CVEs affecting things named and versioned like this - go verify",
never a confirmed vulnerability on its own.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List

from assay import cve as cve_mod
from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding
from assay.modules import Module, register
from assay.software import collect_from_host, collect_from_web, merge

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@register
class InventoryModule(Module):
    name = "inventory"
    stage = "analyze"
    scope = "global"
    impact_class = "passive"
    desc = "Software/version inventory, with an optional NVD CVE cross-reference"

    def run_global(self, ctx: Context) -> List[Finding]:
        items = []
        for t in ctx.targets:
            items.extend(collect_from_host(t))
        for w in ctx.web:
            items.extend(collect_from_web(w))
        rows = merge(items)
        if not rows:
            return []
        ctx.say("inventory", "%d software item(s) identified" % len(rows))

        matches_by_key: Dict[str, List[cve_mod.CveMatch]] = {}
        if ctx.cfg.passive:
            versioned = [r for r in rows if r["version"]]
            if versioned:
                ctx.say("inventory", "checking %d version(s) against NVD (--passive)"
                        % len(versioned))
            for row in versioned:
                matches = cve_mod.lookup(row["name"], row["version"], ctx.http)
                if matches:
                    matches_by_key[_row_key(row)] = matches
            if matches_by_key:
                ctx.say("inventory", "%d software item(s) have known CVEs"
                        % len(matches_by_key))

        self._write_report_data(ctx, rows, matches_by_key)

        return [self._cve_finding(row, matches_by_key[_row_key(row)])
                for row in rows if _row_key(row) in matches_by_key]

    def _write_report_data(self, ctx: Context, rows: List[Dict],
                           matches_by_key: Dict[str, List[cve_mod.CveMatch]]) -> None:
        items = []
        for row in rows:
            matches = matches_by_key.get(_row_key(row), [])
            items.append({
                "name": row["name"],
                "version": row["version"],
                "category": row["category"],
                "sources": row["sources"],
                "where": row["where"],
                "cves": [{"id": m.cve_id, "severity": m.severity, "score": m.score,
                         "summary": m.summary, "url": m.url} for m in matches],
            })
        # cve_checked distinguishes "ran and found nothing" from "did not run
        # (--no-passive)" - the report needs that to word its footnote right.
        doc = {"cve_checked": bool(ctx.cfg.passive), "items": items}
        raw_dir = os.path.join(ctx.cfg.out_dir, "raw")
        try:
            os.makedirs(raw_dir, exist_ok=True)
            with open(os.path.join(raw_dir, "software-inventory.json"), "w",
                     encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
        except OSError:
            pass

    def _cve_finding(self, row: Dict, matches: List[cve_mod.CveMatch]) -> Finding:
        name, version = row["name"], row["version"]
        where = row["where"][0] if row["where"] else name
        worst = min(matches, key=lambda m: _SEV_ORDER.get(m.severity, 4))
        detail = "\n".join(
            "%s (%s%s): %s" % (
                m.cve_id, m.severity,
                " %.1f" % m.score if m.score is not None else "",
                (m.summary[:220] + "...") if len(m.summary) > 220 else m.summary)
            for m in matches[:8])
        return Finding(
            title="%s %s has %d known CVE(s) via NVD, worst %s" % (
                name, version, len(matches), worst.severity),
            target=where,
            severity=worst.severity if worst.severity != "info" else "low",
            confidence="tentative",
            category=owasp.A06,
            cwe="CWE-937",
            module=self.name,
            impact=(
                "NVD's keyword search returns CVEs matching \"%s %s\" by name and "
                "version text, not by a confirmed CPE match - a false positive when "
                "the text happens to line up but the vulnerable configuration does "
                "not. Confirm the specific CVE applies to this build before reporting "
                "it; if it does, this is a standard vulnerable/outdated component."
                % (name, version)
            ),
            detail=detail,
            repro="curl -s 'https://services.nvd.nist.gov/rest/json/cves/2.0"
                  "?keywordSearch=%s+%s' | jq ." % (name.replace(" ", "+"), version),
            refs=[m.url for m in matches[:8]],
            tags=["inventory", "cve", "noise-prone"],
            evidence=[Evidence(kind="note", label="NVD keywordSearch match",
                               output=", ".join(m.cve_id for m in matches))],
            dedupe_key="cve|%s|%s" % (name.lower(), version),
        )


def _row_key(row: Dict) -> str:
    return "%s|%s" % (row["name"].lower(), row["version"])
