"""Cross-reference detected software versions against NVD's public CVE feed.

Query-only: sends a product/version pair to services.nvd.nist.gov's keyword
search and reports back whatever it says. That is a text match, not a CPE
match, so a hit means "NVD has CVEs whose description mentions this name and
version" - worth a look, not a confirmed vulnerability. `assay.modules
.inventory` treats it that way: results land as a low-confidence "tentative"
finding a human is expected to verify.

Third-party traffic derived from what the scan found on the target, so the
caller only runs this under --passive - same rule as the Wayback Machine
lookups in archive.py.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import quote

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Public rate limit is 5 requests / rolling 30s without a key, 50/30s with one
# (set NVD_API_KEY). Stay comfortably under either rather than tune it exactly.
_NO_KEY_DELAY = 6.5
_WITH_KEY_DELAY = 0.7

_SEVERITY_FLOORS = [(9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.0, "low")]

_last_call = [0.0]


@dataclass
class CveMatch:
    cve_id: str
    summary: str
    severity: str            # critical | high | medium | low | info (unscored)
    score: Optional[float]
    published: str
    url: str


def _severity_for(score: Optional[float]) -> str:
    if score is None:
        return "info"
    for floor, label in _SEVERITY_FLOORS:
        if score >= floor:
            return label
    return "info"


def _best_score(cve: dict) -> Optional[float]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            score = entries[0].get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def _summary(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _throttle(has_key: bool) -> None:
    delay = _WITH_KEY_DELAY if has_key else _NO_KEY_DELAY
    wait = delay - (time.monotonic() - _last_call[0])
    if wait > 0:
        time.sleep(wait)
    _last_call[0] = time.monotonic()


def parse(body: str, limit: int = 5) -> List[CveMatch]:
    """Turn an NVD CVE 2.0 API response body into matches, worst-first."""
    try:
        doc = json.loads(body)
    except ValueError:
        return []
    out: List[CveMatch] = []
    for item in doc.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        score = _best_score(cve)
        out.append(CveMatch(
            cve_id=cve_id,
            summary=_summary(cve)[:400],
            severity=_severity_for(score),
            score=score,
            published=cve.get("published", "")[:10],
            url="https://nvd.nist.gov/vuln/detail/%s" % cve_id,
        ))
    out.sort(key=lambda m: (m.score if m.score is not None else -1.0), reverse=True)
    return out[:limit]


def lookup(name: str, version: str, http, limit: int = 5) -> List[CveMatch]:
    """Ask NVD for CVEs matching `name version`. Empty list on any failure -
    a lookup that cannot reach NVD must never break the scan.
    """
    if not name or not version:
        return []
    api_key = os.environ.get("NVD_API_KEY", "")
    _throttle(bool(api_key))
    headers = {"apiKey": api_key} if api_key else None
    query = "%s %s" % (name, version)
    url = "%s?keywordSearch=%s&resultsPerPage=%d" % (NVD_URL, quote(query, safe=""), limit)
    r = http.get(url, through_burp=False, infra=True, timeout=20.0, headers=headers)
    if not r.ok or r.status != 200:
        return []
    return parse(r.body, limit)
