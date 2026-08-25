"""Historical snapshots: secrets that were removed but never rotated.

A key committed into a bundle and quietly deleted next sprint is still live if
nobody rotated it, and the archive still has the file. This is one of the
highest-yield passive techniques in bug bounty precisely because the current
site looks clean.

Everything here queries the Wayback Machine, so it is third-party traffic and
runs only under --passive.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote, urlsplit

CDX = ("https://web.archive.org/cdx/search/cdx?url=%s%%2F*&output=json"
       "&fl=original,timestamp,mimetype,statuscode&collapse=urlkey"
       "&filter=statuscode:200&limit=%d")

SNAPSHOT = "https://web.archive.org/web/%sif_/%s"

# File types worth pulling out of the archive. Everything else is noise.
INTERESTING = re.compile(
    r"\.(?:js|jsx|ts|mjs|json|ya?ml|env|cfg|conf|ini|txt|xml|bak|old|log|"
    r"properties|tf|tfvars|sh|ps1|py|rb|php|map)(?:$|\?)", re.I)

# Paths that are almost always worth a look regardless of extension.
INTERESTING_PATH = re.compile(
    r"/(?:config|settings|secret|credential|backup|admin|internal|api|"
    r"\.env|\.git|swagger|openapi)", re.I)

SKIP = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|css|mp4|mp3|pdf|zip)(?:$|\?)",
    re.I)


@dataclass
class Snapshot:
    url: str
    timestamp: str
    mimetype: str = ""

    @property
    def when(self) -> str:
        t = self.timestamp
        return "%s-%s-%s" % (t[0:4], t[4:6], t[6:8]) if len(t) >= 8 else t

    @property
    def fetch_url(self) -> str:
        return SNAPSHOT % (self.timestamp, self.url)


def cdx_index(host: str, http, limit: int = 400) -> List[Snapshot]:
    """Ask the Wayback CDX index what it holds for this host."""
    url = CDX % (quote(host, safe=""), limit)
    r = http.get(url, through_burp=False, timeout=45.0, infra=True)
    if not r.ok or r.status != 200:
        return []
    try:
        rows = json.loads(r.body)
    except ValueError:
        return []
    if not isinstance(rows, list) or len(rows) < 2:
        return []

    out: List[Snapshot] = []
    seen: Set[str] = set()
    for row in rows[1:]:                       # row 0 is the header
        if len(row) < 3:
            continue
        original, timestamp, mimetype = row[0], row[1], row[2]
        if SKIP.search(original):
            continue
        if not (INTERESTING.search(original) or INTERESTING_PATH.search(original)):
            continue
        key = original.split("?")[0]
        if key in seen:
            continue
        seen.add(key)
        out.append(Snapshot(url=original, timestamp=timestamp, mimetype=mimetype))
    return out


def fetch(snap: Snapshot, http, limit: int = 400000) -> str:
    r = http.get(snap.fetch_url, through_burp=False, timeout=30.0, infra=True)
    if not r.ok or r.status != 200:
        return ""
    return r.body[:limit]


def still_live(url: str, http, needle: str) -> Optional[bool]:
    """Is the secret still in the version served today?

    None means we could not tell - the current URL did not answer.
    """
    r = http.get(url)
    if not r.ok or r.status != 200:
        return None
    return needle in r.body
