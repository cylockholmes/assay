"""An inventory of the places worth testing for broken object-level access.

IDOR is consistently among the best-paid findings and cannot be automated:
deciding whether object 1004 belongs to you needs a second account and a human
who understands what the object is. Testing it automatically would either
produce noise or actually read another user's data.

What can be automated is the queue. Turning "test for IDOR" into a specific
list of endpoints, parameter names and observed values is most of the work, and
it is exactly what gets skipped when a scan produces four hundred rows.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Dict, List, Set, Tuple
from urllib.parse import urlsplit

from assay import owasp, params
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register

# Paths where an object reference is more likely to be an access-control
# boundary than a lookup key.
SENSITIVE_PATH = re.compile(
    r"/(?:account|profile|user|users|member|customer|order|orders|invoice|"
    r"billing|payment|subscription|document|file|report|message|ticket|"
    r"admin|settings|export|download|api)/", re.I)


@register
class IdorInventoryModule(Module):
    name = "idor"
    stage = "analyze"
    scope = "web"
    impact_class = "read"
    desc = "Inventory of object references worth testing with a second account"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        origin = re.sub(r"(https?://[^/]+).*", r"\1", (wt.final_url or wt.url))
        urls = ctx.urls.get(origin, [])
        if not urls:
            return []

        # Group by (path, parameter) so a paginated list contributes once.
        seen: Dict[Tuple[str, str], Tuple[str, str, str]] = {}
        for u in urls:
            path = urlsplit(u).path
            for name, value, kind in params.idor_candidates(u):
                seen.setdefault((path, name), (u, value, kind))
        if not seen:
            return []

        rows: List[str] = []
        sensitive = 0
        for (path, name), (url, value, kind) in sorted(seen.items()):
            hot = bool(SENSITIVE_PATH.search(path))
            sensitive += 1 if hot else 0
            rows.append("%-4s %s   %s=%s   (%s)"
                        % ("***" if hot else "", path, name, value[:32], kind))
        if not rows:
            return []

        return [Finding(
            title="Object references worth testing for broken access control (%d)"
                  % len(rows),
            target=origin,
            severity="info",
            confidence="firm",
            category=owasp.A01,
            cwe="CWE-639",
            module=self.name,
            impact=(
                "Not a vulnerability - a work queue. These endpoints take an "
                "identifier that addresses a specific object, and %d of them sit "
                "on a path that looks like an access-control boundary. Broken "
                "object-level authorization is among the best-paid findings and "
                "cannot be tested automatically: register a second account, "
                "request each of these with the first account's identifier, and "
                "see whether the object comes back. That is the finding; this is "
                "the list of places to try it." % sensitive
            ),
            detail="%d distinct (path, parameter) pairs; *** marks paths that "
                   "look like an access-control boundary." % len(rows),
            repro="# with a second account's session, replay each with the "
                  "first account's identifier",
            refs=["https://cwe.mitre.org/data/definitions/639.html",
                  "https://portswigger.net/web-security/access-control/idor"],
            tags=["idor", "manual-followup", "queue"],
            chainable=True,
            evidence=[Evidence(kind="note", label="Object references",
                               output="\n".join(rows[:60]))],
            dedupe_key="idor|%s" % origin,
        )]
