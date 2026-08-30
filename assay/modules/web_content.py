"""Content discovery: endpoints nothing links to and no archive remembers.

The crawl, the archives and the JavaScript extractor between them find what the
application admits to. This finds what it does not: the admin panel with no
link, the backup directory, the legacy API version still routed. Those are
where unauthenticated findings concentrate, so this closes the last gap in the
injection-point pipeline.

ffuf does the requesting because its auto-calibration is better than anything
worth reimplementing here - it learns the origin's catch-all response and
filters against it. assay then applies its own baseline on top, because ffuf
calibrates per-run and assay has already measured the same origin.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional

from assay import owasp, tools
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register

# Hits worth surfacing on their own rather than only feeding the URL pool.
NOTEWORTHY = re.compile(
    r"^/(?:admin|administrator|manage|management|console|dashboard|internal|"
    r"private|backup|backups|dump|db|database|sql|config|conf|settings|"
    r"debug|test|staging|dev|old|new|tmp|temp|logs?|api/v[0-9]+|actuator|"
    r"phpmyadmin|adminer|jenkins|grafana|kibana|swagger|graphiql)(?:/|$)", re.I)


@register
class ContentDiscoveryModule(Module):
    name = "content"
    stage = "probe"
    scope = "web"
    impact_class = "probe"
    desc = "Unlinked endpoints via wordlist fuzzing (ffuf)"

    def applicable(self, ctx: Context) -> bool:
        if not Module.applicable(self, ctx):
            return False
        if not ctx.cfg.opts.get("content_discovery"):
            return False
        if not ctx.has("ffuf"):
            return False
        return bool(tools.default_wordlist())

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        wordlist = tools.default_wordlist()
        origin = re.sub(r"(https?://[^/]+).*", r"\1", (wt.final_url or wt.url))
        bl = ctx.baseline_for(origin)

        ctx.say("content", "fuzzing %s with %s"
                % (origin, os.path.basename(wordlist)))
        results = tools.ffuf_discover(
            origin, wordlist, ctx.tune,
            proxy=ctx.cfg.burp.proxy,
            extensions=self._extensions(wt),
            timeout=900.0 if ctx.cfg.profile == "deep" else 420.0,
        )
        if not results:
            return []

        cap = ctx.cfg.opts.get("max_urls_per_host", 60) * 3
        discovered: List[str] = []
        found: List[str] = []
        interesting: List[Dict] = []

        for row in results:
            url = row.get("url") or ""
            if not url:
                continue
            status = int(row.get("status") or 0)
            path = "/" + url.split("://", 1)[-1].split("/", 1)[-1] \
                if "://" in url else url

            # ffuf calibrated against its own baseline; re-check against ours.
            if status == 200:
                r = ctx.http.get(url)
                if not r.ok or bl.is_noise(r):
                    continue

            discovered.append(url)
            found.append(url)
            if NOTEWORTHY.match(path) and status in (200, 401, 403, 301, 302):
                interesting.append({"url": url, "status": status,
                                    "length": row.get("length")})

        ctx.add_urls(origin, discovered, cap)
        ctx.say("content", "%s: %d path(s), %d noteworthy"
                % (origin, len(found), len(interesting)))
        if not interesting:
            return []

        listing = "\n".join("%-5s %s" % (i["status"], i["url"])
                            for i in interesting[:40])
        auth_walled = [i for i in interesting if i["status"] in (401, 403)]
        return [Finding(
            title="Unlinked administrative or sensitive paths discovered (%d)"
                  % len(interesting),
            target=origin,
            severity="low",
            confidence="confirmed",
            category=owasp.A05,
            cwe="CWE-425",
            module=self.name,
            impact=(
                "These paths are reachable but not linked from the application, so "
                "they were not exercised by the crawl and are frequently forgotten "
                "by whoever maintains the access control. %s Test each for missing "
                "authorization - an admin route that answers 200 unauthenticated is "
                "the finding, not the discovery itself."
                % ("%d answered 401/403, which confirms they exist and are guarded; "
                   "check whether the guard can be bypassed by method, path casing "
                   "or a trailing slash. " % len(auth_walled) if auth_walled else "")
            ),
            detail="Wordlist: %s" % os.path.basename(wordlist),
            repro="ffuf -u %s/FUZZ -w %s -ac -mc 200,301,302,401,403"
                  % (origin.rstrip("/"), wordlist),
            tags=["discovery", "verified", "manual-followup"],
            chainable=True,
            evidence=[Evidence(kind="command", label="Discovered paths",
                               output=listing)],
            dedupe_key="content|%s" % origin,
        )]

    @staticmethod
    def _extensions(wt: WebTarget) -> str:
        """Guess useful extensions from the detected stack."""
        tech = " ".join(wt.tech).lower()
        if "asp" in tech or ".net" in tech:
            return ".aspx,.asp,.config,.txt,.bak"
        if "wordpress" in tech or "php" in tech or "laravel" in tech:
            return ".php,.txt,.bak,.old,.inc"
        if "java" in tech or "tomcat" in tech or "spring" in tech:
            return ".jsp,.do,.action,.xml,.properties"
        return ".txt,.bak,.old,.json,.xml"
