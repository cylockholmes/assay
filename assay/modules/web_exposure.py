"""Exposed-file and exposed-endpoint detection.

The detection contract, and the reason this module is quiet:
  1. The response must not resemble the origin's catch-all page (Baseline).
  2. The status must be a real hit, not a redirect to a login page.
  3. The Content-Type must be plausible for the artefact (an SPA answering
     text/html for /.env is the classic false positive).
  4. The body must match a content signature. No signature, no finding.
High-value hits then fetch a follow-up path; when that also matches, the
finding is promoted to 'confirmed'.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional

import yaml

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

CATEGORY_MAP = {
    "A01": owasp.A01, "A02": owasp.A02, "A03": owasp.A03, "A04": owasp.A04,
    "A05": owasp.A05, "A06": owasp.A06, "A07": owasp.A07, "A08": owasp.A08,
    "A09": owasp.A09, "A10": owasp.A10, "INFO": owasp.INFO, "HOST": owasp.HOST,
}

TIER_RANK = {"quick": 0, "standard": 1, "deep": 2}

_SIGCACHE: Optional[List[dict]] = None


def load_signatures() -> List[dict]:
    global _SIGCACHE
    if _SIGCACHE is None:
        with open(os.path.join(DATA, "paths.yaml"), "r", encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
        sigs = doc.get("signatures", [])
        for s in sigs:
            s["_re"] = re.compile(s["match"], re.I | re.M)
        _SIGCACHE = sigs
    return _SIGCACHE


@register
class ExposureModule(Module):
    name = "exposure"
    stage = "analyze"
    scope = "web"
    impact_class = "read"
    desc = "Exposed VCS dirs, secrets files, debug endpoints and admin consoles"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        origin = (wt.final_url or wt.url).rstrip("/")
        # Strip any path so signatures are tested against the web root.
        origin = re.sub(r"(https?://[^/]+).*", r"\1", origin)
        max_tier = TIER_RANK.get(ctx.cfg.profile, 1)
        bl = ctx.baseline_for(origin)
        out: List[Finding] = []

        for sig in load_signatures():
            if TIER_RANK.get(sig.get("tier", "standard"), 1) > max_tier:
                continue
            f = self._test(ctx, origin, sig, bl)
            if f:
                out.append(f)
        return out

    # ------------------------------------------------------------------
    def _test(self, ctx: Context, origin: str, sig: dict, bl) -> Optional[Finding]:
        url = origin + sig["path"]
        r = ctx.http.get(url)
        if not self._is_hit(r, sig, bl):
            return None

        confidence = "firm"
        evidence = [r.evidence(label="Signature match on %s" % sig["path"],
                               matched=self._matched_text(sig["_re"], r.body))]

        for extra in sig.get("followup", []) or []:
            fr = ctx.http.get(origin + extra)
            if fr.ok and fr.status == 200 and not bl.is_noise(fr):
                confidence = "confirmed"
                evidence.append(fr.evidence(label="Follow-up confirms: %s" % extra))
                break

        sev = sig.get("severity", "low")
        return Finding(
            title=sig["name"],
            target=url,
            severity=sev,
            confidence=confidence,
            category=CATEGORY_MAP.get(sig.get("category", "A05"), owasp.A05),
            cwe=sig.get("cwe", ""),
            module=self.name,
            impact=" ".join((sig.get("impact") or "").split()),
            detail="Matched signature /%s/ on %s" % (sig["match"], sig["path"]),
            repro=r.curl(),
            refs=sig.get("refs", []) or [],
            tags=["exposure"] + (["verified"] if confidence == "confirmed" else []),
            evidence=evidence,
            dedupe_key="exposure|%s|%s" % (origin, sig["path"]),
        )

    @staticmethod
    def _is_hit(r, sig: dict, bl) -> bool:
        if not r.ok or r.status != 200:
            return False
        if bl.is_noise(r):
            return False
        ct_not = [c.lower() for c in (sig.get("ct_not") or [])]
        if ct_not and r.content_type in ct_not:
            return False
        # An HTML error page that happens to contain the keyword.
        if r.content_type == "text/html" and re.search(
            r"<title[^>]*>\s*(404|not found|error|sign in|log ?in)", r.body[:2000], re.I
        ):
            return False
        return bool(sig["_re"].search(r.body[:60000]))

    @staticmethod
    def _matched_text(rx, body: str) -> str:
        m = rx.search(body[:60000])
        return (m.group(0)[:200] if m else "")


@register
class DirListingModule(Module):
    name = "dirlisting"
    stage = "analyze"
    scope = "web"
    impact_class = "read"
    desc = "Directory indexing"

    INDEX_RE = re.compile(
        r"<title>\s*Index of /|<h1>\s*Index of /|"
        r"\[To Parent Directory\]|Directory Listing For /",
        re.I,
    )

    # Directories worth a look; each is one request, so keep the list tight.
    DIRS = ["/", "/assets/", "/static/", "/uploads/", "/files/", "/backup/",
            "/backups/", "/images/", "/js/", "/css/", "/tmp/", "/logs/",
            "/download/", "/media/", "/data/", "/includes/", "/config/"]

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        origin = re.sub(r"(https?://[^/]+).*", r"\1", (wt.final_url or wt.url))
        bl = ctx.baseline_for(origin)
        limit = 3 if ctx.cfg.profile == "quick" else len(self.DIRS)
        hits: List[str] = []
        first = None
        for d in self.DIRS[:limit]:
            r = ctx.http.get(origin + d)
            if r.ok and r.status == 200 and not bl.is_noise(r) and self.INDEX_RE.search(r.body[:6000]):
                hits.append(d)
                if first is None:
                    first = r
        if not hits or first is None:
            return []

        interesting = [d for d in hits if d.strip("/") in
                       ("backup", "backups", "logs", "config", "data", "tmp",
                        "uploads", "files", "includes")]
        sev = "medium" if interesting else "low"
        return [Finding(
            title="Directory listing enabled (%d path%s)" % (len(hits), "" if len(hits) == 1 else "s"),
            target=origin,
            severity=sev,
            confidence="confirmed",
            category=owasp.A05,
            cwe="CWE-548",
            module=self.name,
            impact=(
                "Browsable index over %s. Directories like these hold backups, logs and "
                "unlinked scripts, so this is usually the fastest route to a real finding "
                "rather than the finding itself - enumerate the contents before reporting."
                % ", ".join(hits[:6])
            ),
            repro=first.curl(),
            tags=["exposure", "verified", "manual-followup"],
            evidence=[first.evidence(label="Index page", body_limit=700)],
            dedupe_key="dirlist|%s" % origin,
        )]


@register
class BackupFileModule(Module):
    name = "backups"
    stage = "analyze"
    scope = "web"
    impact_class = "read"
    desc = "Editor/backup copies of server-side source next to live files"

    SUFFIXES = [".bak", ".old", ".save", "~", ".swp", ".orig", ".txt", ".copy"]
    SOURCE_RE = re.compile(
        r"<\?php|<%@\s*page|<%@\s*Page|using System;|require_once|"
        r"(?:mysqli?|pdo)_?connect|def\s+\w+\(|import\s+\w+|package\s+\w+;",
        re.I,
    )

    def applicable(self, ctx: Context) -> bool:
        return ctx.cfg.profile == "deep" and Module.applicable(self, ctx)

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        origin = re.sub(r"(https?://[^/]+).*", r"\1", (wt.final_url or wt.url))
        bl = ctx.baseline_for(origin)
        candidates = self._candidates(ctx, origin)
        out: List[Finding] = []
        for base in candidates[:12]:
            for suffix in self.SUFFIXES:
                r = ctx.http.get(base + suffix)
                if not (r.ok and r.status == 200) or bl.is_noise(r):
                    continue
                # The point is server-side source served as text, not the app.
                if r.content_type in ("text/html",) and not self.SOURCE_RE.search(r.body[:4000]):
                    continue
                match = self.SOURCE_RE.search(r.body[:8000])
                if not match:
                    continue
                out.append(Finding(
                    title="Server-side source disclosed via backup copy",
                    target=base + suffix,
                    severity="high",
                    confidence="confirmed",
                    category=owasp.A05,
                    cwe="CWE-530",
                    module=self.name,
                    impact=(
                        "The interpreter does not execute this extension, so the raw source "
                        "of a live application file is returned - including any embedded "
                        "database credentials, API keys and authentication logic."
                    ),
                    repro=r.curl(),
                    tags=["exposure", "verified"],
                    evidence=[r.evidence(label="Raw source returned",
                                         matched=match.group(0)[:120])],
                    dedupe_key="backup|%s" % (base + suffix),
                ))
                break
        return out

    def _candidates(self, ctx: Context, origin: str) -> List[str]:
        seen: List[str] = []
        for u in ctx.urls.get(origin, []):
            if re.search(r"\.(php|aspx?|jsp|jspx|cfm|py|rb|pl|inc|config)(\?|$)", u, re.I):
                base = u.split("?")[0]
                if base not in seen:
                    seen.append(base)
        for common in ("/index.php", "/config.php", "/db.php", "/login.php",
                       "/web.config", "/index.aspx"):
            if origin + common not in seen:
                seen.append(origin + common)
        return seen
