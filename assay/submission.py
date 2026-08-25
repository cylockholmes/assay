"""Submission drafts.

Turns a finding into the shape a submission form asks for: title, category,
CVSS, summary, numbered reproduction, impact, remediation. The intent is to
remove the transcription work between "assay found it" and "it is written up",
not to write the report for you.

The CVSS vectors are defensible starting points for the common case. A scanner
cannot know whether the database behind an injection holds test rows or
customer records, so every draft says so and expects you to adjust.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import yaml

from assay.models import Finding

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

_TEMPLATES: Optional[Dict[str, dict]] = None

# CVSS 3.1 base score lookup for the vectors used in the templates, so the
# draft can state a severity without pulling in a scoring library.
_SCORES = {
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": (9.8, "Critical"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N": (7.5, "High"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N": (9.0, "Critical"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N": (8.2, "High"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": (6.1, "Medium"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N": (5.3, "Medium"),
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L": (7.3, "High"),
    "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N": (4.2, "Medium"),
}


def load_templates() -> Dict[str, dict]:
    global _TEMPLATES
    if _TEMPLATES is None:
        with open(os.path.join(DATA, "submissions.yaml"), "r", encoding="utf-8") as fh:
            _TEMPLATES = yaml.safe_load(fh) or {}
    return _TEMPLATES


def _clean(text: str) -> str:
    return " ".join((text or "").split())


def _fields(f: Finding) -> Dict[str, str]:
    url = f.target if f.target.startswith("http") else ""
    parts = urlsplit(url) if url else None
    param = ""
    m = re.search(r"'([^']+)'", f.title)
    if m:
        param = m.group(1)
    matched = ""
    for e in f.evidence:
        if e.matched:
            matched = e.matched[:160]
            break
    return {
        "title": f.title,
        "target": f.target,
        "url": url or f.target,
        "host": parts.hostname if parts else f.target.split(":")[0],
        "path": (parts.path if parts else "") or "/",
        "param": param or "the affected parameter",
        "matched": matched or "(see evidence)",
        "detail": _clean(f.detail),
        "impact": _clean(f.impact),
        "repro": f.repro.splitlines()[0] if f.repro else "",
    }


def _fill(text: str, fields: Dict[str, str]) -> str:
    out = text
    for k, v in fields.items():
        out = out.replace("{%s}" % k, v)
    # Leave any unresolved placeholder visible rather than silently blank.
    return out


def template_for(f: Finding) -> dict:
    tpl = load_templates()
    return tpl.get(f.module) or tpl.get("default", {})


def draft(f: Finding, ai: Optional[Dict] = None) -> str:
    """Render a submission draft as markdown."""
    t = template_for(f)
    fields = _fields(f)
    cvss = t.get("cvss", "")
    score, rating = _SCORES.get(cvss, (0.0, f.severity.title()))

    lines: List[str] = []
    lines.append("# %s" % _fill(t.get("title_override", f.title), fields))
    lines.append("")
    lines.append("**Category:** %s  " % t.get("category", "Security Misconfiguration"))
    lines.append("**CWE:** %s  " % (f.cwe or "n/a"))
    lines.append("**Affected:** `%s`  " % f.target)
    if cvss:
        lines.append("**CVSS 3.1:** `%s`%s  "
                     % (cvss, "  (%.1f %s)" % (score, rating) if score else ""))
    lines.append("**Detection confidence:** %s" % f.confidence)
    lines.append("")

    lines.append("## Summary")
    lines.append(_clean(_fill(t.get("summary", "{title} on {target}. {impact}"), fields)))
    lines.append("")

    lines.append("## Steps to Reproduce")
    for i, step in enumerate(t.get("steps", []) or [], 1):
        lines.append("%d. %s" % (i, _clean(_fill(step, fields))))
    if f.repro:
        lines.append("")
        lines.append("```bash")
        lines.append(f.repro)
        lines.append("```")
    lines.append("")

    if f.evidence:
        lines.append("## Proof of Concept")
        for e in f.evidence[:2]:
            blob = e.compact(1200)
            if not blob:
                continue
            lines.append("")
            lines.append("**%s**" % (e.label or e.kind))
            lines.append("")
            lines.append("```http")
            lines.append(blob)
            lines.append("```")
        lines.append("")

    lines.append("## Impact")
    lines.append(_clean(f.impact) or _clean(_fill(t.get("summary", ""), fields)))
    if ai and ai.get("impact"):
        lines.append("")
        lines.append(_clean(ai["impact"]))
    lines.append("")

    lines.append("## Remediation")
    lines.append(_clean(_fill(t.get("remediation", ""), fields)))
    lines.append("")

    if f.refs:
        lines.append("## References")
        for r in f.refs[:5]:
            lines.append("- %s" % r)
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("**Before you submit**")
    lines.append("")
    lines.append("- %s" % _clean(_fill(t.get("notes", ""), fields)))
    lines.append("- The CVSS vector above is a starting point for the common "
                 "case. Adjust it for the data actually exposed and the "
                 "target's context.")
    lines.append("- Reproduce by hand and capture a fresh request/response "
                 "pair; the evidence above came from an automated pass.")
    if ai and ai.get("next_steps"):
        lines.append("- Open questions from triage:")
        for s in ai["next_steps"][:4]:
            lines.append("  - %s" % _clean(s))
    return "\n".join(lines)


def bundle(findings: List[Finding], store=None, limit: int = 20) -> str:
    """One markdown document containing a draft per finding."""
    out: List[str] = []
    for f in findings[:limit]:
        ai = store.ai_for(f.fingerprint()) if store else None
        out.append(draft(f, ai))
        out.append("\n\n<!-- ------------------------------------------------ -->\n\n")
    return "\n".join(out)
