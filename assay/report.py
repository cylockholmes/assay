"""Self-contained HTML report.

One file, no external assets, opens straight from WSL into the Windows browser.
Ordering is the point: the report opens on what to chase, not on a severity
pie chart.
"""

from __future__ import annotations

import html
import json
import os
import time
from typing import Dict, List, Optional

from assay.models import Finding
from assay.store import Store

SEV_COLOR = {
    "critical": "#ff4d6d", "high": "#ff8c42", "medium": "#ffd166",
    "low": "#7bd389", "info": "#8ab4f8",
}
TRIAGE_LABEL = {
    "CHASE": ("Chase now", "Verified or near-verified with real impact."),
    "LOOK": ("Worth a look", "Probably real; needs a manual step to prove impact."),
    "NOTE": ("Context", "Chain material, recon, and hygiene. Not standalone reports."),
}


def _e(s) -> str:
    return html.escape(str(s or ""), quote=True)


def build(store: Store, assets: Dict, out_path: str, ai: Optional[Dict] = None,
          scan_meta: Optional[Dict] = None) -> str:
    findings = list(store.iter_findings())
    counts = store.counts()
    chains = store.ai_chains()
    meta = scan_meta or {}

    buckets: Dict[str, List[Finding]] = {"CHASE": [], "LOOK": [], "NOTE": []}
    for f in findings:
        buckets.setdefault(f.triage, buckets["NOTE"]).append(f)

    parts: List[str] = [_HEAD, _header(counts, assets, meta, ai)]

    if chains:
        parts.append(_chains_section(chains, findings))

    for bucket in ("CHASE", "LOOK", "NOTE"):
        items = buckets.get(bucket) or []
        if not items:
            continue
        label, blurb = TRIAGE_LABEL[bucket]
        parts.append(
            '<section class="bucket"><h2>%s <span class="count">%d</span></h2>'
            '<p class="blurb">%s</p>' % (_e(label), len(items), _e(blurb))
        )
        for f in items:
            parts.append(_finding_card(f, store))
        parts.append("</section>")

    parts.append(_FOOT)
    doc = "\n".join(parts)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return out_path


def _header(counts: Dict, assets: Dict, meta: Dict, ai: Optional[Dict]) -> str:
    tiles = [
        ("Chase", counts.get("CHASE", 0), "#ff4d6d"),
        ("Look", counts.get("LOOK", 0), "#ffd166"),
        ("Context", counts.get("NOTE", 0), "#8ab4f8"),
        ("Hosts", assets.get("hosts", 0), "#9aa0a6"),
        ("Web endpoints", assets.get("web", 0), "#9aa0a6"),
        ("Requests", assets.get("requests", 0), "#9aa0a6"),
    ]
    tile_html = "".join(
        '<div class="tile"><div class="num" style="color:%s">%s</div>'
        '<div class="lbl">%s</div></div>' % (c, _e(v), _e(k))
        for k, v, c in tiles
    )
    summary = ""
    if ai and ai.get("summary"):
        summary = ('<div class="ai-summary"><h3>AI triage summary '
                   '<span class="pill">%s</span></h3><p>%s</p></div>'
                   % (_e(ai.get("_model", "")), _e(ai["summary"])))
    return (
        '<header><div class="titlebar"><h1>assay</h1>'
        '<div class="meta">%s &middot; profile <b>%s</b> &middot; %.0fs</div></div>'
        '<div class="tiles">%s</div>%s</header>'
        % (_e(time.strftime("%Y-%m-%d %H:%M")), _e(meta.get("profile", "standard")),
           assets.get("duration", 0), tile_html, summary)
    )


def _chains_section(chains: List[Dict], findings: List[Finding]) -> str:
    titles = {f.fingerprint(): f.title for f in findings}
    rows = []
    for c in chains:
        steps = "".join("<li>%s</li>" % _e(s) for s in c.get("steps", []))
        links = ", ".join(_e(titles.get(i, i)) for i in c.get("finding_ids", []))
        rows.append(
            '<div class="chain"><div class="chain-head"><span class="sev" '
            'style="background:%s">%s</span><b>%s</b></div>'
            '<p>%s</p><p class="dim">Combines: %s</p><ol>%s</ol></div>'
            % (SEV_COLOR.get(c.get("severity", "medium"), "#ffd166"),
               _e(c.get("severity", "")), _e(c.get("name", "")),
               _e(c.get("impact", "")), links, steps)
        )
    return ('<section class="bucket"><h2>Attack chains <span class="count">%d</span></h2>'
            '<p class="blurb">Individually unremarkable findings that together '
            'demonstrate higher impact.</p>%s</section>'
            % (len(chains), "".join(rows)))


def _finding_card(f: Finding, store: Store) -> str:
    fid = f.fingerprint()
    ai = store.ai_for(fid)
    ev_html = ""
    for e in f.evidence[:3]:
        blob = e.compact()
        if not blob:
            continue
        ev_html += ('<div class="ev"><div class="ev-label">%s</div><pre>%s</pre></div>'
                    % (_e(e.label or e.kind), _e(blob)))

    ai_html = ""
    if ai:
        steps = "".join("<li>%s</li>" % _e(s) for s in ai.get("next_steps", []))
        ai_html = (
            '<div class="ai"><div class="ai-head">AI triage: '
            '<span class="verdict v-%s">%s</span> '
            '<span class="dim">FP risk %s &middot; priority %s</span></div>'
            '<p>%s</p>%s</div>'
            % (_e(ai.get("verdict", "")), _e(ai.get("verdict", "")),
               _e(ai.get("fp_risk", "")), _e(ai.get("priority", "")),
               _e(ai.get("rationale", "")),
               ("<ol>%s</ol>" % steps) if steps else "")
        )

    refs = "".join('<a href="%s" rel="noreferrer noopener" target="_blank">ref</a>' % _e(r)
                   for r in f.refs[:4])
    tags = "".join('<span class="tag">%s</span>' % _e(t) for t in f.tags[:6])

    return (
        '<article class="card" data-sev="%s">'
        '<div class="card-head">'
        '<span class="sev" style="background:%s">%s</span>'
        '<span class="conf">%s</span>'
        '<h3>%s</h3>'
        '<span class="score">%.0f</span>'
        '</div>'
        '<div class="target">%s</div>'
        '<div class="row"><span class="k">Impact</span><span>%s</span></div>'
        '%s'
        '<div class="row"><span class="k">Class</span><span>%s %s</span></div>'
        '<div class="row"><span class="k">Repro</span><code>%s</code></div>'
        '<div class="tags">%s %s</div>'
        '%s'
        '%s'
        '</article>'
        % (_e(f.severity), SEV_COLOR.get(f.severity, "#8ab4f8"), _e(f.severity),
           _e(f.confidence), _e(f.title), f.score, _e(f.target), _e(f.impact),
           ('<div class="row"><span class="k">Detail</span><span>%s</span></div>' % _e(f.detail))
           if f.detail else "",
           _e(f.category), _e(f.cwe), _e(f.repro), tags, refs,
           ('<details><summary>Evidence (%d)</summary>%s</details>'
            % (len(f.evidence), ev_html)) if ev_html else "",
           ai_html)
    )


_HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>assay report</title><style>
:root{--bg:#0f1115;--card:#171a21;--line:#252a35;--fg:#e6e8eb;--dim:#9aa0a6;--acc:#7aa2f7}
@media(prefers-color-scheme:light){:root{--bg:#f6f7f9;--card:#fff;--line:#e2e5ea;--fg:#1a1c20;--dim:#5f6368}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:28px 32px 20px;border-bottom:1px solid var(--line)}
.titlebar{display:flex;align-items:baseline;gap:16px;flex-wrap:wrap}
h1{margin:0;font-size:26px;letter-spacing:-.5px}
.meta{color:var(--dim);font-size:13px}
.tiles{display:flex;gap:12px;flex-wrap:wrap;margin-top:18px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 18px;min-width:110px}
.tile .num{font-size:24px;font-weight:650}
.tile .lbl{color:var(--dim);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.ai-summary{margin-top:18px;background:var(--card);border:1px solid var(--line);border-left:3px solid var(--acc);border-radius:8px;padding:14px 18px}
.ai-summary h3{margin:0 0 6px;font-size:14px}
.pill{background:var(--line);color:var(--dim);border-radius:20px;padding:2px 9px;font-size:11px;font-weight:400}
main,section.bucket{padding:0 32px}
section.bucket{margin-top:30px}
section.bucket h2{font-size:17px;margin:0 0 2px;display:flex;align-items:center;gap:10px}
.count{background:var(--line);border-radius:20px;padding:1px 10px;font-size:12px;color:var(--dim)}
.blurb{color:var(--dim);margin:0 0 14px;font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:12px}
.card-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.card-head h3{margin:0;font-size:15px;flex:1;min-width:200px}
.sev{color:#0b0d10;border-radius:5px;padding:1px 8px;font-size:11px;font-weight:700;text-transform:uppercase}
.conf{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.05em}
.score{color:var(--dim);font-variant-numeric:tabular-nums;font-size:12px}
.target{color:var(--acc);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;margin:8px 0 12px;word-break:break-all}
.row{display:flex;gap:12px;margin:5px 0}
.row .k{color:var(--dim);min-width:62px;font-size:12px;text-transform:uppercase;letter-spacing:.05em;flex-shrink:0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:2px 7px;word-break:break-all}
.tags{margin-top:10px;display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.tag{background:var(--line);color:var(--dim);border-radius:4px;padding:1px 7px;font-size:11px}
.tags a{color:var(--acc);font-size:11px;text-decoration:none;margin-left:4px}
details{margin-top:12px}
summary{cursor:pointer;color:var(--dim);font-size:12px}
.ev{margin-top:8px}
.ev-label{color:var(--dim);font-size:11px;margin-bottom:3px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px 12px;overflow-x:auto;font-size:11.5px;margin:0;white-space:pre-wrap;word-break:break-word;max-height:340px}
.ai{margin-top:12px;padding:12px 14px;background:var(--bg);border:1px solid var(--line);border-left:3px solid var(--acc);border-radius:6px}
.ai-head{font-size:12px;margin-bottom:6px}
.verdict{border-radius:4px;padding:1px 7px;font-size:11px;font-weight:700;text-transform:uppercase;color:#0b0d10}
.v-report{background:#ff4d6d}.v-investigate{background:#ffd166}.v-discard{background:#5f6368;color:#e6e8eb}
.ai p{margin:4px 0}
.ai ol,.chain ol{margin:6px 0 0 18px;padding:0;font-size:13px}
.chain{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:12px}
.chain-head{display:flex;align-items:center;gap:10px}
.dim{color:var(--dim);font-size:12px}
footer{padding:26px 32px;color:var(--dim);font-size:12px;border-top:1px solid var(--line);margin-top:34px}
</style></head><body><main>"""

_FOOT = ("</main><footer>Generated by assay. Every finding lists the evidence it was "
         "derived from - verify before reporting.</footer></body></html>")
