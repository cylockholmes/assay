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
    # `s or ""` would turn a zero count into an empty cell - the Look and
    # Context tiles rendered blank instead of 0 for exactly that reason.
    return html.escape("" if s is None else str(s), quote=True)


def build(store: Store, assets: Dict, out_path: str, ai: Optional[Dict] = None,
          scan_meta: Optional[Dict] = None, live: bool = False) -> str:
    """Render the report. `live=True` marks the scan as still running.

    A live report reloads itself every few seconds so findings appear while the
    scan is still going - you can start testing the first critical while the
    rest of the netblock is still being swept. Scroll position and filter state
    survive the reload, so it does not fight you.
    """
    findings = list(store.iter_findings())
    counts = store.counts()
    chains = store.ai_chains()
    meta = scan_meta or {}

    buckets: Dict[str, List[Finding]] = {"CHASE": [], "LOOK": [], "NOTE": []}
    for f in findings:
        buckets.setdefault(f.triage, buckets["NOTE"]).append(f)

    modules = sorted({f.module for f in findings if f.module})
    parts: List[str] = [_HEAD, _header(counts, assets, meta, ai),
                        _toolbar(modules, len(findings)),
                        _start_here(findings, store)]

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

    parts.append(_live_script() if live else "")
    parts.append(_FOOT)
    doc = "\n".join(parts)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return out_path


def _live_script() -> str:
    """Auto-reload while a scan is in flight, preserving where you were."""
    return """
<div class="livebar" id="livebar">
  <span class="dot"></span>
  <b>scan running</b>
  <span class="dim">findings appear as they are confirmed</span>
  <label class="cbx"><input type="checkbox" id="autorefresh" checked> auto-refresh</label>
  <span class="dim" id="nextin"></span>
</div>
<script>
(function () {
  var KEY = 'assay.scroll', CB = 'assay.autorefresh';
  var box = document.getElementById('autorefresh');
  try {
    var pref = localStorage.getItem(CB);
    if (pref !== null) box.checked = pref === '1';
    var y = sessionStorage.getItem(KEY);
    if (y) window.scrollTo(0, parseInt(y, 10));
  } catch (e) {}
  box.addEventListener('change', function () {
    try { localStorage.setItem(CB, box.checked ? '1' : '0'); } catch (e) {}
  });
  var left = 5;
  setInterval(function () {
    if (!box.checked) {
      document.getElementById('nextin').textContent = 'paused';
      return;
    }
    left -= 1;
    document.getElementById('nextin').textContent = 'refreshing in ' + left + 's';
    if (left <= 0) {
      try { sessionStorage.setItem(KEY, String(window.scrollY)); } catch (e) {}
      location.reload();
    }
  }, 1000);
})();
</script>
"""


def _toolbar(modules: List[str], total: int) -> str:
    sev_chips = "".join(
        '<button class="chip sev-chip on" data-filter="sev" data-value="%s">%s</button>'
        % (s, s) for s in ("critical", "high", "medium", "low", "info"))
    tri_chips = "".join(
        '<button class="chip tri-chip on" data-filter="triage" data-value="%s">%s</button>'
        % (t, t.lower()) for t in ("CHASE", "LOOK", "NOTE"))
    mods = "".join('<option value="%s">%s</option>' % (_e(m), _e(m)) for m in modules)
    return (
        '<div class="toolbar" id="toolbar">'
        '<input id="q" type="search" placeholder="filter findings&hellip;  ( / )" '
        'autocomplete="off" spellcheck="false">'
        '<div class="chips">%s</div>'
        '<div class="chips">%s</div>'
        '<select id="mod"><option value="">all modules</option>%s</select>'
        '<label class="cbx"><input type="checkbox" id="onlyconf"> confirmed only</label>'
        '<span class="count"><b id="shown">%d</b> / %d</span>'
        '<button class="chip" id="reset">reset</button>'
        '</div>' % (sev_chips, tri_chips, mods, total, total))


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
        '<div class="meta">%s%s &middot; profile <b>%s</b> &middot; %.0fs</div></div>'
        '<div class="tiles">%s</div>%s</header>'
        % (("<b>%s</b> &middot; " % _e(meta.get("codename")))
           if meta.get("codename") else "",
           _e(time.strftime("%Y-%m-%d %H:%M")), _e(meta.get("profile", "standard")),
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


def _start_here(findings: List[Finding], store: Store) -> str:
    """The three things to do first, stated as actions rather than findings."""
    top = [f for f in findings if f.triage == "CHASE"][:3]
    if not top:
        top = findings[:3]
    if not top:
        return ""
    rows = []
    for i, f in enumerate(top, 1):
        ai = store.ai_for(f.fingerprint())
        step = ""
        if ai and ai.get("next_steps"):
            step = ai["next_steps"][0]
        elif f.repro:
            step = f.repro
        rows.append(
            '<li><a href="#f-%s">%s</a>'
            '<div class="sh-why">%s</div>'
            '<code class="sh-cmd">%s</code></li>'
            % (f.fingerprint(), _e(f.title), _e(f.impact[:190]), _e(step[:220]))
        )
    return ('<section class="start"><h2>Start here</h2><ol>%s</ol></section>'
            % "".join(rows))


def _finding_card(f: Finding, store: Store) -> str:
    fid = f.fingerprint()
    ai = store.ai_for(fid)
    try:
        is_new = store.is_new_this_run(fid)
        status = store.status_of(fid)
    except Exception:
        is_new, status = False, "new"
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

    try:
        from assay import submission
        draft = submission.draft(f, ai)
    except Exception:
        draft = ""

    haystack = " ".join([f.title, f.target, f.module, f.category, f.cwe,
                         f.impact, f.detail, " ".join(f.tags)]).lower()

    # Named placeholders, not positional. Twice now a field was added to the
    # template without its argument (or the reverse), silently shifting every
    # value after it and crashing the build. With names, editing one side
    # without the other is impossible to get wrong.
    fields = {
        "id": fid,
        "sev": _e(f.severity),
        "sev_color": SEV_COLOR.get(f.severity, "#8ab4f8"),
        "triage": _e(f.triage),
        "module": _e(f.module),
        "conf": _e(f.confidence),
        "status": _e(status),
        "search": _e(haystack),
        "title": _e(f.title),
        "score": "%.0f" % f.score,
        "target": _e(f.target),
        "impact": _e(f.impact),
        "category": _e(f.category),
        "cwe": _e(f.cwe),
        "repro": _e(f.repro),
        "tags": tags,
        "refs": refs,
        "new_badge": '<span class="newbadge">new</span>' if is_new else "",
        "status_badge": ('<span class="statusbadge s-{0}">{0}</span>'.format(_e(status))
                         if status not in ("new", "") else ""),
        "detail_row": ('<div class="row"><span class="k">Detail</span>'
                       '<span>%s</span></div>' % _e(f.detail)) if f.detail else "",
        "evidence": ('<details><summary>Evidence (%d)</summary>%s</details>'
                     % (len(f.evidence), ev_html)) if ev_html else "",
        "ai": ai_html,
        "draft": ('<details class="draft"><summary>Submission draft</summary>'
                  '<button class="copy wide" data-copy="%s">copy draft</button>'
                  '<pre>%s</pre></details>' % (_e(draft), _e(draft))) if draft else "",
    }
    return (
        '<article class="card" id="f-{id}" data-sev="{sev}" data-triage="{triage}" '
        'data-module="{module}" data-conf="{conf}" data-status="{status}" '
        'data-search="{search}" tabindex="-1">'
        '<div class="card-head">'
        '<span class="sev" style="background:{sev_color}">{sev}</span>'
        '<span class="conf">{conf}</span>'
        '<h3>{title}</h3>{new_badge}{status_badge}'
        '<span class="score" title="priority score">{score}</span>'
        '</div>'
        '<div class="target">{target}</div>'
        '<div class="row"><span class="k">Impact</span><span>{impact}</span></div>'
        '{detail_row}'
        '<div class="row"><span class="k">Class</span><span>{category} {cwe} '
        '<span class="modtag">{module}</span></span></div>'
        '<div class="row"><span class="k">Repro</span>'
        '<span class="cmdwrap"><code>{repro}</code>'
        '<button class="copy" data-copy="{repro}">copy</button></span></div>'
        '<div class="tags">{tags} {refs}</div>'
        '{evidence}'
        '{ai}'
        '{draft}'
        '</article>'
    ).format(**fields)




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

/* ---------- toolbar ---------- */
.toolbar{position:sticky;top:0;z-index:20;display:flex;flex-wrap:wrap;gap:10px;align-items:center;
  padding:12px 32px;background:var(--card);border-bottom:1px solid var(--line);
  backdrop-filter:saturate(140%) blur(6px)}
#q{flex:1 1 240px;min-width:180px;background:var(--bg);color:var(--fg);border:1px solid var(--line);
  border-radius:6px;padding:7px 11px;font:inherit;font-size:13px}
#q:focus{outline:2px solid var(--acc);outline-offset:1px}
.chips{display:flex;gap:5px;flex-wrap:wrap}
.chip{background:var(--bg);color:var(--dim);border:1px solid var(--line);border-radius:20px;
  padding:4px 11px;font-size:11.5px;cursor:pointer;font-family:inherit;transition:all .12s}
.chip:hover{border-color:var(--acc);color:var(--fg)}
.chip.on{background:var(--acc);border-color:var(--acc);color:#0b0d10;font-weight:600}
#mod{background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;
  padding:6px 9px;font:inherit;font-size:12px}
.cbx{display:flex;align-items:center;gap:5px;font-size:12px;color:var(--dim);cursor:pointer}
.count{font-size:12px;color:var(--dim);font-variant-numeric:tabular-nums;margin-left:auto}
.count b{color:var(--fg)}

/* ---------- start here ---------- */
.start{margin:26px 32px 0;background:var(--card);border:1px solid var(--line);
  border-left:3px solid var(--acc);border-radius:8px;padding:16px 20px}
.start h2{font-size:14px;margin:0 0 10px;text-transform:uppercase;letter-spacing:.08em;color:var(--acc)}
.start ol{margin:0;padding-left:20px}
.start li{margin-bottom:12px;font-size:14px}
.start li a{color:var(--fg);font-weight:600;text-decoration:none}
.start li a:hover{color:var(--acc);text-decoration:underline}
.sh-why{color:var(--dim);font-size:12.5px;margin:2px 0 5px}
.sh-cmd{display:block;font-size:11.5px;background:var(--bg);border:1px solid var(--line);
  border-radius:5px;padding:5px 9px;overflow-x:auto;white-space:pre}

/* ---------- copy buttons ---------- */
.cmdwrap{display:flex;gap:8px;align-items:flex-start;flex:1;min-width:0}
.cmdwrap code{flex:1;min-width:0}
.copy{background:var(--bg);border:1px solid var(--line);color:var(--dim);border-radius:5px;
  padding:2px 9px;font-size:11px;cursor:pointer;font-family:inherit;flex-shrink:0}
.copy:hover{border-color:var(--acc);color:var(--acc)}
.copy.done{background:#2f7a4d;border-color:#2f7a4d;color:#fff}
.copy.wide{margin-bottom:8px}
.statusbadge{border-radius:4px;padding:1px 7px;font-size:10.5px;font-weight:700;
  text-transform:uppercase;letter-spacing:.05em;background:var(--line);color:var(--dim)}
.s-reported{background:#2f5f8a;color:#fff}
.s-duplicate,.s-ignored{background:#5f6368;color:#fff}
.s-false-positive{background:#7a3510;color:#fff}
.s-in-progress{background:#8a6a12;color:#fff}
.newbadge{background:#2f7a4d;color:#fff;border-radius:4px;padding:1px 7px;
  font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.05em}
.modtag{background:var(--line);color:var(--dim);border-radius:4px;padding:1px 6px;font-size:11px}
.card:target{box-shadow:0 0 0 2px var(--acc)}
.livebar{position:sticky;top:0;z-index:30;display:flex;gap:10px;align-items:center;flex-wrap:wrap;
  padding:9px 32px;background:#8a3d12;color:#fff;font-size:12.5px}
@media(prefers-color-scheme:dark){.livebar{background:#7a3510}}
.livebar .dim{opacity:.8}
.livebar .cbx{color:#fff}
.livebar .dot{width:8px;height:8px;border-radius:50%;background:#ffd166;
  animation:pulse 1.4s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.25}}
@media(prefers-reduced-motion:reduce){.livebar .dot{animation:none}}
.card.hidden{display:none}
.bucket.empty{display:none}
.draft pre{max-height:420px}
kbd{background:var(--bg);border:1px solid var(--line);border-bottom-width:2px;border-radius:4px;
  padding:1px 5px;font-size:11px;font-family:ui-monospace,monospace}
</style></head><body><main>"""

_SCRIPT = """
<script>
(function () {
  var cards = Array.prototype.slice.call(document.querySelectorAll('.card'));
  var q = document.getElementById('q');
  var mod = document.getElementById('mod');
  var onlyconf = document.getElementById('onlyconf');
  var shown = document.getElementById('shown');
  var KEY = 'assay.filters';

  function activeSet(kind) {
    var out = {};
    document.querySelectorAll('[data-filter="' + kind + '"].on').forEach(function (b) {
      out[b.dataset.value] = true;
    });
    return out;
  }

  function apply() {
    var text = (q.value || '').toLowerCase().trim();
    var sev = activeSet('sev'), tri = activeSet('triage');
    var m = mod.value, conf = onlyconf.checked, n = 0;
    cards.forEach(function (c) {
      var ok = sev[c.dataset.sev] && tri[c.dataset.triage];
      if (ok && m && c.dataset.module !== m) ok = false;
      if (ok && conf && c.dataset.conf !== 'confirmed') ok = false;
      if (ok && text && c.dataset.search.indexOf(text) === -1) ok = false;
      c.classList.toggle('hidden', !ok);
      if (ok) n++;
    });
    shown.textContent = n;
    // hide a bucket heading when everything under it is filtered out
    document.querySelectorAll('section.bucket').forEach(function (s) {
      var vis = s.querySelectorAll('.card:not(.hidden)').length;
      s.classList.toggle('empty', vis === 0 && s.querySelectorAll('.card').length > 0);
    });
    try {
      localStorage.setItem(KEY, JSON.stringify({
        q: q.value, mod: mod.value, conf: conf,
        sev: Object.keys(sev), tri: Object.keys(tri)
      }));
    } catch (e) {}
  }

  document.querySelectorAll('.chip[data-filter]').forEach(function (b) {
    b.addEventListener('click', function () { b.classList.toggle('on'); apply(); });
  });
  [q, mod, onlyconf].forEach(function (el) {
    el.addEventListener('input', apply);
    el.addEventListener('change', apply);
  });
  var reset = document.getElementById('reset');
  if (reset) reset.addEventListener('click', function () {
    q.value = ''; mod.value = ''; onlyconf.checked = false;
    document.querySelectorAll('.chip[data-filter]').forEach(function (b) {
      b.classList.add('on');
    });
    apply();
  });

  try {
    var saved = JSON.parse(localStorage.getItem(KEY) || 'null');
    if (saved) {
      q.value = saved.q || ''; mod.value = saved.mod || '';
      onlyconf.checked = !!saved.conf;
      document.querySelectorAll('.chip[data-filter]').forEach(function (b) {
        var list = b.dataset.filter === 'sev' ? saved.sev : saved.tri;
        if (list) b.classList.toggle('on', list.indexOf(b.dataset.value) !== -1);
      });
    }
  } catch (e) {}

  // copy buttons
  document.addEventListener('click', function (e) {
    var b = e.target.closest('.copy');
    if (!b) return;
    var text = b.getAttribute('data-copy') || '';
    var done = function () {
      var old = b.textContent;
      b.textContent = 'copied'; b.classList.add('done');
      setTimeout(function () { b.textContent = old; b.classList.remove('done'); }, 1200);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {});
    } else {
      var ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); done(); } catch (err) {}
      document.body.removeChild(ta);
    }
  });

  // keyboard: / focus search, j/k move, o toggle evidence, Esc blur
  var idx = -1;
  function visible() { return cards.filter(function (c) { return !c.classList.contains('hidden'); }); }
  function focusAt(i) {
    var v = visible(); if (!v.length) return;
    idx = Math.max(0, Math.min(i, v.length - 1));
    v[idx].scrollIntoView({ block: 'center', behavior: 'smooth' });
    v[idx].focus({ preventScroll: true });
  }
  document.addEventListener('keydown', function (e) {
    var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
    if (e.key === 'Escape') { document.activeElement.blur(); return; }
    if (typing) return;
    if (e.key === '/') { e.preventDefault(); q.focus(); q.select(); }
    else if (e.key === 'j') { e.preventDefault(); focusAt(idx + 1); }
    else if (e.key === 'k') { e.preventDefault(); focusAt(idx - 1); }
    else if (e.key === 'o') {
      var v = visible()[idx]; if (!v) return;
      v.querySelectorAll('details').forEach(function (d) { d.open = !d.open; });
    }
  });

  apply();
})();
</script>
"""

_FOOT = ("</main><footer>Generated by assay. Every finding lists the evidence it "
         "was derived from - verify before reporting.<br>"
         "<kbd>/</kbd> search &middot; <kbd>j</kbd>/<kbd>k</kbd> move &middot; "
         "<kbd>o</kbd> expand evidence</footer>" + _SCRIPT + "</body></html>")
