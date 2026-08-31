"""Terminal UI.

A live dashboard while the scan runs, then a ranked summary you can act on
without opening the report. Deliberately cheap to render: this runs on a small
VM, so refresh is throttled and the findings table is capped.
"""

from __future__ import annotations

import shutil
import time
from collections import deque
from typing import Deque, Dict, List, Optional

from rich.align import Align
from rich.box import ROUNDED, SIMPLE
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from assay.models import Finding
from assay.store import Store

console = Console()

SEV_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "green",
    "info": "dim cyan",
}
TRIAGE_STYLE = {"CHASE": "bold red", "LOOK": "yellow", "NOTE": "dim"}

BANNER = r"""
   ___ ________ ___   __ __
  / _ | __/ __/ _ | \ / / /   assay
 / __ |__ \_\ \ __ |\ V / /    what in this ore is worth extracting
/_/ |_|___/___/_/ |_| \_/     
"""


class Dashboard:
    """Live scan view. Pass .progress as the engine's progress callback."""

    def __init__(self, targets: int, profile: str, quiet: bool = False,
                 codename: str = "") -> None:
        self.targets = targets
        self.profile = profile
        self.codename = codename
        self.quiet = quiet
        self.stage = "starting"
        self.detail = ""
        self.log: Deque[str] = deque(maxlen=6)
        self.hits: Deque[Finding] = deque(maxlen=12)
        self.counts: Dict[str, int] = {"CHASE": 0, "LOOK": 0, "NOTE": 0}
        self.started = time.time()
        self._live: Optional[Live] = None
        self._last_render = 0.0

    # -- lifecycle ---------------------------------------------------------
    def __enter__(self) -> "Dashboard":
        if not self.quiet:
            console.print(Text(BANNER, style="bold cyan"))
            self._live = Live(self._render(), console=console, refresh_per_second=4,
                              transient=False)
            self._live.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        if self._live:
            self._live.update(self._render())
            self._live.__exit__(*exc)
            self._live = None

    # -- engine callback ---------------------------------------------------
    def progress(self, stage: str, msg: str, advance: int = 0) -> None:
        if stage == "finding":
            return
        self.stage = stage
        self.detail = msg
        if advance == 0:
            line = "[%s] %s" % (stage, msg)
            if not self.log or self.log[-1] != line:
                self.log.append(line)
        self._maybe_render()

    def on_finding(self, f: Finding) -> None:
        self.counts[f.triage] = self.counts.get(f.triage, 0) + 1
        if f.triage in ("CHASE", "LOOK"):
            self.hits.append(f)
        self._maybe_render()

    def _maybe_render(self) -> None:
        now = time.time()
        if self._live and now - self._last_render > 0.2:
            self._last_render = now
            self._live.update(self._render())

    # -- rendering ---------------------------------------------------------
    def _render(self):
        width = shutil.get_terminal_size((100, 30)).columns

        head = Table.grid(expand=True)
        head.add_column(justify="left")
        head.add_column(justify="right")
        head.add_row(
            Text.assemble(*(((self.codename + "  ", "bold magenta"),) if self.codename else ()),
                          ("targets ", "dim"), (str(self.targets), "bold"),
                          ("   profile ", "dim"), (self.profile, "bold"),
                          ("   stage ", "dim"), (self.stage, "bold cyan")),
            Text.assemble(
                (str(self.counts.get("CHASE", 0)), "bold red"), (" chase  ", "dim"),
                (str(self.counts.get("LOOK", 0)), "yellow"), (" look  ", "dim"),
                (str(self.counts.get("NOTE", 0)), "dim"), (" note  ", "dim"),
                ("%.0fs" % (time.time() - self.started), "dim"),
            ),
        )

        hits = Table(box=SIMPLE, expand=True, show_edge=False, pad_edge=False)
        hits.add_column("", width=6)
        hits.add_column("finding", overflow="ellipsis", no_wrap=True)
        hits.add_column("target", overflow="ellipsis", no_wrap=True,
                        max_width=max(24, width // 3))
        hits.add_column("", justify="right", width=5)
        if self.hits:
            for f in list(self.hits)[-10:]:
                hits.add_row(
                    Text(f.triage, style=TRIAGE_STYLE.get(f.triage, "")),
                    Text(f.title, style=SEV_STYLE.get(f.severity, "")),
                    Text(f.target, style="cyan"),
                    Text("%.0f" % f.score, style="dim"),
                )
        else:
            hits.add_row("", Text("no findings yet", style="dim"), "", "")

        log = Text("\n".join(self.log) or "warming up", style="dim")

        return Panel(
            Group(head, Text(""), hits, Text(""), log),
            title="[bold]assay[/bold]",
            subtitle=Text(self.detail[:width - 12], style="dim"),
            box=ROUNDED,
            border_style="cyan",
        )


# --------------------------------------------------------------------------
# Static views
# --------------------------------------------------------------------------


def inventory(store: Store, limit_hosts: int = 60) -> None:
    """What was found, before what was wrong with it.

    A scan that reports "no findings" and nothing else is indistinguishable
    from a scan that never reached the targets - which is exactly how a broken
    target list looks. Listing the hosts, their open services and the live web
    endpoints separates "there was nothing wrong" from "there was nothing
    there".
    """
    import json as _json

    hosts = store.host_rows()
    web = store.web_rows()
    if not hosts and not web:
        return

    if hosts:
        t = Table(box=ROUNDED, expand=True, title="Hosts and services",
                  title_style="bold")
        t.add_column("host", overflow="fold")
        t.add_column("ip", style="dim", overflow="fold")
        t.add_column("open", width=5, justify="right", style="dim")
        t.add_column("services", overflow="fold")
        shown = 0
        for r in hosts:
            try:
                data = _json.loads(r["data"] or "{}")
            except ValueError:
                data = {}
            ports = data.get("ports") or []
            if not ports:
                continue
            desc = []
            for p in sorted(ports, key=lambda x: x.get("port", 0)):
                bits = [str(p.get("port"))]
                svc = p.get("service") or ""
                prod = " ".join(x for x in (p.get("product"), p.get("version")) if x)
                if svc:
                    bits.append("/" + svc)
                label = "".join(bits)
                if prod:
                    label += " (%s)" % prod[:38]
                desc.append(label)
            t.add_row(r["host"], r["ip"] or "-", str(len(ports)), ", ".join(desc))
            shown += 1
            if shown >= limit_hosts:
                break
        if shown:
            console.print(t)
            silent = len(hosts) - shown
            if silent > 0:
                console.print("  [dim]%d host(s) had no open ports[/dim]" % silent)

    if web:
        t = Table(box=ROUNDED, expand=True, title="Live web endpoints",
                  title_style="bold")
        t.add_column("url", overflow="fold", style="cyan")
        t.add_column("code", width=4, justify="right")
        t.add_column("title", overflow="fold")
        t.add_column("server", overflow="fold", style="dim")
        t.add_column("tech", overflow="fold", style="dim")
        for r in web[:limit_hosts]:
            try:
                tech = ", ".join(_json.loads(r["tech"] or "[]")[:4])
            except ValueError:
                tech = ""
            code = r["status"] or 0
            style = ("green" if 200 <= code < 300 else
                     "yellow" if code in (401, 403) else
                     "cyan" if 300 <= code < 400 else "dim")
            t.add_row(r["url"], Text(str(code), style=style),
                      (r["title"] or "")[:60], r["server"] or "", tech)
        console.print(t)
        if len(web) > limit_hosts:
            console.print("  [dim]... and %d more endpoint(s)[/dim]"
                          % (len(web) - limit_hosts))


def summary(store: Store, assets: Dict, limit: int = 25) -> None:
    counts = store.counts()
    findings = store.findings(limit=limit)

    t = Table(box=ROUNDED, expand=True, title="Top findings by priority",
              title_style="bold")
    t.add_column("#", width=3, justify="right", style="dim")
    t.add_column("triage", width=6)
    t.add_column("sev", width=8)
    t.add_column("conf", width=10, style="dim")
    t.add_column("finding", overflow="fold")
    t.add_column("target", overflow="fold", style="cyan")
    t.add_column("score", width=5, justify="right", style="dim")

    if not findings:
        hosts = len([h for h in store.host_rows()])
        web = len(store.web_rows())
        if web or hosts:
            console.print(Panel(
                "No findings, but the scan did reach the targets: %d host(s) and "
                "%d live web endpoint(s) are listed above. Nothing matched a "
                "check - which on a hardened estate is a real result, not a "
                "failure." % (hosts, web),
                border_style="yellow"))
        else:
            console.print(Panel(
                "Nothing was reached. No host answered and no endpoint was "
                "found, so there was nothing to test.\n\n"
                "Check in this order: [bold]assay scope <your input>[/bold] to "
                "confirm the targets parsed; whether the hosts are reachable "
                "from here; and [bold]assay doctor[/bold] for missing tools.",
                border_style="red"))
        return

    for i, f in enumerate(findings, 1):
        t.add_row(
            str(i),
            Text(f.triage, style=TRIAGE_STYLE.get(f.triage, "")),
            Text(f.severity, style=SEV_STYLE.get(f.severity, "")),
            f.confidence,
            f.title,
            f.target,
            "%.0f" % f.score,
        )
    console.print(t)

    console.print(
        Text.assemble(
            ("\n  ", ""),
            ("%d chase" % counts.get("CHASE", 0), "bold red"), ("  ", ""),
            ("%d look" % counts.get("LOOK", 0), "yellow"), ("  ", ""),
            ("%d context" % counts.get("NOTE", 0), "dim"), ("   ", ""),
            ("%d hosts / %d web endpoints / %d requests in %ss"
             % (assets.get("hosts", 0), assets.get("web", 0),
                assets.get("requests", 0), assets.get("duration", 0)), "dim"),
        )
    )


def detail(f: Finding, ai: Optional[Dict] = None) -> None:
    body = Table.grid(padding=(0, 2))
    body.add_column(style="dim", width=10)
    body.add_column(overflow="fold")
    body.add_row("target", Text(f.target, style="cyan"))
    body.add_row("severity", Text("%s (%s)" % (f.severity, f.confidence),
                                  style=SEV_STYLE.get(f.severity, "")))
    body.add_row("class", "%s  %s" % (f.category, f.cwe))
    body.add_row("impact", f.impact)
    if f.detail:
        body.add_row("detail", f.detail)
    body.add_row("repro", Text(f.repro, style="green"))
    if f.refs:
        body.add_row("refs", "\n".join(f.refs))
    for e in f.evidence[:2]:
        body.add_row("evidence", Text(e.compact(700), style="dim"))
    if ai:
        body.add_row("ai", "%s (fp risk %s)\n%s\n%s" % (
            ai.get("verdict", ""), ai.get("fp_risk", ""), ai.get("rationale", ""),
            "\n".join("- " + s for s in ai.get("next_steps", []))))
    console.print(Panel(body, title=Text(f.title, style="bold"), border_style="cyan"))


def tool_table(available: Dict[str, Optional[str]], registry: Dict) -> Table:
    t = Table(box=ROUNDED, title="External tools", title_style="bold", expand=True)
    t.add_column("tool", width=12)
    t.add_column("", width=3)
    t.add_column("what assay uses it for", overflow="fold")
    t.add_column("install", overflow="fold", style="dim")
    for name, spec in registry.items():
        ok = bool(available.get(name))
        t.add_row(
            name,
            Text("OK" if ok else "--", style="green" if ok else "yellow"),
            spec.purpose,
            "" if ok else spec.install,
        )
    return t
