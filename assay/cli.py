"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import textwrap
from typing import Dict, List, Optional

from assay import __version__, env, tools
from assay.burp import BurpBridge
from assay.config import BurpConfig, Config, Scope, ScopeError, PROFILES
from assay.store import Store
import time

from assay import report as report_mod
from rich.text import Text

from assay.ui import (Dashboard, SEV_STYLE, console, detail as show_detail,
                      summary, tool_table)

EPILOG = """\
examples:
  assay scan 10.10.0.0/24 --scope scope.txt
  assay scan https://app.target.tld --profile deep --burp auto
  assay scan -f targets.txt --profile quick --open
  assay ai --out ./assay-out --ai-dry-run       # see exactly what would be sent
  assay replay authed.xml --scope scope.txt    # unauth access from a Burp capture
  assay submit 1 > report.md                   # submission draft for finding #1
  assay triage 3 --status reported            # stop a submitted finding resurfacing
  assay followup --scope scope.txt             # preview the AI's verify commands
  assay followup --scope scope.txt --run       # un-redact and execute them
  assay doctor                                  # tools, Burp, WSL, resources
  assay install --dry-run                       # preview external tool install
  assay install -y                              # install everything missing
  assay scan 10.0.0.0/24 --basic admin:admin    # behind HTTP Basic auth
  assay scan target.tld --expand --passive      # grow the surface first
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assay",
        description="Signal-first recon and triage for authorized offensive testing.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version="assay %s" % __version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    # -- scan --------------------------------------------------------------
    s = sub.add_parser("scan", help="run a scan", formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("targets", nargs="*", help="hosts, CIDRs or URLs")
    s.add_argument("-f", "--targets-file", help="file with one target per line")
    s.add_argument("-p", "--profile", choices=sorted(PROFILES), default="standard")
    s.add_argument("-o", "--out", default="./assay-out",
                   help="root output directory; each engagement gets its own subfolder")
    s.add_argument("-n", "--codename", default="",
                   help="engagement codename - names the output folder and the report")
    s.add_argument("--flat", action="store_true",
                   help="write straight into --out instead of a per-engagement subfolder")
    s.add_argument("--scope", help="scope file (allow list; '!' prefix excludes)")

    s.add_argument("-c", "--concurrency", type=int, help="worker threads (auto by default)")
    s.add_argument("-r", "--rate", type=float, help="global requests/second ceiling")
    s.add_argument("--timeout", type=float, default=12.0)
    s.add_argument("--retries", type=int, default=1)

    p_ = s.add_argument_group("pacing and client safety")
    p_.add_argument("--rate-per-host", type=float, default=8.0, metavar="N",
                    help="per-host requests/second ceiling (0 disables). The global "
                         "--rate alone still lets every worker pile onto one host.")
    p_.add_argument("--delay", type=float, default=0.0, metavar="SEC",
                    help="extra jittered pause before each request")
    p_.add_argument("--safe", action="store_true",
                    help="retrieval only: skip every module that sends crafted "
                         "input, unusual verbs or fuzzing traffic")
    p_.add_argument("--proxied-ports", default="", metavar="80,443",
                    help="ports your testing network proxies for every address. "
                         "A connect on these proves nothing, so assay judges them "
                         "purely on the response and will not report them as "
                         "exposed services.")
    p_.add_argument("--no-gateway-filter", action="store_true",
                    help="keep endpoints that look like a proxy's default response. "
                         "By default, when most addresses answer 80/443 identically, "
                         "assay treats that response as 'no service' rather than as "
                         "hundreds of web servers.")
    p_.add_argument("--no-journal", action="store_true",
                    help="do not record activity.log / replay.sh")

    s.add_argument("--no-portscan", action="store_true", help="targets are already URLs")
    s.add_argument("--passive", action="store_true",
                   help="allow third-party OSINT sources (off by default)")
    s.add_argument("--aggressive", action="store_true",
                   help="enable checks that may change state")
    s.add_argument("--only", help="comma-separated module allow list")
    s.add_argument("--skip", help="comma-separated module deny list")

    s.add_argument("-H", "--header", action="append", default=[],
                   help="extra request header, repeatable ('Name: value')")
    s.add_argument("--basic", metavar="USER:PASS",
                   help="HTTP Basic credentials, applied to assay and its tools")
    s.add_argument("--cookie", default="", help="Cookie header to send with every request")
    s.add_argument("--ua", help="override User-Agent")

    g = s.add_argument_group("surface expansion and blind checks")
    g.add_argument("--expand", action="store_true",
                   help="grow the target list: permutations, DNS resolution, "
                        "and (with --passive) CT logs and subdomain sources")
    g.add_argument("--oob-domain", default="", metavar="DOMAIN",
                   help="collaborator domain for blind SSRF payloads; without it "
                        "assay uses interactsh-client when installed")
    g.add_argument("--no-oob", action="store_true",
                   help="do not fire out-of-band payloads at all")

    s.add_argument("--burp", nargs="?", const="auto", metavar="URL",
                   help="proxy through Burp; 'auto' discovers the listener (WSL aware)")
    s.add_argument("--burp-api", nargs="?", const="auto", metavar="URL",
                   help="Burp Professional REST API base URL")
    s.add_argument("--burp-key", help="Burp REST API key")
    s.add_argument("--burp-mirror", action="store_true",
                   help="replay each finding's request through Burp when done")
    s.add_argument("--burp-scan", action="store_true",
                   help="queue a Burp Professional active scan on interesting URLs")

    s.add_argument("--install-missing", action="store_true",
                   help="install any missing external tools before scanning")

    _ai_flags(s)
    s.add_argument("--no-report", action="store_true")
    s.add_argument("--no-live", action="store_true",
                   help="do not update the report while the scan runs")
    s.add_argument("--open", action="store_true",
                   help="open the report as soon as it starts filling in")
    s.add_argument("-q", "--quiet", action="store_true")

    # -- other commands ----------------------------------------------------
    d = sub.add_parser("doctor", help="check tools, Burp reachability and resources")
    d.add_argument("--burp", nargs="?", const="auto", metavar="URL")

    r = sub.add_parser("report", help="rebuild the HTML report from a previous run")
    r.add_argument("-o", "--out", default="./assay-out")
    r.add_argument("--open", action="store_true")

    a = sub.add_parser("ai", help="run AI triage over an existing run")
    a.add_argument("-o", "--out", default="./assay-out")
    _ai_flags(a, standalone=True)

    sh = sub.add_parser("show", help="print one finding in full")
    sh.add_argument("rank", help="rank number from the summary table, or a finding id")
    sh.add_argument("-o", "--out", default="./assay-out")

    b = sub.add_parser("burp", help="push a finished run into Burp")
    b.add_argument("-o", "--out", default="./assay-out")
    b.add_argument("--burp", nargs="?", const="auto", metavar="URL")
    b.add_argument("--burp-api", nargs="?", const="auto", metavar="URL")
    b.add_argument("--burp-key")
    b.add_argument("--mirror", action="store_true", help="replay finding requests")
    b.add_argument("--scan", action="store_true", help="queue an active scan (Pro)")
    b.add_argument("--scope-file", help="write a Burp-importable scope JSON here")

    sb = sub.add_parser("submit", help="generate submission drafts for findings")
    sb.add_argument("rank", nargs="?", help="rank number or finding id (default: all)")
    sb.add_argument("-o", "--out", default="./assay-out")
    sb.add_argument("--min", dest="min_triage", default="LOOK",
                    choices=["CHASE", "LOOK", "NOTE"],
                    help="lowest triage bucket to include (default LOOK)")
    sb.add_argument("--write", metavar="FILE",
                    help="write the drafts to a markdown file instead of stdout")

    rp = sub.add_parser("replay",
                        help="replay an authenticated Burp/HAR capture without "
                             "credentials to find unauthenticated access")
    rp.add_argument("capture", help="Burp XML item export, or a .har file")
    rp.add_argument("-o", "--out", default="./assay-out")
    rp.add_argument("--scope", help="scope file")
    rp.add_argument("--aggressive", action="store_true",
                    help="also replay non-GET requests (these may change state)")
    rp.add_argument("--limit", type=int, default=200)
    rp.add_argument("-r", "--rate", type=float, default=10.0)
    rp.add_argument("--burp", nargs="?", const="auto", metavar="URL",
                    help="send the replayed requests through Burp as well")

    fu = sub.add_parser("followup",
                        help="run the AI's verification commands (un-redacted)")
    fu.add_argument("-o", "--out", default="./assay-out")
    fu.add_argument("--run", action="store_true",
                    help="actually execute; without this the commands are only printed")
    fu.add_argument("-y", "--yes", action="store_true",
                    help="approve every command up front instead of one at a time")
    fu.add_argument("--scope", help="scope file (required to execute)")
    fu.add_argument("--timeout", type=float, default=120.0)
    fu.add_argument("--limit", type=int, default=25)

    i = sub.add_parser("install", help="install the external tools assay orchestrates")
    i.add_argument("--only", help="comma-separated tool names (default: everything missing)")
    i.add_argument("--required-only", action="store_true",
                   help="only tools assay cannot work well without")
    i.add_argument("-n", "--dry-run", action="store_true",
                   help="print the exact commands and exit without running them")
    i.add_argument("-y", "--yes", action="store_true", help="skip the confirmation")

    tr = sub.add_parser("triage",
                        help="record your verdict on a finding so it stops resurfacing")
    tr.add_argument("rank", nargs="?", help="rank number or finding id")
    tr.add_argument("-s", "--status", default="reported",
                    choices=["reported", "duplicate", "false-positive",
                             "ignored", "in-progress", "new"])
    tr.add_argument("--note", default="", help="why - kept with the finding")
    tr.add_argument("-o", "--out", default="./assay-out")
    tr.add_argument("--list", action="store_true",
                    help="show every finding with its current status")

    df = sub.add_parser("diff", help="what changed since the previous run")
    df.add_argument("-o", "--out", default="./assay-out")
    df.add_argument("--run", type=int, help="run id (default: the latest)")

    sub.add_parser("modules", help="list detection modules")
    return p


def _ai_flags(p: argparse.ArgumentParser, standalone: bool = False) -> None:
    g = p.add_argument_group("AI triage (opt-in, redacted)")
    if not standalone:
        g.add_argument("--ai", action="store_true",
                       help="after the scan, send REDACTED findings to Claude for triage")
    g.add_argument("--ai-model", default="claude-opus-5")
    g.add_argument("--ai-max", type=int, default=60, help="max findings to send")
    g.add_argument("--ai-evidence", action="store_true",
                   help="include redacted evidence snippets (default: metadata only)")
    g.add_argument("--ai-dry-run", action="store_true",
                   help="write the exact redacted payload and send nothing")
    g.add_argument("--ai-yes", action="store_true", help="skip the send confirmation")
    g.add_argument("--ai-effort", default="high",
                   choices=["low", "medium", "high", "xhigh", "max"])


# --------------------------------------------------------------------------


def resolve_run_dir(path: str) -> str:
    """Accept either a run directory or the root that holds several.

    `assay report -o ./assay-out` should keep working after runs started being
    written to ./assay-out/<target>/, so when the given path has no database
    but its children do, pick the most recent child.
    """
    if os.path.exists(os.path.join(path, "assay.db")):
        return path
    try:
        subs = [os.path.join(path, d) for d in os.listdir(path)]
    except OSError:
        return path
    runs = [d for d in subs if os.path.isfile(os.path.join(d, "assay.db"))]
    if not runs:
        return path
    newest = max(runs, key=lambda d: os.path.getmtime(os.path.join(d, "assay.db")))
    if len(runs) > 1:
        console.print("  [dim]%d runs under %s; using the most recent: %s[/dim]"
                      % (len(runs), path, os.path.basename(newest)))
    return newest


def open_run(path: str, what: str = "results"):
    """Open an existing run, or explain why there isn't one.

    Store() creates the database if it is missing, so without this check every
    read command silently produces an empty result in a directory that was
    never scanned - and leaves a stray assay.db behind.
    """
    run_dir = resolve_run_dir(path)
    db = os.path.join(run_dir, "assay.db")
    if not os.path.isfile(db):
        console.print("[yellow]no scan found in %s[/yellow]" % path)
        console.print("  [dim]run one first:[/dim]  assay scan <target> "
                      "--scope scope.txt -n CODENAME")
        console.print("  [dim]or point -o at the folder that holds it; each "
                      "engagement gets its own subfolder[/dim]")
        return None, run_dir
    return Store(db), run_dir


def make_config(args) -> Config:
    targets: List[str] = list(getattr(args, "targets", []) or [])
    if getattr(args, "targets_file", None):
        with open(args.targets_file, "r", encoding="utf-8") as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not targets:
        console.print("[red]no targets given[/red]  (positional args or -f file)")
        raise SystemExit(2)

    scope = Scope()
    if getattr(args, "scope", None):
        try:
            scope = Scope.from_file(args.scope)
        except OSError as exc:
            console.print("[red]cannot read scope file:[/red] %s" % exc)
            raise SystemExit(2)

    tune = env.autotune()
    cfg = Config(
        targets=targets,
        profile=args.profile,
        out_dir=args.out,
        scope=scope,
        concurrency=args.concurrency or tune["concurrency"],
        rate=args.rate or tune["rate"],
        rate_per_host=getattr(args, "rate_per_host", 8.0),
        delay=getattr(args, "delay", 0.0),
        safe_mode=getattr(args, "safe", False),
        journal=not getattr(args, "no_journal", False),
        detect_gateway=not getattr(args, "no_gateway_filter", False),
        proxied_ports=[int(x) for x in
                       re.findall(r"\d+", getattr(args, "proxied_ports", "") or "")],
        codename=getattr(args, "codename", "") or "",
        timeout=args.timeout,
        retries=args.retries,
        passive=args.passive,
        portscan=not args.no_portscan,
        expand=getattr(args, "expand", False),
        oob=not getattr(args, "no_oob", False),
        oob_domain=getattr(args, "oob_domain", "") or "",
        aggressive=args.aggressive,
        cookies=args.cookie,
        basic_auth=getattr(args, "basic", None) or "",
        quiet=args.quiet,
    )
    if getattr(args, "basic", None) and ":" not in args.basic:
        console.print("[red]--basic expects USER:PASS[/red]")
        raise SystemExit(2)
    if args.ua:
        cfg.user_agent = args.ua
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            cfg.headers[k.strip()] = v.strip()
    if args.only:
        cfg.only_modules = [x.strip() for x in args.only.split(",") if x.strip()]
    if args.skip:
        cfg.skip_modules = [x.strip() for x in args.skip.split(",") if x.strip()]

    cfg.apply_run_dir(args.out, flat=getattr(args, "flat", False))
    cfg.burp = _burp_config(args)

    if scope.permissive:
        console.print(
            "[yellow]warning:[/yellow] no --scope file given. assay will scan whatever "
            "you named and nothing else, but a scope file is the safety net that stops "
            "a typo or a redirect from touching an out-of-scope host."
        )
    return cfg


def _burp_config(args) -> BurpConfig:
    bc = BurpConfig()
    proxy = getattr(args, "burp", None)
    api = getattr(args, "burp_api", None)
    if proxy:
        bc.proxy = None if proxy == "auto" else proxy
        if proxy == "auto":
            bc.proxy = env.find_burp_proxy()
            if not bc.proxy:
                console.print("[yellow]Burp proxy not found.[/yellow]\n%s" % env.burp_hint())
    if api:
        bc.api_url = None if api == "auto" else api
        if api == "auto":
            bc.api_url = env.find_burp_api()
    bc.api_key = getattr(args, "burp_key", None)
    bc.mirror = bool(getattr(args, "burp_mirror", False))
    bc.scan = bool(getattr(args, "burp_scan", False))
    return bc


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_scan(args) -> int:
    from assay.engine import Engine
    from assay import report as report_mod

    cfg = make_config(args)

    if getattr(args, "install_missing", False):
        _do_install(assume_yes=args.quiet)

    dash = Dashboard(len(cfg.targets), cfg.profile, quiet=cfg.quiet,
                     codename=cfg.codename)

    with dash:
        engine = Engine(cfg, progress=dash.progress)
        original_emit = engine.ctx.emit

        def emit(f):
            new = original_emit(f)
            if new:
                dash.on_finding(f)
            return new

        engine.ctx.emit = emit

        # Keep the report current while the scan runs so the first findings can
        # be worked by hand long before the last host is swept.
        live = not args.no_report and not args.no_live
        report_path = os.path.join(cfg.out_dir, "report.html")
        state = {"last": 0.0, "opened": False}

        def refresh(force: bool = False) -> None:
            if not live:
                return
            now = time.time()
            if not force and now - state["last"] < 4.0:
                return
            state["last"] = now
            try:
                report_mod.build(engine.store, engine.assets(), report_path,
                                 scan_meta={"profile": cfg.profile,
                                            "codename": cfg.codename},
                                 live=True)
            except Exception:
                return
            if args.open and not state["opened"]:
                state["opened"] = True
                env.open_in_browser(report_path)

        original_progress = dash.progress

        def progress(stage: str, msg: str, advance: int = 0) -> None:
            original_progress(stage, msg, advance)
            refresh()

        engine.ctx.progress = progress
        refresh(force=True)

        try:
            engine.run()
        except KeyboardInterrupt:
            console.print("\n[yellow]interrupted - findings so far are saved[/yellow]")
        except ScopeError as exc:
            console.print("[red]scope error:[/red] %s" % exc)
            return 2

    assets = engine.assets()
    summary(engine.store, assets)

    ai_result = None
    if getattr(args, "ai", False):
        ai_result = run_ai(engine.store, cfg, args, assets)

    if cfg.burp.mirror or cfg.burp.scan:
        _burp_push(engine.store, cfg, mirror=cfg.burp.mirror, scan=cfg.burp.scan)

    if not args.no_report:
        path = os.path.join(cfg.out_dir, "report.html")
        report_mod.build(engine.store, assets, path, ai=ai_result,
                         scan_meta={"profile": cfg.profile,
                                    "codename": cfg.codename},
                         live=False)
        console.print("\n  report  [cyan]%s[/cyan]" % path)
        console.print("  data    [dim]%s[/dim]" % cfg.db_path())
        if args.open and not state.get("opened") and not env.open_in_browser(path):
            console.print("  [dim](could not launch a browser; open the path above)[/dim]")

    engine.store.close()
    return 0


def run_ai(store: Store, cfg: Config, args, assets: Dict) -> Optional[Dict]:
    from assay import ai as ai_mod
    from assay.redact import Redactor, terms_from_context

    findings = store.findings()
    if not findings:
        console.print("[yellow]nothing to triage[/yellow]")
        return None

    hosts = [r["host"] for r in store.host_rows()] + [r["host"] for r in store.web_rows()]
    terms = terms_from_context(cfg.targets, cfg.scope.allow, hosts)
    redactor = Redactor(extra_terms=terms)

    ai_cfg = ai_mod.AIConfig(
        enabled=True,
        model=args.ai_model,
        max_findings=args.ai_max,
        include_evidence=args.ai_evidence,
        dry_run=args.ai_dry_run,
        effort=args.ai_effort,
    )

    # Credentials before anything else: no point redacting a payload we cannot
    # send, and no point asking for a key after the user has already waited.
    if not ai_cfg.dry_run:
        have, how = ai_mod.credential_status()
        if have:
            console.print("  [dim]credentials: %s[/dim]" % how)
        elif not ai_mod.prompt_for_key(console):
            console.print("  [yellow]skipping AI triage[/yellow] - no credentials. "
                          "Set ANTHROPIC_API_KEY or run 'ant auth login'.")
            return None

    payload, leaks = ai_mod.build_payload(findings, assets, ai_cfg, redactor)
    if leaks:
        console.print("[red]redaction verification FAILED - nothing was sent.[/red]")
        for l in leaks[:15]:
            console.print("   [red]![/red] %s" % l)
        console.print("[dim]Add the offending values to your scope file so they are "
                      "treated as known client terms, or run without --ai.[/dim]")
        return None

    console.print(
        "\n[bold]AI triage[/bold]  %d finding(s), %s, model %s"
        % (min(len(findings), ai_cfg.max_findings),
           "with redacted evidence" if ai_cfg.include_evidence else "metadata only",
           ai_cfg.model)
    )
    console.print("  [green]redaction verified:[/green] %d pseudonym(s), no residual "
                  "hostnames, IPs, credentials or personal data"
                  % len(redactor.map.reverse))

    if not ai_cfg.dry_run and not args.ai_yes and sys.stdin.isatty():
        console.print("  [dim]this sends the redacted payload to the Anthropic API[/dim]")
        try:
            answer = input("  send? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in ("y", "yes"):
            console.print("  [yellow]skipped[/yellow]")
            ai_cfg.dry_run = True

    try:
        result = ai_mod.analyze(findings, assets, ai_cfg, redactor, cfg.out_dir,
                                on_status=lambda m: console.print("  [dim]%s[/dim]" % m))
    except ai_mod.RedactionFailure as exc:
        console.print("[red]redaction verification failed - nothing sent[/red]")
        for l in exc.leaks[:15]:
            console.print("   [red]![/red] %s" % l)
        return None
    except ai_mod.AIError as exc:
        console.print("[red]AI triage unavailable:[/red] %s" % exc)
        return None

    if result.get("dry_run"):
        console.print("  [yellow]dry run[/yellow] - payload at %s (nothing sent)"
                      % result["payload_path"])
        return None

    store.save_ai(result)
    usage = result.get("_usage", {})
    console.print("  [green]triaged[/green]  %d verdict(s), %d chain(s)  "
                  "[dim]%s in / %s out, ~$%.3f[/dim]"
                  % (len(result.get("triage", [])), len(result.get("chains", [])),
                     usage.get("input_tokens", 0), usage.get("output_tokens", 0),
                     usage.get("cost_estimate_usd", 0.0)))

    local = ai_mod.rehydrate(result, redactor)
    with open(os.path.join(cfg.out_dir, "ai-triage.json"), "w", encoding="utf-8") as fh:
        json.dump(local, fh, indent=2)
    if local.get("summary"):
        console.print("\n[bold]Summary[/bold]\n%s"
                      % textwrap.fill(local["summary"], 96, initial_indent="  ",
                                      subsequent_indent="  "))
    return local


def cmd_ai(args) -> int:
    from assay import report as report_mod
    store, args.out = open_run(args.out, "findings")
    if store is None:
        return 1
    cfg = Config(out_dir=args.out)
    args.ai_yes = getattr(args, "ai_yes", False)
    assets = {"hosts": len(store.host_rows()), "web": len(store.web_rows()),
              "tech": [], "services": []}
    result = run_ai(store, cfg, args, assets)
    if result:
        path = os.path.join(args.out, "report.html")
        report_mod.build(store, assets, path, ai=result)
        console.print("\n  report  [cyan]%s[/cyan]" % path)
    store.close()
    return 0


def cmd_doctor(args) -> int:
    res = env.resources()
    tune = env.autotune(res)
    console.print("[bold]environment[/bold]")
    if env.is_windows():
        if env.use_wsl_bridge():
            console.print("  platform     Windows host, tools via WSL [green](bridge active)[/green]")
            console.print("  distro       %s" % env.wsl_distro())
            gw = env.wsl_gateway_ip()
            console.print("  wsl gateway  %s  [dim](Windows host as WSL sees it)[/dim]"
                          % (gw or "unknown"))
        else:
            console.print("  platform     Windows [red](no WSL distribution found)[/red]")
            console.print("  [yellow]assay runs, but every external scanner is a Linux "
                          "binary.[/yellow] Install WSL with:  wsl --install -d kali-linux")
    elif env.is_wsl():
        console.print("  platform     WSL (%s networking)" % env.wsl_networking_mode())
    else:
        console.print("  platform     %s" % sys.platform)
    console.print("  cpus         %d" % res.cpus)
    console.print("  memory       %d MB available / %d MB total"
                  % (res.mem_avail_mb, res.mem_total_mb))
    console.print("  auto-tuning  %d workers, %.0f req/s%s"
                  % (tune["concurrency"], tune["rate"],
                     "  [yellow](constrained - pacing reduced)[/yellow]"
                     if tune["constrained"] else ""))
    if env.is_wsl():
        console.print("  windows host %s" % (env.windows_host_ip() or "unknown"))

    console.print()
    avail = tools.available()
    console.print(tool_table(avail, tools.REGISTRY))
    missing = [n for n, path in avail.items() if not path]
    if missing:
        console.print("  [dim]%d tool(s) missing.[/dim] Install them with "
                      "[bold]assay install[/bold]  [dim](--dry-run to preview)[/dim]"
                      % len(missing))

    console.print("\n[bold]burp[/bold]")
    bc = BurpConfig()
    if getattr(args, "burp", None) and args.burp != "auto":
        bc.proxy = args.burp
    cfg = Config(burp=bc)
    st = BurpBridge(cfg).detect()
    console.print("  proxy   %s  %s" % ("[green]OK[/green]" if st.proxy_ok else "[yellow]--[/yellow]",
                                        st.proxy or "not found"))
    console.print("  rest    %s  %s" % ("[green]OK[/green]" if st.api_ok else "[yellow]--[/yellow]",
                                        st.api or "not found (Professional only)"))
    if not st.any:
        console.print("[dim]%s[/dim]" % st.detail)

    console.print("\n[bold]ai triage[/bold]")
    try:
        import anthropic  # noqa: F401
        have_sdk = True
    except ImportError:
        have_sdk = False
    console.print("  sdk     %s" % ("[green]installed[/green]" if have_sdk
                                    else "[yellow]not installed[/yellow]  pip install anthropic"))
    if have_sdk:
        from assay import ai as ai_mod
        ok, how = ai_mod.credential_status()
        console.print("  creds   %s  [dim]%s[/dim]"
                      % ("[green]ready[/green]" if ok else "[yellow]none[/yellow]", how))
        if not ok:
            console.print("  [dim]assay will prompt for a key when you use --ai, "
                          "or set ANTHROPIC_API_KEY / run 'ant auth login'[/dim]")
    console.print("  [dim]AI triage is opt-in (--ai) and only ever sends redacted data.[/dim]")
    return 0


def cmd_report(args) -> int:
    from assay import report as report_mod
    store, args.out = open_run(args.out, "results")
    if store is None:
        return 1
    assets = {"hosts": len(store.host_rows()), "web": len(store.web_rows()),
              "requests": 0, "duration": 0}
    ai_path = os.path.join(args.out, "ai-triage.json")
    ai = None
    if os.path.exists(ai_path):
        with open(ai_path, "r", encoding="utf-8") as fh:
            ai = json.load(fh)
    path = report_mod.build(store, assets, os.path.join(args.out, "report.html"), ai=ai)
    console.print("  report  [cyan]%s[/cyan]" % path)
    if args.open:
        env.open_in_browser(path)
    store.close()
    return 0


def cmd_show(args) -> int:
    store, args.out = open_run(args.out, "findings")
    if store is None:
        return 1
    findings = store.findings()
    target = None
    if args.rank.isdigit():
        idx = int(args.rank) - 1
        if 0 <= idx < len(findings):
            target = findings[idx]
    else:
        target = next((f for f in findings if f.fingerprint().startswith(args.rank)), None)
    if target is None:
        console.print("[red]no such finding[/red]")
        return 1
    show_detail(target, store.ai_for(target.fingerprint()))
    store.close()
    return 0


def cmd_burp(args) -> int:
    store, args.out = open_run(args.out, "findings")
    if store is None:
        return 1
    cfg = Config(out_dir=args.out, burp=_burp_config(args))
    bridge = BurpBridge(cfg)
    st = bridge.detect()
    console.print("  proxy %s   rest %s" % (st.proxy_ok, st.api_ok))
    if not st.any:
        console.print("[yellow]%s[/yellow]" % st.detail)
        return 1

    findings = store.findings()
    if args.scope_file:
        hosts = sorted({r["host"] for r in store.web_rows()})
        bridge.write_scope_file(hosts, args.scope_file)
        console.print("  scope written to [cyan]%s[/cyan] "
                      "(Burp: Target > Scope > paste from file)" % args.scope_file)
    if args.mirror:
        n = bridge.mirror(findings)
        console.print("  mirrored %d request(s) into Burp history" % n)
    if args.scan and st.api_ok:
        urls = [f.target for f in findings if f.triage in ("CHASE", "LOOK")
                and f.target.startswith("http")][:50]
        task = bridge.launch_scan(urls)
        console.print("  queued Burp scan task %s over %d URL(s)" % (task or "?", len(urls)))
    store.close()
    return 0


def _burp_push(store: Store, cfg: Config, mirror: bool, scan: bool) -> None:
    bridge = BurpBridge(cfg)
    st = bridge.detect()
    if not st.any:
        console.print("[yellow]Burp not reachable; skipping mirror/scan.[/yellow]")
        return
    findings = store.findings()
    if mirror:
        console.print("  mirrored %d request(s) into Burp" % bridge.mirror(findings))
    if scan and st.api_ok:
        urls = [f.target for f in findings if f.triage in ("CHASE", "LOOK")
                and f.target.startswith("http")][:50]
        task = bridge.launch_scan(urls)
        console.print("  queued Burp scan task %s" % (task or "?"))


def cmd_submit(args) -> int:
    from assay import submission
    store, args.out = open_run(args.out, "findings")
    if store is None:
        return 1
    findings = store.findings()
    if args.rank:
        if args.rank.isdigit():
            i = int(args.rank) - 1
            findings = [findings[i]] if 0 <= i < len(findings) else []
        else:
            findings = [f for f in findings
                        if f.fingerprint().startswith(args.rank)]
    else:
        order = {"CHASE": 0, "LOOK": 1, "NOTE": 2}
        cutoff = order[args.min_triage]
        findings = [f for f in findings if order.get(f.triage, 2) <= cutoff]

    if not findings:
        console.print("[yellow]nothing to draft[/yellow]")
        store.close()
        return 1

    text = submission.bundle(findings, store=store, limit=len(findings))
    if args.write:
        with open(args.write, "w", encoding="utf-8") as fh:
            fh.write(text)
        console.print("  %d draft(s) written to [cyan]%s[/cyan]"
                      % (len(findings), args.write))
    else:
        print(text)
    store.close()
    return 0


def cmd_replay(args) -> int:
    from assay import burpimport, owasp
    from assay.models import Evidence, Finding
    from assay.net import HttpClient, similarity

    requests_, fmt = burpimport.load(args.capture)
    if not requests_:
        console.print("[red]could not parse[/red] %s - expected a Burp XML item "
                      "export or a .har file" % args.capture)
        return 2
    console.print("  parsed [bold]%d[/bold] request(s) from %s" % (len(requests_), fmt))

    cfg = Config(out_dir=args.out, rate=args.rate)
    if getattr(args, "scope", None):
        try:
            cfg.scope = Scope.from_file(args.scope)
        except OSError as exc:
            console.print("[red]cannot read scope file:[/red] %s" % exc)
            return 2
    cfg.aggressive = args.aggressive
    cfg.apply_run_dir(args.out, flat=getattr(args, "flat", False))
    cfg.burp = _burp_config(args)
    cfg.ensure_dirs()

    candidates = []
    reasons: Dict[str, int] = {}
    for r in burpimport.dedupe(requests_):
        ok, why = burpimport.worth_replaying(r, aggressive=args.aggressive)
        if ok and cfg.scope.allows(r.host):
            candidates.append(r)
        else:
            key = why if ok else why
            reasons[key] = reasons.get(key, 0) + 1
    candidates = candidates[: args.limit]

    console.print("  [bold]%d[/bold] worth replaying after dedupe" % len(candidates))
    for why, n in sorted(reasons.items(), key=lambda kv: -kv[1])[:5]:
        console.print("    [dim]%d skipped: %s[/dim]" % (n, why))
    if not candidates:
        return 1

    store = Store(cfg.db_path())
    store.start_run("replay", [args.capture])
    http = HttpClient(cfg)
    hits = 0

    console.print()
    for r in candidates:
        resp = burpimport.replay(http, r)
        is_hit, sim, why = burpimport.verdict(r, resp, similarity)
        if not is_hit:
            continue
        hits += 1
        console.print("  [red]OPEN[/red] %s  [dim]%s[/dim]" % (r.shape(), why))
        f = Finding(
            title="Authenticated endpoint reachable without credentials: %s" % r.shape(),
            target=r.url,
            severity="high",
            confidence="confirmed",
            category=owasp.A01,
            cwe="CWE-306",
            module="replay",
            impact=(
                "This endpoint returned the same content to an anonymous caller as it "
                "did to an authenticated session - the credentials were stripped and "
                "the data came back regardless. Any data or action behind it is "
                "available to anyone who knows the URL. Confirm what the response "
                "contains: if it is another user's data, this is also a horizontal "
                "access-control failure."
            ),
            detail="Captured authenticated (HTTP %d, %d bytes); anonymous replay "
                   "returned HTTP %d with %.0f%% identical content."
                   % (r.status, r.length, resp.status, sim * 100),
            repro=resp.curl(),
            refs=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
            tags=["replay", "verified", "authz"],
            evidence=[
                Evidence(kind="http", label="Authenticated capture (from %s)" % fmt,
                         request="%s %s\n%s" % (r.method, r.url,
                                                "\n".join("%s: %s" % kv
                                                          for kv in r.headers.items())),
                         response=r.response[:900]),
                resp.evidence(label="Anonymous replay - credentials removed"),
            ],
            dedupe_key="replay|%s" % r.shape(),
        )
        store.add_finding(f)

    store.finish_run()
    console.print("\n  [bold]%d[/bold] of %d endpoint(s) served content without "
                  "credentials" % (hits, len(candidates)))
    if hits:
        from assay import report as report_mod
        path = os.path.join(cfg.out_dir, "report.html")
        report_mod.build(store, {"hosts": 0, "web": len(candidates),
                                 "requests": http.count, "duration": 0},
                         path, scan_meta={"profile": "replay"})
        console.print("  report  [cyan]%s[/cyan]" % path)
    else:
        console.print("  [green]access control held on every replayed endpoint[/green]")
    store.close()
    return 0


def cmd_followup(args) -> int:
    from assay import followup
    from assay.redact import RedactionMap

    store, run_dir = open_run(args.out, "findings")
    if store is None:
        return 1
    cfg = Config(out_dir=run_dir)
    if getattr(args, "scope", None):
        try:
            cfg.scope = Scope.from_file(args.scope)
        except OSError as exc:
            console.print("[red]cannot read scope file:[/red] %s" % exc)
            return 2

    if not store.findings():
        console.print("[yellow]no findings to follow up[/yellow]")
        store.close()
        return 1

    # Un-redact locally: the mapping never left this machine.
    redactor = None
    map_path = os.path.join(run_dir, "redaction-map.json")
    if os.path.exists(map_path):
        class _R:
            pass
        redactor = _R()
        redactor.map = RedactionMap.load(map_path)
        console.print("  [dim]un-redacting with %d pseudonym(s) from %s[/dim]"
                      % (len(redactor.map.reverse), map_path))
    else:
        console.print("  [yellow]no redaction map found[/yellow] - commands will be "
                      "shown exactly as the model wrote them")

    cmds = followup.collect(store, redactor)[: args.limit]
    if not cmds:
        console.print("[yellow]no AI-suggested commands.[/yellow] Run 'assay ai' first.")
        store.close()
        return 1

    vetted = [followup.vet(c.raw, cfg) for c in cmds]
    for src, v in zip(cmds, vetted):
        v.finding_id, v.finding_title = src.finding_id, src.finding_title

    runnable = [v for v in vetted if v.ok]
    console.print("\n[bold]%d command(s)[/bold]  %d runnable, %d refused"
                  % (len(vetted), len(runnable), len(vetted) - len(runnable)))
    if cfg.scope.permissive:
        console.print("  [yellow]no --scope given[/yellow] - scope checking cannot "
                      "protect you here; pass --scope to enable it")

    for v in vetted:
        mark = "[green]RUN [/green]" if v.ok else "[red]SKIP[/red]"
        console.print("  %s %s" % (mark, v.display))
        console.print("       [dim]%s - %s[/dim]" % (v.finding_title[:56], v.reason))

    if not args.run:
        console.print("\n[yellow]preview only[/yellow] - re-run with --run to execute.")
        store.close()
        return 0
    if not runnable:
        store.close()
        return 1

    interactive = sys.stdin.isatty() and not args.yes
    if not interactive and not args.yes:
        console.print("[red]refusing to execute non-interactively.[/red] "
                      "Use --yes to approve every command up front.")
        store.close()
        return 2

    console.print("\n[bold]review each command before it runs[/bold]  "
                  "[dim]y = run, n = skip, a = run all remaining, q = quit[/dim]\n"
                  if interactive else "")
    approve_all = args.yes
    ran = skipped = 0

    for v in runnable:
        console.print("  [bold]$ %s[/bold]" % v.display)
        console.print("    [dim]for: %s[/dim]" % v.finding_title[:70])
        if v.hosts:
            console.print("    [dim]targets: %s[/dim]" % ", ".join(v.hosts))

        if not approve_all:
            try:
                answer = input("    run this? [y/N/a/q] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = "q"
            if answer == "q":
                console.print("  [yellow]stopped[/yellow]")
                break
            if answer == "a":
                approve_all = True
            elif answer not in ("y", "yes"):
                skipped += 1
                console.print("    [yellow]skipped[/yellow]\n")
                continue

        followup.run(v, timeout=args.timeout)
        ran += 1
        style = "green" if v.rc == 0 else "yellow"
        head = "\n".join(v.output.splitlines()[:12])
        console.print("    [%s]exit %s[/%s]\n%s\n" % (style, v.rc, style,
                                                       _indent(head, "      ")))
        store.set_status(v.finding_id, "followup-run",
                         notes="$ %s\n(exit %s)\n%s" % (v.display, v.rc,
                                                          v.output[:2000]))

    console.print("[green]%d run[/green], %d skipped - output attached to each "
                  "finding (assay show <n> to read it)" % (ran, skipped))
    store.close()
    return 0


def _indent(text: str, prefix: str = "       ") -> str:
    return "\n".join(prefix + l for l in text.splitlines()) if text else ""


def cmd_install(args) -> int:
    only = [x.strip() for x in (args.only or "").split(",") if x.strip()]
    return _do_install(only=only,
                       include_optional=not args.required_only,
                       dry_run=args.dry_run,
                       assume_yes=args.yes)


def _do_install(only=None, include_optional=True, dry_run=False,
                assume_yes=False) -> int:
    """Shared by 'assay install' and 'scan --install-missing'."""
    from assay import installer

    plan = installer.build_plan(only=only or None, include_optional=include_optional)

    if plan.already:
        console.print("  [green]already installed[/green]  %s" % ", ".join(plan.already))
    if plan.empty:
        if plan.unsupported:
            console.print("[yellow]cannot install automatically here:[/yellow] %s"
                          % ", ".join(plan.unsupported))
            for n in plan.notes:
                console.print("  [dim]%s[/dim]" % n)
            return 1
        console.print("[green]nothing to do - every tool is present.[/green]")
        return 0

    console.print("\n[bold]will install[/bold]  %s" % ", ".join(plan.missing))
    if plan.unsupported:
        console.print("[yellow]skipping (no automatic method here):[/yellow] %s"
                      % ", ".join(plan.unsupported))
    console.print("\n[bold]commands to be run[/bold]")
    for i, step in enumerate(plan.steps, 1):
        console.print("  [dim]%2d.[/dim] %s" % (i, step.display()))
    for n in plan.notes:
        console.print("\n  [yellow]note[/yellow]  %s" % n)

    if dry_run:
        console.print("\n[yellow]dry run[/yellow] - nothing was executed.")
        return 0

    needs_sudo = any(step.needs_sudo for step in plan.steps)
    if needs_sudo:
        console.print("\n  [yellow]this needs sudo.[/yellow] Run [bold]sudo -v[/bold] "
                      "first if you have not recently - assay will not prompt for a "
                      "password mid-install.")

    if not assume_yes:
        if not sys.stdin.isatty():
            console.print("[red]refusing to install non-interactively.[/red] "
                          "Re-run with --yes, or use --dry-run to review first.")
            return 2
        try:
            answer = input("\n  proceed? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in ("y", "yes"):
            console.print("  [yellow]cancelled[/yellow]")
            return 1

    console.print()
    styles = {"start": "dim", "ok": "green", "fail": "red", "skip": "yellow"}
    marks = {"start": "..", "ok": "OK", "fail": "!!", "skip": "--"}

    def on_step(kind: str, msg: str) -> None:
        console.print("  [%s]%s[/%s] %s" % (styles.get(kind, "dim"),
                                            marks.get(kind, "  "),
                                            styles.get(kind, "dim"), msg))

    ok, failed = installer.run_plan(plan, on_step=on_step)
    console.print("\n  %d step(s) succeeded, %d failed" % (ok, failed))

    if plan.path_hint:
        changed = installer.persist_path(plan.path_hint)
        env.augment_path()
        if changed:
            console.print("  added [cyan]%s[/cyan] to %s"
                          % (plan.path_hint, ", ".join(changed)))
        console.print("  [dim]open a new shell (or source your rc file) so the new "
                      "tools are on PATH[/dim]")

    got = installer.verify(plan.missing)
    still = [n for n, path in got.items() if not path]
    if still:
        console.print("  [yellow]still missing:[/yellow] %s" % ", ".join(still))
        console.print("  [dim]assay runs fine without them - 'assay doctor' shows what "
                      "each one buys you[/dim]")
        return 1
    console.print("  [green]all requested tools are now available[/green]")
    return 0


def cmd_triage(args) -> int:
    store, args.out = open_run(args.out, "findings")
    if store is None:
        return 1
    findings = store.findings()

    if not findings:
        console.print("[yellow]no findings recorded yet[/yellow]")
        console.print("  [dim]this run completed but found nothing to report[/dim]")
        store.close()
        return 0

    if args.list or not args.rank:
        from rich.table import Table
        t = Table(box=None, expand=True)
        t.add_column("#", width=3, justify="right", style="dim")
        t.add_column("status", width=14)
        t.add_column("sev", width=8)
        t.add_column("finding", overflow="fold")
        for i, f in enumerate(findings, 1):
            st = store.status_of(f.fingerprint())
            style = "dim" if st in store.MUTED else (
                "yellow" if st == "in-progress" else "green")
            t.add_row(str(i), "[%s]%s[/%s]" % (style, st, style),
                      Text(f.severity, style=SEV_STYLE.get(f.severity, "")),
                      f.title)
        console.print(t)
        counts = store.status_counts()
        console.print("\n  " + "  ".join("%s [bold]%d[/bold]" % (k, v)
                                          for k, v in sorted(counts.items())))
        console.print("  [dim]assay triage <n> --status reported --note '...'[/dim]")
        store.close()
        return 0

    target = None
    if args.rank.isdigit():
        i = int(args.rank) - 1
        if 0 <= i < len(findings):
            target = findings[i]
    else:
        target = next((f for f in findings
                       if f.fingerprint().startswith(args.rank)), None)
    if target is None:
        console.print("[red]no such finding[/red]")
        store.close()
        return 1

    store.set_status(target.fingerprint(), args.status, notes=args.note)
    console.print("  [green]%s[/green]  %s" % (args.status, target.title))
    console.print("  [dim]%s[/dim]" % target.target)
    if args.status in store.MUTED:
        console.print("  [dim]it will no longer appear in 'assay diff' or count "
                      "as new on later runs[/dim]")
    store.close()
    return 0


def cmd_diff(args) -> int:
    store, args.out = open_run(args.out, "runs")
    if store is None:
        return 1
    runs = store.runs()
    if not runs:
        console.print("[yellow]no runs recorded here[/yellow]")
        store.close()
        return 1
    target = args.run or runs[0]["id"]
    d = store.diff(target)

    console.print("\n[bold]run %s[/bold]  %s"
                  % (target, time.strftime("%Y-%m-%d %H:%M",
                                           time.localtime(runs[0]["started"]))))
    if d["is_first_run"]:
        console.print("  [dim]first run for this engagement - everything is new, "
                      "so there is nothing to compare against yet.[/dim]")
        store.close()
        return 0
    console.print("  [dim]compared against run %s[/dim]\n" % d["previous"])

    if d["new_findings"]:
        console.print("[bold green]new findings (%d)[/bold green]"
                      % len(d["new_findings"]))
        for f in d["new_findings"][:25]:
            console.print("  [%s]%-8s[/%s] %s  [cyan]%s[/cyan]"
                          % (SEV_STYLE.get(f.severity, "white"), f.severity,
                             SEV_STYLE.get(f.severity, "white"),
                             f.title[:62], f.target[:52]))
    else:
        console.print("[dim]no new findings[/dim]")

    if d["gone_findings"]:
        console.print("\n[bold]no longer present (%d)[/bold]  "
                      "[dim]fixed, or the host stopped answering[/dim]"
                      % len(d["gone_findings"]))
        for f in d["gone_findings"][:15]:
            console.print("  [dim]%-8s %s  %s[/dim]"
                          % (f.severity, f.title[:62], f.target[:52]))

    if d["new_hosts"]:
        console.print("\n[bold]new hosts (%d)[/bold]" % len(d["new_hosts"]))
        console.print("  " + ", ".join(d["new_hosts"][:20]))
    if d["new_web"]:
        console.print("\n[bold]new endpoints (%d)[/bold]" % len(d["new_web"]))
        for u in d["new_web"][:20]:
            console.print("  [cyan]%s[/cyan]" % u)
    store.close()
    return 0


def cmd_modules(args) -> int:
    from assay.modules import all_modules
    from rich.table import Table
    t = Table(title="detection modules", title_style="bold")
    t.add_column("stage"); t.add_column("scope"); t.add_column("name")
    t.add_column("what it looks for", overflow="fold")
    for m in sorted(all_modules(), key=lambda x: (x.stage, x.name)):
        t.add_row(m.stage, m.scope, m.name, m.desc)
    console.print(t)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "scan": cmd_scan, "doctor": cmd_doctor, "report": cmd_report,
        "ai": cmd_ai, "show": cmd_show, "burp": cmd_burp, "modules": cmd_modules,
        "install": cmd_install, "followup": cmd_followup, "diff": cmd_diff,
        "triage": cmd_triage,
        "replay": cmd_replay, "submit": cmd_submit,
    }
    try:
        return handlers[args.cmd](args)
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
