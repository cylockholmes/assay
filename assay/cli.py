"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import textwrap
from typing import Dict, List, Optional

from assay import env, notify, tools, version_string
from assay.config import Config, Scope, ScopeError, PROFILES
from assay.store import Store
import time

from assay import report as report_mod
from rich.text import Text

from assay.ui import (Dashboard, KeyListener, SEV_STYLE, console,
                      detail as show_detail, inventory, summary, tool_table)

EPILOG = """\
examples:
  assay scan 10.10.0.0/24 --scope scope.txt
  assay scan https://app.target.tld --profile deep
  assay scan -f targets.txt --profile quick --no-open
  assay ai --out ./assay-out --ai-dry-run       # see exactly what would be sent
  assay ai --out ./assay-out --ai-backend claude-cli   # via the Claude desktop app
  assay ai --out ./assay-out --ai-backend api          # via your Anthropic API key
  assay replay authed.xml --scope scope.txt    # unauth access from a Burp capture
  assay submit 1 > report.md                   # submission draft for finding #1
  assay triage 3 --status reported            # stop a submitted finding resurfacing
  assay followup --scope scope.txt             # preview the AI's verify commands
  assay followup --scope scope.txt --run       # un-redact and execute them
  assay doctor                                  # tools, WSL, resources
  assay install --dry-run                       # preview external tool install
  assay install -y                              # install everything missing
  assay scan 10.0.0.0/24 --basic admin:admin    # behind HTTP Basic auth
  assay scan target.tld --no-passive             # stay off third-party lookups
"""


class _VersionAction(argparse.Action):
    """Print the version with its git build and exit. A custom action rather
    than argparse's built-in 'version' so the git lookup happens only when
    --version is actually passed, not on every invocation."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        print(version_string())
        parser.exit()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assay",
        description="Signal-first recon and triage for authorized offensive testing.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action=_VersionAction,
                   help="show the version (with git build) and exit")
    sub = p.add_subparsers(dest="cmd", required=True)

    # -- scan --------------------------------------------------------------
    s = sub.add_parser("scan", help="run a scan", formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("targets", nargs="*", metavar="TARGET",
                   help="what to scan, and by default the scope too: hosts, "
                        "IPs, CIDRs or URLs (comma or space separated), or the "
                        "path to a host list, CSV or Burp scope export. Mix "
                        "freely.")
    s.add_argument("-f", "--targets-file", help=argparse.SUPPRESS)
    s.add_argument("-p", "--profile", choices=sorted(PROFILES), default=None,
                   help="scan depth (default: standard, or asked interactively)")
    s.add_argument("--no-prompt", action="store_true",
                   help="do not ask the first-run option questions; use flag "
                        "defaults (also implied when there is no terminal)")
    s.add_argument("-o", "--out", default="./assay-out",
                   help="root output directory; each engagement gets its own subfolder")
    s.add_argument("-n", "--codename", default="",
                   help="engagement codename - names the output folder and the "
                        "report; asked for interactively when omitted")
    s.add_argument("--flat", action="store_true",
                   help="write straight into --out instead of a per-engagement subfolder")
    s.add_argument("--resume", action="store_true",
                   help="reuse -n's existing raw/nmap.xml instead of re-scanning "
                        "ports nmap already finished - recovers hosts even from a "
                        "scan that was killed mid-run; hosts not in that file are "
                        "still scanned fresh")
    s.add_argument("--scope", metavar="FILE_OR_LIST",
                   help="override the scope, when what may be reached differs "
                        "from what is being scanned. Defaults to the targets.")

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
    s.add_argument("--no-udp", action="store_true",
                   help="skip the curated-port UDP sweep (on by default; also off under --safe)")
    s.add_argument("--rescan", action="store_true",
                   help="scan every target even if a previous run of this "
                        "engagement already covered it; by default hosts "
                        "already fully scanned are skipped (their stored "
                        "results still flow into the report)")
    s.add_argument("--sweep-batches", type=int, default=None, metavar="N",
                   help="split the port sweep into N batches so a time limit costs "
                        "a slice, not the whole sweep; a batch that times out is "
                        "halved and re-run. Default: sized automatically (or "
                        "asked on deep). Hosts still unswept are listed in "
                        "raw/unscanned-*.txt; --resume continues from them")
    s.add_argument("--no-deep-ports", action="store_true",
                   help="skip the serial full-range naabu wave for obscure TCP ports "
                        "(on by default except the deep profile, which already sweeps all ports)")
    s.add_argument("--no-passive", action="store_true",
                   help="do not query third-party OSINT/CVE sources (on by default)")
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
    s.add_argument("--tag", default="", metavar="VALUE",
                   help="identifying value sent on every request assay and its "
                        "tools make, so the traffic can be attributed to you and "
                        "the engagement. Some programmes require this for "
                        "authorised automated testing.")
    s.add_argument("--tag-header", default="X-Scan-Tag", metavar="NAME",
                   help="header name carrying --tag. Programme-specific; set it "
                        "to whatever yours mandates (default X-Scan-Tag)")

    g = s.add_argument_group("surface expansion and blind checks")
    g.add_argument("--no-expand", action="store_true",
                   help="do not grow the target list beyond what was given "
                        "(on by default: permutations, DNS resolution, and, "
                        "unless --no-passive, CT logs and subdomain sources)")
    g.add_argument("--oob-domain", default="", metavar="DOMAIN",
                   help="collaborator domain for blind SSRF payloads; without it "
                        "the blind checks are skipped")
    g.add_argument("--no-oob", action="store_true",
                   help="do not fire out-of-band payloads at all")

    g.add_argument("--slack-webhook", default="", metavar="URL",
                   help="Slack incoming-webhook URL; pings when the scan finishes "
                        "or stops for input (or set ASSAY_SLACK_WEBHOOK)")


    s.add_argument("--install-missing", action="store_true",
                   help="install any missing external tools before scanning")

    _ai_flags(s)
    s.add_argument("--no-report", action="store_true")
    s.add_argument("--no-live", action="store_true",
                   help="do not update the report while the scan runs")
    # Opening is the default; --open is accepted but hidden for old scripts.
    s.add_argument("--open", dest="open", action="store_true", default=True,
                   help=argparse.SUPPRESS)
    s.add_argument("--no-open", dest="open", action="store_false",
                   help="do not open the report in a browser; just print its path")
    s.add_argument("-q", "--quiet", action="store_true")

    # -- other commands ----------------------------------------------------
    d = sub.add_parser("doctor", help="check tools, WSL and resources")

    r = sub.add_parser("report", help="rebuild the HTML report from a previous run")
    r.add_argument("-o", "--out", default="./assay-out")
    r.add_argument("--open", dest="open", action="store_true", default=True,
                   help=argparse.SUPPRESS)
    r.add_argument("--no-open", dest="open", action="store_false",
                   help="do not open the rebuilt report; just print its path")

    a = sub.add_parser("ai", help="run AI triage over an existing run")
    a.add_argument("-o", "--out", default="./assay-out")
    _ai_flags(a, standalone=True)

    sh = sub.add_parser("show", help="print one finding in full")
    sh.add_argument("rank", help="rank number from the summary table, or a finding id")
    sh.add_argument("-o", "--out", default="./assay-out")

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

    sc = sub.add_parser("scope",
                        help="show what assay reads from a scope or target file")
    sc.add_argument("input", nargs="+", metavar="TARGET",
                    help="the same thing you would pass to scan: inline hosts, "
                         "or a host list, CSV or Burp scope export")

    sub.add_parser("modules", help="list detection modules")
    return p


def _ai_flags(p: argparse.ArgumentParser, standalone: bool = False) -> None:
    g = p.add_argument_group("AI triage (opt-in, redacted)")
    if not standalone:
        g.add_argument("--ai", action="store_true",
                       help="after the scan, send REDACTED findings to Claude for triage")
        # Three of the four gates in `assay followup` are mechanical and still
        # apply to every command. The fourth is consent, and a scan has nobody
        # to ask mid-run - so this flag is that consent, given up front.
        g.add_argument("--ai-followup", action="store_true",
                       help="run the AI's verification commands as part of the "
                            "scan (implies --ai). They stay allow-listed, "
                            "shell-free and in-scope; passing this flag is the "
                            "approval 'assay followup --run' asks for one "
                            "command at a time")
        g.add_argument("--ai-followup-limit", type=int, default=25, metavar="N",
                       help="most commands --ai-followup may run (default: 25)")
        g.add_argument("--ai-followup-timeout", type=float, default=120.0,
                       metavar="SEC",
                       help="per-command timeout for --ai-followup (default: 120)")
        # Iterative loop (PLAN-LOOP §2). Subsumes --ai + --ai-followup.
        g.add_argument("--ai-loop", action="store_true",
                       help="iterative triage: each round triages, then auto-runs the "
                            "passive suggested commands (active ones queue for consent). "
                            "Implies --ai")
        g.add_argument("--ai-loop-rounds", type=int, default=None, metavar="N",
                       help="max loop rounds (default: 3, or asked interactively; "
                            "the dependable stop)")
        g.add_argument("--ai-loop-auto", choices=["passive", "none"], default="passive",
                       help="which suggested commands auto-run without consent "
                            "(default: passive; 'none' queues everything)")
        g.add_argument("--ai-loop-rate", type=int, default=5, metavar="N",
                       help="max passive auto-runs per host per round (default: 5)")
        g.add_argument("--ai-loop-resend", action="store_true",
                       help=argparse.SUPPRESS)   # now the default; kept for old scripts
        g.add_argument("--ai-loop-no-resend", action="store_true",
                       help="do not feed command results back to the model "
                            "(single round). By default results go back redacted: "
                            "full output for send-eligible tools, a content-free "
                            "digest for the rest")
        g.add_argument("--ai-loop-budget", type=float, default=0.0, metavar="USD",
                       help="additional cumulative-cost ceiling for the loop, API "
                            "backend only (0 = off; rounds remain the universal cap)")
    # No default. The two backends spend different money - an API key bills
    # per token, the CLI bills whatever Claude plan it is signed in to - so
    # assay makes you say which one rather than guessing on your behalf.
    g.add_argument("--ai-backend", choices=["api", "claude-cli"], default=None,
                   help="how to reach Claude. 'api' = your Anthropic API key "
                        "(billed per token); 'claude-cli' = hand the request to "
                        "the Claude Code CLI, which shares a sign-in with the "
                        "Claude desktop app (billed to that plan). Required "
                        "unless --ai-dry-run.")
    g.add_argument("--ai-claude-bin", default="claude",
                   help="claude-cli backend: binary name or path "
                        "(default: claude)")
    g.add_argument("--ai-model", default="claude-opus-4-8")
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


def _ask_codename(targets: List[str]) -> str:
    """Ask for the engagement codename when -n was not given.

    The codename names the output folder and titles the report, and targets
    are usually known by it rather than by a hostname - so a run started
    without one is the run nobody can find again a week later. Prompt for it
    rather than silently falling back to a hash of the target set.

    Returns "" when there is no one to ask (piped input, CI, cron), which
    leaves the existing target-derived naming in place.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return ""
    derived = Config.slug_for(targets)
    try:
        answer = console.input(
            "\n  [bold]engagement codename[/bold] "
            "[dim](Enter for '%s')[/dim]: " % derived)
    except (EOFError, KeyboardInterrupt):
        console.print()
        return ""
    return answer.strip()


def _ask_scan_options(args) -> None:
    """The first-run questions, in place of remembering flags. Skipped without
    a terminal, so scripted runs behave exactly as they always did."""
    from assay import wizard
    if not wizard.interactive():
        return
    try:
        from rich.markup import escape
        # Prompts contain "[Y/n]", which rich would parse as a markup tag.
        chosen = wizard.ask_options(
            args, lambda q: console.input(escape(q)), console.print)
    except (EOFError, KeyboardInterrupt):
        console.print("\n  [dim]questions skipped - using defaults for the rest[/dim]")
        return
    console.print("  [dim]running: %s[/dim]" % ", ".join(chosen))


def make_config(args) -> Config:
    from assay import targets as tload

    raw = list(getattr(args, "targets", []) or [])
    if getattr(args, "targets_file", None):          # historical alias
        raw.append(args.targets_file)
    if not raw:
        console.print("[red]nothing to scan.[/red]")
        console.print("  [dim]assay scan 10.20.0.0/24,app.example.com[/dim]")
        console.print("  [dim]assay scan targets.txt[/dim]")
        console.print("  [dim]assay scan burp-scope.json[/dim]")
        raise SystemExit(2)

    parsed = tload.resolve_inputs(raw)

    # A wildcard constrains the scan without being scannable itself.
    wildcards = [x for x in parsed.targets if x.startswith("*.")]
    targets = [x for x in parsed.targets if not x.startswith("*.")]

    allow, deny = tload.as_scope(parsed)
    scope = Scope(allow=allow, deny=deny)
    scope_source = "the targets"

    # --scope only matters when reachable differs from scanned.
    if getattr(args, "scope", None):
        if os.path.isfile(args.scope):
            try:
                scope = Scope.from_file(args.scope)
            except OSError as exc:
                console.print("[red]cannot read scope file:[/red] %s" % exc)
                raise SystemExit(2)
            from assay.config import unrepresentable_rules
            for rule in unrepresentable_rules()[:5]:
                console.print("  [yellow]scope rule not applied[/yellow] %s "
                              "[dim](path-scoped; assay's scope is host-level)[/dim]"
                              % rule)
        else:
            override = tload.parse(args.scope.replace(",", "\n"))
            a, d = tload.as_scope(override)
            scope = Scope(allow=a, deny=d)
        scope_source = args.scope

    if not targets:
        console.print("[red]nothing scannable in that input.[/red]")
        for w in parsed.warnings:
            console.print("  [yellow]%s[/yellow]" % w)
        raise SystemExit(2)

    console.print("  [dim]%d target(s) from %s; scope from %s[/dim]"
                  % (len(targets), parsed.source_format, scope_source))
    if wildcards:
        console.print("  [dim]%d wildcard(s) in scope but not scanned (%s) - "
                      "--expand enumerates them[/dim]"
                      % (len(wildcards), ", ".join(wildcards[:3])))
    if deny:
        console.print("  [dim]%d exclusion(s) applied[/dim]" % len(deny))
    for sk in parsed.skipped[:5]:
        console.print("  [yellow]skipped[/yellow] %s" % sk)
    for w in parsed.warnings:
        console.print("  [yellow]%s[/yellow]" % w)

    codename = getattr(args, "codename", "") or ""
    if not codename and not getattr(args, "quiet", False):
        codename = _ask_codename(targets)

    if not getattr(args, "quiet", False) and not getattr(args, "no_prompt", False):
        _ask_scan_options(args)
    args.profile = args.profile or "standard"

    tune = env.autotune()
    cfg = Config(
        targets=targets,
        profile=args.profile,
        out_dir=args.out,
        resume=getattr(args, "resume", False),
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
        codename=codename,
        timeout=args.timeout,
        retries=args.retries,
        passive=not getattr(args, "no_passive", False),
        portscan=not args.no_portscan,
        # UDP runs on every scan by default; --safe (retrieval-only) and
        # --no-udp are the two ways to turn it off.
        udp=not getattr(args, "no_udp", False) and not getattr(args, "safe", False),
        deep_ports=not getattr(args, "no_deep_ports", False),
        sweep_batches=int(getattr(args, "sweep_batches", 0) or 0),
        rescan=bool(getattr(args, "rescan", False)),
        expand=not getattr(args, "no_expand", False),
        oob=not getattr(args, "no_oob", False),
        oob_domain=getattr(args, "oob_domain", "") or "",
        slack_webhook=getattr(args, "slack_webhook", "") or "",
        aggressive=args.aggressive,
        cookies=args.cookie,
        basic_auth=getattr(args, "basic", None) or "",
        traffic_tag=getattr(args, "tag", "") or "",
        traffic_tag_header=(getattr(args, "tag_header", "") or "X-Scan-Tag"),
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

    if scope.permissive:
        console.print(
            "[yellow]warning:[/yellow] no --scope file given. assay will scan whatever "
            "you named and nothing else, but a scope file is the safety net that stops "
            "a typo or a redirect from touching an out-of-scope host."
        )
    return cfg


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def _decide_rescan(cfg) -> None:
    """Look at what this engagement already scanned and decide whether to redo
    the covered hosts. Runs before the live view so it can prompt cleanly.

    --rescan (or the first-run question) already settled it -> respect that.
    Otherwise: if some target hosts were fully scanned in an earlier run, show
    how many and, on a terminal, ask. Default is to skip them - the efficient,
    still-complete choice, since new and partially-swept hosts are always
    scanned and the skipped ones' stored results still reach the report.
    """
    from assay import tools
    from assay.store import Store
    if cfg.rescan:
        return
    spec = cfg.opts.get("port_spec", "top-1000")
    store = Store(cfg.db_path())
    try:
        hist = store.scan_history()
    finally:
        store.close()
    if not hist:
        return
    covered = [h for h in cfg.targets
               if hist.get(h) is not None
               and not int(hist[h]["timed_out"] or 0)
               and tools.spec_covers(hist[h]["port_spec"], spec)]
    if not covered:
        return
    console.print("  [dim]%d of %d target host(s) were fully scanned (%s) in an "
                  "earlier run of this engagement[/dim]"
                  % (len(covered), len(cfg.targets), spec))
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        console.print("  [dim]skipping them (pass --rescan to redo); new and "
                      "partially-swept hosts are still scanned[/dim]")
        return
    try:
        answer = input("  re-scan those already-covered hosts? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    cfg.rescan = answer in ("y", "yes")
    console.print("  [dim]%s[/dim]" % ("re-scanning everything"
                  if cfg.rescan else "skipping already-covered hosts"))


def _finalize_content(engine, args) -> None:
    """Offer, once the scan is otherwise done, to finish any content-discovery
    passes that stopped on their time budget before reaching the end of the
    wordlist. Deep in particular only ever covers the first few percent of the
    list inside one host's budget, so the rest is there for the asking.

    Prompts only when attached to a terminal - finishing a pass can take hours,
    so a non-interactive or -y run is told what was left rather than silently
    launching it.
    """
    jobs = engine.ctx.deferred_content
    if not jobs:
        return
    from assay.modules import web_content

    n = len(jobs)
    console.print("\n[bold]%d content-discovery pass(es) did not finish the "
                  "wordlist[/bold]" % n)
    for j in jobs[:10]:
        console.print("  [dim]%s - %s[/dim]"
                      % (j.get("origin", "?"), j.get("coverage", "partial")))
    if n > 10:
        console.print("  [dim]... and %d more[/dim]" % (n - 10))

    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        console.print("  [dim]not a terminal - leaving them unfinished. Re-run "
                      "with --profile deep to carry on.[/dim]")
        return
    # The scan is otherwise done and now blocks on this prompt; if the operator
    # walked away during a long run, bring them back to answer it.
    notify.from_cfg(engine.ctx.cfg).needs_input(
        "%d content-discovery pass(es) unfinished - resume them? (waiting at the "
        "terminal)" % n)
    try:
        answer = input("  resume them now from where each stopped (may take "
                       "hours)? [y/N] ").strip().lower()
    except EOFError:
        return
    if answer not in ("y", "yes"):
        return

    # The live dashboard has torn down by now, so ctx.say would be silent;
    # route its progress to the plain console for the duration of the pass.
    saved = engine.ctx.progress
    engine.ctx.progress = lambda stage, msg, advance=0: console.print(
        "  [dim]%s[/dim] %s" % (stage, msg))
    try:
        ran = web_content.finalize_pending(engine.ctx)
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted - whatever finished is saved[/yellow]")
        ran = 0
    finally:
        engine.ctx.progress = saved
    if ran:
        console.print("  [green]finalized %d pass(es)[/green]" % ran)


def cmd_scan(args) -> int:
    from assay.engine import Engine
    from assay import report as report_mod

    cfg = make_config(args)
    _decide_rescan(cfg)

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
        state = {"last": 0.0, "opened": False, "found": -1}

        def refresh(force: bool = False) -> None:
            if not live:
                return
            now = time.time()
            # Rebuilding re-queries every finding and rewrites the document;
            # a progress tick only changes the ~100 bytes of the live bar. Now
            # that the port stages report every few seconds, holding both to
            # the same 4s cadence would turn one long sweep into a hundred-odd
            # rebuilds of byte-identical output. A new finding still lands
            # promptly; a status-only change waits longer.
            found = sum(dash.counts.values())
            due = 4.0 if found != state["found"] else 20.0
            if not force and now - state["last"] < due:
                return
            state["last"] = now
            state["found"] = found
            try:
                report_mod.build(engine.store, engine.assets(), report_path,
                                 scan_meta={"profile": cfg.profile,
                                            "codename": cfg.codename},
                                 live=True, status=dash.status())
            except Exception:
                return
            if args.open and not state["opened"]:
                state["opened"] = True
                env.open_in_browser(report_path)

        original_progress = dash.progress

        def progress(stage: str, msg: str, advance: int = 0) -> None:
            # The header is built from the target SPECS, because that is all
            # there is before _stage_resolve runs. One "10.0.0.0/22" is one
            # spec and 1024 hosts, so leaving it there makes the dashboard
            # disagree with the report, which counts what was actually scanned.
            dash.targets = len(engine.ctx.targets) or dash.targets
            original_progress(stage, msg, advance)
            refresh()

        engine.ctx.progress = progress
        refresh(force=True)

        # 's' moves the run past whatever is currently dragging - content
        # discovery grinding through a long wordlist against every web
        # target is the case this exists for. Acknowledged immediately
        # under the stage that is running, since the cutoff itself can take
        # a few seconds to actually land (see tools.SKIP's own comment) and
        # a keypress with no visible response reads as "did that work at
        # all?" rather than "still in progress."
        skip_listener = KeyListener()

        def on_key(ch: str) -> None:
            # Runs on the listener's own thread, so it only sets the SKIP
            # mechanism and flips a single flag the owning render thread reads.
            # It must not call into dash.progress(): that mutates shared
            # Dashboard state and draws from the wrong thread.
            if ch.lower() == "s":
                tools.SKIP.set()
                dash.skip_requested = True

        skip_listener.on_key = on_key
        dash.skip_available = skip_listener.start()
        try:
            engine.run()
        except KeyboardInterrupt:
            console.print("\n[yellow]interrupted - findings so far are saved[/yellow]")
        except ScopeError as exc:
            console.print("[red]scope error:[/red] %s" % exc)
            return 2
        finally:
            # Restores the terminal's own settings (see KeyListener._loop) -
            # must run even on an exception neither except clause above
            # catches, or the shell is left in cbreak mode afterward.
            skip_listener.stop()

    _finalize_content(engine, args)

    assets = engine.assets()
    inventory(engine.store)
    summary(engine.store, assets)

    ai_result = None
    if getattr(args, "ai_loop", False):
        # The loop subsumes --ai + --ai-followup: it triages and runs the
        # passive suggested commands itself, round by round.
        ai_result = run_ai_loop(engine.store, cfg, args, assets)
    elif getattr(args, "ai", False):
        ai_result = run_ai(engine.store, cfg, args, assets)
        # Only after a pass that actually returned triage: a dry run, a
        # refused send or a redaction failure all leave ai_result None, and
        # none of them should lead to commands running.
        if ai_result and getattr(args, "ai_followup", False):
            run_ai_followup(engine.store, cfg, args)
    elif getattr(args, "ai_followup", False):
        console.print("[yellow]--ai-followup needs --ai[/yellow] - there are no "
                      "suggested commands without a triage pass")

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

    _notify_scan_done(engine.store, cfg, assets)
    engine.store.close()
    return 0


def _notify_scan_done(store: Store, cfg: Config, assets: Dict) -> None:
    """Ping Slack with a one-line result summary once the run is complete.
    A no-op unless a webhook is configured."""
    n = notify.from_cfg(cfg)
    if not n.enabled:
        return
    c = store.counts()
    summary = ("%d chase, %d look, %d context  |  %d hosts / %d web / %d reqs in %ss"
               % (c.get("CHASE", 0), c.get("LOOK", 0), c.get("NOTE", 0),
                  assets.get("hosts", 0), assets.get("web", 0),
                  assets.get("requests", 0), assets.get("duration", 0)))
    n.scan_done(summary)


def run_ai_followup(store: Store, cfg: Config, args) -> int:
    """Execute the AI's verification commands as a stage of the scan.

    `assay followup` gates execution four ways. Three of them are mechanical
    and are enforced here unchanged, per command, by followup.vet(): the
    read-only allow-list, the shlex parse that refuses shell metacharacters
    rather than escaping them, and the scope check that refuses the whole
    command if any host in it is out of scope.

    The fourth gate is a human approving each command as it comes up, and a
    scan has nobody to ask. --ai-followup is that approval, given up front
    and covering every command the pass produces. Two conditions still stop
    the stage outright rather than trusting the flag: --safe, because these
    commands send crafted traffic, and a permissive scope, because gate three
    cannot protect anything without one.
    """
    from assay import followup

    if cfg.safe_mode:
        console.print("  [yellow]AI followup skipped[/yellow] - --safe is set and "
                      "these commands send crafted traffic")
        return 0
    if cfg.scope.permissive:
        console.print("  [yellow]AI followup skipped[/yellow] - the scope is "
                      "permissive, so commands cannot be checked against it")
        return 0

    rmap = _redaction_map(cfg.out_dir)
    if rmap is None:
        console.print("  [yellow]AI followup skipped[/yellow] - no redaction map, "
                      "so the commands still carry pseudonyms")
        return 0

    cmds = followup.collect(store, rmap)[: args.ai_followup_limit]
    if not cmds:
        return 0

    vetted = [followup.vet(c.raw, cfg) for c in cmds]
    for src, v in zip(cmds, vetted):
        v.finding_id, v.finding_title = src.finding_id, src.finding_title
    runnable = [v for v in vetted if v.ok]

    console.print("\n[bold]AI followup[/bold]  %d suggested, %d runnable, "
                  "%d refused" % (len(vetted), len(runnable),
                                  len(vetted) - len(runnable)))
    for v in vetted:
        if not v.ok:
            console.print("  [red]SKIP[/red] %s" % v.display)
            console.print("       [dim]%s[/dim]" % v.reason)

    ran = 0
    for v in runnable:
        console.print("  [bold]$ %s[/bold]" % v.display)
        followup.run(v, timeout=args.ai_followup_timeout)
        ran += 1
        style = "green" if v.rc == 0 else "yellow"
        console.print("    [%s]exit %s[/%s]  [dim]%s[/dim]"
                      % (style, v.rc, style, v.finding_title[:60]))
        store.set_status(v.finding_id, "followup-run",
                         notes="$ %s\n(exit %s)\n%s"
                               % (v.display, v.rc, v.output[:2000]))

    if ran:
        console.print("  [green]%d command(s) run[/green] - output attached to "
                      "each finding (assay show <n> to read it)" % ran)
    return ran


def _redaction_map(run_dir: str):
    """The run's pseudonym map, or None when the AI pass never wrote one."""
    from assay.redact import RedactionMap
    path = os.path.join(run_dir, "redaction-map.json")
    if not os.path.exists(path):
        return None
    try:
        return RedactionMap.load(path)
    except (OSError, ValueError):
        return None


def run_ai(store: Store, cfg: Config, args, assets: Dict,
           redactor=None, followups=None) -> Optional[Dict]:
    from assay import ai as ai_mod
    from assay.redact import Redactor, terms_from_context

    findings = store.findings()
    if not findings:
        console.print("[yellow]nothing to triage[/yellow]")
        return None

    # The loop reuses one redactor across rounds so its pseudonym map grows
    # (mint-on-miss) and stays consistent; a one-shot caller passes none and
    # we build it from the run's known client terms.
    if redactor is None:
        hosts = [r["host"] for r in store.host_rows()] + [r["host"] for r in store.web_rows()]
        terms = terms_from_context(cfg.targets, cfg.scope.allow, hosts)
        redactor = Redactor(extra_terms=terms)

    ai_cfg = ai_mod.AIConfig(
        enabled=True,
        backend=getattr(args, "ai_backend", None) or "",
        model=args.ai_model,
        max_findings=args.ai_max,
        include_evidence=args.ai_evidence,
        dry_run=args.ai_dry_run,
        effort=args.ai_effort,
        claude_bin=getattr(args, "ai_claude_bin", "claude") or "claude",
    )

    # A dry run never reaches a backend, so it does not need one chosen.
    if not ai_cfg.dry_run and ai_cfg.backend not in ai_mod.BACKENDS:
        console.print("[yellow]skipping AI triage[/yellow] - no backend chosen.")
        console.print("  [dim]pick one with --ai-backend:[/dim]")
        for name in ai_mod.BACKENDS:
            console.print("    [bold]%-11s[/bold] %s" % (name, ai_mod.BACKEND_HELP[name]))
        console.print("  [dim]or --ai-dry-run to write the payload and send "
                      "nothing[/dim]")
        return None

    # Credentials before anything else: no point redacting a payload we cannot
    # send, and no point asking for a key after the user has already waited.
    if not ai_cfg.dry_run:
        have, how = ai_mod.backend_status(ai_cfg)
        if have:
            console.print("  [dim]backend: %s - %s[/dim]" % (ai_cfg.backend, how))
        elif ai_cfg.backend == ai_mod.BACKEND_API and ai_mod.prompt_for_key(console):
            pass
        elif ai_cfg.backend == ai_mod.BACKEND_API:
            console.print("  [yellow]skipping AI triage[/yellow] - no credentials. "
                          "Set ANTHROPIC_API_KEY or run 'ant auth login'.")
            return None
        else:
            console.print("  [yellow]skipping AI triage[/yellow] - %s" % how)
            console.print("  [dim]the claude-cli backend needs Claude Code "
                          "installed and signed in; 'claude' ships with the "
                          "Claude desktop app and shares its sign-in[/dim]")
            return None

    payload, leaks = ai_mod.build_payload(findings, assets, ai_cfg, redactor,
                                          followups=followups)
    if leaks:
        console.print("[red]redaction verification FAILED - nothing was sent.[/red]")
        for l in leaks[:15]:
            console.print("   [red]![/red] %s" % l)
        console.print("[dim]Add the offending values to your scope file so they are "
                      "treated as known client terms, or run without --ai.[/dim]")
        return None

    console.print(
        "\n[bold]AI triage[/bold]  %d finding(s), %s, model %s, via %s"
        % (min(len(findings), ai_cfg.max_findings),
           "with redacted evidence" if ai_cfg.include_evidence else "metadata only",
           ai_cfg.model, ai_cfg.backend or "dry run")
    )
    console.print("  [green]redaction verified:[/green] %d pseudonym(s), no residual "
                  "hostnames, IPs, credentials or personal data"
                  % len(redactor.map.reverse))

    if not ai_cfg.dry_run and not args.ai_yes and sys.stdin.isatty():
        console.print("  [dim]this sends the redacted payload %s[/dim]"
                      % ("to the Anthropic API, billed per token"
                         if ai_cfg.backend == ai_mod.BACKEND_API else
                         "to the Claude Code CLI, billed to the Claude plan it "
                         "is signed in to"))
        notify.from_cfg(cfg).needs_input(
            "AI triage is ready to send the redacted payload - approve at the "
            "terminal?")
        try:
            answer = input("  send? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in ("y", "yes"):
            console.print("  [yellow]skipped[/yellow]")
            ai_cfg.dry_run = True

    try:
        result = ai_mod.analyze(findings, assets, ai_cfg, redactor, cfg.out_dir,
                                on_status=lambda m: console.print("  [dim]%s[/dim]" % m),
                                payload=payload)
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
    # Both backends report a dollar figure but they do not mean the same thing:
    # the API one is what the key is billed, the CLI one is Claude Code costing
    # the run at the equivalent API rate while actually spending plan quota.
    # Label it, rather than letting the two read as the same number.
    cost = usage.get("cost_estimate_usd", 0.0)
    if ai_cfg.backend == ai_mod.BACKEND_CLI:
        spend = ("~$%.3f equiv, billed to the Claude plan" % cost) if cost \
            else "billed to the Claude plan"
    else:
        spend = "~$%.3f" % cost
    console.print("  [green]triaged[/green]  %d verdict(s), %d chain(s)  "
                  "[dim]%s in / %s out, %s[/dim]"
                  % (len(result.get("triage", [])), len(result.get("chains", [])),
                     usage.get("input_tokens", 0), usage.get("output_tokens", 0),
                     spend))

    local = ai_mod.rehydrate(result, redactor)
    triage_path = os.path.join(cfg.out_dir, "ai-triage.json")
    with open(triage_path, "w", encoding="utf-8") as fh:
        json.dump(local, fh, indent=2)
    # Unlike ai-payload.json (redacted, safe to leave at default permissions),
    # this is the rehydrated version - real hostnames and IPs are back in it,
    # same as redaction-map.json, so it gets the same 0600 treatment.
    try:
        os.chmod(triage_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    if local.get("summary"):
        console.print("\n[bold]Summary[/bold]\n%s"
                      % textwrap.fill(local["summary"], 96, initial_indent="  ",
                                      subsequent_indent="  "))
    return local


def run_ai_loop(store: Store, cfg: Config, args, assets: Dict) -> Optional[Dict]:
    """Iterative AI triage (PLAN-LOOP §2). Each round: triage -> collect the
    model's suggested commands -> auto-run the passive, in-scope ones (the
    active ones are queued for `assay followup --run` consent) -> record each
    result. One redactor is reused across rounds so its map grows consistently.

    With --ai-loop-resend, a round's send-eligible output is re-scrubbed (§3)
    and fed into the next round; without it the loop runs a single round, since
    re-triaging identical input would just repeat itself. Stops are the round
    cap (dependable), a fixpoint (nothing new fed back and nothing queued), and
    an optional USD budget on the API backend (§4).

    RoE gate (§0.2, minimal in-code): auto-run is refused under --safe (these
    commands send crafted traffic) and under a permissive scope (the scope gate
    cannot protect anything without one) - the same two hard stops the one-shot
    followup already enforces.
    """
    from assay import ai as ai_mod
    from assay import followup
    from assay.redact import Redactor, terms_from_context

    hosts = [r["host"] for r in store.host_rows()] + [r["host"] for r in store.web_rows()]
    redactor = Redactor(extra_terms=terms_from_context(cfg.targets, cfg.scope.allow, hosts))

    rounds = max(1, int(getattr(args, "ai_loop_rounds", 3) or 3))
    auto_mode = getattr(args, "ai_loop_auto", "passive") or "passive"
    # assay -> claude -> assay -> claude: results go back unless switched off.
    # Every one is redacted through the shared map and verify()'d first.
    resend = not bool(getattr(args, "ai_loop_no_resend", False))
    rate_cap = int(getattr(args, "ai_loop_rate", 5) or 5)
    limit = int(getattr(args, "ai_followup_limit", 25) or 25)
    timeout = float(getattr(args, "ai_followup_timeout", 120.0) or 120.0)
    # §4 budget: rounds are the universal ceiling; a USD budget is an ADDITIONAL
    # cap that only means anything on the API backend (the CLI bills to a plan,
    # where the reported cost is an equivalent, not a charge), so it is ignored
    # for claude-cli.
    budget_usd = float(getattr(args, "ai_loop_budget", 0.0) or 0.0)
    backend = getattr(args, "ai_backend", "") or ""
    spent_usd = 0.0

    auto_ok = auto_mode == "passive" and not cfg.safe_mode and not cfg.scope.permissive
    if auto_mode == "passive" and cfg.safe_mode:
        console.print("  [dim]loop auto-run disabled: --safe is set[/dim]")
    elif auto_mode == "passive" and cfg.scope.permissive:
        console.print("  [dim]loop auto-run disabled: scope is permissive[/dim]")

    from assay.store import TOOL_OUTPUT_CAP

    last: Optional[Dict] = None
    sendable: List[Dict] = []   # redacted results accumulated across rounds
    seen_cmds: set = set()      # commands already run, so rounds don't repeat them
    for rnd in range(rounds):
        console.print("\n[bold]AI loop[/bold] round %d/%d" % (rnd + 1, rounds))
        result = run_ai(store, cfg, args, assets, redactor=redactor,
                        followups=sendable or None)
        if not result:
            break
        last = result

        # The last round is judgement only. Anything run now could never be
        # shown to the model, so the loop ends on Claude's verdict, not on
        # unread output; the commands queue for `assay followup --run`.
        final_round = resend and rounds > 1 and rnd == rounds - 1
        cmds = [c for c in followup.collect(store, redactor.map)[:limit]
                if c.raw not in seen_cmds]
        vetted = [followup.vet(c.raw, cfg) for c in cmds]
        for src, v in zip(cmds, vetted):
            v.finding_id, v.finding_title = src.finding_id, src.finding_title
        auto, queued, refused = followup.plan_followups(
            vetted, auto_mode if auto_ok and not final_round else "none", rate_cap)
        if final_round and vetted:
            console.print("  [dim]final round: not running new commands, their "
                          "output could not be reviewed[/dim]")

        console.print("  [dim]%d new suggested: %d auto-run, %d queued for consent, "
                      "%d refused[/dim]" % (len(vetted), len(auto), len(queued), len(refused)))

        new_sendable: List[Dict] = []
        for v in auto:
            console.print("  [bold]$ %s[/bold]" % v.display)
            followup.run(v, timeout=timeout)
            seen_cmds.add(v.raw)
            state = "ok" if v.rc == 0 else "broke"
            tool = v.argv[0].split("/")[-1] if v.argv else "?"

            # Re-scrub (§3). The raw output stays LOCAL always (proof page).
            # Only send-eligible tools are candidates to go back, and only when
            # --ai-loop-resend is on: redact through the SHARED map, cap, then
            # verify() per result - residue drops THIS result, never the run.
            sent_text, did_send = "", False
            if resend:
                red, leaks = followup.rescrub(v.output, tool, redactor, cap=TOOL_OUTPUT_CAP)
                if red is not None:
                    sent_text, did_send = red, True
                    new_sendable.append({
                        "finding_id": v.finding_id,
                        "command": redactor.text(v.display),
                        "tool": tool,
                        "output": red,
                    })
                elif leaks:
                    console.print("    [yellow]not sent[/yellow] - %d residual item(s) "
                                  "after redaction (kept local only)" % len(leaks))
                elif v.output or v.rc:
                    # Not send-eligible: the body stays local, but the model
                    # still learns that it ran and how it ended. Same shared
                    # map, same verify() backstop as everything else.
                    red = redactor.text(followup.digest(v.output, v.rc))
                    if not redactor.verify(red):
                        sent_text, did_send = red, True
                        new_sendable.append({
                            "finding_id": v.finding_id,
                            "command": redactor.text(v.display),
                            "tool": tool,
                            "output": red,
                        })

            store.record_followup_result(
                round=rnd, finding_id=v.finding_id, finding_title=v.finding_title,
                tool=tool, argv=v.display, tier=v.tier, rc=v.rc or 0, state=state,
                output_local=v.output, output_sent=sent_text, sent=did_send)
            store.set_status(v.finding_id, "followup-run",
                             notes="$ %s\n(exit %s)\n%s" % (v.display, v.rc, v.output[:2000]))

        for v in queued:
            why = "active - needs consent" if v.tier != "passive" else "over rate cap"
            console.print("  [yellow]QUEUE[/yellow] %s [dim](%s)[/dim]" % (v.display, why))
            tool = v.argv[0].split("/")[-1] if v.argv else "?"
            # Recorded so the report can list what's waiting and remind the
            # reader to run `assay followup --run` - without this, a queued
            # command that nobody approves before the report is generated
            # leaves no trace anywhere.
            store.record_followup_result(
                round=rnd, finding_id=v.finding_id, finding_title=v.finding_title,
                tool=tool, argv=v.display, tier=v.tier, rc=None, state="queued",
                output_local=why)
        if queued:
            console.print("  [dim]run queued commands with: assay followup --run[/dim]")

        if not resend:
            if rounds > 1:
                console.print("  [dim]single round: --ai-loop-no-resend is set, so "
                              "results are not fed back (re-triage would be "
                              "identical)[/dim]")
            break
        sendable.extend(new_sendable)
        # Fixpoint stop: a round that fed nothing new back and left nothing
        # queued cannot change the next triage, so stop rather than re-sending
        # an identical payload. The round cap remains the dependable bound.
        if not new_sendable and not queued:
            console.print("  [dim]nothing new to feed back - stopping[/dim]")
            break
        # §4 USD budget (API backend only): stop before the NEXT round's send
        # once cumulative spend would exceed the ceiling.
        spent_usd += float((last.get("_usage") or {}).get("cost_estimate_usd", 0.0) or 0.0)
        if budget_usd and backend == ai_mod.BACKEND_API and spent_usd >= budget_usd:
            console.print("  [yellow]budget reached[/yellow] - ~$%.3f spent of $%.2f "
                          "ceiling; stopping before the next round"
                          % (spent_usd, budget_usd))
            break

    return last


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

    console.print("\n[bold]ai triage[/bold]")
    from assay import ai as ai_mod

    # --ai-backend api: the SDK plus a key.
    try:
        import anthropic  # noqa: F401
        have_sdk = True
    except ImportError:
        have_sdk = False
    console.print("  [bold]api[/bold]         [dim]%s[/dim]"
                  % ai_mod.BACKEND_HELP[ai_mod.BACKEND_API])
    console.print("    sdk       %s"
                  % ("[green]installed[/green]" if have_sdk
                     else "[yellow]not installed[/yellow]  pip install anthropic"))
    if have_sdk:
        ok, how = ai_mod.credential_status()
        console.print("    creds     %s  [dim]%s[/dim]"
                      % ("[green]ready[/green]" if ok else "[yellow]none[/yellow]", how))
        if not ok:
            console.print("    [dim]assay will prompt for a key when you use "
                          "--ai-backend api, or set ANTHROPIC_API_KEY / run "
                          "'ant auth login'[/dim]")

    # --ai-backend claude-cli: the binary the Claude desktop app installs.
    cli_ok, cli_how = ai_mod.cli_status(ai_mod.AIConfig(
        claude_bin=getattr(args, "ai_claude_bin", "claude") or "claude"))
    console.print("  [bold]claude-cli[/bold]  [dim]%s[/dim]"
                  % ai_mod.BACKEND_HELP[ai_mod.BACKEND_CLI])
    console.print("    binary    %s  [dim]%s[/dim]"
                  % ("[green]ready[/green]" if cli_ok else "[yellow]none[/yellow]",
                     cli_how))
    if not cli_ok:
        console.print("    [dim]install Claude Code (it ships with the Claude "
                      "desktop app and shares its sign-in), or point "
                      "--ai-claude-bin at the binary[/dim]")
    elif env.is_wsl() or env.is_windows():
        console.print("    [dim]assay runs the binary it finds on this side of "
                      "the WSL boundary - a Windows-only install will not be "
                      "visible here[/dim]")

    console.print("  [dim]AI triage is opt-in (--ai), needs an explicit "
                  "--ai-backend, and only ever sends redacted data.[/dim]")
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
    cfg.ensure_dirs()

    candidates = []
    reasons: Dict[str, int] = {}
    for r in burpimport.dedupe(requests_):
        ok, why = burpimport.worth_replaying(r, aggressive=args.aggressive)
        if ok and cfg.scope.allows(r.host):
            candidates.append(r)
        else:
            reasons[why] = reasons.get(why, 0) + 1
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
    rmap = _redaction_map(run_dir)
    if rmap is not None:
        console.print("  [dim]un-redacting with %d pseudonym(s)[/dim]"
                      % len(rmap.reverse))
    else:
        console.print("  [yellow]no redaction map found[/yellow] - commands will be "
                      "shown exactly as the model wrote them")

    cmds = followup.collect(store, rmap)[: args.limit]
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


def cmd_scope(args) -> int:
    from assay import targets as tload
    from assay.config import Scope
    from rich.table import Table
    parsed = tload.resolve_inputs(args.input)

    console.print("\n  read as: [bold]%s[/bold]" % parsed.source_format)
    wild = [t for t in parsed.targets if t.startswith("*.")]
    scannable = [t for t in parsed.targets if not t.startswith("*.")]

    tbl = Table(box=None, expand=False)
    tbl.add_column("", width=3, style="dim", justify="right")
    tbl.add_column("target", overflow="fold")
    tbl.add_column("kind", style="dim")
    for i, t in enumerate(scannable[:60], 1):
        tbl.add_row(str(i), t, tload.classify(t))
    if scannable:
        console.print(tbl)
        if len(scannable) > 60:
            console.print("  [dim]... and %d more[/dim]" % (len(scannable) - 60))
    else:
        console.print("  [yellow]no scannable targets found[/yellow]")

    if wild:
        console.print("\n  [bold]scope only[/bold] (not directly scannable; "
                      "use --expand to enumerate)")
        for w in wild:
            console.print("    %s" % w)
    if parsed.excluded:
        console.print("\n  [bold]excluded[/bold]")
        for e in parsed.excluded[:20]:
            console.print("    %s" % e)
    if parsed.skipped:
        console.print("\n  [bold]skipped[/bold]")
        for s in parsed.skipped[:20]:
            console.print("    [yellow]%s[/yellow]" % s)
    for w in parsed.warnings:
        console.print("\n  [yellow]%s[/yellow]" % w)

    allow, deny = tload.as_scope(parsed)
    s = Scope(allow=allow, deny=deny)
    console.print("\n  [bold]resulting scope[/bold]  %d allowed, %d denied%s"
                  % (len(allow), len(deny),
                     "" if not s.permissive else "  [yellow](permissive!)[/yellow]"))
    probe = [t for t in scannable[:2]] + ["example.invalid"]
    for h in probe:
        host = h.split("://")[-1].split("/")[0].split(":")[0]
        ok = s.allows(host)
        console.print("    %s %s" % ("[green]allow[/green]" if ok
                                     else "[red]block[/red]", host))

    console.print("\n  [dim]scan it with:[/dim]  assay scan %s"
                  % " ".join(args.input))
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
        "ai": cmd_ai, "show": cmd_show, "modules": cmd_modules,
        "install": cmd_install, "followup": cmd_followup, "diff": cmd_diff,
        "triage": cmd_triage, "scope": cmd_scope,
        "replay": cmd_replay, "submit": cmd_submit,
    }
    try:
        return handlers[args.cmd](args)
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
