"""First-run questions: the scan options a person would otherwise have to
remember as flags.

Asked right after the codename, on an interactive terminal only. Anything the
user already decided with a flag is not asked again, so flags still win and a
script, cron job or CI run - no TTY - sees no questions at all and gets the
flag defaults, exactly as before. Enter accepts the default shown.

The module only reads and writes the argparse namespace; it builds nothing
itself, which keeps it testable with a scripted `ask`.
"""

from __future__ import annotations

import sys
from typing import Callable, List, Optional, Sequence

Ask = Callable[[str], str]

PROFILES = ("quick", "standard", "deep")
BACKENDS = ("claude-cli", "api")


def interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _yes_no(ask: Ask, text: str, default: bool, hint: str = "") -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        raw = ask("  %s %s %s: " % (text, suffix, ("(%s)" % hint) if hint else "")
                  ).strip().lower()
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False


def _choice(ask: Ask, text: str, options: Sequence[str], default: str) -> str:
    shown = "/".join(o.upper() if o == default else o for o in options)
    while True:
        raw = ask("  %s [%s]: " % (text, shown)).strip().lower()
        if not raw:
            return default
        hit = [o for o in options if o == raw or o.startswith(raw)]
        if len(hit) == 1:
            return hit[0]


def _number(ask: Ask, text: str, default: int, lo: int, hi: int) -> int:
    while True:
        raw = ask("  %s [%d]: " % (text, default)).strip()
        if not raw:
            return default
        if raw.isdigit() and lo <= int(raw) <= hi:
            return int(raw)


def ask_options(args, ask: Ask, say: Callable[[str], None] = print) -> List[str]:
    """Ask the scan questions, write the answers onto `args`, and return a
    short list of what was chosen for the run summary."""
    chosen: List[str] = []
    safe = bool(getattr(args, "safe", False))
    say("\n  [bold]scan options[/bold] [dim](Enter accepts the default)[/dim]")

    # Depth.
    if not getattr(args, "profile", None):
        args.profile = _choice(ask, "depth - quick / standard / deep",
                               PROFILES, "standard")
    chosen.append(args.profile)

    # Reach.
    if not getattr(args, "no_expand", False):
        if not _yes_no(ask, "expand the target list?", True,
                       "subdomains, permutations, CT logs"):
            args.no_expand = True
    if not getattr(args, "no_passive", False):
        if not _yes_no(ask, "query third-party OSINT / CVE sources?", True):
            args.no_passive = True
    if not safe and not getattr(args, "no_udp", False):
        if not _yes_no(ask, "UDP sweep?", True, "curated ports"):
            args.no_udp = True
    if args.profile != "deep" and not getattr(args, "no_deep_ports", False):
        if not _yes_no(ask, "deep port wave?", True, "full-range, obscure TCP ports"):
            args.no_deep_ports = True

    # Coverage: a long sweep split into batches loses a slice if it times out,
    # not everything. Only worth asking on the full-range profile.
    if args.profile == "deep" and getattr(args, "sweep_batches", None) is None:
        args.sweep_batches = _number(
            ask, "split the port sweep into how many batches? (0 = automatic)",
            0, 0, 50)
        if args.sweep_batches:
            chosen.append("%d sweep batches" % args.sweep_batches)

    # Intrusiveness.
    if not safe and not getattr(args, "aggressive", False):
        args.aggressive = _yes_no(ask, "aggressive checks?", False,
                                  "may change state on the target")
    if getattr(args, "aggressive", False):
        chosen.append("aggressive")

    # AI.
    loop = bool(getattr(args, "ai_loop", False))
    use_ai = loop or bool(getattr(args, "ai", False))
    if not use_ai:
        use_ai = _yes_no(ask, "AI triage of the findings?", False,
                         "redacted before anything is sent")
        args.ai = use_ai
    if use_ai and not loop:
        loop = _yes_no(ask, "iterate - let the AI propose checks, run them, "
                            "and re-triage?", True,
                       "results go back redacted")
        args.ai_loop = loop
    if use_ai and getattr(args, "ai_backend", None) is None \
            and not getattr(args, "ai_dry_run", False):
        args.ai_backend = _choice(ask, "AI backend - claude-cli (your plan) / api "
                                       "(billed per token)", BACKENDS, "claude-cli")
    if loop and not getattr(args, "ai_loop_rounds", None):
        args.ai_loop_rounds = _number(ask, "max AI rounds", 3, 1, 10)
    if use_ai:
        chosen.append("AI loop" if loop else "AI triage")
    return chosen
