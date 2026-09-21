"""Optional AI triage pass over scan results.

This is off by default and it never sends raw scan data. The flow is:

    findings -> redact -> VERIFY (hard gate) -> Claude -> merge back locally

There are two ways to reach Claude and you have to pick one; there is no
default, because the two spend different money:

    api         the Anthropic SDK with your own API key. Billed per token.
    claude-cli  the Claude Code CLI in headless mode, which is how the Claude
                desktop app is driven from a script. Billed against whatever
                Claude plan that CLI is signed in to, not per token.

Both send the identical redacted payload and get the identical JSON back. The
CLI backend is launched with every tool, skill, MCP server and project setting
turned off, in an empty working directory, so it can only answer the question.

The verification gate is not advisory. If any known client term, hostname, IP,
credential or personal identifier survives redaction, the payload is not
transmitted and the run aborts with the residue printed. `--ai-dry-run` writes
the exact bytes that would be sent to disk so you can read them first.

What the model is asked for is judgement, not detection: which findings are
worth a report, which look like false positives, what the next manual step is,
and which findings chain together. All of that reasoning works fine on
pseudonymised data - the model never needs to know who the client is.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from assay.models import Finding
from assay.redact import Redactor, terms_from_context

MODEL = "claude-opus-5"
INPUT_PRICE_PER_MTOK = 5.00
OUTPUT_PRICE_PER_MTOK = 25.00

# The transports. Deliberately no default - see the module docstring.
BACKEND_API = "api"
BACKEND_CLI = "claude-cli"
BACKENDS = (BACKEND_API, BACKEND_CLI)

BACKEND_HELP = {
    BACKEND_API: "Anthropic API key (billed per token)",
    BACKEND_CLI: "Claude Code CLI / desktop app sign-in (billed to that plan)",
}

# Headless Claude Code, stripped to a single question-answering turn: no
# command or code execution, no web fetch, no MCP servers, no skills, no
# project or local settings, and nothing written to the session store.
CLI_ISOLATION_FLAGS = [
    "--restricted",
    "--strict-mcp-config",
    "--disable-slash-commands",
    "--no-session-persistence",
]

SYSTEM_PROMPT = """You are triaging the output of an automated security scan for a \
bug bounty researcher working an authorized engagement.

All client-identifying data has been replaced with stable pseudonyms in square \
brackets: [CLIENT-01], [HOST-02], [IP-03], [EMAIL-01], [SECRET-04] and similar. \
Treat each token as an opaque stable identifier. The same token always means the \
same real value. Never speculate about what a token stands for, and never ask for \
the real values - you do not need them and they will not be provided.

Your job is judgement, not detection. The scanner already decided what exists. \
For each finding decide:

1. verdict - "report" when the evidence shown would stand up in a bug bounty \
   submission on its own; "investigate" when it is probably real but needs a \
   specific manual step to demonstrate impact; "discard" when the evidence is \
   consistent with a benign explanation or the issue has no realistic security \
   consequence for this kind of target.
2. false_positive_risk - based only on whether the evidence logically compels the \
   conclusion. Signature matches on file content are strong. Behavioural \
   inferences from status codes and response lengths are weak.
3. next_steps - concrete, specific actions. "Verify the finding" is useless. \
   "Request the /actuator/heapdump endpoint and grep the dump for JSESSIONID to \
   recover a live session" is useful. Prefer steps that turn a medium into a high \
   by demonstrating real impact.
4. impact_statement - one sentence a triager would accept, describing what an \
   attacker gains. Avoid restating the vulnerability class.

Then identify chains: sets of findings that are individually low or medium but \
together demonstrate materially higher impact. This is where most of the value is. \
Be strict - only propose a chain if each step genuinely enables the next.

Calibration rules:
- Missing security headers, verbose banners and TLS hygiene are almost never \
  reportable alone. Mark them "discard" unless they enable a specific chain you \
  are also proposing.
- Prefer fewer, higher-quality "report" verdicts. A researcher acting on your \
  output has finite time and duplicate/N-A submissions cost them reputation.
- Do not invent findings that are not in the input. Do not assume an endpoint \
  exists because it commonly does.
- If a finding's evidence does not actually support its stated severity, say so \
  in the rationale and lower the verdict."""

RESPONSE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "string",
            "description": "3-5 sentences: what this target surface looks like and "
                           "where the researcher should spend their next hour.",
        },
        "triage": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "verdict": {"type": "string", "enum": ["report", "investigate", "discard"]},
                    "priority": {"type": "integer", "description": "1 = look at first"},
                    "false_positive_risk": {"type": "string",
                                            "enum": ["low", "medium", "high"]},
                    "rationale": {"type": "string"},
                    "impact_statement": {"type": "string"},
                    "next_steps": {"type": "array", "items": {"type": "string"}},
                    "commands": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Runnable shell commands that verify or "
                                       "escalate this finding. One command per "
                                       "entry, no pipes or shell operators. Use "
                                       "the pseudonym tokens verbatim where a "
                                       "host is needed - they are substituted "
                                       "locally before execution.",
                    },
                },
                "required": ["id", "verdict", "priority", "false_positive_risk",
                             "rationale", "impact_statement", "next_steps",
                             "commands"],
                "additionalProperties": False,
            },
        },
        "chains": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "finding_ids": {"type": "array", "items": {"type": "string"}},
                    "combined_severity": {"type": "string",
                                          "enum": ["critical", "high", "medium", "low"]},
                    "combined_impact": {"type": "string"},
                    "steps": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["name", "finding_ids", "combined_severity",
                             "combined_impact", "steps"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["summary", "triage", "chains"],
    "additionalProperties": False,
}


class AIError(Exception):
    pass


class BackendUnset(AIError):
    """Neither backend was chosen. The caller has to ask."""

    def __init__(self) -> None:
        super().__init__(
            "no AI backend selected. Pass --ai-backend with one of: "
            + ", ".join("%s (%s)" % (b, BACKEND_HELP[b]) for b in BACKENDS)
        )


class RedactionFailure(AIError):
    def __init__(self, leaks: List[str]) -> None:
        self.leaks = leaks
        super().__init__("redaction verification failed (%d residual item(s))" % len(leaks))


@dataclass
class AIConfig:
    enabled: bool = False
    backend: str = ""                # "api" or "claude-cli"; no default on purpose
    model: str = MODEL
    max_findings: int = 60
    include_evidence: bool = False   # False = metadata only (strictest)
    evidence_chars: int = 400
    dry_run: bool = False
    effort: str = "high"
    inference_geo: str = "us"
    api_key: Optional[str] = None
    claude_bin: str = "claude"       # CLI backend: binary name or absolute path
    cli_timeout: int = 1800


# --------------------------------------------------------------------------
# Payload construction
# --------------------------------------------------------------------------


def build_payload(findings: List[Finding], assets: Dict[str, Any],
                  cfg: AIConfig, redactor: Redactor) -> Tuple[Dict[str, Any], List[str]]:
    """Return (redacted payload, residual leaks). Non-empty leaks == do not send."""
    items: List[Dict[str, Any]] = []
    for f in findings[: cfg.max_findings]:
        item: Dict[str, Any] = {
            "id": f.fingerprint(),
            "title": f.title,
            "scanner_severity": f.severity,
            "scanner_confidence": f.confidence,
            "owasp": f.category,
            "cwe": f.cwe,
            "module": f.module,
            "scanner_impact": f.impact,
            "detail": f.detail,
            "tags": f.tags,
            # The target is pseudonymised but kept so the model can group
            # findings that share an origin - that is what makes chains findable.
            "target": f.target,
        }
        if cfg.include_evidence:
            item["evidence"] = [
                e.compact(cfg.evidence_chars) for e in f.evidence[:2]
            ]
        items.append(item)

    payload = {
        "scan_summary": {
            "total_findings": len(findings),
            "included": len(items),
            "hosts": assets.get("hosts", 0),
            "web_endpoints": assets.get("web", 0),
            "technologies": sorted(assets.get("tech", []))[:40],
            "open_service_types": sorted(assets.get("services", []))[:40],
        },
        "findings": items,
    }

    redacted = redactor.obj(payload)
    blob = json.dumps(redacted, indent=2, sort_keys=True)
    leaks = redactor.verify(blob)
    return redacted, leaks


def estimate_cost(input_tokens: int, output_tokens: int = 4000) -> float:
    return (input_tokens / 1e6) * INPUT_PRICE_PER_MTOK + \
           (output_tokens / 1e6) * OUTPUT_PRICE_PER_MTOK


# --------------------------------------------------------------------------
# The call
# --------------------------------------------------------------------------


def credential_status() -> Tuple[bool, str]:
    """How would the SDK authenticate right now?

    The SDK resolves in a fixed order: ANTHROPIC_API_KEY, then
    ANTHROPIC_AUTH_TOKEN, then an OAuth profile stored by `ant auth login`.
    An unset environment variable therefore does not mean "no credentials".
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return True, "ANTHROPIC_API_KEY is set"
    if os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return True, "ANTHROPIC_AUTH_TOKEN is set"
    try:
        p = subprocess.run(["ant", "auth", "status"], capture_output=True,
                           text=True, timeout=15)
        out = (p.stdout or "") + (p.stderr or "")
        if p.returncode == 0 and re.search(r"active|logged in|profile", out, re.I):
            return True, "authenticated via an 'ant auth login' profile"
    except (OSError, subprocess.SubprocessError):
        pass
    return False, "no API key and no stored profile"


def resolve_cli(name: str) -> Optional[str]:
    """Absolute path to the Claude binary, or None.

    Absolute matters: the CLI is launched in a scratch directory, so a relative
    path like ./claude would resolve against that instead of the user's cwd.
    """
    found = shutil.which(name)
    if found:
        return os.path.abspath(found)
    if os.path.isfile(name) and os.access(name, os.X_OK):
        return os.path.abspath(name)
    return None


def cli_status(cfg: Optional["AIConfig"] = None) -> Tuple[bool, str]:
    """Is there a usable Claude Code CLI to hand the request to?

    The CLI is what the Claude desktop app installs and shares a sign-in with,
    so "the desktop app is logged in" and "this binary can answer" are the same
    question. `claude --version` only proves the binary runs - a stale sign-in
    surfaces at call time, where the error text is far more useful than
    anything we could guess here.
    """
    name = (cfg.claude_bin if cfg else "claude") or "claude"
    path = resolve_cli(name)
    if not path:
        return False, ("'%s' is not on PATH - install Claude Code, or point "
                       "--ai-claude-bin at the binary" % name)
    try:
        p = subprocess.run([path, "--version"], capture_output=True, text=True,
                           timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "%s would not run: %s" % (path, exc)
    if p.returncode != 0:
        return False, "%s --version exited %d" % (path, p.returncode)
    return True, "%s (%s)" % (path, (p.stdout or "").strip() or "version unknown")


def backend_status(cfg: "AIConfig") -> Tuple[bool, str]:
    """Can the selected backend be used right now?"""
    if cfg.backend == BACKEND_API:
        return credential_status()
    if cfg.backend == BACKEND_CLI:
        return cli_status(cfg)
    raise BackendUnset()


def prompt_for_key(console=None) -> bool:
    """Ask for an API key interactively. Session-only, never written to disk.

    Persisting a provider key is the user's decision to make deliberately, so
    this sets it for the current process and tells them how to make it stick.
    """
    import getpass
    if not sys.stdin.isatty():
        return False
    say = console.print if console else (lambda *a, **k: None)
    say("\n  [bold]AI triage needs an Anthropic API key.[/bold]")
    say("  [dim]It is used only to send the redacted payload you can inspect "
        "first with --ai-dry-run.[/dim]")
    say("  [dim]Leave blank to skip AI triage; the scan results are unaffected.[/dim]")
    try:
        key = getpass.getpass("  API key (input hidden): ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    if not key:
        return False
    if not key.startswith("sk-ant-"):
        say("  [yellow]that does not look like an Anthropic key "
            "(expected it to start with 'sk-ant-')[/yellow]")
    os.environ["ANTHROPIC_API_KEY"] = key
    say("  [green]key set for this run only.[/green] To persist it:")
    say("     [dim]export ANTHROPIC_API_KEY=...   (add to ~/.bashrc)[/dim]")
    say("     [dim]or run 'ant auth login' once, which stores a profile[/dim]")
    return True


def _client(cfg: AIConfig):
    try:
        import anthropic
    except ImportError:
        raise AIError(
            "the 'anthropic' package is not installed. Install it with:\n"
            "    pip install 'anthropic'\n"
            "or run assay without --ai."
        )
    kwargs: Dict[str, Any] = {"timeout": 600.0}
    if cfg.api_key:
        kwargs["api_key"] = cfg.api_key
    try:
        return anthropic.Anthropic(**kwargs)
    except Exception as exc:                       # missing credentials, bad config
        raise AIError(
            "could not initialise the Anthropic client: %s\n"
            "Set ANTHROPIC_API_KEY, or authenticate once with 'ant auth login'." % exc
        )


def count_tokens(cfg: AIConfig, payload: Dict[str, Any]) -> int:
    client = _client(cfg)
    try:
        resp = client.messages.count_tokens(
            model=cfg.model,
            system=[{"type": "text", "text": SYSTEM_PROMPT,
                     "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": _user_message(payload)}],
        )
        return int(resp.input_tokens)
    except Exception:
        # Token counting is a convenience; never block a scan on it.
        return len(json.dumps(payload)) // 3


def _user_message(payload: Dict[str, Any]) -> str:
    return (
        "Triage the following pseudonymised scan results.\n\n"
        "```json\n%s\n```\n\n"
        "Return every finding in `triage`, ordered by priority (1 first). "
        "Propose chains only where each step genuinely enables the next."
        % json.dumps(payload, indent=2, sort_keys=True)
    )


def _call_api(cfg: AIConfig, payload: Dict[str, Any], say) -> Tuple[str, Dict[str, Any]]:
    """Transport 1: the Anthropic SDK, billed per token against an API key."""
    client = _client(cfg)
    tokens = count_tokens(cfg, payload)
    say("sending ~%s input tokens (est. $%.3f) to %s" %
        (f"{tokens:,}", estimate_cost(tokens), cfg.model))

    try:
        # Streaming because triage over a large finding set can produce long
        # output, and a non-streaming request at this max_tokens risks a timeout.
        with client.messages.stream(
            model=cfg.model,
            max_tokens=32000,
            system=[{"type": "text", "text": SYSTEM_PROMPT,
                     "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": _user_message(payload)}],
            thinking={"type": "adaptive"},
            # Some programmes require that data is not processed outside the
            # United States. Pinning the geography makes that checkable rather
            # than assumed.
            inference_geo=cfg.inference_geo,
            output_config={
                "effort": cfg.effort,
                "format": {"type": "json_schema", "schema": RESPONSE_SCHEMA},
            },
        ) as stream:
            message = stream.get_final_message()
    except Exception as exc:
        raise AIError("Claude API call failed: %s" % exc)

    if getattr(message, "stop_reason", None) == "refusal":
        raise AIError("the model declined to answer (stop_reason=refusal). "
                      "Nothing was triaged; scan results are unaffected.")

    text = "".join(b.text for b in message.content if b.type == "text")
    usage = getattr(message, "usage", None)
    return text, {
        "input_tokens": getattr(usage, "input_tokens", 0),
        "output_tokens": getattr(usage, "output_tokens", 0),
        "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", 0),
        "cost_estimate_usd": round(estimate_cost(
            getattr(usage, "input_tokens", 0), getattr(usage, "output_tokens", 0)), 4),
    }


def _cli_argv(cfg: AIConfig, binary: str) -> List[str]:
    """The exact command line. Separate so a test can assert on it."""
    return [
        binary,
        "--print",                       # headless: answer once, exit
        "--model", cfg.model,
        "--effort", cfg.effort,
        "--output-format", "json",
        "--json-schema", json.dumps(RESPONSE_SCHEMA),
        "--system-prompt", SYSTEM_PROMPT,
    ] + list(CLI_ISOLATION_FLAGS)


def _call_cli(cfg: AIConfig, payload: Dict[str, Any],
              say) -> Tuple[str, Dict[str, Any]]:
    """Transport 2: hand the request to the Claude Code CLI / desktop app.

    Same prompt, same schema, same redacted payload as the API backend - the
    difference is who pays. The CLI shares a sign-in with the desktop app, so
    this spends that Claude plan instead of API credit.

    The prompt goes in on stdin rather than argv: a 60-finding payload is well
    past the point where an argument list is a sensible place to put it.
    """
    ok, how = cli_status(cfg)
    if not ok:
        raise AIError("the Claude Code CLI is not usable: %s" % how)
    binary = resolve_cli(cfg.claude_bin)
    if not binary:                      # cli_status passed, so this is a race
        raise AIError("%s disappeared between the check and the call"
                      % cfg.claude_bin)
    argv = _cli_argv(cfg, binary)

    say("handing the payload to %s (%s, no API key used)" % (binary, cfg.model))
    # An empty working directory: restricted mode confines the file tools to
    # the cwd and reads CLAUDE.md from it, so give it nothing to find. The run
    # directory is full of scan output and is not it.
    with tempfile.TemporaryDirectory(prefix="assay-ai-") as sandbox:
        try:
            proc = subprocess.run(argv, input=_user_message(payload),
                                  capture_output=True, text=True,
                                  cwd=sandbox, timeout=cfg.cli_timeout)
        except subprocess.TimeoutExpired:
            raise AIError("the Claude CLI did not finish within %ds. Retry, or "
                          "lower --ai-max." % cfg.cli_timeout)
        except (OSError, subprocess.SubprocessError) as exc:
            raise AIError("could not run %s: %s" % (binary, exc))

    if proc.returncode != 0 and not (proc.stdout or "").strip():
        raise AIError("the Claude CLI exited %d: %s"
                      % (proc.returncode,
                         (proc.stderr or "").strip()[:400] or "no output"))

    try:
        envelope = json.loads(proc.stdout)
    except ValueError:
        raise AIError("the Claude CLI returned output that is not JSON: %s"
                      % (proc.stdout or proc.stderr or "")[:400])

    # `is_error` is the authoritative field. `subtype` stays "success" even for
    # an auth failure, so keying off that would silently swallow one.
    if envelope.get("is_error"):
        raise AIError("the Claude CLI reported an error: %s"
                      % str(envelope.get("result", "unknown"))[:400])

    denials = envelope.get("permission_denials") or []
    if denials:
        say("note: the CLI asked for %d tool permission(s) and was refused - "
            "triage only needs to answer, not to act" % len(denials))

    usage = envelope.get("usage") or {}
    # The CLI splits input across three counters and puts almost all of a
    # first-turn prompt in cache_creation, so `input_tokens` alone reads as
    # single digits for a payload of thousands. Report what the model actually
    # read, and keep cache reads separate the way the API backend does.
    fresh_input = (int(usage.get("input_tokens") or 0)
                   + int(usage.get("cache_creation_input_tokens") or 0))
    return str(envelope.get("result", "")), {
        "input_tokens": fresh_input,
        "output_tokens": int(usage.get("output_tokens") or 0),
        "cache_read_input_tokens": int(usage.get("cache_read_input_tokens") or 0),
        # What the CLI itself reports. Claude Code costs a run at the equivalent
        # API rate even when it is signed in to a plan, so this is a yardstick
        # for how big the run was, not necessarily money leaving an account.
        "cost_estimate_usd": round(float(envelope.get("total_cost_usd") or 0.0), 4),
        "session_id": envelope.get("session_id", ""),
    }


def _parse_result(text: str, out_dir: str) -> Dict[str, Any]:
    """Both backends are asked for the same schema. Both can still miss."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    # A model that wrapped the object in prose or a fence is recoverable and
    # not worth throwing a whole triage pass away over.
    match = re.search(r"\{.*\}", text or "", re.S)
    if match:
        try:
            return json.loads(match.group(0))
        except ValueError:
            pass
    raw_path = os.path.join(out_dir, "ai-raw.txt")
    try:
        with open(raw_path, "w", encoding="utf-8") as fh:
            fh.write(text or "")
    except OSError:
        raw_path = "(could not be written)"
    raise AIError("model returned unparseable output; raw response kept in %s"
                  % raw_path)


def analyze(findings: List[Finding], assets: Dict[str, Any], cfg: AIConfig,
            redactor: Redactor, out_dir: str,
            on_status=None) -> Dict[str, Any]:
    """Run the triage pass. Raises RedactionFailure rather than leaking."""
    def say(msg: str) -> None:
        if on_status:
            on_status(msg)

    # Checked before the payload is built: a dry run is allowed without a
    # backend, because a dry run never reaches one.
    if not cfg.dry_run and cfg.backend not in BACKENDS:
        raise BackendUnset()

    payload, leaks = build_payload(findings, assets, cfg, redactor)
    if leaks:
        raise RedactionFailure(leaks)

    preview_path = os.path.join(out_dir, "ai-payload.json")
    with open(preview_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    say("redacted payload written to %s" % preview_path)

    map_path = os.path.join(out_dir, "redaction-map.json")
    redactor.map.save(map_path)
    say("pseudonym map saved locally (0600) to %s" % map_path)

    if cfg.dry_run:
        return {"dry_run": True, "payload_path": preview_path,
                "estimated_input_tokens": len(json.dumps(payload)) // 3}

    # Explicit, not `api if ... else cli`: an unrecognised backend string must
    # not quietly become "shell out to Claude Code". Belt and braces with the
    # guard above, which is the one that normally catches this.
    transports = {BACKEND_API: _call_api, BACKEND_CLI: _call_cli}
    if cfg.backend not in transports:
        raise BackendUnset()
    text, usage = transports[cfg.backend](cfg, payload, say)

    result = _parse_result(text, out_dir)
    result["_usage"] = usage
    result["_model"] = cfg.model
    result["_backend"] = cfg.backend
    return result


def rehydrate(result: Dict[str, Any], redactor: Redactor) -> Dict[str, Any]:
    """Put the real hostnames back for local display only."""
    blob = json.dumps(result)
    return json.loads(redactor.map.rehydrate(blob))
