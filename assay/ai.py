"""Optional AI triage pass over scan results.

This is off by default and it never sends raw scan data. The flow is:

    findings -> redact -> VERIFY (hard gate) -> Claude -> merge back locally

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
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from assay.models import Finding
from assay.redact import Redactor, terms_from_context

MODEL = "claude-opus-5"
INPUT_PRICE_PER_MTOK = 5.00
OUTPUT_PRICE_PER_MTOK = 25.00

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


class RedactionFailure(AIError):
    def __init__(self, leaks: List[str]) -> None:
        self.leaks = leaks
        super().__init__("redaction verification failed (%d residual item(s))" % len(leaks))


@dataclass
class AIConfig:
    enabled: bool = False
    model: str = MODEL
    max_findings: int = 60
    include_evidence: bool = False   # False = metadata only (strictest)
    evidence_chars: int = 400
    dry_run: bool = False
    effort: str = "high"
    inference_geo: str = "us"
    api_key: Optional[str] = None


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


def analyze(findings: List[Finding], assets: Dict[str, Any], cfg: AIConfig,
            redactor: Redactor, out_dir: str,
            on_status=None) -> Dict[str, Any]:
    """Run the triage pass. Raises RedactionFailure rather than leaking."""
    def say(msg: str) -> None:
        if on_status:
            on_status(msg)

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
            inference_geo="us",
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
    try:
        result = json.loads(text)
    except ValueError:
        raise AIError("model returned unparseable output; raw response kept in "
                      "ai-raw.txt")

    usage = getattr(message, "usage", None)
    result["_usage"] = {
        "input_tokens": getattr(usage, "input_tokens", 0),
        "output_tokens": getattr(usage, "output_tokens", 0),
        "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", 0),
        "cost_estimate_usd": round(estimate_cost(
            getattr(usage, "input_tokens", 0), getattr(usage, "output_tokens", 0)), 4),
    }
    result["_model"] = cfg.model
    return result


def rehydrate(result: Dict[str, Any], redactor: Redactor) -> Dict[str, Any]:
    """Put the real hostnames back for local display only."""
    blob = json.dumps(result)
    return json.loads(redactor.map.rehydrate(blob))
