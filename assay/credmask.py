"""Keep the engagement's credentials out of everything assay writes to share.

Session cookies, auth headers and API keys travel to the target and to the
external tools on their command lines. The store, the HTML report and the
submission exports are meant to be handed to other people, so every
credential value registered here is replaced with a marker before it reaches
them. The journal (activity.log, replay.sh) is owner-only and keeps the real
values on purpose: replaying a command needs the session.
"""

from __future__ import annotations

import re
import threading

MASK = "[redacted]"

# Header names whose value is a credential.
_SENSITIVE_HEADER = re.compile(
    r"cookie|authori[sz]ation|token|secret|session|passw|api-?key|auth|(?:^|-)key$",
    re.I)

_lock = threading.Lock()
_secrets: set[str] = set()


def register(value: str) -> None:
    """Mask `value` from now on. Short values are ignored: masking a value
    like "1" would shred every command line it appears in."""
    value = (value or "").strip()
    if len(value) >= 6:
        with _lock:
            _secrets.add(value)


def register_headers(headers: dict[str, str] | None) -> None:
    """Register the credential-bearing values of a header set."""
    for name, value in (headers or {}).items():
        if not _SENSITIVE_HEADER.search(name or ""):
            continue
        register(value)
        # The parts too: a tool that echoes one cookie, or the bare bearer
        # token, would otherwise slip past a mask of the whole header value.
        if name.lower() == "cookie":
            for part in (value or "").split(";"):
                register(part.partition("=")[2])
        else:
            register((value or "").partition(" ")[2])


def mask(text: str) -> str:
    """`text` with every registered credential value replaced by MASK."""
    if not text:
        return text
    with _lock:
        secrets = sorted(_secrets, key=len, reverse=True)
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, MASK)
    return text


def clear() -> None:
    """Forget every registered value (tests, and a fresh engagement)."""
    with _lock:
        _secrets.clear()
