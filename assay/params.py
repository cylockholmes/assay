"""What a parameter probably is, and therefore what is worth injecting.

The active checks previously took every parameter and tried everything on it.
That is slow and imprecise: firing traversal payloads at `page=2` wastes the
request budget, and firing SQL syntax at `redirect=https://...` produces
nothing while the SSRF check that would have paid never runs.

Inference uses the name and the *observed value* together, because either
alone is misleading - `id=/etc/passwd` is a file parameter whatever it is
called, and `file=3` is probably a record id. Where the signals disagree or
neither is decisive the parameter is treated as unknown, which means every
check still runs; the inference narrows work when it is confident and gets out
of the way when it is not.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlsplit

# Parameter classes, and the checks each is worth spending requests on.
CHECKS_FOR: Dict[str, Set[str]] = {
    "numeric":  {"sqli", "idor"},
    "url":      {"ssrf", "openredirect", "crlf"},
    "path":     {"traversal", "sqli"},
    "text":     {"reflection", "ssti", "sqli", "crlf"},
    "template": {"ssti", "reflection"},
    "token":    {"idor"},
    "bool":     set(),
    "unknown":  {"sqli", "reflection", "ssti", "traversal", "ssrf",
                 "openredirect", "crlf"},
}

NAME_HINTS: List[Tuple[str, re.Pattern]] = [
    ("url", re.compile(
        r"^(?:url|uri|link|src|source|dest|destination|redirect(?:_?uri|_?url)?|"
        r"next|return(?:_?url|_?to)?|continue|callback|webhook|endpoint|feed|"
        r"proxy|fetch|target|goto|forward|image_?url|remote|site|domain|host)$",
        re.I)),
    ("path", re.compile(
        r"^(?:file|filename|filepath|path|dir|folder|doc|document|template|tpl|"
        r"include|load|read|download|attachment|resource|asset|view)$", re.I)),
    ("numeric", re.compile(
        r"^(?:id|.*_id|uid|pid|gid|oid|no|num|number|page|offset|limit|count|"
        r"start|size|index|idx|qty|quantity|amount|year|month|day)$", re.I)),
    ("token", re.compile(
        r"^(?:token|auth|session|sid|key|api_?key|access|jwt|nonce|state|"
        r"signature|sig|hash|csrf|xsrf)$", re.I)),
    ("bool", re.compile(
        r"^(?:debug|verbose|enable[d]?|disable[d]?|active|admin|is_?\w+|"
        r"has_?\w+|show|hide|force|dry_?run|test)$", re.I)),
    ("text", re.compile(
        r"^(?:q|s|query|search|term|keyword|name|title|message|msg|comment|"
        r"body|content|text|description|subject|note|label|email|user(?:name)?)$",
        re.I)),
    ("template", re.compile(
        r"^(?:template|tpl|layout|theme|render|format|view_?name|pattern)$", re.I)),
]

VALUE_HINTS: List[Tuple[str, re.Pattern]] = [
    ("url", re.compile(r"^(?:https?|ftp|file|gopher)://|^//[\w.-]+\.", re.I)),
    ("path", re.compile(r"^[./\\]|/.*\.[A-Za-z0-9]{1,5}$|^[A-Za-z]:\\")),
    ("token", re.compile(
        r"^eyJ[A-Za-z0-9_-]{8,}\.|^[0-9a-f]{32,}$|"
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)),
    ("numeric", re.compile(r"^-?\d{1,12}$")),
    ("bool", re.compile(r"^(?:true|false|yes|no|on|off|0|1)$", re.I)),
]


def classify(name: str, value: str = "") -> str:
    """Best guess at what a parameter carries.

    The value wins where it is unambiguous - a URL in `id` is still a URL - and
    the name decides otherwise. Disagreement that cannot be resolved returns
    'unknown', which enables every check rather than guessing wrong.
    """
    value = (value or "").strip()
    by_value = ""
    for kind, rx in VALUE_HINTS:
        if value and rx.search(value):
            by_value = kind
            break
    by_name = ""
    for kind, rx in NAME_HINTS:
        if rx.match(name or ""):
            by_name = kind
            break

    # An absolute URL is unambiguous and overrides any name.
    if by_value == "url":
        return by_value
    # A path-like value overrides the name too - id=/etc/passwd is a file
    # parameter whatever it is called - except where the name says redirect.
    # `next=/dashboard` is a relative redirect, which is the single most
    # common shape of an open redirect, and reading it as a path means the
    # redirect check never runs on it.
    if by_value == "path" and by_name != "url":
        return by_value
    if by_name:
        # A numeric name holding something non-numeric is not a record id.
        if by_name == "numeric" and by_value and by_value != "numeric":
            return "unknown"
        # A boolean-looking name holding something that is not boolean is not
        # a flag - debug=<script> is a reflection candidate, and treating it as
        # a flag means nothing ever tests it.
        if by_name == "bool" and value and by_value != "bool":
            return "unknown"
        return by_name
    return by_value or "unknown"


def wants(check: str, name: str, value: str = "") -> bool:
    """Should `check` spend requests on this parameter?"""
    return check in CHECKS_FOR.get(classify(name, value), CHECKS_FOR["unknown"])


def parameters(url: str) -> List[Tuple[str, str]]:
    return parse_qsl(urlsplit(url).query, keep_blank_values=True)


def targets_for(check: str, url: str, fallback: Optional[List[str]] = None
                ) -> List[str]:
    """Parameter names on `url` worth testing with `check`.

    When the URL carries no parameters the caller's fallback list is used, so a
    bare endpoint is still probed with plausible names.
    """
    params = parameters(url)
    if not params:
        return list(fallback or [])
    return [n for n, v in params
            if not n.startswith("assay_") and wants(check, n, v)]


# Numeric parameters that address a position in a list rather than an object.
PAGINATION = re.compile(
    r"^(?:page|p|offset|start|limit|size|per_?page|count|max|top|skip|"
    r"index|idx|from|to|year|month|day|width|height|zoom|version|v)$", re.I)


def idor_candidates(url: str) -> List[Tuple[str, str, str]]:
    """Parameters that look like they address someone else's object.

    Returns (name, value, kind). These are not tested automatically - deciding
    whether object 41 belongs to you needs a second account - but collecting
    them turns "test for IDOR" into a specific list of places to look.
    """
    out: List[Tuple[str, str, str]] = []
    for name, value in parameters(url):
        if name.startswith("assay_"):
            continue
        kind = classify(name, value)
        if kind not in ("numeric", "token") or not value:
            continue
        # Pagination addresses a position, not somebody's record.
        if kind == "numeric" and PAGINATION.match(name):
            continue
        out.append((name, value, kind))
    return out
