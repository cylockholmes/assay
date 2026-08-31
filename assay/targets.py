"""Reading targets out of whatever the engagement actually gave you.

Scope arrives in inconsistent shapes: a Burp project scope export, a plain list
of hosts, a CSV, or a block of text pasted out of a portal complete with
headings and table pipes. Making the operator reformat that by hand is where
mistakes enter - a dropped host is a missed finding, and a stray one is a
request somewhere it should not go.

This normalises all of it, reports what it understood, and refuses to guess
where guessing would be dangerous.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit

# A line that is a section heading rather than a target. Anything under an
# out-of-scope heading is treated as an exclusion.
OUT_OF_SCOPE_HEADING = re.compile(
    r"^\W*(?:out[\s\-_]*of[\s\-_]*scope|excluded?|not[\s\-_]*in[\s\-_]*scope|"
    r"do[\s\-_]*not[\s\-_]*test|prohibited)\b", re.I)
IN_SCOPE_HEADING = re.compile(
    r"^\W*(?:in[\s\-_]*scope|scope|targets?|included?|assets?)\b\W*$", re.I)

# Tokens that look like a host, an address, a range or a URL.
HOSTLIKE = re.compile(
    r"^(?:\*\.)?(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+"
    r"[A-Za-z]{2,24}\.?$")
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
CIDR = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
IPRANGE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$")

# Cell separators in pasted tables and CSVs.
SPLIT = re.compile(r"[,;|\t]+|\s{2,}")

# Extensions that are never a real TLD. Without this, "hosts.txt" satisfies the
# hostname pattern and a mistyped filename becomes a scan target that silently
# resolves to nothing.
DATA_EXT = {"txt", "json", "csv", "tsv", "lst", "list", "md", "yaml", "yml",
            "xml", "scope", "log", "bak", "old", "conf", "cfg", "ini", "dat",
            "out", "tmp"}

# A value meant as a filename: has a path separator, or a data-file extension.
LOOKS_LIKE_PATH = re.compile(
    r"[/\\]|\.(?:txt|json|csv|tsv|lst|list|md|yaml|yml|xml|scope)$", re.I)

# Never scannable, and almost always a paste accident.
DANGEROUS = {"0.0.0.0/0", "::/0", "*", "*.*", ".", "localhost", "127.0.0.1"}


@dataclass
class ParsedTargets:
    targets: List[str] = field(default_factory=list)
    excluded: List[str] = field(default_factory=list)
    source_format: str = "list"
    skipped: List[str] = field(default_factory=list)   # (value, reason)
    warnings: List[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.targets)


def _clean(token: str) -> str:
    t = token.strip().strip("\"'`,;")
    # Bullets require whitespace after the marker: '- host' is a bullet,
    # '*.example.com' is a wildcard host and must keep its asterisk.
    t = re.sub(r"^[-+\u2022]\s+|^\*\s+", "", t)
    t = re.sub(r"^\d+[.)]\s+", "", t)              # numbered list
    t = t.strip().rstrip(".")
    return t


def classify(token: str) -> str:
    """What kind of target is this, if any?"""
    t = token.strip()
    if not t:
        return ""
    if "://" in t:
        return "url"
    if CIDR.match(t):
        return "cidr"
    if IPRANGE.match(t):
        return "range"
    if IPV4.match(t):
        try:
            ipaddress.ip_address(t)
            return "ip"
        except ValueError:
            return ""
    if ":" in t and t.count(":") >= 2:
        try:
            ipaddress.ip_address(t.split("/")[0])
            return "ipv6"
        except ValueError:
            pass
    host = t.split(":")[0]
    if HOSTLIKE.match(host):
        if host.rsplit(".", 1)[-1].lower() in DATA_EXT:
            return ""
        return "wildcard" if host.startswith("*.") else "host"
    return ""


def expand_range(token: str) -> List[str]:
    """Turn 10.0.0.1-10.0.0.9 or 10.0.0.1-9 into individual addresses."""
    m = IPRANGE.match(token.strip())
    if not m:
        return []
    start, end = m.group(1), m.group(2)
    if "." not in end:
        end = start.rsplit(".", 1)[0] + "." + end
    try:
        a, b = ipaddress.ip_address(start), ipaddress.ip_address(end)
    except ValueError:
        return []
    if int(b) < int(a) or int(b) - int(a) > 4096:
        return []
    return [str(ipaddress.ip_address(i)) for i in range(int(a), int(b) + 1)]


def from_burp(raw: str) -> Optional[ParsedTargets]:
    """Derive scannable targets from a Burp project scope export."""
    try:
        doc = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(doc, dict):
        return None
    scope = (doc.get("target") or {}).get("scope")
    if not isinstance(scope, dict):
        scope = doc.get("scope") if isinstance(doc.get("scope"), dict) else None
    if not isinstance(scope, dict):
        return None

    out = ParsedTargets(source_format="burp")
    for key, bucket in (("include", out.targets), ("exclude", out.excluded)):
        for e in scope.get(key) or []:
            if not isinstance(e, dict) or e.get("enabled") is False:
                continue
            prefix = e.get("prefix")
            if prefix:
                parts = urlsplit(prefix)
                if not parts.hostname:
                    continue
                # A path-scoped Burp exclusion cannot be expressed against a
                # host-level target list. Recording it as a host exclusion
                # would drop an in-scope target entirely, so report instead.
                if key == "exclude" and parts.path not in ("", "/"):
                    out.skipped.append(
                        "%s (excludes a path, not a host - assay's scope is "
                        "host-level, so this rule cannot be applied)" % prefix)
                    continue
                port = ":%d" % parts.port if parts.port else ""
                bucket.append("%s://%s%s/" % (parts.scheme or "https",
                                              parts.hostname, port))
                continue
            host = _host_from_regex(e.get("host") or "")
            if host:
                bucket.append(host)
            elif e.get("host"):
                out.skipped.append("%s (host pattern too general to scan)"
                                   % e.get("host"))
    return out


def _host_from_regex(pattern: str) -> str:
    """Recover a hostname from Burp's advanced-mode regex, where possible."""
    p = (pattern or "").strip()
    if not p:
        return ""
    p = p.lstrip("^").rstrip("$")
    wildcard = False
    for lead in (r".*\.", r"[^.]*\.", r".*"):
        if p.startswith(lead):
            p = p[len(lead):]
            wildcard = True
            break
    p = p.replace(r"\.", ".").replace(r"\-", "-")
    # Anything with regex metacharacters left is not a literal host.
    if re.search(r"[\\\[\]\(\)\|\+\?\*\{\}]", p):
        return ""
    if not p or not HOSTLIKE.match(p):
        return ""
    return ("*." + p) if wildcard else p


def parse(raw: str) -> ParsedTargets:
    """Read targets from any of the shapes scope actually arrives in."""
    burp = from_burp(raw)
    if burp is not None:
        return burp

    out = ParsedTargets()
    excluding = False
    seen: Set[str] = set()

    for line in raw.splitlines():
        line = line.rstrip()
        if not line.strip():
            continue
        stripped = line.strip()

        # Comments, but '#' can also start a markdown heading we care about.
        if stripped.startswith("#"):
            heading = stripped.lstrip("#").strip()
            if OUT_OF_SCOPE_HEADING.match(heading):
                excluding = True
            elif IN_SCOPE_HEADING.match(heading):
                excluding = False
            continue
        if OUT_OF_SCOPE_HEADING.match(stripped):
            excluding = True
            continue
        if IN_SCOPE_HEADING.match(stripped):
            excluding = False
            continue
        # Markdown table rule.
        if re.match(r"^\|?[\s:\-|]+\|?$", stripped):
            continue

        # An explicit per-line exclusion marker wins over the section.
        line_excluded = excluding
        if stripped[0] in "!" or stripped.startswith("- !"):
            line_excluded = True
            stripped = stripped.lstrip("!-").strip()

        for token in SPLIT.split(stripped):
            tok = _clean(token)
            if not tok:
                continue
            if tok.lower() in DANGEROUS:
                out.skipped.append("%s (too broad to be a target)" % tok)
                continue
            kind = classify(tok)
            if not kind:
                continue
            if kind == "range":
                expanded = expand_range(tok)
                if not expanded:
                    out.skipped.append("%s (range too large or malformed)" % tok)
                    continue
                for ip in expanded:
                    if ip not in seen:
                        seen.add(ip)
                        (out.excluded if line_excluded else out.targets).append(ip)
                continue
            key = tok.lower()
            if key in seen:
                continue
            seen.add(key)
            (out.excluded if line_excluded else out.targets).append(tok)

    if any(classify(t) == "cidr" and int(t.split("/")[1]) < 16
           for t in out.targets if CIDR.match(t)):
        out.warnings.append(
            "a CIDR larger than /16 is present - that is over 65,000 hosts, so "
            "confirm it is really in scope before scanning it")
    if not out.targets:
        out.warnings.append("no targets recognised in this file")
    return out


def load(path: str) -> ParsedTargets:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse(fh.read())


def resolve_inputs(values: Iterable[str]) -> ParsedTargets:
    """Read targets from anything the operator typed or pointed at.

    One argument covers every case, because requiring a target list *and* a
    separate scope file means keeping two things in step by hand, and the
    moment they diverge either something goes untested or something gets a
    request it should not have.

      assay scan 10.20.0.0/24,app.example.com
      assay scan targets.txt
      assay scan burp-scope.json
      assay scan a.example.com b.example.com

    A value that names an existing file is read as one; anything else is
    treated as an inline list, split on commas or whitespace.
    """
    import os

    merged = ParsedTargets()
    formats: List[str] = []
    seen: Set[str] = set()

    def absorb(part: ParsedTargets) -> None:
        for t in part.targets:
            if t.lower() not in seen:
                seen.add(t.lower())
                merged.targets.append(t)
        merged.excluded += [e for e in part.excluded if e not in merged.excluded]
        merged.skipped += part.skipped
        merged.warnings += [w for w in part.warnings if w not in merged.warnings]
        formats.append(part.source_format)

    for value in values:
        value = (value or "").strip()
        if not value:
            continue
        if os.path.isfile(value):
            try:
                absorb(load(value))
            except OSError as exc:
                merged.warnings.append("cannot read %s: %s" % (value, exc))
            continue
        # A value that is plainly meant to be a file but is not one would
        # otherwise be silently accepted as a hostname, and the scan would run
        # against a target that does not exist. Being in the wrong directory
        # should say so, not quietly produce a scan of nothing.
        # Only for values that are not already a valid target: a CIDR contains
        # a slash and a hostname can end in anything, so the path heuristic must
        # never override a successful classification.
        if not classify(value.split(",")[0].strip()) and LOOKS_LIKE_PATH.search(value):
            merged.warnings.append(
                "%s looks like a file but does not exist here (cwd: %s)"
                % (value, os.getcwd()))
            merged.skipped.append("%s (no such file)" % value)
            continue
        # Inline: commas or whitespace, so both shell styles work.
        absorb(parse(value.replace(",", "\n")))

    merged.warnings = [w for w in merged.warnings
                       if w != "no targets recognised in this file"]
    if not merged.targets:
        merged.warnings.append(
            "nothing recognisable as a target - pass hosts, IPs or CIDRs "
            "directly, or a path to a host list or Burp scope export")
    merged.source_format = "+".join(sorted(set(formats))) or "none"
    return merged


def as_scope(parsed: ParsedTargets) -> "Tuple[List[str], List[str]]":
    """Allow/deny lists implied by what was parsed.

    Wildcards belong in the allow list even though they are not scannable:
    they are how a programme says 'anything under here', and dropping them
    would put a discovered subdomain out of scope.
    """
    allow = list(parsed.targets)
    for t in parsed.targets:
        if "://" in t:
            host = urlsplit(t).hostname
            if host and host not in allow:
                allow.append(host)
    deny: List[str] = []
    for e in parsed.excluded:
        host = urlsplit(e).hostname if "://" in e else e
        if host and host not in deny:
            deny.append(host)
    return allow, deny
