"""Software and version inventory: what is actually running, by name and
version, across both the host-level services nmap identified and the
frontend components a web application ships.

This is the data `assay.cve` cross-references against NVD. It is deliberately
useful on its own, before any CVE lookup runs: a detected (name, version)
pair is exactly the asset inventory a client's security team usually does not
have, so it goes into the report regardless of whether anything looks
vulnerable.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Dict, List, Tuple

from assay.models import Target, WebTarget


@dataclass
class Software:
    name: str
    version: str            # "" when only the name could be identified
    category: str           # service | web-component | cms
    where: str               # host:port or URL it was seen at
    source: str               # how it was detected, e.g. "nmap service detection"
    proof: str = ""           # the literal text the version was read from
    repro: str = ""           # shell command that shows the same text again

    def key(self) -> Tuple[str, str]:
        return (self.name.lower(), self.version)


# name -> regex with one capture group for the version. Checked against a
# blob of script/link src attributes and inline body text, so the pattern
# matches both a filename ("jquery-3.4.1.min.js") and an embedded version
# string ("Bootstrap v5.1.3").
_JS_LIB_PATTERNS: List[Tuple[str, str]] = [
    ("jQuery", r"jquery[/-]?(\d+\.\d+\.\d+)"),
    ("jQuery UI", r"jquery-ui[/-]?(\d+\.\d+\.\d+)"),
    ("Bootstrap", r"bootstrap(?:\.bundle)?[/-]?v?(\d+\.\d+\.\d+)"),
    ("AngularJS", r"angular(?:\.min)?[/-]?(\d+\.\d+\.\d+)"),
    ("Vue.js", r"vue(?:\.min|\.runtime)?[/-]?(\d+\.\d+\.\d+)"),
    ("React", r"react(?:-dom)?(?:\.production\.min)?[/-]?(\d+\.\d+\.\d+)"),
    ("Lodash", r"lodash(?:\.min)?[/-]?(\d+\.\d+\.\d+)"),
    ("Moment.js", r"moment(?:\.min)?[/-]?(\d+\.\d+\.\d+)"),
    ("D3.js", r"d3(?:\.v\d+)?[/-]?(\d+\.\d+\.\d+)"),
    ("Handlebars", r"handlebars[/-]?(\d+\.\d+\.\d+)"),
    ("CKEditor", r"ckeditor[/-]?(\d+\.\d+\.\d+)"),
    ("TinyMCE", r"tinymce[/-]?(\d+\.\d+\.\d+)"),
    ("Swagger UI", r"swagger-ui[/-]?(\d+\.\d+\.\d+)"),
    ("Font Awesome", r"font-?awesome[/-]?(\d+\.\d+\.\d+)"),
    ("Popper.js", r"popper(?:\.min)?[/-]?(\d+\.\d+\.\d+)"),
    ("Axios", r"axios[/-]?(\d+\.\d+\.\d+)"),
    ("Chart.js", r"chart(?:\.min)?[/-]?(\d+\.\d+\.\d+)"),
    ("Select2", r"select2[/-]?(\d+\.\d+\.\d+)"),
    ("Highcharts", r"highcharts[/-]?(\d+\.\d+\.\d+)"),
    ("PDF.js", r"pdf\.?js[/-]?(\d+\.\d+\.\d+)"),
]
_JS_LIB_RE = [(name, re.compile(pat, re.I)) for name, pat in _JS_LIB_PATTERNS]

# CMS/platform generator meta tags and their own version schemes.
_GENERATOR_PATTERNS: List[Tuple[str, str]] = [
    ("WordPress", r"generator[\"']\s+content=[\"']WordPress\s+(\d+\.\d+(?:\.\d+)?)"),
    ("Drupal", r"generator[\"']\s+content=[\"']Drupal\s+(\d+(?:\.\d+)?)"),
    ("Joomla!", r"generator[\"']\s+content=[\"']Joomla!?\s*-?\s*(\d+\.\d+(?:\.\d+)?)"),
    ("MediaWiki", r"generator[\"']\s+content=[\"']MediaWiki\s+(\d+\.\d+(?:\.\d+)?)"),
    ("TYPO3", r"generator[\"']\s+content=[\"']TYPO3\s+(\d+\.\d+)"),
    ("Ghost", r"generator[\"']\s+content=[\"']Ghost\s+(\d+\.\d+(?:\.\d+)?)"),
]
_GENERATOR_RE = [(name, re.compile(pat, re.I)) for name, pat in _GENERATOR_PATTERNS]

# "Apache/2.4.41 (Ubuntu)" -> ("Apache", "2.4.41"); a bare "nginx" with no
# slash yields nothing here and falls back to the name-only signature path.
_HEADER_VERSION_RE = re.compile(r"^([A-Za-z][\w.+-]*?)/(\d[\w.+-]*)$")


def _from_header(value: str) -> List[Tuple[str, str]]:
    """Split a `Server`/`X-Powered-By`-style header into (product, version)
    pairs. These headers can list more than one token, e.g.
    "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3" - each space-separated
    token with a name/version shape is its own piece of software.
    """
    out: List[Tuple[str, str]] = []
    for tok in value.split():
        m = _HEADER_VERSION_RE.match(tok)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _snippet(blob: str, m: "re.Match", pad: int = 70) -> str:
    """The match with surrounding text, whitespace collapsed, so the reader
    can see the tag or filename the version came out of."""
    lo, hi = max(0, m.start() - pad), min(len(blob), m.end() + pad)
    text = re.sub(r"\s+", " ", blob[lo:hi]).strip()
    return ("..." if lo else "") + text + ("..." if hi < len(blob) else "")


def _grep_repro(url: str, pattern: str) -> str:
    return "curl -sk %s | grep -oiE %s" % (shlex.quote(url), shlex.quote(pattern))


def collect_from_web(wt: WebTarget) -> List[Software]:
    """Server/X-Powered-By headers, generator meta tags, and bundled JS/CSS
    libraries - the components a web application actually ships.
    """
    found: List[Software] = []
    where = wt.final_url or wt.url

    if wt.server:
        for name, version in _from_header(wt.server):
            found.append(Software(
                name, version, "service", where, "Server header",
                proof="Server: %s" % wt.server,
                repro="curl -skI %s | grep -i '^server:'" % shlex.quote(where)))
    powered = wt.headers.get("X-Powered-By") or wt.headers.get("x-powered-by")
    if powered:
        for name, version in _from_header(powered):
            found.append(Software(
                name, version, "service", where, "X-Powered-By header",
                proof="X-Powered-By: %s" % powered,
                repro="curl -skI %s | grep -i '^x-powered-by:'"
                      % shlex.quote(where)))

    blob = wt.body_sample or ""
    for name, rx in _JS_LIB_RE:
        m = rx.search(blob)
        if m:
            found.append(Software(
                name, m.group(1), "web-component", where, "asset reference",
                proof=_snippet(blob, m), repro=_grep_repro(where, rx.pattern)))
    for name, rx in _GENERATOR_RE:
        m = rx.search(blob)
        if m:
            found.append(Software(
                name, m.group(1), "cms", where, "generator meta tag",
                proof=_snippet(blob, m), repro=_grep_repro(where, rx.pattern)))

    # wt.tech (Engine._fingerprint) already carries broader signature matches
    # with no version - fold in whatever this pass has not already found a
    # version for, so the inventory is not narrower than the existing tech
    # detection just because this module cannot pin a version number.
    seen = {f.name.lower() for f in found}
    for name in wt.tech:
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        found.append(Software(
            name, "", "web-component", where, "signature match",
            proof="matched a technology signature in the response "
                  "(no version present)"))
    return found


def collect_from_host(target: Target) -> List[Software]:
    """nmap's own product/version service detection."""
    found: List[Software] = []
    for port in target.ports:
        if not port.product or not port.version:
            continue
        where = "%s:%d" % (target.host, port.port)
        found.append(Software(
            port.product, port.version, "service", where,
            "nmap service detection",
            proof="nmap -sV reported %s/%s: product=%r version=%r"
                  % (port.port, port.proto, port.product, port.version),
            repro="nmap -sV -Pn -p %d %s" % (port.port, target.host)))
    return found


def merge(items: List[Software]) -> List[Dict]:
    """Collapse to one row per (name, version), collecting every place seen."""
    rows: Dict[Tuple[str, str], Dict] = {}
    for it in items:
        row = rows.setdefault(it.key(), {
            "name": it.name, "version": it.version, "category": it.category,
            "sources": set(), "where": [], "proof": [],
        })
        row["sources"].add(it.source)
        entry = {"where": it.where, "source": it.source,
                 "proof": it.proof, "repro": it.repro}
        if entry not in row["proof"]:
            row["proof"].append(entry)
        if it.where not in row["where"]:
            row["where"].append(it.where)
    out = []
    for row in rows.values():
        row["sources"] = sorted(row["sources"])
        out.append(row)
    out.sort(key=lambda r: (r["name"].lower(), r["version"]))
    return out
