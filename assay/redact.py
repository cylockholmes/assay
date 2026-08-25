"""Redaction of client-identifying data before anything leaves the machine.

Design rules:
  * Deterministic pseudonyms, not deletion. "HOST-03" appearing in two findings
    still means the same host, so an analyst (or a model) can reason about
    relationships, and the mapping file lets us re-hydrate the answer locally.
  * The mapping never leaves the box. It is written to the output directory
    with 0600 permissions and is the only thing that can reverse a token.
  * Redaction is verified, not assumed. verify() re-scans the output with the
    same detectors *plus* the run's known client terms. Anything that survives
    is a hard failure and the caller must not transmit.

This module is deliberately conservative: it over-redacts. A pseudonymised
finding that is slightly harder to read is always preferable to leaking a
client hostname into a third-party API.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Pattern, Tuple

# Domains that belong to the security community, not to the client. These are
# the only hostnames allowed through, because they appear in our own reference
# links and carry no client information.
ALLOWED_DOMAINS = {
    "owasp.org", "cwe.mitre.org", "portswigger.net", "nvd.nist.gov",
    "cve.mitre.org", "example.com", "example.net", "example.org",
    "github.com", "projectdiscovery.io", "rfc-editor.org", "w3.org",
    "localhost", "ietf.org", "mitre.org", "first.org",
}

# Technology tokens that look like hostnames but are product names.
TECH_WORDS = {
    "spring.io", "asp.net", "vue.js", "node.js", "next.js", "nuxt.js",
    "jquery.js", "angular.js", "react.js", "d3.js", "bootstrap.css",
}


def _rx(pattern: str, flags: int = 0) -> Pattern:
    return re.compile(pattern, flags)


# --------------------------------------------------------------------------
# Detectors. Order is significant: earlier detectors win the text they claim.
# --------------------------------------------------------------------------

DETECTORS: List[Tuple[str, Pattern]] = [
    # -- high-entropy credentials first, before anything can fragment them ---
    ("KEY", _rx(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"
                r"[\s\S]{0,4000}?-----END (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----")),
    ("JWT", _rx(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b")),
    ("AWSKEY", _rx(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[0-9A-Z]{16}\b")),
    ("SECRET", _rx(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("SECRET", _rx(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("SECRET", _rx(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b")),
    ("SECRET", _rx(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("SECRET", _rx(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("SECRET", _rx(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    # key=value style secrets in config dumps and .env files
    ("SECRET", _rx(r"(?i)(?<![A-Za-z])(?:pass(?:word|wd)?|pwd|secret|token|"
                   r"api[_-]?key|auth|credential|private[_-]?key|client[_-]?secret|"
                   r"access[_-]?key|app[_-]?key|session)\s*[:=]\s*"
                   r"[\"']?([^\s\"'&;,}\]]{4,})")),
    # credentials inside URLs and connection strings
    ("CRED", _rx(r"(?<=//)[A-Za-z0-9._%+-]{1,64}:[^\s/@\"']{1,64}(?=@)")),
    ("COOKIE", _rx(r"(?im)^(?:set-)?cookie:\s*(.+)$")),
    ("AUTHHDR", _rx(r"(?im)^(?:authorization|proxy-authorization|x-api-key|"
                    r"x-auth-token):\s*(.+)$")),

    # -- direct personal identifiers ----------------------------------------
    ("EMAIL", _rx(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b")),
    ("CARD", _rx(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|"
                 r"3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")),
    ("SSN", _rx(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("PHONE", _rx(r"(?<![\w.])(?:\+?1[-. ])?\(?[2-9]\d{2}\)?[-. ]\d{3}[-. ]\d{4}(?![\w.])")),

    # -- account names embedded in filesystem paths -------------------------
    ("USER", _rx(r"(?i)(?<=[/\\])(?:home|users)[/\\]([A-Za-z0-9._-]{2,32})")),
    ("USER", _rx(r"(?i)\b(?:user(?:name)?|login|account|uid)\b\s*[:=]\s*"
                 r"[\"']?([A-Za-z0-9._@-]{2,64})")),
    # /etc/passwd rows recovered by the traversal module: the whole row goes,
    # since the GECOS field carries real names and the shell/home reveal accounts.
    ("PASSWDROW", _rx(r"(?m)^[A-Za-z0-9._-]+:x?:\d+:\d+:[^\n]*$")),

]

# Detectors that must run after the known-client-term pass. Splitting here keeps
# the client-term substitution from fragmenting an email or a credential before
# its own detector has had a chance to claim the whole string.
NETWORK_DETECTORS: List[Tuple[str, Pattern]] = [
    ("MAC", _rx(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")),
    ("IPV6", _rx(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")),
    ("IP", _rx(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
               r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:/\d{1,2})?\b")),
    # Hostnames last: by now URLs have had their credentials stripped, and
    # anything left that looks like a FQDN is either client infrastructure or
    # on the allow list.
    ("HOST", _rx(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
                 r"[A-Za-z]{2,24}\b")),

    # -- opaque identifiers that may encode tenancy -------------------------
    ("UUID", _rx(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                 r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")),
    ("BLOB", _rx(r"\b[A-Za-z0-9+/]{60,}={0,2}\b")),
]

ALL_DETECTORS: List[Tuple[str, Pattern]] = DETECTORS + NETWORK_DETECTORS

# Detectors whose *capture group 1* is the sensitive part (the rest is a label
# we want to keep so the model still understands the shape of the data).
GROUP_DETECTORS = {"SECRET", "COOKIE", "AUTHHDR", "USER"}


@dataclass
class RedactionMap:
    """Bidirectional map between real values and their pseudonyms."""

    forward: Dict[str, str] = field(default_factory=dict)   # real -> token
    reverse: Dict[str, str] = field(default_factory=dict)   # token -> real
    counters: Dict[str, int] = field(default_factory=dict)

    def token_for(self, kind: str, value: str) -> str:
        key = "%s\x00%s" % (kind, value)
        existing = self.forward.get(key)
        if existing:
            return existing
        n = self.counters.get(kind, 0) + 1
        self.counters[kind] = n
        token = "[%s-%02d]" % (kind, n)
        self.forward[key] = token
        self.reverse[token] = value
        return token

    def save(self, path: str) -> None:
        payload = {"reverse": self.reverse, "counters": self.counters}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)   # 0600, owner only
        except OSError:
            pass

    @classmethod
    def load(cls, path: str) -> "RedactionMap":
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        m = cls()
        m.reverse = payload.get("reverse", {})
        m.counters = payload.get("counters", {})
        for token, real in m.reverse.items():
            kind = token.strip("[]").rsplit("-", 1)[0]
            m.forward["%s\x00%s" % (kind, real)] = token
        return m

    def rehydrate(self, text: str) -> str:
        """Put the real values back. Local display only."""
        for token, real in sorted(self.reverse.items(), key=lambda kv: -len(kv[0])):
            text = text.replace(token, real)
        return text


class Redactor:
    def __init__(self, extra_terms: Optional[Iterable[str]] = None) -> None:
        self.map = RedactionMap()
        # Terms we positively know identify this client: scope entries, target
        # hostnames, resolved IPs. Used both to redact and to verify.
        self.extra_terms: List[str] = sorted(
            {t.strip().lower() for t in (extra_terms or []) if t and len(t.strip()) > 3},
            key=len, reverse=True,
        )

    # -- redaction ---------------------------------------------------------
    def text(self, value: str) -> str:
        if not value:
            return value
        out = value

        # Phase 1 - credentials and personal identifiers, whole-match first.
        for kind, rx in DETECTORS:
            out = rx.sub(lambda m, k=kind: self._replace(m, k), out)

        # Phase 2 - terms we positively know identify this client. Ground truth,
        # so it runs even where the generic detectors would not fire.
        for term in self.extra_terms:
            if term in out.lower():
                out = re.sub(re.escape(term), self.map.token_for("CLIENT", term),
                             out, flags=re.I)

        # Phase 3 - remaining network and opaque identifiers.
        for kind, rx in NETWORK_DETECTORS:
            out = rx.sub(lambda m, k=kind: self._replace(m, k), out)
        return out

    def _replace(self, m: "re.Match", kind: str) -> str:
        whole = m.group(0)
        if kind in GROUP_DETECTORS and m.lastindex:
            sensitive = m.group(1)
            if not sensitive or self._is_boring(kind, sensitive):
                return whole
            return whole.replace(sensitive, self.map.token_for(kind, sensitive))

        if kind == "HOST" and self._is_boring(kind, whole):
            return whole
        if kind == "IP" and self._is_boring(kind, whole):
            return whole
        return self.map.token_for(kind, whole)

    @staticmethod
    def _is_boring(kind: str, value: str) -> bool:
        low = value.lower().strip("\"' ")
        if kind == "HOST":
            if low in TECH_WORDS:
                return True
            if low in ALLOWED_DOMAINS:
                return True
            # any subdomain of an allowed domain
            for d in ALLOWED_DOMAINS:
                if low.endswith("." + d):
                    return True
            # file names like "index.php" are not hostnames
            if re.search(r"\.(?:php|aspx?|jsp|html?|js|css|json|xml|ya?ml|txt|log|"
                         r"png|jpe?g|gif|svg|map|bak|old|zip|sql|env|ini|conf)$", low):
                return True
            return False
        if kind == "IP":
            try:
                ip = ipaddress.ip_address(low.split("/")[0])
            except ValueError:
                return True
            # Loopback carries no client information; everything else does,
            # including RFC1918 space (it identifies the client's topology).
            return ip.is_loopback or low.startswith("0.0.0.0")
        if kind in ("SECRET", "USER"):
            return low in ("", "true", "false", "null", "none", "nil", "yes", "no",
                           "root", "admin", "user", "test", "example", "changeme")
        return False

    def obj(self, value: Any) -> Any:
        """Recursively redact strings inside dicts/lists."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {k: self.obj(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.obj(v) for v in value]
        return value

    # -- verification ------------------------------------------------------
    def verify(self, text: str) -> List[str]:
        """Re-scan redacted output. Returns a list of residual leaks.

        A non-empty result means the payload MUST NOT be transmitted.
        """
        leaks: List[str] = []

        for term in self.extra_terms:
            if term in text.lower():
                leaks.append("known client term: %s" % term)

        # Any real value we have already mapped must not still be present.
        for token, real in self.map.reverse.items():
            if len(real) > 6 and real.lower() in text.lower():
                leaks.append("unmapped occurrence of %s value" % token)

        for kind, rx in ALL_DETECTORS:
            if kind in ("BLOB", "UUID", "PHONE"):
                continue  # high-noise detectors; tokenised but not fatal
            for m in rx.finditer(text):
                candidate = m.group(1) if (kind in GROUP_DETECTORS and m.lastindex) \
                    else m.group(0)
                if not candidate or candidate.startswith("["):
                    continue
                if self._is_boring(kind, candidate):
                    continue
                leaks.append("%s: %s" % (kind, candidate[:60]))

        # Deduplicate while preserving order.
        seen: set = set()
        return [x for x in leaks if not (x in seen or seen.add(x))]


def terms_from_context(targets: Iterable[str], scope_allow: Iterable[str],
                       hosts: Iterable[str]) -> List[str]:
    """Build the known-client-term list used for redaction and verification."""
    terms: set = set()
    for group in (targets, scope_allow, hosts):
        for item in group or []:
            item = (item or "").strip().lower()
            item = re.sub(r"^\w+://", "", item).split("/")[0].split(":")[0]
            item = item.lstrip("*.").lstrip("!-")
            if len(item) > 3 and not item.replace(".", "").isdigit():
                terms.add(item)
                # also register the registrable domain
                parts = item.split(".")
                if len(parts) >= 2:
                    terms.add(".".join(parts[-2:]))
            elif len(item) > 3:
                terms.add(item)
    return sorted(terms, key=len, reverse=True)
