"""Run configuration, profiles, and the scope guard.

The scope guard is deliberately strict: on a a managed engagement, a request
to an out-of-scope host is worse than a missed finding, so every outbound
request in this tool funnels through Scope.allows().
"""

from __future__ import annotations

import base64
import fnmatch
import json
import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlsplit

import yaml

DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36 assay/1.0"
)


class ScopeError(Exception):
    pass


@dataclass
class Scope:
    """Allow/deny lists for hosts, wildcards and CIDRs."""

    allow: List[str] = field(default_factory=list)
    deny: List[str] = field(default_factory=list)
    # When no allow rules are supplied we run in permissive mode but the CLI
    # shouts about it; deny rules still apply.
    permissive: bool = True

    _allow_nets: List[object] = field(default_factory=list, repr=False)
    _deny_nets: List[object] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self.permissive = not self.allow
        self._allow_nets = [n for n in (_as_net(x) for x in self.allow) if n]
        self._deny_nets = [n for n in (_as_net(x) for x in self.deny) if n]

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        """Load scope from a file. Four formats, detected automatically:

          * Burp project scope JSON (exported from Target > Scope, or lifted
            out of a .json project settings export)
          * YAML with allow:/deny: keys
          * plain newline list, '!' or '-' prefix excludes
        """
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()

        burp = cls._from_burp(raw)
        if burp is not None:
            return burp

        try:
            doc = yaml.safe_load(raw)
        except yaml.YAMLError:
            doc = None
        if isinstance(doc, dict) and ("allow" in doc or "deny" in doc):
            return cls(allow=list(doc.get("allow") or []), deny=list(doc.get("deny") or []))
        allow, deny = [], []
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line[0] in "!-":
                deny.append(line[1:].strip())
            else:
                allow.append(line)
        return cls(allow=allow, deny=deny)

    @classmethod
    def _from_burp(cls, raw: str) -> Optional["Scope"]:
        """Parse Burp's scope JSON. Returns None when this is not that format."""
        try:
            doc = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(doc, dict):
            return None
        scope = (doc.get("target") or {}).get("scope")
        if scope is None:
            scope = doc.get("scope") if isinstance(doc.get("scope"), dict) else None
        if not isinstance(scope, dict):
            return None

        def convert(entries) -> List[str]:
            out: List[str] = []
            for e in entries or []:
                if not isinstance(e, dict) or e.get("enabled") is False:
                    continue
                # Simple mode: a URL prefix.
                prefix = e.get("prefix")
                if prefix:
                    host = urlsplit(prefix).hostname
                    if host:
                        out.append(host)
                    continue
                # Advanced mode: the host field is a regex.
                host_rx = e.get("host")
                if not host_rx:
                    continue
                plain = cls._plain_host(host_rx)
                out.append(plain if plain else "re:" + host_rx)
            return out

        allow = convert(scope.get("include"))
        deny = convert(scope.get("exclude"))
        if not allow and not deny:
            return None
        return cls(allow=allow, deny=deny)

    @staticmethod
    def _plain_host(pattern: str) -> str:
        """Turn Burp's ^example\\.com$ back into example.com where possible."""
        p = pattern.strip()
        anchored_start = p.startswith("^")
        p = p.lstrip("^").rstrip("$")
        p = p.replace("\\.", ".")
        # ^.*\.example\.com$ means "any subdomain" -> *.example.com
        if p.startswith(".*."):
            p = "*" + p[2:]
        elif p.startswith(".*"):
            p = "*" + p[2:]
        if re.search(r"[\\()\[\]+?{}|]", p):
            return ""          # still a real regex; keep it as one
        return p

    def allows(self, host: str) -> bool:
        if not host:
            return False
        host = host.strip().lower().rstrip(".")
        if self._matches(host, self.deny, self._deny_nets):
            return False
        if self.permissive:
            return True
        return self._matches(host, self.allow, self._allow_nets)

    def check(self, host: str) -> None:
        if not self.allows(host):
            raise ScopeError("out of scope: %s" % host)

    @staticmethod
    def _matches(host: str, patterns: List[str], nets: List[object]) -> bool:
        ip = None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            pass
        if ip is not None:
            for net in nets:
                if ip in net:
                    return True
        for pat in patterns:
            pat = pat.strip().lower().rstrip(".")
            if not pat or "/" in pat:
                continue
            if pat.startswith("re:"):
                if re.search(pat[3:], host):
                    return True
            elif "*" in pat:
                if fnmatch.fnmatch(host, pat):
                    return True
            elif host == pat or host.endswith("." + pat):
                return True
        return False


def _as_net(value: str):
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Profiles
# --------------------------------------------------------------------------

PROFILES: Dict[str, Dict] = {
    # ~2 min/target. Live-host + obvious wins. Use while triaging a fresh list.
    "quick": {
        "port_spec": "top-100",
        "http_paths": 40,
        "nuclei_severity": "critical,high",
        "nuclei": True,
        "crawl": False,
        "active_web": True,
        "content_discovery": False,
        "param_discovery": False,
        "max_urls_per_host": 15,
    },
    # Default. Balanced coverage, still hands-off.
    "standard": {
        "port_spec": "top-1000",
        "http_paths": 120,
        "nuclei_severity": "critical,high,medium",
        "nuclei": True,
        "crawl": True,
        "active_web": True,
        "content_discovery": True,
        "param_discovery": True,
        "max_urls_per_host": 60,
    },
    # Long tail. Run overnight on a shortlist, not on the whole netblock.
    "deep": {
        "port_spec": "all",
        "http_paths": 400,
        "nuclei_severity": "critical,high,medium,low",
        "nuclei": True,
        "crawl": True,
        "active_web": True,
        "content_discovery": True,
        "param_discovery": True,
        "max_urls_per_host": 200,
    },
}


@dataclass
class BurpConfig:
    proxy: Optional[str] = None             # http://127.0.0.1:8080
    api_url: Optional[str] = None           # http://127.0.0.1:1337
    api_key: Optional[str] = None
    mirror: bool = False                    # replay findings' requests via proxy
    scan: bool = False                      # launch Burp active scans via REST API

    @property
    def enabled(self) -> bool:
        return bool(self.proxy or self.api_url)

    def proxies(self) -> Optional[Dict[str, str]]:
        if not self.proxy:
            return None
        return {"http": self.proxy, "https": self.proxy}


@dataclass
class Config:
    targets: List[str] = field(default_factory=list)
    profile: str = "standard"
    out_dir: str = "./assay-out"
    scope: Scope = field(default_factory=Scope)

    # pacing -- the gateway links are shared, be a good neighbour
    concurrency: int = 12
    rate: float = 25.0                      # global requests/second ceiling
    timeout: float = 12.0
    retries: int = 1

    # behaviour switches
    passive: bool = False                   # allow third-party OSINT sources
    portscan: bool = True
    expand: bool = False                    # grow the target list via recon
    oob: bool = True                        # out-of-band callbacks for blind checks
    oob_domain: str = ""                    # e.g. a Burp Collaborator payload domain
    verify: bool = True                     # second-request confirmation pass
    aggressive: bool = False                # enable checks that mutate state
    insecure: bool = True                   # the gateway targets have broken certs constantly

    # http
    user_agent: str = DEFAULT_UA
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: str = ""
    # HTTP Basic credentials as "user:pass". Applied to every in-scope request
    # and handed to the external tools that accept a header.
    basic_auth: str = ""

    burp: BurpConfig = field(default_factory=BurpConfig)

    only_modules: List[str] = field(default_factory=list)
    skip_modules: List[str] = field(default_factory=list)

    resume: bool = False
    quiet: bool = False

    @property
    def opts(self) -> Dict:
        return PROFILES.get(self.profile, PROFILES["standard"])

    def db_path(self) -> str:
        return os.path.join(self.out_dir, "assay.db")

    def ensure_dirs(self) -> None:
        for sub in ("", "raw", "evidence"):
            os.makedirs(os.path.join(self.out_dir, sub), exist_ok=True)

    def module_enabled(self, name: str) -> bool:
        if self.only_modules:
            return name in self.only_modules
        return name not in self.skip_modules

    def request_headers(self) -> Dict[str, str]:
        h = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        if self.basic_auth:
            token = base64.b64encode(
                self.basic_auth.encode("utf-8")).decode("ascii")
            h["Authorization"] = "Basic " + token
        h.update(self.headers)
        if self.cookies:
            h["Cookie"] = self.cookies
        return h

    def auth_header(self) -> Optional[str]:
        """The Authorization header value, for passing to external tools."""
        if not self.basic_auth:
            return None
        token = base64.b64encode(self.basic_auth.encode("utf-8")).decode("ascii")
        return "Basic " + token
