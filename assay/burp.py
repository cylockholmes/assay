"""Burp Suite integration.

Three independent levels, because most researchers have a different one
available on any given day:

  proxy   - route every assay request (and every external tool's requests)
            through Burp so the whole scan lands in Proxy history and the
            site map. Works with Community.
  mirror  - after the scan, replay the exact request behind each finding
            through the proxy, so the interesting requests are sitting in
            Burp ready to send to Repeater. Works with Community.
  api     - drive Burp Professional's REST API to launch its active scanner
            against the URLs assay found worth attention. Professional only.

Under WSL, Burp usually runs on the Windows side; see env.burp_hint() for the
listener/firewall configuration that makes it reachable.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import requests

from assay import env
from assay.config import BurpConfig, Config
from assay.models import Finding


@dataclass
class BurpStatus:
    proxy: Optional[str] = None
    api: Optional[str] = None
    proxy_ok: bool = False
    api_ok: bool = False
    version: str = ""
    detail: str = ""

    @property
    def any(self) -> bool:
        return self.proxy_ok or self.api_ok


class BurpBridge:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.burp: BurpConfig = cfg.burp

    # -- discovery ---------------------------------------------------------
    def detect(self, autodiscover: bool = True) -> BurpStatus:
        st = BurpStatus(proxy=self.burp.proxy, api=self.burp.api_url)
        if autodiscover and not st.proxy:
            st.proxy = env.find_burp_proxy()
        if autodiscover and not st.api:
            st.api = env.find_burp_api()

        if st.proxy:
            st.proxy_ok, st.detail = self._check_proxy(st.proxy)
            if st.proxy_ok:
                self.burp.proxy = st.proxy
        if st.api:
            st.api_ok, st.version = self._check_api(st.api)
            if st.api_ok:
                self.burp.api_url = st.api
        if not st.proxy_ok and not st.api_ok:
            st.detail = st.detail or env.burp_hint()
        return st

    def _check_proxy(self, proxy: str) -> Tuple[bool, str]:
        """Burp answers http://burp/ with its own landing page."""
        try:
            r = requests.get("http://burp/", proxies={"http": proxy, "https": proxy},
                             timeout=6)
            if "burp" in r.text.lower():
                m = re.search(r"Burp Suite[^<]*", r.text)
                return True, (m.group(0).strip() if m else "Burp proxy reachable")
            return True, "proxy reachable (did not identify as Burp)"
        except requests.RequestException as exc:
            return False, "proxy %s unreachable: %s" % (proxy, type(exc).__name__)

    def _check_api(self, api_url: str) -> Tuple[bool, str]:
        base = api_url.rstrip("/")
        url = "%s/%s/v0.1/" % (base, self.burp.api_key) if self.burp.api_key \
            else "%s/v0.1/" % base
        try:
            r = requests.get(url, timeout=6)
            return r.status_code < 500, "REST API HTTP %d" % r.status_code
        except requests.RequestException as exc:
            return False, "REST API unreachable: %s" % type(exc).__name__

    # -- mirror ------------------------------------------------------------
    def mirror(self, findings: List[Finding], limit: int = 80) -> int:
        """Replay finding requests through Burp so they appear in history."""
        if not self.burp.proxy:
            return 0
        proxies = {"http": self.burp.proxy, "https": self.burp.proxy}
        sent = 0
        for f in findings[:limit]:
            for ev in f.evidence[:1]:
                req = self._parse_request(ev.request)
                if not req:
                    continue
                method, url, headers, body = req
                if not self.cfg.scope.allows(urlsplit(url).hostname or ""):
                    continue
                headers["X-Assay-Finding"] = f.title[:80]
                headers["X-Assay-Severity"] = f.severity
                try:
                    requests.request(method, url, headers=headers, data=body or None,
                                     proxies=proxies, timeout=10, verify=False,
                                     allow_redirects=False)
                    sent += 1
                except requests.RequestException:
                    continue
        return sent

    @staticmethod
    def _parse_request(raw: str):
        """Turn stored evidence back into (method, url, headers, body)."""
        if not raw:
            return None
        lines = raw.splitlines()
        if not lines:
            return None
        m = re.match(r"([A-Z]+)\s+(\S+)", lines[0])
        if not m:
            return None
        method, url = m.group(1), m.group(2)
        if not url.startswith("http"):
            return None
        headers: Dict[str, str] = {}
        body_lines: List[str] = []
        in_body = False
        for line in lines[1:]:
            if not line.strip() and not in_body:
                in_body = True
                continue
            if in_body:
                body_lines.append(line)
            elif ":" in line:
                k, v = line.split(":", 1)
                if k.strip().lower() not in ("content-length", "host", "connection"):
                    headers[k.strip()] = v.strip()
        return method, url, headers, "\n".join(body_lines)

    # -- Professional REST API --------------------------------------------
    def _api_base(self) -> str:
        base = (self.burp.api_url or "").rstrip("/")
        return "%s/%s/v0.1" % (base, self.burp.api_key) if self.burp.api_key \
            else "%s/v0.1" % base

    def launch_scan(self, urls: List[str],
                    scan_config: str = "Crawl and Audit - Lightweight") -> Optional[str]:
        """Queue a Burp Professional scan. Returns the task id."""
        if not self.burp.api_url:
            return None
        payload: Dict = {
            "urls": urls[:50],
            "scan_configurations": [
                {"type": "NamedConfiguration", "name": scan_config}
            ],
        }
        try:
            r = requests.post("%s/scan" % self._api_base(), json=payload, timeout=20)
        except requests.RequestException:
            return None
        if r.status_code not in (200, 201):
            return None
        # Burp returns the task id in the Location header.
        loc = r.headers.get("Location", "")
        return loc.strip("/").split("/")[-1] or None

    def scan_status(self, task_id: str) -> Dict:
        try:
            r = requests.get("%s/scan/%s" % (self._api_base(), task_id), timeout=20)
            return r.json() if r.status_code == 200 else {}
        except (requests.RequestException, ValueError):
            return {}

    # -- scope export ------------------------------------------------------
    def write_scope_file(self, hosts: List[str], path: str) -> str:
        """Emit a Burp-importable project scope so Burp matches assay's scope."""
        include = []
        for h in sorted(set(hosts)):
            if not h:
                continue
            include.append({
                "enabled": True,
                "file": "^/.*",
                "host": "^%s$" % re.escape(h),
                "protocol": "any",
            })
        doc = {"target": {"scope": {"advanced_mode": True, "include": include,
                                    "exclude": []}}}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        return path
