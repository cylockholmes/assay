"""Replay an authenticated Burp capture without credentials.

The premise: you have already browsed the application as a logged-in user and
saved the traffic. Every one of those requests is a documented, working call to
an authenticated endpoint. Strip the session and send them again - anything
that still returns the same data is broken access control, and it is proven by
a direct before/after comparison rather than inference.

This stays inside the unauthenticated remit. assay never logs in; it only asks
whether the endpoints you reached while logged in are reachable when you are not.

Accepts Burp's XML item export ("Save selected items" or a site-map export)
and HAR files, which most proxies and browsers can produce.
"""

from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit

# Headers that carry identity. All are removed before replay.
AUTH_HEADERS = {
    "cookie", "authorization", "proxy-authorization", "x-api-key", "x-apikey",
    "x-auth-token", "x-authorization", "x-access-token", "x-session-token",
    "x-csrf-token", "x-xsrf-token", "x-requested-with", "authentication",
    "x-user-token", "x-client-token", "bearer", "api-key", "apikey",
    "x-amz-security-token", "x-ms-token", "x-forwarded-user", "remote-user",
}

# Responses that mean "you are not logged in" rather than "here is the data".
LOGIN_MARKERS = re.compile(
    r"(?:<form[^>]*(?:login|signin|sign-in)|name=[\"']?(?:password|passwd)|"
    r"please (?:log|sign) ?in|authentication required|unauthorized|"
    r"access denied|not authorized|session (?:expired|timed out)|"
    r"\"error\"\s*:\s*\"(?:unauthorized|forbidden|invalid[_ ]token))", re.I)

STATIC_RE = re.compile(
    r"\.(?:js|css|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map|mp4|mp3)(?:$|\?)",
    re.I)


@dataclass
class CapturedRequest:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    status: int = 0
    response: str = ""
    length: int = 0

    @property
    def host(self) -> str:
        return urlsplit(self.url).hostname or ""

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    @property
    def had_auth(self) -> bool:
        return any(k.lower() in AUTH_HEADERS for k in self.headers)

    def stripped_headers(self) -> Dict[str, str]:
        return {k: v for k, v in self.headers.items()
                if k.lower() not in AUTH_HEADERS and k.lower() != "host"}

    def shape(self) -> str:
        """Group by method + path with numeric/uuid segments generalised."""
        p = re.sub(r"/\d+(?=/|$)", "/{id}", self.path)
        p = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                   "/{uuid}", p, flags=re.I)
        return "%s %s" % (self.method, p)


# --------------------------------------------------------------------------
# Parsers
# --------------------------------------------------------------------------


def _decode(el: Optional[ET.Element]) -> str:
    if el is None or el.text is None:
        return ""
    if (el.get("base64") or "").lower() == "true":
        try:
            return base64.b64decode(el.text).decode("utf-8", "replace")
        except (ValueError, TypeError):
            return ""
    return el.text


def _split_http(raw: str) -> Tuple[str, Dict[str, str], str]:
    """Split a raw HTTP message into (start-line, headers, body)."""
    if not raw:
        return "", {}, ""
    head, _, body = raw.partition("\r\n\r\n")
    if not _:
        head, _, body = raw.partition("\n\n")
    lines = head.replace("\r\n", "\n").split("\n")
    start = lines[0] if lines else ""
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return start, headers, body


def parse_burp_xml(path: str) -> List[CapturedRequest]:
    out: List[CapturedRequest] = []
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError):
        return out
    for item in tree.getroot().iter("item"):
        url = (item.findtext("url") or "").strip()
        if not url:
            continue
        raw_req = _decode(item.find("request"))
        raw_resp = _decode(item.find("response"))
        start, headers, body = _split_http(raw_req)
        method = (item.findtext("method") or start.split(" ")[0] or "GET").strip()
        _, _, resp_body = _split_http(raw_resp)
        try:
            status = int(item.findtext("status") or 0)
        except ValueError:
            status = 0
        out.append(CapturedRequest(
            method=method.upper(), url=url, headers=headers, body=body,
            status=status, response=resp_body[:200000], length=len(resp_body)))
    return out


def parse_har(path: str) -> List[CapturedRequest]:
    out: List[CapturedRequest] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return out
    for entry in (doc.get("log", {}).get("entries") or []):
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        url = req.get("url") or ""
        if not url:
            continue
        headers = {h.get("name", ""): h.get("value", "")
                   for h in (req.get("headers") or []) if h.get("name")}
        body = ((req.get("postData") or {}).get("text") or "")
        content = ((resp.get("content") or {}).get("text") or "")
        out.append(CapturedRequest(
            method=(req.get("method") or "GET").upper(), url=url, headers=headers,
            body=body, status=int(resp.get("status") or 0),
            response=content[:200000], length=len(content)))
    return out


def load(path: str) -> Tuple[List[CapturedRequest], str]:
    """Detect the format and parse. Returns (requests, format-name)."""
    lower = path.lower()
    if lower.endswith(".har") or lower.endswith(".json"):
        got = parse_har(path)
        if got:
            return got, "HAR"
    got = parse_burp_xml(path)
    if got:
        return got, "Burp XML"
    got = parse_har(path)
    return got, "HAR" if got else ""


# --------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------


def worth_replaying(r: CapturedRequest, aggressive: bool = False) -> Tuple[bool, str]:
    """Which captured requests could demonstrate broken access control."""
    if not r.had_auth:
        return False, "request carried no credentials, so nothing to strip"
    if STATIC_RE.search(r.path):
        return False, "static asset"
    if r.status < 200 or r.status >= 400:
        return False, "authenticated response was %d, not a success" % r.status
    if r.method not in ("GET", "HEAD") and not aggressive:
        return False, "%s may change state (use --aggressive to include)" % r.method
    if len(r.response) < 32:
        return False, "authenticated response too small to compare"
    if LOGIN_MARKERS.search(r.response[:4000]):
        return False, "authenticated response already looks like a login page"
    return True, "ready"


def dedupe(requests: Iterable[CapturedRequest]) -> List[CapturedRequest]:
    """One representative per (method, generalised path)."""
    seen: Dict[str, CapturedRequest] = {}
    for r in requests:
        seen.setdefault(r.shape(), r)
    return list(seen.values())


def looks_unauthenticated(body: str, status: int) -> bool:
    """Does this response represent a rejection rather than data?"""
    if status in (401, 403, 407):
        return True
    if status in (301, 302, 303, 307, 308):
        return True
    return bool(LOGIN_MARKERS.search(body[:6000]))


# --------------------------------------------------------------------------
# Replay
# --------------------------------------------------------------------------


def replay(http, r: CapturedRequest):
    """Re-issue the captured request with every credential removed."""
    return http.request(r.method, r.url, headers=r.stripped_headers(),
                        data=r.body or None, allow_redirects=False)


def verdict(r: CapturedRequest, resp, similarity_fn) -> Tuple[bool, float, str]:
    """Did the endpoint serve authenticated content to an anonymous caller?

    Returns (is_finding, similarity, reason).
    """
    if not resp.ok:
        return False, 0.0, "no response: %s" % (resp.error or "unknown")
    if looks_unauthenticated(resp.body, resp.status):
        return False, 0.0, "correctly rejected (HTTP %d)" % resp.status
    if resp.status != r.status:
        # A different success code can still be the same data, but a 2xx->4xx
        # move means the control is working.
        if resp.status >= 400:
            return False, 0.0, "rejected with HTTP %d" % resp.status
    sim = similarity_fn(resp.body, r.response)
    if sim < 0.85:
        return False, sim, "different content (similarity %.2f)" % sim
    return True, sim, "same content returned without credentials (similarity %.2f)" % sim
