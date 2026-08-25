"""Offline test harness.

Detection logic is exercised against canned responses only - assay's tests never
open a listening socket and never stand up a vulnerable service. A route is a
callable that receives (method, url, headers, body) and returns
(status, headers, body) or None to fall through to the catch-all.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from assay.config import Config
from assay.context import Context
from assay.models import Finding, WebTarget
from assay.net import Baseline, Resp

Route = Callable[[str, str, Dict[str, str], str], Optional[Tuple[int, Dict[str, str], str]]]

# The classic false-positive generator: a single-page app that answers 200 with
# the same HTML shell for every unknown path.
SOFT404_BODY = ("<html><head><title>Acme App</title></head><body><div id=app>"
                "Application shell. Nothing to see.</div></body></html>")


class StubHttp:
    """Drop-in replacement for net.HttpClient backed by canned routes."""

    def __init__(self, routes: List[Route], catch_all=(200, {}, SOFT404_BODY)) -> None:
        self.routes = routes
        self.catch_all = catch_all
        self.calls: List[Tuple[str, str]] = []
        self.count = 0

    def request(self, method: str, url: str, headers: Optional[Dict] = None,
                data=None, **kw) -> Resp:
        method = method.upper()
        headers = headers or {}
        body = data if isinstance(data, str) else ""
        self.calls.append((method, url))
        self.count += 1
        for route in self.routes:
            res = route(method, url, headers, body)
            if res is not None:
                status, rheaders, rbody = res
                break
        else:
            status, rheaders, rbody = self.catch_all
        return Resp(
            url=url, status=status, headers=dict(rheaders), body=rbody,
            elapsed=0.01, method=method,
            request_line="%s %s HTTP/1.1" % (method, url),
            request_headers=dict(headers), request_body=body or "",
            raw_len=len(rbody),
        )

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def post(self, url, data=None, **kw):
        return self.request("POST", url, data=data, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def blocked_hosts(self):
        return []


def path_route(path: str, status: int = 200, ctype: str = "text/plain",
               body: str = "", headers: Optional[Dict] = None,
               method: str = "GET") -> Route:
    def route(m, url, h, b):
        if m != method:
            return None
        if urlsplit(url).path != path:
            return None
        hdrs = {"Content-Type": ctype}
        hdrs.update(headers or {})
        return status, hdrs, body
    return route


def make_ctx(routes: List[Route], profile: str = "standard",
             urls: Optional[Dict[str, List[str]]] = None,
             soft404: bool = True) -> Tuple[Context, StubHttp]:
    cfg = Config(profile=profile, out_dir="/tmp/assay-test")
    http = StubHttp(routes, catch_all=(200, {"Content-Type": "text/html"}, SOFT404_BODY)
                    if soft404 else (404, {"Content-Type": "text/html"}, "not found"))

    class NullStore:
        def add_finding(self, f):
            return True

    ctx = Context(cfg=cfg, store=NullStore(), http=http, tune={"concurrency": 4},
                  urls=urls or {})

    # Calibrate the baseline the same way the engine does, from the stub.
    from assay.net import build_baseline
    ctx.baselines = {}
    orig = ctx.baseline_for

    def baseline_for(origin: str) -> Baseline:
        if origin not in ctx.baselines:
            ctx.baselines[origin] = build_baseline(http, origin)
        return ctx.baselines[origin]

    ctx.baseline_for = baseline_for
    return ctx, http


def web_target(url: str = "http://target.test:8080/",
               headers: Optional[Dict] = None,
               ctype: str = "text/html") -> WebTarget:
    host, _, rest = url.split("://", 1)[1].partition("/")
    hostname, _, port = host.partition(":")
    scheme = url.split("://", 1)[0]
    wt = WebTarget(url=url, host=hostname, port=int(port or (443 if scheme == "https" else 80)),
                   scheme=scheme, status=200, content_type=ctype,
                   headers=headers or {}, final_url=url)
    return wt


def titles(findings: List[Finding]) -> List[str]:
    return [f.title for f in findings]
