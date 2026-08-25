"""URL and parameter sourcing.

The active checks are only as good as the injection points they are given. A
live crawl finds what the application links to today; it misses the endpoints
that were linked three years ago, the parameters no page ever emits, and the
routes that exist only inside a JavaScript bundle. Every published bug bounty
methodology draws from all four sources, so assay does too.

  crawl       katana (or a native link pass)  - what is linked now
  historical  gau / waybackurls               - what was ever linked   [passive]
  javascript  native path extraction          - what the client knows about
  parameters  arjun                           - what the server accepts

Historical sources query third-party archives, so they are gated behind
--passive and never run by default on an engagement.
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

from assay import tools

# Paths and endpoints embedded in JavaScript. Deliberately conservative: the
# permissive version of this regex matches every string in a minified bundle.
JS_PATH_RE = re.compile(
    r"""["'`](/(?:[A-Za-z0-9_\-./]{2,120}))["'`]"""
)
JS_URL_RE = re.compile(
    r"""["'`](https?://[A-Za-z0-9._\-]+(?::\d+)?/[A-Za-z0-9_\-./?=&%]{0,160})["'`]"""
)
# fetch("/api/x"), axios.get('/v1/y'), url: "/z"
JS_CALL_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|patch|delete)|\.open|url\s*:)\s*\(?\s*"""
    r"""["'`]([^"'`]{2,160})["'`]""",
    re.I,
)

# Extensions that are assets, not endpoints worth injecting into.
ASSET_RE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|css|scss|mp4|webm|mp3|"
    r"pdf|zip|gz|tar|avif|map)(?:$|\?)", re.I)

# Paths that are obviously framework internals rather than app routes.
JS_NOISE_RE = re.compile(
    r"^/(?:$|\*|@|node_modules/|__webpack|\d+$|[A-Za-z]$)|"
    r"^/(?:application|text|image|video|audio)/|"      # mime types
    r"^/(?:UTC|GMT|Etc)/", re.I)


def normalise(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def is_useful(url: str) -> bool:
    if not url.startswith("http"):
        return False
    if ASSET_RE.search(url):
        return False
    return True


def param_signature(url: str) -> str:
    """Group URLs by (path, sorted param names) so we test shapes, not values."""
    parts = urlsplit(url)
    names = sorted({kv.split("=")[0] for kv in parts.query.split("&") if kv})
    return "%s|%s" % (parts.path, ",".join(names))


def dedupe_by_shape(urls: Iterable[str], cap: int) -> List[str]:
    """Collapse to one representative URL per (path, parameter-set).

    A crawl of a paginated list yields hundreds of URLs that differ only by id.
    Testing all of them wastes the request budget and finds nothing extra.
    """
    seen: Dict[str, str] = {}
    for u in urls:
        if not is_useful(u):
            continue
        seen.setdefault(param_signature(u), normalise(u))
        if len(seen) >= cap:
            break
    return list(seen.values())


# --------------------------------------------------------------------------
# JavaScript extraction
# --------------------------------------------------------------------------


def extract_from_js(body: str, base_url: str, host: str,
                    limit: int = 300) -> Tuple[List[str], List[str]]:
    """Pull endpoints out of a JS bundle.

    Returns (same-origin URLs, foreign absolute URLs). Foreign URLs are kept
    separately because they are recon leads, not injection targets.
    """
    local: List[str] = []
    foreign: List[str] = []
    seen: Set[str] = set()

    def add(path_or_url: str) -> None:
        if len(local) + len(foreign) >= limit:
            return
        if path_or_url.startswith("http"):
            if urlsplit(path_or_url).hostname == host:
                target, bucket = normalise(path_or_url), local
            else:
                target, bucket = path_or_url, foreign
        else:
            if JS_NOISE_RE.match(path_or_url) or ASSET_RE.search(path_or_url):
                return
            target, bucket = normalise(urljoin(base_url, path_or_url)), local
        if target in seen:
            return
        seen.add(target)
        bucket.append(target)

    for m in JS_CALL_RE.finditer(body):
        cand = m.group(1)
        if cand.startswith(("/", "http")):
            add(cand)
    for m in JS_URL_RE.finditer(body):
        add(m.group(1))
    for m in JS_PATH_RE.finditer(body):
        add(m.group(1))

    return local, foreign


# --------------------------------------------------------------------------
# Historical archives
# --------------------------------------------------------------------------


def historical(domain: str, limit: int) -> Tuple[List[str], str]:
    """Query archive services for URLs this host has ever served."""
    if tools.have("gau"):
        return tools.gau_urls(domain, limit), "gau"
    if tools.have("waybackurls"):
        return tools.waybackurls_urls(domain, limit), "waybackurls"
    return [], ""


# --------------------------------------------------------------------------
# Parameter discovery
# --------------------------------------------------------------------------


def with_params(url: str, names: List[str]) -> str:
    """Attach discovered parameter names so the active checks can inject."""
    if not names:
        return url
    parts = urlsplit(url)
    existing = {kv.split("=")[0] for kv in parts.query.split("&") if kv}
    extra = "&".join("%s=1" % n for n in names if n not in existing)
    query = "&".join(x for x in (parts.query, extra) if x)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, ""))
