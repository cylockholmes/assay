"""Netlas.io lookups: open ports already indexed for a host.

Netlas scans the internet continuously, so for many hosts the answer to "what
is listening" is one HTTP call away instead of a probe per port. That is a
third-party lookup of in-scope hosts, so it is opt-in by key (NETLAS_API_KEY)
and off under --no-passive.

What comes back is a *hint*, never a verdict: Netlas can be stale, and a host
it has not indexed says nothing about that host. Callers treat these ports as
candidates for nmap -sV to confirm, and a missing host as "unknown", not
"closed".
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Callable, Dict, List, Optional, Sequence

import requests

API = "https://app.netlas.io/api"
# 60 requests/minute for search endpoints; stay just under it.
MIN_INTERVAL = 1.1
KEY_ENV = "NETLAS_API_KEY"


def api_key() -> str:
    return os.environ.get(KEY_ENV, "").strip()


def available() -> bool:
    return bool(api_key())


def parse_host_ports(body: dict) -> List[int]:
    """TCP ports from a /host/{host}/ response. Entries look like
    {"protocol": "https", "prot4": "tcp", "port": 443, "prot7": "http"}."""
    out = set()
    for entry in (body or {}).get("ports") or []:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("prot4", "tcp")).lower() != "tcp":
            continue
        try:
            port = int(entry.get("port"))
        except (TypeError, ValueError):
            continue
        if 0 < port < 65536:
            out.add(port)
    return sorted(out)


class QuotaExhausted(Exception):
    """Netlas refused further requests (bad key or plan limit)."""


def _fetch(session: requests.Session, host: str, key: str,
           timeout: float = 20.0) -> Optional[List[int]]:
    """Ports for one host, [] when Netlas knows the host but lists no TCP
    ports, None when it has no data. Retries once on a 429."""
    url = "%s/host/%s/" % (API, host)
    for attempt in (0, 1):
        r = session.get(url, headers={"Authorization": "Bearer " + key},
                        params={"fields": "ports,ip", "source_type": "include"},
                        timeout=timeout)
        if r.status_code == 429 and attempt == 0:
            try:
                wait = min(90.0, float(r.headers.get("Retry-After", 30)))
            except ValueError:
                wait = 30.0
            time.sleep(wait)
            continue
        if r.status_code in (401, 402, 403):
            raise QuotaExhausted("HTTP %d" % r.status_code)
        if r.status_code != 200:
            return None
        try:
            return parse_host_ports(r.json())
        except ValueError:
            return None
    return None


def lookup(hosts: Sequence[str], say: Callable[[str], None] = lambda m: None,
           cache_path: Optional[str] = None,
           stop: Optional[threading.Event] = None,
           fetch: Optional[Callable[[str], Optional[List[int]]]] = None,
           ) -> Dict[str, List[int]]:
    """Known open TCP ports per host. Hosts Netlas has nothing on are absent.

    `cache_path` persists every answer (including "no data") so a resumed or
    repeated run does not spend quota or time re-asking. `fetch` replaces the
    HTTP call (tests).
    """
    key = api_key()
    if fetch is None:
        if not key:
            return {}
        session = requests.Session()
        fetch = lambda h: _fetch(session, h, key)  # noqa: E731

    cache: Dict[str, Optional[List[int]]] = {}
    if cache_path and os.path.isfile(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as fh:
                cache = json.load(fh)
        except (OSError, ValueError):
            cache = {}

    def save() -> None:
        if not cache_path:
            return
        try:
            with open(cache_path, "w", encoding="utf-8") as fh:
                json.dump(cache, fh)
        except OSError:
            pass

    todo = [h for h in hosts if h not in cache]
    if len(hosts) - len(todo):
        say("netlas: %d host(s) answered from cache" % (len(hosts) - len(todo)))
    if todo:
        say("netlas: querying %d host(s) (~%d min at the API's rate limit)"
            % (len(todo), max(1, int(len(todo) * MIN_INTERVAL / 60))))
    last = 0.0
    for i, host in enumerate(todo, 1):
        if stop is not None and stop.is_set():
            say("netlas: stopped by request - %d host(s) not queried" % (len(todo) - i + 1))
            break
        wait = MIN_INTERVAL - (time.time() - last)
        if wait > 0 and fetch is not None and key:
            time.sleep(wait)
        last = time.time()
        try:
            cache[host] = fetch(host)
        except QuotaExhausted as exc:
            say("netlas: refused (%s) - check the key/plan; continuing without it" % exc)
            break
        except requests.RequestException:
            continue                    # transient: not cached, asked again next run
        if i % 25 == 0:
            save()
    save()
    return {h: cache[h] for h in hosts if cache.get(h)}


def prompt_for_key(console=None) -> bool:
    """Ask for a Netlas key interactively. Session-only, never written to disk.

    Blank skips Netlas; the scan then probes every host with naabu as usual.
    """
    import getpass
    import sys
    if available() or not sys.stdin.isatty():
        return available()
    say = console.print if console else (lambda *a, **k: None)
    say("\n  [bold]Netlas.io API key[/bold] [dim](optional)[/dim]")
    say("  [dim]Netlas already knows open ports for many hosts, which makes port "
        "discovery much faster. Target hostnames/IPs are sent to Netlas to look "
        "them up. Leave blank to skip: naabu then sweeps every host itself.[/dim]")
    try:
        key = getpass.getpass("  Netlas API key (input hidden, Enter to skip): ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    if not key:
        say("  [dim]no key - naabu will sweep every host[/dim]")
        return False
    os.environ[KEY_ENV] = key
    say("  [green]key set for this run only.[/green] To persist it: "
        "[dim]export NETLAS_API_KEY=...  (add to ~/.bashrc)[/dim]")
    return True
