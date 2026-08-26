"""Scan orchestration.

Stages run in order; work inside a stage is parallel across targets. Ordering
matters for signal quality: baselines are calibrated before any content check
runs, crawling happens before the active checks so they have real parameters to
inject into, and nuclei runs last so its volume cannot delay the checks that
produce the highest-confidence findings.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

from assay import env, recon, tools, urls as urlsrc
from assay.journal import Journal
from assay.oob import OOBSession
from assay.burp import BurpBridge
from assay.config import Config
from assay.context import Context
from assay.models import Finding, Port, Target, WebTarget, host_port_from_url, normalize_url
from assay.net import HttpClient, build_baseline
from assay.store import Store

# Ports we will try HTTP against when no service detection says otherwise.
WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 7001, 8081, 9000,
             9090, 9200, 10000, 4443, 8180, 8181, 2375, 5601, 15672]

HTTP_SERVICES = {"http", "https", "http-alt", "https-alt", "http-proxy",
                 "ssl/http", "www", "webcache", "tomcat", "nginx"}

TECH_SIGNATURES: List[Tuple[str, str]] = [
    ("WordPress", r"/wp-content/|/wp-includes/|name=[\"']generator[\"'] content=[\"']WordPress"),
    ("Drupal", r"Drupal\.settings|/sites/default/files/|X-Generator: Drupal"),
    ("Joomla", r"/media/jui/|option=com_"),
    ("Laravel", r"laravel_session|XSRF-TOKEN"),
    ("Django", r"csrfmiddlewaretoken|__admin_media_prefix__"),
    ("Rails", r"csrf-param|authenticity_token"),
    ("Spring Boot", r"Whitelabel Error Page|X-Application-Context"),
    ("ASP.NET", r"__VIEWSTATE|X-AspNet-Version|\.aspx"),
    ("Next.js", r"__NEXT_DATA__|/_next/static/"),
    ("Nuxt", r"__NUXT__|/_nuxt/"),
    ("React", r"react(?:-dom)?(?:\.production)?\.min\.js|data-reactroot"),
    ("Angular", r"ng-version=|/runtime\.[0-9a-f]+\.js"),
    ("Vue", r"__vue__|vue(?:\.runtime)?\.min\.js"),
    ("GraphQL", r"__typename|graphql"),
    ("Jenkins", r"X-Jenkins|Jenkins-Agent-Protocols"),
    ("Grafana", r"grafana_session|Grafana"),
    ("Kibana", r"kbn-name|Kibana"),
    ("Swagger UI", r"swagger-ui|swagger-init"),
]


class Engine:
    def __init__(self, cfg: Config, progress: Optional[Callable] = None) -> None:
        cfg.ensure_dirs()
        env.augment_path()
        self.cfg = cfg
        self.tune = env.autotune()
        # Explicit CLI values win over autotuning.
        self.tune["concurrency"] = cfg.concurrency
        self.tune["rate"] = cfg.rate
        self.store = Store(cfg.db_path())
        self.http = HttpClient(cfg)
        self.ctx = Context(cfg=cfg, store=self.store, http=self.http, tune=self.tune,
                           tools=tools.available(), progress=progress)
        self.burp = BurpBridge(cfg)
        self.journal = Journal(cfg.out_dir, enabled=cfg.journal)
        self.http.journal = self.journal
        tools.JOURNAL = self.journal
        self.started = 0.0

    # ------------------------------------------------------------------
    def run(self) -> Context:
        self.started = time.time()
        self.store.start_run(self.cfg.profile, self.cfg.targets)
        self.journal.open(self.cfg.targets, self.cfg.profile)
        say = self.ctx.say

        if self.cfg.burp.enabled:
            st = self.burp.detect()
            say("burp", "proxy=%s api=%s %s" % (st.proxy_ok, st.api_ok, st.detail[:80]))

        # Blind checks need a callback channel; start it before anything fires.
        self.oob = OOBSession(self.cfg.out_dir, domain=self.cfg.oob_domain,
                              enabled=self.cfg.oob)
        say("oob", self.oob.start())
        self.ctx.oob = self.oob

        self._stage_resolve()
        if self.cfg.expand:
            self._stage_recon()
        if self.cfg.portscan:
            self._stage_portscan()
        self._stage_probe()
        if self.cfg.module_enabled("crawl"):
            self._stage_urls()
        # Content discovery runs after the other URL sources so it can add to
        # the same pool, and before the checks that consume it.
        self._stage_modules("probe")
        self._stage_modules("analyze")
        if self.cfg.opts.get("active_web"):
            self._stage_modules("active")
        self._stage_modules("external")

        fired, hits = self.oob.stats()
        if fired:
            ledger = self.oob.flush_ledger()
            say("oob", "%d payload(s) fired, %d callback(s) observed%s"
                % (fired, hits, (" - ledger: %s" % ledger) if ledger else ""))
        self.oob.stop()

        self.journal.close()
        if self.cfg.journal:
            say("journal", "%d request(s) and %d command(s) recorded - replay.sh"
                % (self.journal.requests, self.journal.commands))
        self.store.finish_run()
        say("done", "%d finding(s) in %.0fs, %d requests"
            % (self.store.counts().get("total", 0), time.time() - self.started,
               self.http.count))
        blocked = self.http.blocked_hosts()
        if blocked:
            say("scope", "blocked %d out-of-scope host(s): %s"
                % (len(blocked), ", ".join(blocked[:5])))
        return self.ctx

    # -- stage 1: resolve ------------------------------------------------
    def _stage_resolve(self) -> None:
        self.ctx.say("resolve", "expanding %d target spec(s)" % len(self.cfg.targets))
        targets: Dict[str, Target] = {}
        seeds: List[WebTarget] = []

        for raw in self.cfg.targets:
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
                host, port, scheme = host_port_from_url(raw)
                if not self.cfg.scope.allows(host):
                    continue
                t = targets.setdefault(host, Target(raw=raw, host=host, kind="url"))
                if not any(p.port == port for p in t.ports):
                    t.ports.append(Port(port=port, service=scheme,
                                        tunnel="ssl" if scheme == "https" else ""))
                seeds.append(WebTarget(url=normalize_url(raw), host=host, port=port,
                                       scheme=scheme))
                continue
            for host in self._expand(raw):
                if self.cfg.scope.allows(host):
                    targets.setdefault(host, Target(raw=raw, host=host))

        for t in targets.values():
            t.ip = self._resolve(t.host)
            if t.ip:
                t.resolved = [t.ip]
        self.ctx.targets = list(targets.values())
        self.ctx.web = seeds
        self.ctx.say("resolve", "%d host(s), %d seeded URL(s)"
                     % (len(self.ctx.targets), len(seeds)))

    @staticmethod
    def _expand(raw: str, cap: int = 1024) -> List[str]:
        if "/" in raw:
            try:
                net = ipaddress.ip_network(raw, strict=False)
                if net.num_addresses > cap:
                    return [str(net.network_address)]
                return [str(ip) for ip in net.hosts()] or [str(net.network_address)]
            except ValueError:
                pass
        return [raw.split("/")[0]]

    @staticmethod
    def _resolve(host: str) -> str:
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        try:
            return socket.gethostbyname(host)
        except (socket.gaierror, OSError):
            return ""

    # -- stage 1b: surface expansion --------------------------------------
    def _stage_recon(self) -> None:
        """Grow the target list before scanning it.

        Permutation and resolution touch only DNS. Archive and CT-log lookups
        touch a third party, so they stay behind --passive.
        """
        apexes: Dict[str, Set[str]] = {}
        for t in self.ctx.targets:
            if t.is_ip:
                continue
            parts = t.host.split(".")
            if len(parts) >= 2:
                apexes.setdefault(".".join(parts[-2:]), set()).add(t.host)
        if not apexes:
            return

        known = {t.host for t in self.ctx.targets}
        candidates: Set[str] = set()

        for apex, hosts in apexes.items():
            if self.cfg.passive:
                found, via = recon.passive_subdomains(apex, self.http)
                if via:
                    self.ctx.say("recon", "%s: %d name(s) from %s"
                                 % (apex, len(found), via))
                    candidates.update(found)
            candidates.update(recon.permute(hosts, apex,
                                            cap=120 if self.cfg.profile == "quick" else 400))

        candidates -= known
        candidates = {c for c in candidates if self.cfg.scope.allows(c)}
        if not candidates:
            self.ctx.say("recon", "no new in-scope candidates")
            return

        self.ctx.say("recon", "resolving %d candidate name(s)" % len(candidates))
        resolved = recon.resolve_bulk(sorted(candidates),
                                      workers=self.tune["concurrency"])

        # Discard anything that merely matched a wildcard record.
        wildcards: Set[str] = set()
        for apex in apexes:
            wildcards |= recon.wildcard_ips(apex)
        added = 0
        for host, ip in sorted(resolved.items()):
            if ip in wildcards or host in known:
                continue
            self.ctx.targets.append(Target(raw=host, host=host, ip=ip,
                                           resolved=[ip], tags=["expanded"]))
            added += 1
        self.ctx.say("recon", "surface expanded by %d host(s)%s"
                     % (added, " (%d wildcard hits discarded)"
                        % (len(resolved) - added) if len(resolved) > added else ""))

    # -- stage 2: port scan ----------------------------------------------
    def _stage_portscan(self) -> None:
        hosts = [t.host for t in self.ctx.targets if t.kind != "url"]
        if not hosts:
            return
        spec = self.cfg.opts.get("port_spec", "top-1000")

        # naabu sweeps far faster than nmap; when both are present, use naabu to
        # find the open ports and nmap only to fingerprint them. On a /24 this
        # is the difference between minutes and most of an hour.
        if self.ctx.has("naabu") and self.ctx.has("nmap") and len(hosts) > 1:
            self.ctx.say("ports", "naabu sweep (%s) across %d host(s)"
                         % (spec, len(hosts)))
            swept = tools.naabu_scan(hosts, spec, self.tune)
            open_ports = sorted({p for ports in swept.values() for p in ports})
            if open_ports:
                self.ctx.say("ports", "naabu found %d distinct open port(s); "
                                      "nmap -sV on those only" % len(open_ports))
                spec = ",".join(str(p) for p in open_ports)
                hosts = sorted(swept.keys()) or hosts
            else:
                self.ctx.say("ports", "naabu found nothing open")
                return

        if not self.ctx.has("nmap"):
            self.ctx.say("ports", "nmap not installed - falling back to a %d-port sweep"
                         % len(WEB_PORTS))
            self._native_portscan(hosts)
            return

        self.ctx.say("ports", "nmap -sV %s across %d host(s)" % (spec, len(hosts)))
        results = tools.nmap_scan(hosts, spec, self.tune, out_dir=self.cfg.out_dir)
        by_host = {t.host: t for t in self.ctx.targets}
        by_ip = {t.ip: t for t in self.ctx.targets if t.ip}
        found = 0
        for key, ports in results.items():
            t = by_host.get(key) or by_ip.get(key)
            if t is None:
                continue
            t.ports = ports
            found += len(ports)
            self.store.save_host(t.host, t.ip or "", {
                "ports": [p.__dict__ for p in ports]})
        self.ctx.say("ports", "%d open port(s) across %d host(s)" % (found, len(results)))

    def _native_portscan(self, hosts: List[str]) -> None:
        by_host = {t.host: t for t in self.ctx.targets}

        def check(host: str, port: int) -> Optional[Tuple[str, int]]:
            try:
                with socket.create_connection((host, port), timeout=3):
                    return host, port
            except OSError:
                return None

        jobs = [(h, p) for h in hosts for p in WEB_PORTS]
        with ThreadPoolExecutor(max_workers=self.tune["concurrency"]) as pool:
            for fut in as_completed([pool.submit(check, h, p) for h, p in jobs]):
                res = fut.result()
                if not res:
                    continue
                host, port = res
                t = by_host.get(host)
                if t is not None and not any(x.port == port for x in t.ports):
                    t.ports.append(Port(port=port,
                                        service="https" if port in (443, 8443, 9443) else "http",
                                        tunnel="ssl" if port in (443, 8443, 9443) else ""))

    # -- stage 3: HTTP probe ---------------------------------------------
    def _stage_probe(self) -> None:
        candidates: List[Tuple[Target, Port]] = []
        for t in self.ctx.targets:
            for p in t.ports:
                if p.service in HTTP_SERVICES or p.is_tls or p.port in WEB_PORTS:
                    candidates.append((t, p))
        if not candidates:
            self.ctx.say("probe", "no HTTP candidates found")
            return

        self.ctx.say("probe", "probing %d host:port candidate(s)" % len(candidates))
        seen: Set[str] = {w.key() for w in self.ctx.web}

        # httpx probes far faster than a Python thread pool once there are many
        # candidates. Below that threshold the process spawn costs more than it
        # saves, so the native path stays.
        if self.ctx.has("httpx") and len(candidates) >= 25:
            got = self._probe_via_httpx(candidates, seen)
            if got:
                self.ctx.say("probe", "httpx: %d live endpoint(s)" % got)
                self._calibrate()
                return
        with ThreadPoolExecutor(max_workers=self.tune["concurrency"]) as pool:
            futures = [pool.submit(self._probe_one, t, p) for t, p in candidates]
            for fut in as_completed(futures):
                wt = fut.result()
                if wt is None or wt.key() in seen:
                    continue
                seen.add(wt.key())
                self.ctx.web.append(wt)
                self.store.save_web(wt.url, wt.host, wt.port, wt.status, wt.title,
                                    wt.server, wt.tech,
                                    {"content_type": wt.content_type,
                                     "final_url": wt.final_url,
                                     "length": wt.length})
        self.ctx.say("probe", "%d live web endpoint(s)" % len(self.ctx.web))

        # Calibrate soft-404 baselines up front; every content check depends on it.
        self._calibrate()

    def _probe_via_httpx(self, candidates, seen: Set[str]) -> int:
        targets = ["%s:%d" % (t.host, p.port) for t, p in candidates]
        added = 0
        try:
            stream = tools.httpx_probe(targets, self.tune,
                                       proxy=self.cfg.burp.proxy,
                                       headers=self._tool_headers() or None)
            for obj in stream:
                url = obj.get("url") or ""
                if not url:
                    continue
                host = obj.get("host") or obj.get("input", "").split(":")[0]
                port = int(obj.get("port") or 0) or (443 if url.startswith("https") else 80)
                scheme = url.split("://", 1)[0]
                wt = WebTarget(
                    url=url, host=host, port=port, scheme=scheme,
                    status=int(obj.get("status_code") or 0),
                    title=(obj.get("title") or "")[:120],
                    server=obj.get("webserver") or "",
                    content_type=(obj.get("content_type") or "").split(";")[0],
                    length=int(obj.get("content_length") or 0),
                    words=int(obj.get("words") or 0),
                    tech=list(obj.get("tech") or []),
                    final_url=obj.get("final_url") or url,
                )
                if obj.get("favicon"):
                    try:
                        wt.favicon_hash = int(obj["favicon"])
                    except (TypeError, ValueError):
                        pass
                if wt.key() in seen:
                    continue
                seen.add(wt.key())
                self.ctx.web.append(wt)
                self.store.save_web(wt.url, wt.host, wt.port, wt.status, wt.title,
                                    wt.server, wt.tech,
                                    {"content_type": wt.content_type,
                                     "final_url": wt.final_url, "length": wt.length})
                added += 1
        except Exception:
            # httpx is an optimisation; fall back to the native probe.
            return 0
        return added

    def _calibrate(self) -> None:
        origins = sorted({re.sub(r"(https?://[^/]+).*", r"\1", w.final_url or w.url)
                          for w in self.ctx.web})
        self.ctx.say("probe", "calibrating %d baseline(s)" % len(origins))
        with ThreadPoolExecutor(max_workers=min(6, self.tune["concurrency"])) as pool:
            list(pool.map(self.ctx.baseline_for, origins))

    def _probe_one(self, t: Target, p: Port) -> Optional[WebTarget]:
        schemes = ("https", "http") if (p.is_tls or p.port in (443, 8443, 9443)) \
            else ("http", "https")
        for scheme in schemes:
            url = "%s://%s:%d/" % (scheme, t.host, p.port)
            r = self.http.get(url, allow_redirects=True)
            if not r.ok:
                continue
            wt = WebTarget(
                url=url, host=t.host, port=p.port, scheme=scheme,
                status=r.status, title=r.title, server=r.header("Server"),
                content_type=r.content_type, length=len(r.body),
                words=len(r.body.split()), headers=dict(r.headers),
                body_sample=r.body[:4000], final_url=r.url or url,
                redirect_chain=r.history,
            )
            wt.tech = self._fingerprint(r.body[:200000], r.headers)
            return wt
        return None

    @staticmethod
    def _fingerprint(body: str, headers: Dict[str, str]) -> List[str]:
        blob = body + "\n" + "\n".join("%s: %s" % kv for kv in headers.items())
        tech = [name for name, pattern in TECH_SIGNATURES
                if re.search(pattern, blob, re.I)]
        server = headers.get("Server") or headers.get("server")
        if server:
            tech.append(server.split("/")[0].strip())
        powered = headers.get("X-Powered-By") or headers.get("x-powered-by")
        if powered:
            tech.append(powered.split("/")[0].strip())
        seen: List[str] = []
        for x in tech:
            if x and x not in seen:
                seen.append(x)
        return seen

    # -- stage 4: URL + parameter sourcing --------------------------------
    def _stage_urls(self) -> None:
        """Assemble injection points from crawl, archives, JS and arjun.

        Each source is independent and additive; a missing tool costs reach but
        never breaks the stage.
        """
        if not self.ctx.web:
            return
        cap = self.cfg.opts.get("max_urls_per_host", 60)
        raw: Dict[str, List[str]] = {}

        def add(origin: str, found: Iterable[str]) -> int:
            bucket = raw.setdefault(origin, [])
            n = 0
            for u in found:
                bucket.append(u)
                n += 1
            return n

        origins = [re.sub(r"(https?://[^/]+).*", r"\1", (w.final_url or w.url))
                   for w in self.ctx.web]

        # 1. crawl -----------------------------------------------------------
        if self.cfg.opts.get("crawl"):
            self._source_crawl(add, cap)

        # 2. historical archives (third-party; opt-in) ------------------------
        if self.cfg.passive:
            self._source_historical(add, cap)
        elif tools.have("gau") or tools.have("waybackurls"):
            self.ctx.say("urls", "historical archives available but skipped "
                                 "(third-party lookup; enable with --passive)")

        # 3. javascript ------------------------------------------------------
        self._source_javascript(add, cap)

        # Collapse to distinct (path, parameter-set) shapes before spending
        # any further budget on them.
        for origin in set(origins):
            self.ctx.urls[origin] = urlsrc.dedupe_by_shape(raw.get(origin, []), cap)

        # 4. parameter discovery on what survived ----------------------------
        if self.cfg.opts.get("param_discovery") and self.ctx.has("arjun"):
            self._source_params()

        total = sum(len(v) for v in self.ctx.urls.values())
        withp = sum(1 for v in self.ctx.urls.values() for u in v if "?" in u)
        self.ctx.say("urls", "%d injection point(s), %d carrying parameters"
                     % (total, withp))

    def _source_crawl(self, add, cap: int) -> None:
        targets = [w.final_url or w.url for w in self.ctx.web]
        if self.ctx.has("katana"):
            self.ctx.say("urls", "katana over %d endpoint(s)" % len(targets))
            results = tools.katana_crawl(targets, depth=2, tune=self.tune,
                                         max_urls=cap * max(1, len(targets)),
                                         proxy=self.cfg.burp.proxy,
                                         headers=self._tool_headers())
            n = 0
            for obj in results:
                u = (obj.get("request") or {}).get("endpoint") or obj.get("endpoint")
                if u:
                    n += add(re.sub(r"(https?://[^/]+).*", r"\1", u), [u])
            self.ctx.say("urls", "crawl: %d URL(s)" % n)
        else:
            self.ctx.say("urls", "katana not installed - native link pass")
            self._native_crawl(add, cap)

    def _source_historical(self, add, cap: int) -> None:
        hosts = sorted({w.host for w in self.ctx.web})
        found = 0
        for host in hosts:
            got, via = urlsrc.historical(host, cap * 4)
            if not via:
                self.ctx.say("urls", "no archive tool installed (gau/waybackurls)")
                return
            for u in got:
                if urlsplit(u).hostname == host:
                    found += add(re.sub(r"(https?://[^/]+).*", r"\1", u), [u])
        self.ctx.say("urls", "historical: %d URL(s)" % found)

    def _source_javascript(self, add, cap: int) -> None:
        script_re = re.compile(r"""<script[^>]+src=["']?([^"'\s>]+)""", re.I)
        found = leads = 0
        budget = 8 if self.cfg.profile == "quick" else (
            20 if self.cfg.profile == "standard" else 50)
        for w in self.ctx.web:
            base = w.final_url or w.url
            origin = re.sub(r"(https?://[^/]+).*", r"\1", base)
            scripts = [urljoin(base, src) for src in
                       script_re.findall(w.body_sample or "")]
            r = self.http.get(base)
            if r.ok:
                scripts += [urljoin(r.url, src) for src in
                            script_re.findall(r.body[:400000])]
            seen_js: Set[str] = set()
            for js_url in scripts:
                if js_url in seen_js or js_url.startswith("data:"):
                    continue
                seen_js.add(js_url)
                if len(seen_js) > budget:
                    break
                jr = self.http.get(js_url)
                if not jr.ok or jr.status != 200:
                    continue
                local, foreign = urlsrc.extract_from_js(
                    jr.body[:600000], js_url, w.host)
                found += add(origin, local)
                leads += len(foreign)
        self.ctx.say("urls", "javascript: %d endpoint(s), %d foreign host lead(s)"
                     % (found, leads))

    def _source_params(self) -> None:
        """Ask arjun for parameters no page ever emits."""
        budget = 4 if self.cfg.profile == "standard" else 12
        enriched = 0
        for origin, bucket in self.ctx.urls.items():
            # Prefer parameterless URLs - those are the ones a crawl cannot help.
            targets = [u for u in bucket if "?" not in u][:budget]
            for i, u in enumerate(targets):
                names = tools.arjun_params(u, self.tune)
                if not names:
                    continue
                idx = bucket.index(u)
                bucket[idx] = urlsrc.with_params(u, names[:8])
                enriched += 1
        if enriched:
            self.ctx.say("urls", "arjun: enriched %d endpoint(s) with hidden params"
                         % enriched)

    def _native_crawl(self, add, cap: int) -> None:
        link_re = re.compile(r"""(?:href|src|action)=["']([^"'#>]+)""", re.I)
        for w in self.ctx.web:
            base = w.final_url or w.url
            origin = re.sub(r"(https?://[^/]+).*", r"\1", base)
            r = self.http.get(base)
            if not r.ok:
                continue
            found = []
            for href in link_re.findall(r.body[:300000]):
                if href.startswith(("mailto:", "javascript:", "tel:", "data:")):
                    continue
                full = urljoin(base, href)
                if urlsplit(full).hostname == w.host:
                    found.append(full)
            add(origin, found[:cap])

    # -- stage 5+: modules ------------------------------------------------
    def _stage_modules(self, stage: str) -> None:
        from assay.modules import modules_for_stage

        mods = [m for m in modules_for_stage(stage) if m.applicable(self.ctx)]
        if not mods:
            return
        self.ctx.say(stage, "running %s" % ", ".join(m.name for m in mods))

        jobs: List[Tuple] = []
        for m in mods:
            if m.scope == "web":
                jobs += [(m, "web", w) for w in self.ctx.web]
            elif m.scope == "host":
                jobs += [(m, "host", t) for t in self.ctx.targets if t.ports]
            else:
                jobs.append((m, "global", None))
        if not jobs:
            return

        done = 0
        with ThreadPoolExecutor(max_workers=self.tune["concurrency"]) as pool:
            futures = {pool.submit(self._run_module, m, kind, subject): (m, subject)
                       for m, kind, subject in jobs}
            for fut in as_completed(futures):
                m, subject = futures[fut]
                done += 1
                try:
                    for f in fut.result():
                        self.ctx.emit(f)
                except Exception as exc:                 # one module must not sink the run
                    self.ctx.say("error", "%s failed on %s: %s"
                                 % (m.name, getattr(subject, "url",
                                                    getattr(subject, "host", "-")),
                                    type(exc).__name__))
                self.ctx.say(stage, "%d/%d" % (done, len(jobs)), advance=1)

    def _run_module(self, module, kind: str, subject) -> List[Finding]:
        if kind == "web":
            return module.run_web(self.ctx, subject)
        if kind == "host":
            return module.run_host(self.ctx, subject)
        return module.run_global(self.ctx)

    def _tool_headers(self) -> Dict[str, str]:
        """Auth and custom headers to hand to external tools."""
        h: Dict[str, str] = {}
        auth = self.cfg.auth_header()
        if auth:
            h["Authorization"] = auth
        h.update(self.cfg.headers)
        if self.cfg.cookies:
            h["Cookie"] = self.cfg.cookies
        return h

    # -- summary ----------------------------------------------------------
    def assets(self) -> Dict:
        tech: Set[str] = set()
        services: Set[str] = set()
        for w in self.ctx.web:
            tech.update(w.tech)
        for t in self.ctx.targets:
            for p in t.ports:
                if p.service:
                    services.add(p.service)
        return {"hosts": len(self.ctx.targets), "web": len(self.ctx.web),
                "tech": sorted(tech), "services": sorted(services),
                "requests": self.http.count,
                "duration": round(time.time() - self.started, 1)}
