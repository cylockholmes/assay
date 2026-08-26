"""Surface that DNS does not advertise: virtual hosts and exposed origins."""

from __future__ import annotations

import socket
from typing import List, Optional

from assay import owasp, recon
from assay.context import Context
from assay.models import Evidence, Finding, WebTarget
from assay.modules import Module, register


@register
class OriginExposureModule(Module):
    name = "origin"
    stage = "analyze"
    scope = "web"
    impact_class = "read"
    desc = "CDN/WAF bypass via a directly reachable origin server"

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        if wt.host.replace(".", "").isdigit():
            return []          # already an IP; nothing to bypass
        try:
            ip = socket.gethostbyname(wt.host)
        except (socket.gaierror, OSError):
            return []
        if ip == wt.host:
            return []

        edge = ctx.http.get("%s://%s/" % (wt.scheme, wt.host))
        if not edge.ok:
            return []
        cdn = recon.detect_cdn(edge)
        if not cdn:
            return []          # nothing in front, so nothing to bypass

        # Candidate origins: the resolved address, plus siblings that were never
        # put behind the edge, plus the mail and SPF infrastructure.
        candidates = {ip: "DNS: %s" % wt.host}
        if recon.is_cdn_ip(ip):
            candidates.pop(ip, None)
        candidates.update(recon.origin_candidates(
            wt.host, {t.host for t in ctx.targets},
            workers=min(12, ctx.tune.get("concurrency", 8))))
        candidates = {k: v for k, v in candidates.items()
                      if ctx.cfg.scope.allows(k)}
        if not candidates:
            return []

        direct = None
        source = ""
        for cand_ip, src in candidates.items():
            direct = recon.confirm_origin(ctx.http, wt.host, cand_ip, wt.scheme, edge)
            if direct:
                ip, source = cand_ip, src
                break
        if not direct:
            return []
        via_cdn = edge
        return [Finding(
            title="Origin server reachable directly, bypassing %s" % cdn,
            target="%s (%s)" % (wt.host, ip),
            severity="medium",
            confidence="confirmed",
            category=owasp.A05,
            cwe="CWE-693",
            module=self.name,
            impact=(
                "The same application answers on the origin IP with the %s edge removed. "
                "Every control implemented at the edge - WAF rules, rate limiting, bot "
                "filtering, IP allow-listing and DDoS protection - is bypassed by "
                "addressing the origin directly with the right Host header. Re-run any "
                "check that the WAF previously blocked against this address." % cdn
            ),
            detail="Direct request to %s with Host: %s returns the application "
                   "without %s headers. Candidate found via %s."
                   % (ip, wt.host, cdn, source or "DNS"),
            repro="curl -sSik --resolve %s:%d:%s %s://%s/"
                  % (wt.host, wt.port, ip, wt.scheme, wt.host),
            refs=["https://owasp.org/www-project-web-security-testing-guide/"],
            tags=["recon", "waf-bypass", "verified"],
            chainable=True,
            evidence=[
                via_cdn.evidence(label="Via %s edge" % cdn, body_limit=300),
                direct.evidence(label="Direct to origin IP", body_limit=300),
            ],
            dedupe_key="origin|%s" % wt.host,
        )]


@register
class VhostModule(Module):
    name = "vhost"
    stage = "analyze"
    scope = "web"
    impact_class = "probe"
    desc = "Virtual hosts served by an IP but not advertised in DNS"

    def applicable(self, ctx: Context) -> bool:
        if not Module.applicable(self, ctx):
            return False
        return ctx.cfg.profile in ("standard", "deep")

    def run_web(self, ctx: Context, wt: WebTarget) -> List[Finding]:
        candidates = self._candidates(ctx, wt)
        if not candidates:
            return []
        base = "%s://%s:%d/" % (wt.scheme, wt.host, wt.port)
        hits = recon.vhost_probe(ctx.http, base, candidates,
                                 workers=min(8, ctx.tune.get("concurrency", 8)))
        if not hits:
            return []

        names = [h for h, _ in hits]
        first = hits[0][1]
        return [Finding(
            title="%d undisclosed virtual host(s) on this address" % len(hits),
            target=base,
            severity="low",
            confidence="confirmed",
            category=owasp.INFO,
            cwe="CWE-200",
            module=self.name,
            impact=(
                "These hostnames return a different application from the default site "
                "on the same address: %s. Virtual hosts reached only by Host header are "
                "routinely staging, admin or internal applications that were never "
                "meant to be discoverable - scan each one as a target in its own right, "
                "which is where the real finding usually is."
                % ", ".join(names[:6])
            ),
            detail="Differs from both the default response and a random-hostname baseline.",
            repro="curl -sSik -H 'Host: %s' %s" % (names[0], base),
            tags=["recon", "verified", "manual-followup"],
            chainable=True,
            evidence=[first.evidence(label="Response for Host: %s" % names[0],
                                     body_limit=400)],
            dedupe_key="vhost|%s" % base,
        )]

    def _candidates(self, ctx: Context, wt: WebTarget) -> List[str]:
        """Names worth trying: siblings already known, plus permutations."""
        parts = wt.host.split(".")
        if wt.host.replace(".", "").isdigit() or len(parts) < 2:
            return []
        apex = ".".join(parts[-2:])
        known = {t.host for t in ctx.targets}
        cap = 40 if ctx.cfg.profile == "standard" else 120
        cands = [c for c in recon.permute(known, apex, cap=cap) if c != wt.host]
        return cands[:cap]
