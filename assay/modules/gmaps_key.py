"""Verify Google API keys found in client-side assets (gmapsapiscanner logic).

The secrets module only notes that an AIza... key exists; whether it matters
depends on whether Google accepts it without a referrer restriction. This
module asks Google, once per distinct key, across the same API set as
gmapsapiscanner. Requests go to Google, not the target, and bill the key's
owner a few requests' worth.
"""

from __future__ import annotations

from typing import List

from assay import gmaps, owasp, tools
from assay.context import Context
from assay.models import Evidence, Finding
from assay.modules import Module, register


@register
class GoogleKeyModule(Module):
    name = "gmaps_key"
    stage = "external"
    scope = "global"
    impact_class = "probe"
    desc = "Test exposed Google API keys against billable Google APIs"

    def run_global(self, ctx: Context) -> List[Finding]:
        out: List[Finding] = []
        with ctx._lock:
            keys = dict(ctx.google_keys)
        for key, source in keys.items():
            ctx.say("external", "gmaps_key: testing %s..." % key[:10])
            results = gmaps.verify_key(ctx.http, key, stop=tools.SKIP.is_set)
            if not results:
                continue
            out.append(self._finding(key, source, results))
        return out

    @staticmethod
    def _finding(key: str, source: str, results) -> Finding:
        accepted = [r for r in results if r.accepted]
        masked = key[:10] + "..."
        evidence = [Evidence(
            kind="http", label="Probe results (%d/%d accepted)" % (len(accepted), len(results)),
            output="\n".join("%-28s %s" % (r.probe.name, "ACCEPTED" if r.accepted
                                          else "rejected: %s" % r.reason[:90])
                             for r in results))]
        if not accepted:
            return Finding(
                title="Google API key is restricted (no tested API accepted it)",
                target=source, severity="info", confidence="confirmed",
                category=owasp.INFO, cwe="CWE-798", module="gmaps_key",
                impact="Google rejected the key on every tested API from a client with no "
                       "referrer; it appears locked down. Nothing to report.",
                detail="Key %s" % masked, tags=["secrets", "verified"],
                evidence=evidence, dedupe_key="gmapskey|%s" % key[:24])

        bumped = [r for r in accepted if r.probe.severity_bump]
        names = ", ".join(r.probe.name for r in accepted)
        evidence.append(Evidence(
            kind="http", label="Reproduction (one per accepted API)",
            output="\n".join("# %s  (%s)\n%s" % (r.probe.name, r.probe.cost,
                                                gmaps.poc_curl(r.probe, key))
                             for r in accepted)))
        evidence.append(Evidence(
            kind="http", label="Maps JavaScript API PoC (manual: open from disk)",
            output=gmaps.jsapi_poc(key)))
        return Finding(
            title="Unrestricted Google API key accepted by %d API(s)" % len(accepted),
            target=source,
            severity="high" if bumped else "medium",
            confidence="confirmed",
            category=owasp.A05, cwe="CWE-798", module="gmaps_key",
            impact=("Anyone who reads the key can call these APIs billed to the owner's "
                    "Google Cloud project: %s.%s" % (
                        names,
                        " FCM / Gemini acceptance goes beyond billing (push takeover or "
                        "data exposure)." if bumped else "")),
            detail="Key %s found in %s; accepted with no Referer header." % (masked, source),
            repro=gmaps.poc_curl(accepted[0].probe, key),
            refs=["https://github.com/ozguralp/gmapsapiscanner",
                  "https://developers.google.com/maps/api-security-best-practices"],
            tags=["secrets", "verified", "manual-followup"],
            evidence=evidence, dedupe_key="gmapskey|%s" % key[:24])
