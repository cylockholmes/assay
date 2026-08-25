"""Dangling-CNAME subdomain takeover detection.

Two independent conditions must both hold before this reports: the CNAME points
at a known third-party service, and the service answers with its own
'nothing is claimed here' page. Either alone is a false positive generator.
"""

from __future__ import annotations

import re
import subprocess
from typing import Dict, List, Optional, Tuple

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, Target
from assay.modules import Module, register

# provider -> (cname substring, body fingerprint)
FINGERPRINTS: List[Tuple[str, str, str]] = [
    ("GitHub Pages", "github.io", "There isn't a GitHub Pages site here"),
    ("Heroku", "herokuapp.com", "No such app"),
    ("AWS S3", "s3.amazonaws.com", "NoSuchBucket"),
    ("AWS S3 website", "s3-website", "NoSuchBucket"),
    ("Shopify", "myshopify.com", "Sorry, this shop is currently unavailable"),
    ("Fastly", "fastly.net", "Fastly error: unknown domain"),
    ("Pantheon", "pantheonsite.io", "The gods are wise"),
    ("Tumblr", "domains.tumblr.com", "Whatever you were looking for doesn't currently exist"),
    ("Ghost", "ghost.io", "Domain error"),
    ("Surge", "surge.sh", "project not found"),
    ("Bitbucket", "bitbucket.io", "Repository not found"),
    ("Zendesk", "zendesk.com", "Help Center Closed"),
    ("Unbounce", "unbouncepages.com", "The requested URL was not found on this server"),
    ("Readthedocs", "readthedocs.io", "unknown to Read the Docs"),
    ("Netlify", "netlify.app", "Not Found - Request ID"),
    ("Azure", "azurewebsites.net", "Error 404 - Web app not found"),
    ("Azure Traffic Manager", "trafficmanager.net", "Error 404 - Web app not found"),
    ("Cargo", "cargocollective.com", "404 Not Found"),
    ("Webflow", "proxy-ssl.webflow.com", "The page you are looking for doesn't exist"),
    ("Help Scout", "helpscoutdocs.com", "No settings were found for this company"),
]


def resolve_cname(host: str) -> str:
    """CNAME lookup via dig or host; returns '' when neither is available."""
    for cmd in (["dig", "+short", "CNAME", host], ["host", "-t", "CNAME", host]):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        if not out.strip():
            continue
        m = re.search(r"(?:alias for\s+)?([A-Za-z0-9_.-]+\.)\s*$", out.strip().splitlines()[-1])
        if m:
            return m.group(1).rstrip(".").lower()
    return ""


@register
class TakeoverModule(Module):
    name = "takeover"
    stage = "analyze"
    scope = "host"
    desc = "Dangling CNAME / subdomain takeover"

    def run_host(self, ctx: Context, target: Target) -> List[Finding]:
        host = target.host
        if target.is_ip:
            return []
        cname = resolve_cname(host)
        if not cname:
            return []
        provider = fingerprint = None
        for name, needle, body_sig in FINGERPRINTS:
            if needle in cname:
                provider, fingerprint = name, body_sig
                break
        if not provider:
            return []

        hit = None
        for scheme in ("https", "http"):
            r = ctx.http.get("%s://%s/" % (scheme, host))
            if r.ok and fingerprint.lower() in r.body[:20000].lower():
                hit = r
                break
        if hit is None:
            return []

        return [Finding(
            title="Subdomain takeover: dangling CNAME to %s" % provider,
            target=host,
            severity="high",
            confidence="confirmed",
            category=owasp.A05,
            cwe="CWE-350",
            module=self.name,
            impact=(
                "The DNS record still points at %s but no account there claims it, so "
                "anyone can register the name on that service and serve content from this "
                "hostname. That yields convincing phishing on a trusted domain, cookie "
                "access for any cookie scoped to the parent domain, and defeat of any CORS "
                "or CSP rule that trusts subdomains of the parent." % provider
            ),
            detail="CNAME %s -> %s; provider returned its unclaimed-resource page."
                   % (host, cname),
            repro="dig +short CNAME %s ; curl -sSik https://%s/" % (host, host),
            refs=["https://github.com/EdOverflow/can-i-take-over-xyz"],
            tags=["takeover", "verified"],
            chainable=True,
            evidence=[
                Evidence(kind="dns", label="CNAME chain", output="%s -> %s" % (host, cname)),
                hit.evidence(label="Provider unclaimed-resource page", matched=fingerprint),
            ],
            dedupe_key="takeover|%s" % host,
        )]
