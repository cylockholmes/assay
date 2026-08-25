"""Certificate and TLS transport checks using the standard library only."""

from __future__ import annotations

import datetime
import socket
import ssl
from typing import List, Optional, Tuple

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, Target
from assay.modules import Module, register


def fetch_cert(host: str, port: int, timeout: float = 8.0) -> Tuple[Optional[dict], str]:
    """Grab the certificate without validating it, plus the negotiated version."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                version = ss.version() or ""
        if not der:
            return None, version
        # getpeercert() returns {} when verification is disabled, so decode the DER.
        return _decode(der), version
    except (OSError, ssl.SSLError, ValueError):
        return None, ""


def _decode(der: bytes) -> Optional[dict]:
    import tempfile
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(pem)
            path = fh.name
        try:
            return ssl._ssl._test_decode_cert(path)
        finally:
            import os
            try:
                os.unlink(path)
            except OSError:
                pass
    except (ssl.SSLError, ValueError, AttributeError, OSError):
        return None


def supports_protocol(host: str, port: int, proto) -> bool:
    ctx = ssl.SSLContext(proto)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (AttributeError, ValueError):
        pass
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (OSError, ssl.SSLError, ValueError):
        return False


@register
class TlsModule(Module):
    name = "tls"
    stage = "analyze"
    scope = "host"
    desc = "Certificate validity and legacy TLS protocol support"

    def run_host(self, ctx: Context, target: Target) -> List[Finding]:
        host = target.host
        out: List[Finding] = []
        for port in target.ports:
            if not (port.is_tls or port.port in (443, 8443, 9443, 4443, 993, 995, 465)):
                continue
            out.extend(self._check(ctx, host, port.port))
        return out

    def _check(self, ctx: Context, host: str, port: int) -> List[Finding]:
        cert, version = fetch_cert(host, port)
        out: List[Finding] = []
        where = "%s:%d" % (host, port)
        if cert:
            out.extend(self._cert_findings(host, port, cert))

        # Legacy protocol support is a common compliance-driven report.
        legacy = []
        for name, proto in (("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1", None)),
                            ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None))):
            if proto is None:
                continue
            if supports_protocol(host, port, proto):
                legacy.append(name)
        if legacy:
            out.append(Finding(
                title="Legacy TLS versions accepted: %s" % ", ".join(legacy),
                target=where,
                severity="low",
                confidence="confirmed",
                category=owasp.A02,
                cwe="CWE-327",
                module=self.name,
                impact=(
                    "Deprecated TLS versions remain negotiable, so a network-positioned "
                    "attacker can downgrade a client that still offers them. Usually "
                    "accepted only as a compliance finding unless you can also show a "
                    "client that negotiates it."
                ),
                repro="openssl s_client -connect %s:%d -tls1_1" % (host, port),
                tags=["tls", "verified", "noise-prone"],
                evidence=[Evidence(kind="tls", label="handshake",
                                   output="Accepted: %s (current default: %s)"
                                          % (", ".join(legacy), version))],
                dedupe_key="tls-legacy|%s" % where,
            ))
        return out

    def _cert_findings(self, host: str, port: int, cert: dict) -> List[Finding]:
        out: List[Finding] = []
        where = "%s:%d" % (host, port)
        subject = dict(x[0] for x in cert.get("subject", []) if x)
        issuer = dict(x[0] for x in cert.get("issuer", []) if x)
        cn = subject.get("commonName", "")
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days = (exp - datetime.datetime.utcnow()).days
                if days < 0:
                    out.append(Finding(
                        title="TLS certificate expired %d days ago" % abs(days),
                        target=where,
                        severity="low",
                        confidence="confirmed",
                        category=owasp.A02,
                        cwe="CWE-298",
                        module=self.name,
                        impact=(
                            "Users are trained to click through the browser warning, which "
                            "removes the signal that would otherwise reveal an interception "
                            "attempt against this host."
                        ),
                        repro="openssl s_client -connect %s:%d | openssl x509 -noout -dates"
                              % (host, port),
                        tags=["tls", "verified"],
                        evidence=[Evidence(kind="tls", label="certificate",
                                           output="CN=%s notAfter=%s" % (cn, not_after))],
                        dedupe_key="tls-expired|%s" % where,
                    ))
            except (ValueError, TypeError):
                pass

        if issuer and issuer == subject:
            out.append(Finding(
                title="Self-signed TLS certificate",
                target=where,
                severity="low",
                confidence="confirmed",
                category=owasp.A02,
                cwe="CWE-295",
                module=self.name,
                impact=(
                    "No chain of trust, so clients cannot distinguish this host from an "
                    "interception proxy. Materially serious only where a machine client "
                    "connects here and has certificate validation disabled to cope."
                ),
                repro="openssl s_client -connect %s:%d" % (host, port),
                tags=["tls", "verified", "noise-prone"],
                evidence=[Evidence(kind="tls", label="certificate",
                                   output="subject == issuer: CN=%s" % cn)],
                dedupe_key="tls-selfsigned|%s" % where,
            ))

        # SANs are recon gold: they name sibling hosts that are in scope.
        extra = [s for s in sans if s.lower() not in (host.lower(), "*." + host.lower())]
        if len(extra) > 1:
            out.append(Finding(
                title="Certificate SANs disclose %d additional hostnames" % len(extra),
                target=where,
                severity="info",
                confidence="confirmed",
                category=owasp.INFO,
                cwe="",
                module=self.name,
                impact=(
                    "Not a vulnerability. These names are additional attack surface that "
                    "may be in scope and are often internal-only hosts that were never "
                    "meant to be enumerable - feed them back into the scan."
                ),
                repro="openssl s_client -connect %s:%d | openssl x509 -noout -text | grep DNS:"
                      % (host, port),
                tags=["tls", "recon"],
                evidence=[Evidence(kind="tls", label="subjectAltName",
                                   output="\n".join(extra[:40]))],
                dedupe_key="tls-sans|%s" % where,
            ))
        return out
