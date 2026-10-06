"""Active confirmation of exposed services.

The port scan says a port is *open*; this module says what actually *answers*
on it. For every open TCP port it makes one read-only connection and records
whatever the service volunteers - a protocol banner (SSH, FTP, SMTP, POP3,
IMAP, MySQL, ...), an HTTP response line and Server header, or a TLS
certificate and negotiated version. A service is only listed as confirmed when
it returned something; a port that completes a TCP handshake but says nothing
is left to the raw nmap inventory rather than claimed as a running service.

This is inventory, not a finding: the output is a separate "confirmed services"
table in the report, sortable by host and by service, so a reviewer can see at
a glance which of the scanned ports are genuinely live and what version each
one reported. The vulnerability-bearing probes (anonymous Redis, open Docker
API, ...) stay in host_services; this module only proves liveness and identity.

Everything here is read-only: a plain connect-and-read for banners, an ordinary
GET for HTTP, and a handshake with no application data for TLS. The one place
bytes are sent to a silent service is a short, standard, protocol-correct nudge
(e.g. Redis PING), and that is skipped entirely under --safe.
"""

from __future__ import annotations

import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional

from assay import owasp
from assay.context import Context
from assay.modules import Module, register
from assay.models import Evidence, Finding

# Connect generously (an engagement host can be slow or far), but read briefly:
# a service that greets does so immediately, so a long read timeout only adds
# dead wait on the silent ones, of which there are always many.
_CONNECT_TIMEOUT = 6.0
_READ_TIMEOUT = 4.0
_BANNER_MAX = 2048

# nmap service names (and the odd product string) that mean "speak HTTP here".
_HTTP_SERVICES = {
    "http", "https", "http-alt", "https-alt", "http-proxy", "sip",
    "ssl/http", "http-mgmt", "soap", "upnp", "websocket",
}
# Ports we will try HTTP on even when nmap did not name the service, because
# they are overwhelmingly web and nmap sometimes only reports "tcpwrapped" or a
# bare "open" with no service detection.
_HTTP_PORTS = {80, 81, 88, 443, 591, 2080, 2443, 3000, 3128, 4443, 5000, 7001,
               8000, 8008, 8042, 8080, 8081, 8088, 8443, 8444, 8888, 9000,
               9080, 9443, 10000}
# Ports that strongly imply TLS even when nmap did not flag the tunnel.
_TLS_PORTS = {443, 465, 636, 853, 989, 990, 993, 995, 4443, 8443, 9443, 9093}

# Silent, request-first services where one standard, read-only line draws out a
# versioned reply. Only sent when not --safe. Kept deliberately tiny: these are
# protocol-correct health pokes, not crafted input.
_NUDGES: Dict[str, bytes] = {
    "redis": b"PING\r\n",
    "memcached": b"version\r\n",
    "memcache": b"version\r\n",
}

# Read-only next-step enumeration per confirmed service: a single standard
# command a hunter would run next. {host}/{port} are filled in. This is the
# baseline the report always shows; the AI pass proposes more on top of it
# (see ServiceConfirmModule - each confirmed non-web service is emitted as an
# info finding so AI triage returns enumeration commands for it too).
_ENUM: Dict[str, str] = {
    "ssh": "nmap -Pn -p{port} --script ssh2-enum-algos,ssh-auth-methods {host}",
    "ftp": "nmap -Pn -p{port} --script ftp-anon,ftp-syst {host}",
    "ftp-data": "nmap -Pn -p{port} --script ftp-anon,ftp-syst {host}",
    "smtp": "nmap -Pn -p{port} --script smtp-commands,smtp-open-relay,smtp-enum-users {host}",
    "smtps": "nmap -Pn -p{port} --script smtp-commands,smtp-open-relay {host}",
    "submission": "nmap -Pn -p{port} --script smtp-commands,smtp-open-relay {host}",
    "pop3": "nmap -Pn -p{port} --script pop3-capabilities {host}",
    "pop3s": "nmap -Pn -p{port} --script pop3-capabilities {host}",
    "imap": "nmap -Pn -p{port} --script imap-capabilities {host}",
    "imaps": "nmap -Pn -p{port} --script imap-capabilities {host}",
    "mysql": "nmap -Pn -p{port} --script mysql-info,mysql-empty-password {host}",
    "ms-sql-s": "nmap -Pn -p{port} --script ms-sql-info,ms-sql-ntlm-info {host}",
    "postgresql": "nmap -Pn -p{port} --script pgsql-brute --script-args 'brute.firstonly' {host}",
    "oracle-tns": "nmap -Pn -p{port} --script oracle-tns-version,oracle-sid-brute {host}",
    "redis": "redis-cli -h {host} -p {port} INFO server",
    "mongodb": "nmap -Pn -p{port} --script mongodb-info {host}",
    "telnet": "nmap -Pn -p{port} --script telnet-encryption,banner {host}",
    "ldap": "nmap -Pn -p{port} --script ldap-rootdse {host}",
    "ldaps": "nmap -Pn -p{port} --script ldap-rootdse {host}",
    "ldapssl": "nmap -Pn -p{port} --script ldap-rootdse {host}",
    "microsoft-ds": "nmap -Pn -p{port} --script smb-os-discovery,smb-enum-shares,smb2-security-mode {host}",
    "netbios-ssn": "nmap -Pn -p{port} --script smb-os-discovery,smb-enum-shares {host}",
    "ms-wbt-server": "nmap -Pn -p{port} --script rdp-ntlm-info,rdp-enum-encryption {host}",
    "vnc": "nmap -Pn -p{port} --script vnc-info,realvnc-auth-bypass {host}",
    "rsync": "rsync --list-only rsync://{host}:{port}/",
    "snmp": "snmpwalk -v2c -c public {host}",
    "rpcbind": "rpcinfo -p {host}",
    "nfs": "showmount -e {host}",
    "memcached": "nmap -Pn -p{port} --script memcached-info {host}",
    "memcache": "nmap -Pn -p{port} --script memcached-info {host}",
    # UDP services (nmap's -sU service names).
    "domain": "nmap -Pn -sU -p{port} --script dns-recursion,dns-nsid {host}",
    "ntp": "nmap -Pn -sU -p{port} --script ntp-info,ntp-monlist {host}",
    "snmp": "snmpwalk -v2c -c public {host}",
    "upnp": "nmap -Pn -sU -p{port} --script upnp-info {host}",
    "ssdp": "nmap -Pn -sU -p{port} --script upnp-info {host}",
    "mdns": "nmap -Pn -sU -p{port} --script dns-service-discovery {host}",
    "zeroconf": "nmap -Pn -sU -p{port} --script dns-service-discovery {host}",
    "tftp": "nmap -Pn -sU -p{port} --script tftp-enum {host}",
    "netbios-ns": "nmap -Pn -sU -p{port} --script nbstat {host}",
    "isakmp": "ike-scan {host}",
    "ike": "ike-scan {host}",
    "asf-rmcp": "nmap -Pn -sU -p{port} --script ipmi-version,ipmi-cipher-zero {host}",
    "ipmi": "nmap -Pn -sU -p{port} --script ipmi-version,ipmi-cipher-zero {host}",
    "ms-sql-m": "nmap -Pn -sU -p{port} --script ms-sql-dac {host}",
}


def _enum_for(service: str, host: str, port: int, proto: str = "tcp") -> str:
    default = ("nmap -Pn -sU -p{port} {host}" if proto == "udp"
               else "nmap -Pn -sV -p{port} --script banner {host}")
    tmpl = _ENUM.get((service or "").lower(), default)
    return tmpl.format(host=host, port=port)


def _udp_banner(data: bytes) -> str:
    """A printable rendering of a UDP reply: the text if it is mostly
    printable (SSDP, mDNS names), otherwise a short hex preview."""
    if not data:
        return ""
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    if printable >= len(data) * 0.8:
        return data.decode("utf-8", "replace").strip()[:_BANNER_MAX]
    return "%d-byte reply (hex: %s%s)" % (
        len(data), data[:48].hex(), "..." if len(data) > 48 else "")


# -- raw probes (module-level so tests can substitute them offline) ---------
#
# The test harness stubs HTTP with a canned-route client but never opens a
# socket; these two functions are the only things in the module that touch the
# network at the socket layer, so a test monkeypatches them to feed fixtures.

def _grab_banner(host: str, port: int, nudge: Optional[bytes] = None) -> bytes:
    """Connect, read any unprompted greeting, and - if asked and nothing came
    back - send one short nudge and read again. Returns raw bytes (possibly
    empty). Never raises."""
    try:
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as s:
            s.settimeout(_READ_TIMEOUT)
            data = b""
            try:
                data = s.recv(_BANNER_MAX)
            except (OSError, socket.timeout):
                data = b""
            if not data and nudge:
                try:
                    s.sendall(nudge)
                    data = s.recv(_BANNER_MAX)
                except (OSError, socket.timeout):
                    data = b""
            return data or b""
    except OSError:
        return b""


def _udp_probe(host: str, port: int, payload: bytes) -> bytes:
    """Send one protocol-correct datagram and wait briefly for a reply. A reply
    is the confirmation - UDP has no handshake, so silence (or an ICMP
    port-unreachable, surfaced as an OSError) means 'not answering'. Never
    raises."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(_READ_TIMEOUT)
        s.sendto(payload, (host, port))
        data, _ = s.recvfrom(_BANNER_MAX)
        return data or b""
    except OSError:
        return b""
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


# Standard, read-only UDP service queries, keyed by port. Each is a function of
# the target address (SSDP/mDNS need it in the datagram). A reply to any of
# these confirms the service; the payloads are the same fingerprinting queries
# every UDP scanner sends.
def _dns_version_query(_addr: str) -> bytes:
    # Standard query, RD set, for version.bind CHAOS TXT.
    return (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x07version\x04bind\x00\x00\x10\x00\x03")


def _ntp_client(_addr: str) -> bytes:
    return b"\x1b" + b"\x00" * 47          # LI=0 VN=3 Mode=3 (client)


def _snmp_get_sysdescr(_addr: str) -> bytes:
    # SNMPv1 GET-request for sysDescr.0, community "public".
    return bytes.fromhex(
        "302902010004067075626c6963a01c020400000001020100020100"
        "300e300c06082b060102010101000500")


def _ssdp_msearch(addr: str) -> bytes:
    return ("M-SEARCH * HTTP/1.1\r\nHOST: %s:1900\r\n"
            "MAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
            % addr).encode("ascii", "replace")


def _mdns_services(_addr: str) -> bytes:
    return (b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01")


def _memcached_udp_version(_addr: str) -> bytes:
    return b"\x00\x00\x00\x00\x00\x01\x00\x00version\r\n"


_UDP_PROBES = {
    53: _dns_version_query,
    123: _ntp_client,
    161: _snmp_get_sysdescr,
    1900: _ssdp_msearch,
    5353: _mdns_services,
    11211: _memcached_udp_version,
}


def _grab_tls(host: str, port: int) -> Dict:
    """Handshake only (no application data) and report the certificate and the
    negotiated version. Reuses the host-deep TLS cert grabber so verification
    is disabled the same way everywhere. Returns {} on any failure."""
    from assay.modules.tls import fetch_cert
    cert, version = fetch_cert(host, port, timeout=_CONNECT_TIMEOUT)
    if not cert and not version:
        return {}
    out: Dict = {"version": version}
    if cert:
        subject = dict(x[0] for x in cert.get("subject", []) if x)
        issuer = dict(x[0] for x in cert.get("issuer", []) if x)
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        out.update({
            "cn": subject.get("commonName", ""),
            "issuer": issuer.get("commonName", "") or issuer.get("organizationName", ""),
            "san": sans[:12],
            "not_after": cert.get("notAfter", ""),
        })
    return out


def _text(data: bytes) -> str:
    return data.decode("utf-8", "replace").strip()


def _first_line(s: str, limit: int = 160) -> str:
    line = s.splitlines()[0] if s else ""
    return line[:limit]


@register
class ServiceConfirmModule(Module):
    name = "confirm"
    stage = "probe"
    scope = "global"
    impact_class = "read"
    desc = "Active confirmation of exposed services (banner / version / headers)"

    def run_global(self, ctx: Context) -> List[Finding]:
        jobs = []  # (host, ip, Port)
        for t in ctx.targets:
            if t.kind == "url":
                continue
            host = t.ip or t.host
            if not ctx.cfg.scope.allows(host):
                continue
            for p in t.ports:
                if ctx.cfg.is_proxied_port(p.port):
                    continue
                if p.proto == "tcp":
                    if p.state not in ("open", ""):
                        continue
                elif p.proto == "udp":
                    # open|filtered is UDP's "no reply yet" - still worth an
                    # active probe, which can turn it into a real confirmation.
                    if p.state not in ("open", "open|filtered"):
                        continue
                else:
                    continue
                jobs.append((t.host, t.ip or "", p))
        if not jobs:
            return []

        ctx.say("confirm", "confirming %d open port(s) across %d host(s)"
                % (len(jobs), len({j[0] for j in jobs})))

        workers = max(4, min(int(ctx.tune.get("concurrency", 8)) * 4, 32))
        records: List[Dict] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(self._confirm_one, ctx, h, ip, p): (h, p)
                    for (h, ip, p) in jobs}
            for fut in as_completed(futs):
                try:
                    rec = fut.result()
                except Exception:   # a single bad port must not sink the sweep
                    rec = None
                if rec:
                    records.append(rec)

        # Sorted by host then port on the way out so the report's default view
        # is stable even before anyone clicks a column header.
        records.sort(key=lambda r: (r["host"], r["ip"], r["port"]))
        self._write(ctx, records, scanned=len(jobs))
        ctx.say("confirm", "%d of %d open port(s) returned a service response"
                % (len(records), len(jobs)))

        # Every confirmed non-web service becomes a low-noise info finding so it
        # flows through the normal pipeline: the AI pass triages it and proposes
        # enumeration commands, and the report renders those AI steps on the
        # card like any other finding. Web services are left out - the web
        # modules and the live-endpoints table already cover them.
        return [self._finding(r) for r in records
                if r.get("method") in ("banner", "tls", "udp", "udp-scan")]

    def _finding(self, r: Dict) -> Finding:
        where = "%s:%d" % (r["host"], r["port"])
        svc = r.get("service") or "service"
        live = r.get("summary") or r.get("detail") or ""
        nmap_ver = " ".join(x for x in (r.get("product"), r.get("version")) if x)
        detail = live
        if nmap_ver:
            detail = (live + "  (nmap: %s)" % nmap_ver) if live else "nmap: " + nmap_ver
        ev_out = r.get("banner") or r.get("detail") or live
        return Finding(
            title="%s confirmed on %s/%d" % (svc, r["proto"], r["port"]),
            target=where,
            severity="info",
            confidence="confirmed",
            category=owasp.HOST,
            cwe="",
            module=self.name,
            impact=("Service confirmed live and responding without authentication - "
                    "it reported: %s. Not a vulnerability on its own; listed so its "
                    "unauthenticated attack surface is enumerated rather than assumed."
                    % (live or "a response")),
            detail=detail,
            repro=r.get("enum") or r.get("repro") or "",
            tags=["host", "service", "confirmed-service", "verified"],
            evidence=[Evidence(kind="command", label="%s on %s" % (svc, where),
                               request=r.get("repro", ""), output=(ev_out or "")[:1200])],
            dedupe_key="confirmed|%s|%s|%d" % (r["host"], r["proto"], r["port"]),
        )

    # ------------------------------------------------------------------
    def _confirm_one(self, ctx: Context, host: str, ip: str, port) -> Optional[Dict]:
        addr = ip or host
        base = {
            "host": host, "ip": ip, "port": port.port, "proto": port.proto,
            "service": port.service or "", "product": port.product or "",
            "version": port.version or "",
            "enum": _enum_for(port.service, addr, port.port, port.proto),
        }
        if port.proto == "udp":
            return self._confirm_udp(ctx, addr, port, base)

        is_tls = port.is_tls or port.port in _TLS_PORTS
        is_http = (port.service in _HTTP_SERVICES or port.port in _HTTP_PORTS
                   or "http" in (port.product or "").lower())

        # TLS first: the handshake both confirms the port and yields the cert,
        # and tells us the scheme to use if HTTP also lives here.
        tls = _grab_tls(addr, port.port) if is_tls else {}

        if is_http or is_tls:
            rec = self._confirm_http(ctx, addr, port, prefer_tls=is_tls or bool(tls))
            if rec:
                rec.update(base)
                if tls:
                    rec["tls"] = tls
                    rec["method"] = "tls+http"   # HTTPS: cert AND an HTTP answer
                    rec["detail"] = self._join(rec.get("detail", ""), self._tls_detail(tls))
                return rec

        # A bare TLS service that is not HTTP (LDAPS, SMTPS, a mail port) is
        # still confirmed by its certificate alone.
        if tls:
            summary = self._tls_detail(tls)
            return dict(base, method="tls", confirmed=True,
                        summary=summary, detail=summary,
                        banner="", server="", status=0, title="", tls=tls,
                        repro="openssl s_client -connect %s:%d </dev/null"
                              % (addr, port.port))

        # Everything else: read a protocol banner off the raw socket.
        nudge = None if ctx.cfg.safe_mode else _NUDGES.get(port.service)
        raw = _grab_banner(addr, port.port, nudge=nudge)
        if not raw:
            return None   # open but silent - not a confirmed, responding service
        banner = _text(raw)
        line = _first_line(banner)
        return dict(base, method="banner", confirmed=True,
                    summary=line or "(returned %d bytes)" % len(raw),
                    detail=line, banner=banner[:_BANNER_MAX], server="",
                    status=0, title="",
                    repro="nc %s %d" % (addr, port.port))

    def _confirm_udp(self, ctx: Context, addr: str, port, base: Dict) -> Optional[Dict]:
        """Confirm a UDP service. First by sending its own standard query and
        reading the reply (the real confirmation); failing that, by trusting
        nmap's own result - a UDP port nmap reports plainly 'open' (not
        'open|filtered') answered nmap's protocol probe, which is itself a
        received response. An 'open|filtered' port with no reply here is not
        claimed."""
        nmap_ver = " ".join(x for x in (port.product, port.version) if x)
        probe = _UDP_PROBES.get(port.port)
        if probe is not None and not ctx.cfg.safe_mode:
            reply = _udp_probe(addr, port.port, probe(addr))
            if reply:
                shown = _udp_banner(reply)
                summary = shown or "UDP reply (%d bytes)" % len(reply)
                return dict(base, method="udp", confirmed=True,
                            summary=summary,
                            detail=self._join(shown, "nmap: " + nmap_ver if nmap_ver else ""),
                            banner=shown, server="", status=0, title="",
                            repro="%s  # protocol query, expect a reply"
                                  % base.get("enum", "nmap -sU -p%d %s" % (port.port, addr)))

        if port.state == "open":
            summary = ("responded to nmap's UDP probe"
                       + (" · " + nmap_ver if nmap_ver else ""))
            return dict(base, method="udp-scan", confirmed=True,
                        summary=summary, detail=summary, banner="",
                        server="", status=0, title="",
                        repro="nmap -Pn -sUV -p%d %s" % (port.port, addr))
        return None   # open|filtered, no reply - ambiguous, not confirmed

    def _confirm_http(self, ctx: Context, addr: str, port, prefer_tls: bool) -> Optional[Dict]:
        schemes = ("https", "http") if prefer_tls else ("http", "https")
        for scheme in schemes:
            url = "%s://%s:%d/" % (scheme, addr, port.port)
            r = ctx.http.get(url)
            if not getattr(r, "ok", False) or r.status <= 0:
                continue
            server = r.header("Server")
            title = r.title
            bits = ["HTTP %d" % r.status]
            if server:
                bits.append(server)
            if title:
                bits.append('"%s"' % title)
            return dict(method="http", confirmed=True,
                        summary=" \u00b7 ".join(bits),
                        detail=r.response_text(body_limit=0),
                        banner="", server=server, status=r.status, title=title,
                        url=url, repro="curl -sSIk %s" % url)
        return None

    @staticmethod
    def _tls_detail(tls: Dict) -> str:
        bits = []
        if tls.get("version"):
            bits.append(tls["version"])
        if tls.get("cn"):
            bits.append("CN=%s" % tls["cn"])
        if tls.get("issuer"):
            bits.append("issuer %s" % tls["issuer"])
        return " \u00b7 ".join(bits) or "TLS handshake succeeded"

    @staticmethod
    def _join(a: str, b: str) -> str:
        a, b = (a or "").strip(), (b or "").strip()
        return (a + ("\n" if a and b else "") + b) if (a or b) else ""

    def _write(self, ctx: Context, records: List[Dict], scanned: int) -> None:
        doc = {"scanned": scanned, "confirmed": len(records), "items": records}
        raw_dir = os.path.join(ctx.cfg.out_dir, "raw")
        try:
            os.makedirs(raw_dir, exist_ok=True)
            with open(os.path.join(raw_dir, "confirmed-services.json"), "w",
                     encoding="utf-8") as fh:
                json.dump(doc, fh, indent=2)
        except OSError:
            pass
