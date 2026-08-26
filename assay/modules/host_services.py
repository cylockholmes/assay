"""Host-side triage: exposed services that are interesting without credentials.

Where a service can be safely proven unauthenticated with one read-only
request, this module proves it (Redis PING, Elasticsearch /_cluster/health,
Docker /version, kubelet /pods). Where it cannot, the finding stays tentative
and says exactly which manual step would confirm it, rather than claiming a
vulnerability from a port number.
"""

from __future__ import annotations

import json
import socket
from typing import Dict, List, Optional

from assay import owasp
from assay.context import Context
from assay.models import Evidence, Finding, Port, Target
from assay.modules import Module, register

# Services that are noteworthy purely by being reachable, with the manual step
# that turns each into a demonstrable finding.
NOTEWORTHY: Dict[str, Dict] = {
    "mongodb": dict(sev="high", cwe="CWE-306", cat=owasp.HOST,
                    impact="MongoDB reachable. If it accepts an unauthenticated "
                           "connection every database is readable and writable.",
                    step="mongosh --host TARGET --eval 'db.adminCommand({listDatabases:1})'"),
    "mysql": dict(sev="medium", cwe="CWE-668", cat=owasp.HOST,
                  impact="Database port exposed to the testing network. Value depends "
                         "on whether it is meant to be internal-only.",
                  step="mysql -h TARGET -u root  (check for blank/default credentials)"),
    "ms-sql-s": dict(sev="medium", cwe="CWE-668", cat=owasp.HOST,
                     impact="Microsoft SQL Server exposed.",
                     step="impacket-mssqlclient -windows-auth TARGET"),
    "postgresql": dict(sev="medium", cwe="CWE-668", cat=owasp.HOST,
                       impact="PostgreSQL exposed.",
                       step="psql -h TARGET -U postgres  (check trust auth)"),
    "oracle-tns": dict(sev="medium", cwe="CWE-668", cat=owasp.HOST,
                       impact="Oracle TNS listener exposed.",
                       step="odat all -s TARGET"),
    "telnet": dict(sev="medium", cwe="CWE-319", cat=owasp.A02,
                   impact="Telnet transmits credentials in cleartext and is trivially "
                          "captured by anyone on the path.",
                   step="nc TARGET 23  (record the banner and any login prompt)"),
    "ftp": dict(sev="medium", cwe="CWE-306", cat=owasp.HOST,
                impact="FTP exposed. Anonymous access, if enabled, is a direct file "
                       "disclosure and sometimes a write primitive.",
                step="ftp TARGET  then log in as 'anonymous'"),
    "vnc": dict(sev="high", cwe="CWE-306", cat=owasp.HOST,
                impact="VNC reachable. Without authentication this is interactive "
                       "desktop access.",
                step="vncviewer TARGET  (check whether auth is required)"),
    "ms-wbt-server": dict(sev="low", cwe="CWE-1392", cat=owasp.HOST,
                          impact="RDP exposed. Check whether NLA is enforced; without "
                                 "it the host is exposed to credential attacks.",
                          step="nmap --script rdp-ntlm-info,rdp-enum-encryption -p3389 TARGET"),
    "microsoft-ds": dict(sev="low", cwe="CWE-306", cat=owasp.HOST,
                         impact="SMB exposed. Check signing enforcement and null-session "
                                "share enumeration.",
                         step="nmap --script smb2-security-mode,smb-enum-shares -p445 TARGET"),
    "rsync": dict(sev="high", cwe="CWE-306", cat=owasp.HOST,
                  impact="rsync daemon reachable. Listable modules frequently allow "
                         "unauthenticated read of entire filesystems.",
                  step="rsync rsync://TARGET/"),
    "ldap": dict(sev="medium", cwe="CWE-306", cat=owasp.HOST,
                 impact="LDAP exposed. Anonymous bind exposes the full directory "
                        "including user accounts.",
                 step="ldapsearch -x -H ldap://TARGET -s base namingcontexts"),
    "smtp": dict(sev="low", cwe="CWE-305", cat=owasp.HOST,
                 impact="SMTP exposed. Check for open relay and VRFY user enumeration.",
                 step="nmap --script smtp-open-relay,smtp-enum-users -p25 TARGET"),
    "java-rmi": dict(sev="high", cwe="CWE-502", cat=owasp.A08,
                     impact="Java RMI registry exposed - historically a direct "
                            "deserialization-to-RCE path.",
                     step="nmap --script rmi-dumpregistry -p PORT TARGET"),
    "jdwp": dict(sev="critical", cwe="CWE-489", cat=owasp.A05,
                 impact="Java Debug Wire Protocol is unauthenticated by design; "
                        "reaching it is remote code execution.",
                 step="jdwp-shellifier.py -t TARGET -p PORT"),
}


@register
class ServiceTriageModule(Module):
    name = "services"
    stage = "analyze"
    scope = "host"
    impact_class = "probe"
    desc = "Exposed network services worth manual attention"

    def run_host(self, ctx: Context, target: Target) -> List[Finding]:
        out: List[Finding] = []
        host = target.ip or target.host
        for port in target.ports:
            probed = self._probe(ctx, host, port)
            if probed:
                out.append(probed)
                continue
            rule = NOTEWORTHY.get(port.service)
            if not rule:
                continue
            out.append(Finding(
                title="%s exposed on %d/%s" % (port.service, port.port, port.proto),
                target="%s:%d" % (host, port.port),
                severity=rule["sev"],
                confidence="tentative",
                category=rule["cat"],
                cwe=rule["cwe"],
                module=self.name,
                impact=rule["impact"],
                detail="nmap: %s %s %s" % (port.service, port.product, port.version),
                repro=rule["step"].replace("TARGET", host).replace("PORT", str(port.port)),
                tags=["host", "manual-followup"],
                evidence=[Evidence(kind="command", label="service detection",
                                   output="%d/%s %s %s %s" % (port.port, port.proto,
                                                              port.service, port.product,
                                                              port.version))],
                dedupe_key="svc|%s|%d" % (host, port.port),
            ))
        return out

    # -- active, read-only confirmations ---------------------------------
    def _probe(self, ctx: Context, host: str, port: Port) -> Optional[Finding]:
        if port.service in ("redis",) or port.port == 6379:
            return self._redis(ctx, host, port)
        if port.port == 11211 or port.service == "memcached":
            return self._memcached(ctx, host, port)
        if port.port in (9200, 9201) or "elastic" in (port.product or "").lower():
            return self._http_json(ctx, host, port, "/_cluster/health",
                                   ['"cluster_name"', '"status"'],
                                   "Elasticsearch cluster readable without authentication",
                                   "critical",
                                   "Unauthenticated Elasticsearch. Every index is readable "
                                   "via /_all/_search and, unless the cluster is read-only, "
                                   "writable and deletable. Retrieve one document to "
                                   "demonstrate data exposure, then stop.")
        if port.port in (2375, 2376):
            return self._http_json(ctx, host, port, "/version",
                                   ['"ApiVersion"', '"Os"'],
                                   "Docker Engine API exposed without TLS/auth",
                                   "critical",
                                   "The Docker API grants container creation with host "
                                   "filesystem mounts, which is root on the host. Prove it "
                                   "with GET /containers/json and stop - do not create "
                                   "containers.")
        if port.port == 10250:
            return self._http_json(ctx, host, port, "/pods",
                                   ['"kind"', '"PodList"'],
                                   "Kubelet read-only API exposed",
                                   "high",
                                   "The kubelet API discloses every pod spec on the node, "
                                   "including environment variables holding secrets; on "
                                   "misconfigured nodes /run permits command execution "
                                   "inside pods.")
        if port.port in (8888, 8889):
            return self._http_json(ctx, host, port, "/api/kernels", ["["],
                                   "Jupyter API reachable without a token",
                                   "critical",
                                   "An unauthenticated Jupyter server executes arbitrary "
                                   "Python as the service account - remote code execution.")
        return None

    def _redis(self, ctx: Context, host: str, port: Port) -> Optional[Finding]:
        if not ctx.cfg.scope.allows(host):
            return None
        try:
            with socket.create_connection((host, port.port), timeout=6) as s:
                s.sendall(b"PING\r\n")
                data = s.recv(128).decode("utf-8", "replace")
                if "+PONG" not in data:
                    return None
                s.sendall(b"INFO server\r\n")
                info = s.recv(2048).decode("utf-8", "replace")
        except OSError:
            return None
        return Finding(
            title="Redis reachable without authentication",
            target="%s:%d" % (host, port.port),
            severity="critical",
            confidence="confirmed",
            category=owasp.HOST,
            cwe="CWE-306",
            module=self.name,
            impact=(
                "An unauthenticated Redis instance exposes all cached data - commonly "
                "session tokens, which is instant account takeover - and its CONFIG SET "
                "command is a well-known path to writing files (authorized_keys, cron, "
                "webshells) and from there to code execution as the redis user."
            ),
            detail="PING returned +PONG with no AUTH.",
            repro="redis-cli -h %s -p %d ping" % (host, port.port),
            refs=["https://redis.io/docs/latest/operate/oss_and_stack/management/security/"],
            tags=["host", "verified"],
            evidence=[Evidence(kind="command", label="Redis PING/INFO",
                               request="PING\\r\\nINFO server",
                               output=info[:600])],
            dedupe_key="redis|%s|%d" % (host, port.port),
        )

    def _memcached(self, ctx: Context, host: str, port: Port) -> Optional[Finding]:
        if not ctx.cfg.scope.allows(host):
            return None
        try:
            with socket.create_connection((host, port.port), timeout=6) as s:
                s.sendall(b"stats\r\n")
                data = s.recv(2048).decode("utf-8", "replace")
        except OSError:
            return None
        if "STAT " not in data:
            return None
        return Finding(
            title="Memcached reachable without authentication",
            target="%s:%d" % (host, port.port),
            severity="high",
            confidence="confirmed",
            category=owasp.HOST,
            cwe="CWE-306",
            module=self.name,
            impact=(
                "Cached objects are readable and writable by anyone who can reach the "
                "port. Applications routinely cache session data and query results here, "
                "so this is both a data disclosure and a cache-poisoning primitive."
            ),
            repro="echo stats | nc %s %d" % (host, port.port),
            tags=["host", "verified"],
            evidence=[Evidence(kind="command", label="memcached stats", output=data[:600])],
            dedupe_key="memcached|%s|%d" % (host, port.port),
        )

    def _http_json(self, ctx: Context, host: str, port: Port, path: str,
                   needles: List[str], title: str, sev: str,
                   impact: str) -> Optional[Finding]:
        for scheme in ("https", "http") if port.is_tls else ("http", "https"):
            url = "%s://%s:%d%s" % (scheme, host, port.port, path)
            r = ctx.http.get(url)
            if not r.ok or r.status != 200:
                continue
            if not all(n in r.body[:8000] for n in needles):
                continue
            return Finding(
                title=title,
                target=url,
                severity=sev,
                confidence="confirmed",
                category=owasp.HOST,
                cwe="CWE-306",
                module=self.name,
                impact=impact,
                repro=r.curl(),
                tags=["host", "verified"],
                evidence=[r.evidence(label="Unauthenticated API response")],
                dedupe_key="svcapi|%s|%d|%s" % (host, port.port, path),
            )
        return None
