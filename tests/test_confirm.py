"""Offline tests for the service-confirmation module and its report section.

No socket is opened: the two network primitives (_grab_banner, _grab_tls) are
module globals, substituted here with fixtures, and HTTP goes through the
canned-route stub client.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from tests.stub import make_ctx
from assay.models import Port, Target
from assay.modules import host_confirm as hc


def _ctx_with_ports(ports, out_dir):
    ctx, http = make_ctx([])          # every HTTP GET hits the 200 HTML catch-all
    ctx.cfg.out_dir = out_dir
    ctx.targets = [Target(raw="10.0.0.9", host="10.0.0.9", ip="10.0.0.9",
                          kind="host", ports=ports)]
    return ctx, http


class ConfirmTests(unittest.TestCase):
    def setUp(self):
        self._orig = (hc._grab_banner, hc._grab_tls)

    def tearDown(self):
        hc._grab_banner, hc._grab_tls = self._orig

    def test_banner_service_is_confirmed_and_becomes_a_finding(self):
        ports = [Port(port=22, service="ssh")]
        hc._grab_banner = lambda host, port, nudge=None: b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"
        hc._grab_tls = lambda host, port: {}
        with tempfile.TemporaryDirectory() as d:
            ctx, _ = _ctx_with_ports(ports, d)
            findings = hc.ServiceConfirmModule().run_global(ctx)
            doc = json.load(open(os.path.join(d, "raw", "confirmed-services.json")))

        self.assertEqual(doc["confirmed"], 1)
        rec = doc["items"][0]
        self.assertEqual(rec["method"], "banner")
        self.assertIn("OpenSSH_8.9p1", rec["summary"])
        self.assertIn("ssh2-enum-algos", rec["enum"])       # per-service next step

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "info")
        self.assertEqual(f.confidence, "confirmed")
        self.assertIn("ssh2-enum-algos", f.repro)           # enum command on the card
        self.assertTrue(f.evidence and "OpenSSH" in f.evidence[0].output)

    def test_open_but_silent_port_is_not_confirmed(self):
        ports = [Port(port=2222, service="ssh")]
        hc._grab_banner = lambda host, port, nudge=None: b""   # connects, says nothing
        hc._grab_tls = lambda host, port: {}
        with tempfile.TemporaryDirectory() as d:
            ctx, _ = _ctx_with_ports(ports, d)
            findings = hc.ServiceConfirmModule().run_global(ctx)
            doc = json.load(open(os.path.join(d, "raw", "confirmed-services.json")))
        self.assertEqual(doc["confirmed"], 0)
        self.assertEqual(findings, [])

    def test_http_service_confirmed_but_not_emitted_as_finding(self):
        # The web pipeline already owns HTTP, so an http-confirmed port lands in
        # the table but must not also become a host finding.
        ports = [Port(port=8080, service="http")]
        hc._grab_banner = lambda host, port, nudge=None: b""
        hc._grab_tls = lambda host, port: {}
        with tempfile.TemporaryDirectory() as d:
            ctx, _ = _ctx_with_ports(ports, d)
            findings = hc.ServiceConfirmModule().run_global(ctx)
            doc = json.load(open(os.path.join(d, "raw", "confirmed-services.json")))
        self.assertEqual(doc["confirmed"], 1)
        self.assertEqual(doc["items"][0]["method"], "http")
        self.assertEqual(findings, [])

    def test_tls_only_service_confirmed_by_certificate(self):
        ports = [Port(port=636, service="ldaps")]
        hc._grab_banner = lambda host, port, nudge=None: b""
        hc._grab_tls = lambda host, port: {"version": "TLSv1.3",
                                           "cn": "dc01.corp.test",
                                           "issuer": "corp-CA", "san": []}
        # A real HTTP GET to an LDAPS port errors out; model that so the probe
        # falls through to the certificate branch rather than the stub's
        # answer-everything catch-all.
        def fail_636(m, url, h, b):
            return (0, {}, "") if ":636/" in url else None
        with tempfile.TemporaryDirectory() as d:
            ctx, http = _ctx_with_ports(ports, d)
            http.routes = [fail_636]
            findings = hc.ServiceConfirmModule().run_global(ctx)
            doc = json.load(open(os.path.join(d, "raw", "confirmed-services.json")))
        rec = doc["items"][0]
        self.assertEqual(rec["method"], "tls")
        self.assertIn("dc01.corp.test", rec["summary"])
        self.assertEqual(len(findings), 1)                  # tls-only is enumerable
        self.assertIn("ldap-rootdse", findings[0].repro)

    def test_udp_service_confirmed_by_reply(self):
        ports = [Port(port=161, proto="udp", state="open|filtered", service="snmp")]
        self._orig_udp = hc._udp_probe
        hc._grab_banner = lambda *a, **k: b""
        hc._grab_tls = lambda *a, **k: {}
        hc._udp_probe = lambda host, port, payload: b"\x30\x2b\x02\x01\x00\x04\x06public..."
        try:
            with tempfile.TemporaryDirectory() as d:
                ctx, _ = _ctx_with_ports(ports, d)
                findings = hc.ServiceConfirmModule().run_global(ctx)
                doc = json.load(open(os.path.join(d, "raw", "confirmed-services.json")))
        finally:
            hc._udp_probe = self._orig_udp
        rec = doc["items"][0]
        self.assertEqual(rec["method"], "udp")
        self.assertEqual(rec["proto"], "udp")
        self.assertEqual(len(findings), 1)
        self.assertIn("snmpwalk", findings[0].repro)        # udp enum command

    def test_udp_open_filtered_without_reply_is_not_confirmed(self):
        # No probe reply and only open|filtered from nmap -> too ambiguous to list.
        ports = [Port(port=69, proto="udp", state="open|filtered", service="tftp")]
        self._orig_udp = hc._udp_probe
        hc._grab_banner = lambda *a, **k: b""
        hc._grab_tls = lambda *a, **k: {}
        hc._udp_probe = lambda host, port, payload: b""
        try:
            with tempfile.TemporaryDirectory() as d:
                ctx, _ = _ctx_with_ports(ports, d)
                findings = hc.ServiceConfirmModule().run_global(ctx)
                doc = json.load(open(os.path.join(d, "raw", "confirmed-services.json")))
        finally:
            hc._udp_probe = self._orig_udp
        self.assertEqual(doc["confirmed"], 0)
        self.assertEqual(findings, [])

    def test_udp_open_state_confirmed_via_nmap_even_without_probe(self):
        # A port with no crafted probe but nmap state "open" answered nmap.
        ports = [Port(port=500, proto="udp", state="open", service="isakmp")]
        self._orig_udp = hc._udp_probe
        hc._grab_banner = lambda *a, **k: b""
        hc._grab_tls = lambda *a, **k: {}
        hc._udp_probe = lambda host, port, payload: b""
        try:
            with tempfile.TemporaryDirectory() as d:
                ctx, _ = _ctx_with_ports(ports, d)
                findings = hc.ServiceConfirmModule().run_global(ctx)
                doc = json.load(open(os.path.join(d, "raw", "confirmed-services.json")))
        finally:
            hc._udp_probe = self._orig_udp
        self.assertEqual(doc["items"][0]["method"], "udp-scan")
        self.assertEqual(len(findings), 1)

    def test_proxied_port_is_skipped(self):
        ports = [Port(port=22, service="ssh")]
        hc._grab_banner = lambda host, port, nudge=None: b"SSH-2.0-x\r\n"
        hc._grab_tls = lambda host, port: {}
        with tempfile.TemporaryDirectory() as d:
            ctx, _ = _ctx_with_ports(ports, d)
            ctx.cfg.proxied_ports = [22]
            findings = hc.ServiceConfirmModule().run_global(ctx)
            wrote = os.path.exists(os.path.join(d, "raw", "confirmed-services.json"))
        # Nothing to probe -> no findings, and no inventory file to render.
        self.assertFalse(wrote)
        self.assertEqual(findings, [])


class ConfirmReportTests(unittest.TestCase):
    def test_section_renders_rows_and_is_sortable(self):
        from assay import report
        items = [
            {"host": "10.0.0.9", "ip": "10.0.0.9", "port": 22, "proto": "tcp",
             "service": "ssh", "product": "OpenSSH", "version": "8.9p1",
             "method": "banner", "summary": "SSH-2.0-OpenSSH_8.9p1",
             "banner": "SSH-2.0-OpenSSH_8.9p1", "enum": "nmap -Pn -p22 ... 10.0.0.9",
             "repro": "nc 10.0.0.9 22"},
        ]
        with tempfile.TemporaryDirectory() as d:
            raw = os.path.join(d, "raw")
            os.makedirs(raw)
            with open(os.path.join(raw, "confirmed-services.json"), "w") as fh:
                json.dump({"scanned": 3, "confirmed": 1, "items": items}, fh)
            html = report._render_confirmed(os.path.join(raw, "confirmed-services.json"))
        self.assertIn("Confirmed services", html)
        self.assertIn("1 of 3 open", html)
        self.assertIn("OpenSSH", html)
        self.assertIn('class="sortable"', html)             # click-to-sort enabled
        self.assertIn("enumerate next", html)

    def test_missing_file_renders_nothing(self):
        from assay import report
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(report._confirmed_services(d), "")


if __name__ == "__main__":
    unittest.main()
