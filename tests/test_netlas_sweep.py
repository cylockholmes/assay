"""Offline tests for Netlas port seeding and naabu batch sizing."""

from __future__ import annotations

import os
import tempfile
import unittest

from assay import netlas, tools


class NetlasTests(unittest.TestCase):
    def test_parse_keeps_tcp_only(self):
        body = {"ports": [{"port": 443, "prot4": "tcp"}, {"port": 53, "prot4": "udp"},
                          {"port": "8080", "prot4": "tcp"}, {"port": 0, "prot4": "tcp"}, "junk"]}
        self.assertEqual(netlas.parse_host_ports(body), [443, 8080])
        self.assertEqual(netlas.parse_host_ports({}), [])

    def test_lookup_drops_unknown_hosts_and_caches(self):
        calls = []

        def fetch(h):
            calls.append(h)
            return {"a.example.com": [22, 443], "b.example.com": None}[h]

        with tempfile.TemporaryDirectory() as d:
            cache = os.path.join(d, "c.json")
            hosts = ["a.example.com", "b.example.com"]
            self.assertEqual(netlas.lookup(hosts, cache_path=cache, fetch=fetch),
                             {"a.example.com": [22, 443]})
            netlas.lookup(hosts, cache_path=cache, fetch=fetch)
            self.assertEqual(len(calls), 2)       # second run answered from cache

    def test_quota_error_stops_without_raising(self):
        def fetch(h):
            raise netlas.QuotaExhausted("HTTP 402")
        self.assertEqual(netlas.lookup(["a.example.com"], fetch=fetch), {})


class SweepSizingTests(unittest.TestCase):
    TUNE = {"nmap_min_rate": 300}

    def test_full_range_batches_fit_the_deadline(self):
        hosts = ["10.0.%d.%d" % (i // 250, i % 250) for i in range(2911)]
        batches = tools.plan_batches(hosts, "all", self.TUNE)
        biggest = max(len(b) for b in batches)
        deadline = tools.naabu_timeout(batches[0], "all", self.TUNE)
        # Raw probing time must sit well inside the per-batch limit.
        self.assertLess(tools.sweep_seconds(biggest, "all", self.TUNE),
                        tools.NAABU_TIMEOUT_CAP / 2)
        self.assertLessEqual(deadline, tools.NAABU_TIMEOUT_CAP)
        self.assertGreater(len(batches), 50)

    def test_small_sweep_is_one_batch(self):
        self.assertEqual(len(tools.plan_batches(["a", "b"], "top-100", self.TUNE)), 1)


if __name__ == "__main__":
    unittest.main()
