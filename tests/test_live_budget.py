"""Tests for URL dedupe-by-registrable-domain and the --live lookup budget."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentryai import enrichment as enr  # noqa: E402
from sentryai.stage3_iocs import enrich_iocs  # noqa: E402


class CountingEnricher(enr.StubEnricher):
    """Counts VirusTotal URL calls and marks every URL malicious."""
    def __init__(self):
        super().__init__()
        self.url_calls = 0

    def virustotal_url_scan(self, url):
        self.url_calls += 1
        return {"url": url, "malicious_votes": 9, "suspicious_votes": 0,
                "harmless_votes": 0, "categories": ["phishing"], "final_url": url}


class TestUrlDedupeAndBudget(unittest.TestCase):
    def test_same_domain_urls_one_lookup_scored_once(self):
        e = CountingEnricher()
        iocs = {"ips": [], "hashes": [], "emails": [], "domains": [],
                "urls": ["http://evil.com/a", "http://evil.com/b", "http://evil.com/c"]}
        results, notes = enrich_iocs(iocs, e)
        url_results = [r for r in results if r.ioc_type == "url"]
        # 3 URLs in output, but only ONE VirusTotal call (deduped by domain).
        self.assertEqual(len(url_results), 3)
        self.assertEqual(e.url_calls, 1)
        # Only the representative contributes points; siblings are 0.
        pts = sorted(r.points_contributed for r in url_results)
        self.assertEqual(pts, [0, 0, 45])

    def test_budget_caps_distinct_domain_lookups(self):
        e = CountingEnricher()
        iocs = {"ips": [], "hashes": [], "emails": [], "domains": [],
                "urls": ["http://a.com/1", "http://b.com/1", "http://c.com/1"]}
        results, notes = enrich_iocs(iocs, e, max_url_lookups=2)
        self.assertEqual(e.url_calls, 2)  # only 2 distinct-domain lookups
        skipped = [r for r in results if r.ioc_type == "url" and r.verdict == "unknown"]
        self.assertEqual(len(skipped), 1)
        self.assertTrue(any("budget" in n for n in notes))

    def test_no_budget_means_all_distinct_domains_checked(self):
        e = CountingEnricher()
        iocs = {"ips": [], "hashes": [], "emails": [], "domains": [],
                "urls": ["http://a.com/1", "http://b.com/1"]}
        enrich_iocs(iocs, e)  # default: no cap
        self.assertEqual(e.url_calls, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestHostlessAndNegativeBudget(unittest.TestCase):
    def test_hostless_urls_not_looked_up(self):
        e = CountingEnricher()
        iocs = {"ips": [], "hashes": [], "emails": [], "domains": [],
                "urls": ["http://", "https:///path", "http://real.com/ok"]}
        results, _ = enrich_iocs(iocs, e)
        # Only the one URL with a real host triggers a lookup.
        self.assertEqual(e.url_calls, 1)
        unknown = [r for r in results if r.ioc_type == "url" and r.verdict == "unknown"]
        self.assertEqual(len(unknown), 2)
        self.assertTrue(any("no resolvable host" in r.detail for r in unknown))

    def test_cli_negative_budget_means_unlimited(self):
        from sentryai.cli import _run
        # negative budget should NOT skip everything (treated as unlimited).
        # We exercise the clamp via _run with a benign offline email.
        out = _run({"email_id": "n", "headers": {"from": "a@b.com",
                    "received_spf": "pass", "dkim_result": "pass",
                    "dmarc_result": "pass"}, "body_text": "hi http://x.com/a"},
                   max_url_lookups=-5)
        urls = [i for i in out["signals"]["ioc_enrichment"] if i["ioc_type"] == "url"]
        # The URL is still enriched (not budget-skipped).
        self.assertTrue(all("budget" not in i["detail"].lower() for i in urls))
