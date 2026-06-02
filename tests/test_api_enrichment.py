"""Tests for the API-backed Enricher (offline, mocked HTTP)."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentryai.api_enrichment import ApiEnricher  # noqa: E402
from sentryai.stage3_iocs import enrich_iocs  # noqa: E402


def make_http(routes):
    """routes: list of (substr, (status, body)). First matching substr wins."""
    def http(method, url, headers, data):
        for substr, resp in routes:
            if substr in url:
                return resp
        return (0, None)
    return http


class TestApiEnricher(unittest.TestCase):
    def _enricher(self, routes):
        return ApiEnricher(vt_key="x", abuseipdb_key="y", greynoise_key="z",
                           http=make_http(routes))

    def test_abuseipdb_mapping(self):
        e = self._enricher([("api.abuseipdb.com", (200, {"data": {
            "ipAddress": "1.2.3.4", "abuseConfidenceScore": 100, "isPublic": True,
            "usageType": "Data Center", "isp": "EvilISP", "domain": "evil.tld",
            "totalReports": 42}}))])
        r = e.abuseipdb_lookup("1.2.3.4")
        self.assertEqual(r["abuse_confidence_score"], 100)
        self.assertEqual(r["total_reports"], 42)
        self.assertEqual(r["isp"], "EvilISP")

    def test_greynoise_404_is_unknown_not_none(self):
        e = self._enricher([("greynoise", (404, None))])
        r = e.greynoise_lookup("8.8.8.8")
        self.assertIsNotNone(r)
        self.assertEqual(r["classification"], "unknown")

    def test_virustotal_url_stats(self):
        e = self._enricher([("/api/v3/urls/", (200, {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 9, "suspicious": 2, "harmless": 50},
            "categories": {"x": "phishing", "y": "phishing"},
            "last_final_url": "http://evil/login"}}}))])
        r = e.virustotal_url_scan("http://evil/login")
        self.assertEqual(r["malicious_votes"], 9)
        self.assertEqual(r["categories"], ["phishing"])

    def test_virustotal_url_404_returns_none(self):
        e = self._enricher([("/api/v3/urls/", (404, None))])
        self.assertIsNone(e.virustotal_url_scan("http://never-scanned/"))

    def test_virustotal_hash_stats(self):
        e = self._enricher([("/api/v3/files/", (200, {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 60, "suspicious": 1},
            "type_description": "Win32 EXE"}}}))])
        r = e.virustotal_hash_lookup("a" * 64)
        self.assertEqual(r["malicious_votes"], 60)
        self.assertEqual(r["file_type"], "Win32 EXE")

    def test_whois_rdap_age(self):
        e = self._enricher([("rdap.org", (200, {
            "events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}],
            "entities": [{"roles": ["registrar"],
                          "vcardArray": ["vcard", [["fn", {}, "text", "BigRegistrar"]]]}],
            "country": "US"}))])
        r = e.whois_lookup("example.com")
        self.assertGreater(r["age_days"], 9000)
        self.assertEqual(r["registrar"], "BigRegistrar")

    def test_missing_key_returns_none(self):
        e = ApiEnricher(vt_key="", abuseipdb_key="", http=make_http([]))
        self.assertIsNone(e.abuseipdb_lookup("1.2.3.4"))
        self.assertIsNone(e.virustotal_url_scan("http://x/"))

    def test_network_failure_returns_none_not_raise(self):
        e = self._enricher([])  # every route -> (0, None)
        self.assertIsNone(e.abuseipdb_lookup("1.2.3.4"))
        self.assertIsNone(e.whois_lookup("x.com"))

    def test_end_to_end_with_stage3(self):
        # Malicious IP + URL via API enricher → stage3 scores malicious.
        routes = [
            ("api.abuseipdb.com", (200, {"data": {"ipAddress": "185.220.101.45",
                "abuseConfidenceScore": 100, "isPublic": True, "usageType": "DC",
                "isp": "x", "domain": "", "totalReports": 9}})),
            ("greynoise", (200, {"ip": "185.220.101.45", "noise": True, "riot": False,
                "classification": "malicious", "name": "Scanner", "last_seen": "2026-05"})),
            ("/api/v3/urls/", (200, {"data": {"attributes": {
                "last_analysis_stats": {"malicious": 12, "suspicious": 1, "harmless": 3},
                "categories": {"a": "phishing"}}}})),
            ("rdap.org", (200, {"events": [{"eventAction": "registration",
                "eventDate": "2026-05-28T00:00:00Z"}], "entities": []})),
        ]
        e = self._enricher(routes)
        iocs = {"ips": ["185.220.101.45"], "urls": ["http://paypa1-verify.com/login"],
                "domains": ["paypa1-verify.com"], "hashes": [], "emails": []}
        results, notes = enrich_iocs(iocs, e)
        by = {r.value: r for r in results}
        self.assertEqual(by["185.220.101.45"].verdict, "malicious")
        self.assertEqual(by["http://paypa1-verify.com/login"].verdict, "malicious")
        self.assertEqual(by["paypa1-verify.com"].verdict, "suspicious")  # ~5 days old
        self.assertEqual(notes, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
