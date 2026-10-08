"""Regression cases reproduced during the repository review."""
import unittest
from functools import partial
from sentryai.pipeline import analyze as _analyze
from sentryai.models import EmailInput
from sentryai.enrichment import StubEnricher
from sentryai.api_enrichment import ApiEnricher
from sentryai.stage2_content import _is_lookalike_domain
from sentryai.stage3_iocs import enrich_iocs

AUTH = {"received_spf": "pass", "dkim_result": "pass", "dmarc_result": "pass"}

# Fixture authentication values represent separately verified results.
analyze = partial(_analyze, trusted_auth_results=True)

class PathEnricher(StubEnricher):
    def __init__(self):
        super().__init__()
        self.calls = []
    def virustotal_url_scan(self, url):
        self.calls.append(url)
        return {"malicious_votes": 10 if "/bad" in url else 0}

class TestDetectionRegressions(unittest.TestCase):
    def test_clean_path_does_not_hide_malicious_path_or_subdomain(self):
        for bad in ("https://example.com/bad", "https://other.example.com/bad"):
            with self.subTest(bad=bad):
                e = PathEnricher()
                v = analyze({"headers": AUTH, "urls_extracted": ["https://example.com/good", bad]}, e)
                urls = [i for i in v["signals"]["ioc_enrichment"] if i["ioc_type"] == "url"]
                self.assertEqual([i["verdict"] for i in urls], ["clean", "malicious"])
                self.assertEqual(v["verdict"], "PHISHING")
                self.assertEqual(len(e.calls), 2)

    def test_duplicate_url_checked_and_scored_once(self):
        e = PathEnricher()
        results, _ = enrich_iocs({"urls": ["https://example.com/bad"] * 2}, e)
        self.assertEqual(len(e.calls), 1)
        self.assertEqual(sum(i.points_contributed for i in results), 45)
        self.assertTrue(all(i.verdict == "malicious" for i in results))

    def test_budget_applies_to_paths_on_same_domain(self):
        e = PathEnricher()
        results, notes = enrich_iocs({"urls": ["https://example.com/good", "https://example.com/bad"]}, e, max_url_lookups=1)
        self.assertEqual(results[1].verdict, "unknown")
        self.assertEqual(len(e.calls), 1)
        self.assertTrue(notes)

    def test_unavailable_intel_requires_review(self):
        e = ApiEnricher(vt_key="", abuseipdb_key="", http=lambda *args: (0, None))
        v = analyze({"headers": AUTH, "urls_extracted": ["https://example.com/bad"]}, e)
        self.assertEqual(v["confidence"], "low")
        self.assertTrue(v["human_review_recommended"])
        self.assertIn("returned no data", v["analysis_metadata"]["processing_notes"])
        self.assertTrue(any("Hold" in a for a in v["recommended_actions"]))
        self.assertFalse(any(a.startswith("Deliver") for a in v["recommended_actions"]))

    def test_truncation_requires_review_without_mutating_input(self):
        for field in ("body_text", "body_html"):
            with self.subTest(field=field):
                body = "x" * 200000 + " password urgent verify now account suspended"
                email = EmailInput.from_dict({"headers": AUTH, field: body})
                v = analyze(email)
                self.assertEqual(getattr(email, field), body)
                self.assertEqual(v["confidence"], "low")
                self.assertTrue(v["human_review_recommended"])
                self.assertIn("truncated", v["analysis_metadata"]["processing_notes"])

    def test_security_advice_and_credential_mentions_are_not_requests(self):
        for body in ("Google security notice: never share your password.", "Your password was changed.", "Do not send your OTP."):
            with self.subTest(body=body):
                v = analyze({"headers": AUTH, "body_text": body})
                self.assertEqual(v["verdict"], "BENIGN")
                self.assertFalse(any(i["signal_type"] == "credential_harvest" for i in v["signals"]["content_signals"]))

    def test_advice_does_not_hide_following_request(self):
        for body in ("Never share your password. Send your OTP here.", "Never share your password but enter your OTP here.", "Please provide your password."):
            with self.subTest(body=body):
                v = analyze({"headers": AUTH, "body_text": body})
                self.assertTrue(any(i["signal_type"] == "credential_harvest" for i in v["signals"]["content_signals"]))

    def test_noncredential_form_is_not_a_password_form(self):
        v = analyze({"headers": AUTH, "body_text": "Survey", "body_html": '<form><input type="text"></form>'})
        self.assertFalse(any(i["signal_type"] == "credential_harvest" for i in v["signals"]["content_signals"]))
        v = analyze({"headers": AUTH, "body_text": "Survey", "body_html": '<input type="password">'})
        self.assertTrue(any(i["points_contributed"] == 40 for i in v["signals"]["content_signals"]))

    def test_brand_label_on_untrusted_suffix_is_flagged(self):
        for host in ("paypal.attacker", "paypal.net", "www.google.attacker"):
            self.assertTrue(_is_lookalike_domain(host), host)
        for host in ("paypal.com", "www.paypal.co.uk", "accounts.google.com"):
            self.assertFalse(_is_lookalike_domain(host), host)

    def test_stub_does_not_invent_clean_reputation(self):
        e = StubEnricher()
        for lookup, value in ((e.abuseipdb_lookup, "1.2.3.4"), (e.greynoise_lookup, "1.2.3.4"), (e.virustotal_url_scan, "https://example.com"), (e.virustotal_hash_lookup, "a" * 64), (e.whois_lookup, "example.com")):
            self.assertIsNone(lookup(value))
        v = analyze({"headers": AUTH, "urls_extracted": ["https://example.com"], "attachments": [{"sha256": "a" * 64}]})
        self.assertTrue(all(i["verdict"] == "unknown" for i in v["signals"]["ioc_enrichment"]))
        self.assertEqual(v["confidence"], "low")

    def test_unknown_domain_age_stays_unknown(self):
        class MissingAge(StubEnricher):
            def whois_lookup(self, domain):
                return {"age_days": None}
        results, notes = enrich_iocs({"domains": ["example.com"]}, MissingAge())
        self.assertEqual(results[0].verdict, "unknown")
        self.assertTrue(notes)

    def test_greynoise_unobserved_ip_is_unknown(self):
        e = ApiEnricher(abuseipdb_key="", http=lambda *args: (404, None))
        results, notes = enrich_iocs({"ips": ["1.2.3.4"]}, e)
        self.assertEqual(results[0].verdict, "unknown")
        self.assertTrue(notes)

    def test_empty_virustotal_statistics_are_unknown(self):
        e = ApiEnricher(vt_key="x", http=lambda *args: (200, {"data": {"attributes": {}}}))
        self.assertIsNone(e.virustotal_url_scan("https://example.com"))
        self.assertIsNone(e.virustotal_hash_lookup("a" * 64))


if __name__ == "__main__":
    unittest.main()
