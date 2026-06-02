"""Regression tests for the code-review findings (one block per finding).

Each test pins the behaviour a fix was meant to produce, so the issue cannot
silently regress. Findings are numbered to match the review.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentryai.models import EmailInput  # noqa: E402
from sentryai import enrichment as enr  # noqa: E402
from sentryai import stage2_content as s2  # noqa: E402
from sentryai import stage3_iocs as s3  # noqa: E402
from sentryai.stage5_scoring import total_score  # noqa: E402
from sentryai.pipeline import analyze  # noqa: E402


# ---------------------------------------------------------------------------
# #1 — lookalike domain must not flag legitimate brand subdomains
# ---------------------------------------------------------------------------
class TestLookalikeDomain(unittest.TestCase):
    LEGIT = [
        "paypal.com", "www.paypal.com", "accounts.google.com",
        "mail.google.com", "id.apple.com", "signin.amazon.com",
        "login.microsoft.com", "paypal.co.uk",
    ]
    LOOKALIKE = [
        "paypa1.com", "paypa1-verify.com", "paypal-verify.com",
        "secure-paypal.ru", "amaz0n.com", "paypal.evil.com",
        "micr0soft-support.net",
    ]

    def test_legit_brand_domains_not_flagged(self):
        for d in self.LEGIT:
            self.assertFalse(s2._is_lookalike_domain(d), f"false positive on {d}")

    def test_lookalikes_still_caught(self):
        for d in self.LOOKALIKE:
            self.assertTrue(s2._is_lookalike_domain(d), f"missed lookalike {d}")

    def test_generic_bank_token_not_flagged(self):
        # 'bank' is no longer a brand root (code-review C); a hyphen token
        # like secure-bank.com must not be flagged as a lookalike.
        self.assertFalse(s2._is_lookalike_domain("secure-bank.com"))
        self.assertFalse(s2._is_lookalike_domain("mybank.com"))

    def test_legit_brand_link_no_credential_harvest(self):
        # A legitimate brand subdomain link with no cred-request / form must
        # not raise a credential_harvest signal via the lookalike path.
        email = EmailInput.from_dict({
            "email_id": "legit",
            "headers": {"from": "no-reply@google.com"},
            "body_text": "Review your settings at https://accounts.google.com/security",
            "urls_extracted": ["https://accounts.google.com/security"],
        })
        signals, _, _ = s2.analyze_content(email)
        self.assertFalse(any(s.signal_type == "credential_harvest" for s in signals))


# ---------------------------------------------------------------------------
# #2 — base64 evasion must not fire on benign long tokens
# ---------------------------------------------------------------------------
class TestBase64Evasion(unittest.TestCase):
    def _evasion_types(self, email):
        signals, _, _ = s2.analyze_content(email)
        return [s for s in signals if s.signal_type == "evasion"
                and "base64" in s.description.lower()]

    def test_long_html_token_not_flagged(self):
        # A long lowercase+digit tracking token inside HTML is not base64.
        token = "a1b2c3d4e5f6g7h8i9j0" * 4  # 80 chars, lower+digit, no +/=
        email = EmailInput.from_dict({
            "email_id": "html",
            "headers": {"from": "a@b.com"},
            "body_html": f"<img src='https://cdn.x/track?id={token}'>",
        })
        self.assertEqual(self._evasion_types(email), [])

    def test_data_uri_is_flagged(self):
        email = EmailInput.from_dict({
            "email_id": "datauri",
            "headers": {"from": "a@b.com"},
            "body_text": "image follows: data:image/png;base64,iVBORw0KGgoAAAANSUhEUg",
        })
        self.assertTrue(self._evasion_types(email))

    def test_real_base64_blob_in_text_flagged(self):
        blob = "TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVy"  # mixed+/=
        email = EmailInput.from_dict({
            "email_id": "blob",
            "headers": {"from": "a@b.com"},
            "body_text": f"payload {blob} end",
        })
        self.assertTrue(self._evasion_types(email))


# ---------------------------------------------------------------------------
# #3 — Stage 2 and Stage 3 must extract identical URL sets
# ---------------------------------------------------------------------------
class TestUrlParity(unittest.TestCase):
    def test_same_urls(self):
        email = EmailInput.from_dict({
            "email_id": "urls",
            "headers": {"from": "a@b.com"},
            "body_text": "click http://evil.com/a) and (http://evil.com/b].",
            "body_html": "<a href='http://evil.com/c'>x</a>",
            "urls_extracted": ["http://evil.com/seed"],
        })
        s2_urls = set(s2._collect_urls(email.urls_extracted, email.body_text, email.body_html))
        s3_urls = set(s3.extract_iocs(email)["urls"])
        self.assertEqual(s2_urls, s3_urls)


# ---------------------------------------------------------------------------
# #6 — total_score no longer takes the unused injection flag
# ---------------------------------------------------------------------------
class TestTotalScoreSignature(unittest.TestCase):
    def test_three_arg_signature(self):
        self.assertEqual(total_score(10, [], []), 10)
        with self.assertRaises(TypeError):
            total_score(10, [], [], True)  # old 4-arg form must be gone


# ---------------------------------------------------------------------------
# #7 — _is_valid_ip must reject non-IP strings containing colons
# ---------------------------------------------------------------------------
class TestValidIp(unittest.TestCase):
    def test_valid_and_invalid(self):
        self.assertTrue(s3._is_valid_ip("1.2.3.4"))
        self.assertTrue(s3._is_valid_ip("::1"))
        self.assertFalse(s3._is_valid_ip("999.1.1.1"))
        self.assertFalse(s3._is_valid_ip("not:an:ip"))
        self.assertFalse(s3._is_valid_ip("time:12:30"))


# ---------------------------------------------------------------------------
# #8 — oversized bodies are truncated, not crashed on
# ---------------------------------------------------------------------------
class TestBodySizeGuard(unittest.TestCase):
    def test_huge_body_truncated(self):
        huge = "word " * 60000  # 300k chars
        verdict = analyze({
            "email_id": "huge",
            "headers": {"from": "a@b.com", "received_spf": "pass",
                        "dkim_result": "pass", "dmarc_result": "pass"},
            "body_text": huge,
        })
        self.assertIn("truncated", verdict["analysis_metadata"]["processing_notes"].lower())
        self.assertIn(verdict["verdict"], ("BENIGN", "SUSPICIOUS", "PHISHING"))


# ---------------------------------------------------------------------------
# #9 — confidence drops to "low" when IOC enrichment is degraded
# ---------------------------------------------------------------------------
class TestLowConfidenceOnFailure(unittest.TestCase):
    def test_failed_lookups_lower_confidence(self):
        class BrokenEnricher(enr.StubEnricher):
            def abuseipdb_lookup(self, ip):
                raise RuntimeError("net down")

            def greynoise_lookup(self, ip):
                raise RuntimeError("net down")

            def virustotal_url_scan(self, url):
                raise RuntimeError("net down")

            def whois_lookup(self, domain):
                raise RuntimeError("net down")

        verdict = analyze({
            "email_id": "degraded",
            "headers": {"from": "security@paypa1-verify.com",
                        "reply_to": "c@harvester.ru",
                        "received_spf": "fail", "dkim_result": "none",
                        "dmarc_result": "fail",
                        "x_originating_ip": "185.220.101.45"},
            "body_text": "Urgent: account suspended, verify now http://paypa1-verify.com/login",
            "urls_extracted": ["http://paypa1-verify.com/login"],
        }, enricher=BrokenEnricher())
        self.assertEqual(verdict["confidence"], "low")
        self.assertEqual(verdict["verdict"], "PHISHING")  # content+header still strong


# ---------------------------------------------------------------------------
# #10 — bounded prize regex doesn't match across huge gaps
# ---------------------------------------------------------------------------
class TestPrizeRegexBound(unittest.TestCase):
    def test_far_apart_no_match(self):
        far = "congratulations " + ("x" * 80) + " you won"
        self.assertIsNone(s2._PRIZE_RE.search(far))

    def test_close_matches(self):
        near = "congratulations, you won a prize"
        self.assertIsNotNone(s2._PRIZE_RE.search(near))


if __name__ == "__main__":
    unittest.main(verbosity=2)
