"""Tests for the trust_missing_auth option (Gmail-source false-positive fix).

ABSENT auth headers become neutral; explicit fail/none results still score.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentryai.models import EmailInput  # noqa: E402
from sentryai.stage1_headers import analyze_headers  # noqa: E402
from sentryai.pipeline import analyze  # noqa: E402


class TestTrustMissingAuth(unittest.TestCase):
    def _email(self, **headers):
        return EmailInput.from_dict({"email_id": "x", "headers": headers,
                                     "body_text": "hello"})

    def test_absent_auth_scored_by_default(self):
        # No auth headers, default behaviour -> +50 (15+15+20).
        sig, _ = analyze_headers(self._email(**{"from": "a@b.com"}))
        self.assertEqual(sig.points_contributed, 50)

    def test_absent_auth_neutral_when_trusted(self):
        sig, _ = analyze_headers(self._email(**{"from": "a@b.com"}),
                                 trust_missing_auth=True)
        self.assertEqual(sig.points_contributed, 0)

    def test_explicit_fail_still_scored_when_trusted(self):
        # spf explicitly fails (+15); dkim/dmarc absent -> neutral.
        sig, _ = analyze_headers(
            self._email(**{"from": "a@b.com", "received_spf": "fail"}),
            trust_missing_auth=True,
        )
        self.assertEqual(sig.points_contributed, 15)

    def test_mismatch_still_scored_when_trusted(self):
        sig, _ = analyze_headers(
            self._email(**{"from": "a@b.com", "reply_to": "x@evil.ru"}),
            trust_missing_auth=True,
        )
        self.assertTrue(sig.from_reply_to_mismatch)
        self.assertEqual(sig.points_contributed, 20)

    def test_pipeline_gmail_benign_not_phishing_with_flag(self):
        # A benign Gmail-style email (no auth headers, benign body).
        gmail_like = {
            "email_id": "g1",
            "headers": {"from": "newsletter@nvidia.com",
                        "subject": "Weekly update"},
            "body_text": "Here is our weekly newsletter. Thanks for subscribing.",
        }
        without = analyze(gmail_like)
        with_flag = analyze(gmail_like, trust_missing_auth=True)
        # Without the flag, missing auth alone pushes it to PHISHING (the FP).
        self.assertEqual(without["verdict"], "PHISHING")
        # With the flag, it is no longer flagged as phishing.
        self.assertNotEqual(with_flag["verdict"], "PHISHING")
        self.assertLess(with_flag["risk_score"], without["risk_score"])
        self.assertIn("neutral", with_flag["analysis_metadata"]["processing_notes"].lower())

    def test_pipeline_explicit_fail_still_phishing_with_flag(self):
        # Genuinely bad auth must still be caught even with the flag on.
        bad = {
            "email_id": "b1",
            "headers": {"from": "security@paypa1-verify.com",
                        "reply_to": "collect@harvester.ru",
                        "received_spf": "fail", "dkim_result": "none",
                        "dmarc_result": "fail",
                        "x_originating_ip": "185.220.101.45"},
            "body_text": "Urgent: account suspended, verify now http://paypa1-verify.com/login",
            "urls_extracted": ["http://paypa1-verify.com/login"],
        }
        v = analyze(bad, trust_missing_auth=True)
        self.assertEqual(v["verdict"], "PHISHING")


if __name__ == "__main__":
    unittest.main(verbosity=2)
