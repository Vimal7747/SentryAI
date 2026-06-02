"""Tests for the Gmail -> SentryAI input adapter.

Uses synthetic Gmail-shaped payloads (no live mailbox access) and verifies the
mapped dict runs cleanly through the full pipeline.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentryai.gmail_adapter import (  # noqa: E402
    gmail_message_to_email_input,
    gmail_thread_to_email_inputs,
)
from sentryai.pipeline import analyze  # noqa: E402


class TestGmailAdapter(unittest.TestCase):
    def test_headers_as_list_and_auth_results(self):
        msg = {
            "id": "msg1",
            "plaintext_body": "Verify now at http://paypa1-verify.com/login",
            "headers": [
                {"name": "Subject", "value": "Urgent: verify your account"},
                {"name": "From", "value": "Security <security@paypa1-verify.com>"},
                {"name": "Reply-To", "value": "collect@harvester.ru"},
                {"name": "Authentication-Results",
                 "value": "mx.google.com; spf=fail smtp.mailfrom=x; dkim=none; dmarc=fail"},
                {"name": "X-Originating-IP", "value": "[185.220.101.45]"},
            ],
        }
        out = gmail_message_to_email_input(msg)
        h = out["headers"]
        self.assertEqual(h["from"], "Security <security@paypa1-verify.com>")
        self.assertEqual(h["subject"], "Urgent: verify your account")
        self.assertEqual(h["received_spf"], "fail")
        self.assertEqual(h["dkim_result"], "none")
        self.assertEqual(h["dmarc_result"], "fail")
        self.assertEqual(h["x_originating_ip"], "185.220.101.45")
        self.assertIn("http://paypa1-verify.com/login", out["urls_extracted"])

    def test_headers_as_flat_fields(self):
        msg = {
            "id": "msg2",
            "subject": "Hello",
            "from": "a@b.com",
            "plaintext_body": "no links here",
        }
        out = gmail_message_to_email_input(msg)
        self.assertEqual(out["headers"]["from"], "a@b.com")
        self.assertIsNone(out["headers"]["received_spf"])  # absent -> null
        self.assertEqual(out["urls_extracted"], [])

    def test_attachments_mapped(self):
        msg = {
            "id": "m3", "from": "a@b.com", "subject": "doc",
            "plaintext_body": "see attached",
            "attachments": [{"filename": "invoice.pdf", "mimeType": "application/pdf"}],
        }
        out = gmail_message_to_email_input(msg)
        self.assertEqual(out["attachments"][0]["filename"], "invoice.pdf")
        self.assertEqual(out["attachments"][0]["mime_type"], "application/pdf")

    def test_end_to_end_through_pipeline(self):
        msg = {
            "id": "phish1",
            "plaintext_body": "Your PayPal account is suspended. Verify now: http://paypa1-verify.com/login",
            "headers": [
                {"name": "Subject", "value": "Urgent: account suspended"},
                {"name": "From", "value": "security@paypa1-verify.com"},
                {"name": "Reply-To", "value": "collect@harvester.ru"},
                {"name": "Authentication-Results", "value": "spf=fail; dkim=none; dmarc=fail"},
                {"name": "X-Originating-IP", "value": "[185.220.101.45]"},
            ],
        }
        verdict = analyze(gmail_message_to_email_input(msg))
        self.assertEqual(verdict["verdict"], "PHISHING")
        self.assertGreaterEqual(verdict["risk_score"], 85)

    def test_thread_maps_all_messages(self):
        thread = {
            "id": "t1",
            "messages": [
                {"id": "a", "from": "x@y.com", "subject": "hi", "plaintext_body": "lunch?"},
                {"id": "b", "from": "z@w.com", "subject": "re", "plaintext_body": "sure"},
            ],
        }
        inputs = gmail_thread_to_email_inputs(thread)
        self.assertEqual(len(inputs), 2)
        self.assertEqual(inputs[0]["email_id"], "a")
        self.assertEqual(inputs[1]["email_id"], "b")


if __name__ == "__main__":
    unittest.main(verbosity=2)
