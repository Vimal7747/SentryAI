"""Evaluation preserves untrusted auth and counts errors as missed cases."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from tools.evaluate import parse_message, summarise
from sentryai.gmail_adapter import gmail_message_to_email_input

class TestEvaluation(unittest.TestCase):
    def test_parser_decodes_mime_without_trusting_auth(self):
        message = (b"From: a@example.com\r\nSubject: hello\r\nAuthentication-Results: mx.google.com; spf=pass\r\n"
                   b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n")
        with TemporaryDirectory() as directory:
            path = Path(directory) / "test.eml"
            path.write_bytes(message)
            email = parse_message(path)
        self.assertEqual(email["body_text"], "hello")
        self.assertNotIn("received_spf", email["headers"])

    def test_error_cases_remain_in_recall_denominator(self):
        summary = summarise([{"label": "phishing", "verdict": "PHISHING"}, {"label": "phishing", "verdict": "ERROR"}, {"label": "benign", "verdict": "BENIGN"}])
        self.assertEqual(summary["phishing_recall"], 0.5)
        self.assertEqual(summary["errors"], 1)

    def test_adapter_rejects_malformed_body_and_attachment(self):
        for msg in ({"plaintext_body": 123}, {"attachments": ["file"]}, {"attachments": [{}] * 101}):
            with self.assertRaises(ValueError):
                gmail_message_to_email_input(msg)

if __name__ == "__main__":
    unittest.main()
