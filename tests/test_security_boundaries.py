"""Trust boundaries, malformed submissions, and bounded provider work."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch
from sentryai.cli import _read_input, _run, main
from sentryai.enrichment import StubEnricher
from sentryai.gmail_adapter import gmail_message_to_email_input
from sentryai.models import EmailInput, Headers
from sentryai.pipeline import analyze, analyze_batch
from sentryai.validation import InputValidationError, MAX_INPUT_BYTES

AUTH = {"received_spf": "pass", "dkim_result": "pass", "dmarc_result": "pass"}

class Counting(StubEnricher):
    def __init__(self, fail=False):
        super().__init__()
        self.calls = []
        self.fail = fail
    def lookup(self, kind, value):
        self.calls.append((kind, value))
        if self.fail:
            raise RuntimeError("unavailable")
        return None
    def abuseipdb_lookup(self, value):
        return self.lookup("ip", value)
    def greynoise_lookup(self, value):
        return self.lookup("grey", value)
    def virustotal_url_scan(self, value):
        return self.lookup("url", value)
    def virustotal_hash_lookup(self, value):
        return self.lookup("hash", value)
    def whois_lookup(self, value):
        return self.lookup("domain", value)

class TestAuthTrust(unittest.TestCase):
    def test_claimed_passes_are_ignored_without_caller_authorization(self):
        v = analyze({"headers": AUTH, "body_text": "Hello", "trusted_auth_results": True}, trust_missing_auth=True)
        self.assertIsNone(v["signals"]["header_authentication"]["spf"])
        self.assertEqual(v["confidence"], "low")
        self.assertTrue(v["human_review_recommended"])
        self.assertIn("Unverified", v["analysis_metadata"]["processing_notes"])

    def test_verified_passes_and_failures_are_honored(self):
        v = analyze({"headers": AUTH}, trusted_auth_results=True)
        self.assertEqual(v["signals"]["header_authentication"]["points_contributed"], 0)
        self.assertEqual(v["confidence"], "high")
        fail = dict(AUTH, received_spf="fail")
        v = analyze({"headers": fail}, trusted_auth_results=True, trust_missing_auth=True)
        self.assertEqual(v["signals"]["header_authentication"]["points_contributed"], 15)

    def test_raw_gmail_auth_and_arc_are_not_verifier_output(self):
        for headers in (
                [{"name": "Authentication-Results", "value": "mx.google.com; spf=pass; dkim=pass; dmarc=pass"}],
                [{"name": "Authentication-Results", "value": "mx.google.com; spf=fail"}, {"name": "Authentication-Results", "value": "evil; spf=pass; dkim=pass; dmarc=pass"}],
                {"ARC-Authentication-Results": "i=1; mx.google.com; spf=pass; dkim=pass; dmarc=pass", "Received-SPF": "pass"}):
            out = gmail_message_to_email_input({"headers": headers, "verified_auth_results": {"spf": "pass"}})
            self.assertIsNone(out["headers"]["received_spf"])
            self.assertIsNone(out["headers"]["dkim_result"])
            self.assertIsNone(out["headers"]["dmarc_result"])

    def test_separate_verifier_results_override_all_raw_headers(self):
        out = gmail_message_to_email_input({"headers": {"Authentication-Results": "spf=pass; dkim=pass; dmarc=pass"}}, verified_auth_results={"spf": "fail", "dkim": "fail", "dmarc": "fail"})
        v = analyze(out, trusted_auth_results=True)
        self.assertEqual(v["signals"]["header_authentication"]["points_contributed"], 50)
        with self.assertRaises(ValueError):
            gmail_message_to_email_input({}, verified_auth_results={"spf": "magic"})

    def test_neutral_missing_auth_still_requires_review(self):
        v = analyze({"headers": {}, "body_text": "Hello"}, trust_missing_auth=True)
        self.assertEqual(v["verdict"], "BENIGN")
        self.assertEqual(v["confidence"], "low")
        self.assertTrue(v["human_review_recommended"])
        self.assertTrue(any("Hold" in a for a in v["recommended_actions"]))

    def test_dataclass_does_not_bypass_trust(self):
        v = analyze(EmailInput("id", Headers(received_spf="pass", dkim_result="pass", dmarc_result="pass")), trust_missing_auth=True)
        self.assertIsNone(v["signals"]["header_authentication"]["spf"])

class TestInputValidation(unittest.TestCase):
    def test_malformed_shapes_fail_before_provider_calls(self):
        invalid = [None, [], "email", 0, {"headers": []}, {"headers": "x"}, {"body_text": []}, {"body_html": 2},
                   {"headers": {"received_spf": True}}, {"headers": {"received_spf": "magic"}},
                   {"attachments": "file"}, {"attachments": ["file"]}, {"attachments": [None]},
                   {"attachments": [{"filename": []}]}, {"attachments": [{"sha256": "bad"}]},
                   {"urls_extracted": "https://example.com"}, {"urls_extracted": [None]}, {"urls_extracted": [{}]},
                   {"email_id": 123}]
        for data in invalid:
            with self.subTest(data=data):
                e = Counting()
                with self.assertRaises(InputValidationError):
                    analyze(data, e)
                self.assertEqual(e.calls, [])

    def test_collection_and_field_limits(self):
        invalid = [{"attachments": [{}] * 101}, {"urls_extracted": ["https://example.com"] * 101},
                   {"body_text": "x" * 1_000_001}, {"headers": {"subject": "x" * 4097}},
                   {"urls_extracted": ["https://example.com/" + "x" * 4096]}]
        for data in invalid:
            with self.assertRaises(InputValidationError):
                analyze(data)
        with self.assertRaises(InputValidationError):
            analyze_batch([{}] * 101)

    def test_dataclass_shape_is_validated(self):
        with self.assertRaises(InputValidationError):
            analyze(EmailInput("id", Headers(), body_text=123))
        with self.assertRaises(InputValidationError):
            analyze(EmailInput("id", "invalid"))

    def test_invalid_caller_options_rejected(self):
        for value in (-1, 1001, True, "100"):
            with self.assertRaises(InputValidationError):
                analyze({}, max_lookup_calls=value)
        with self.assertRaises(InputValidationError):
            analyze({}, trusted_auth_results="false")

    def test_cli_size_limit_and_malformed_json_exit_one(self):
        for data in ("x" * (MAX_INPUT_BYTES + 1), "{bad", '{"body_text": []}'):
            with patch("sys.stdin", io.StringIO(data)), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    _run(_read_input(None))
                self.assertEqual(caught.exception.code, 1)

    def test_cli_trust_is_a_caller_flag(self):
        payload = json.dumps({"headers": AUTH, "trusted_auth_results": True})
        for flags, expected in (([], None), (["--trusted-auth-results"], "pass")):
            stdout = io.StringIO()
            with patch("sys.stdin", io.StringIO(payload)), patch("sentryai.config.load_dotenv"), contextlib.redirect_stdout(stdout):
                with self.assertRaises(SystemExit) as caught:
                    main(flags)
            self.assertEqual(caught.exception.code, 0)
            self.assertEqual(json.loads(stdout.getvalue())["signals"]["header_authentication"]["spf"], expected)

    def test_batch_fault_isolation_and_cli_failure_exit(self):
        data = [{"body_text": []}, {"headers": AUTH}]
        results = analyze_batch(data, trusted_auth_results=True)
        self.assertEqual(results[0]["verdict"], "ERROR")
        self.assertEqual(results[1]["verdict"], "BENIGN")
        self.assertNotIn("Traceback", results[0]["analysis_metadata"]["processing_notes"])
        with patch("sys.stdin", io.StringIO(json.dumps(data))), patch("sentryai.config.load_dotenv"), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                main(["--trusted-auth-results"])
        self.assertEqual(caught.exception.code, 2)

class TestResourceBudgets(unittest.TestCase):
    def payload(self):
        return {"headers": dict(AUTH, x_originating_ip="1.2.3.4"),
                "body_text": "https://example.com/a https://other.com/b",
                "attachments": [{"sha256": "a" * 64}]}

    def test_all_provider_types_share_one_budget(self):
        for fail in (False, True):
            e = Counting(fail=fail)
            v = analyze(self.payload(), e, max_lookup_calls=3, trusted_auth_results=True)
            self.assertEqual(len(e.calls), 3)
            self.assertEqual(v["confidence"], "low")
            self.assertTrue(v["human_review_recommended"])

    def test_zero_budget_performs_no_provider_calls(self):
        e = Counting()
        v = analyze(self.payload(), e, max_lookup_calls=0, trusted_auth_results=True)
        self.assertEqual(e.calls, [])
        self.assertEqual(v["confidence"], "low")

    def test_budget_resets_per_email_and_metadata_isolated(self):
        e = Counting()
        results = analyze_batch([self.payload(), {"headers": AUTH}], e, max_lookup_calls=2, trusted_auth_results=True)
        self.assertEqual(len(e.calls), 2)
        self.assertEqual(results[1]["analysis_metadata"]["tools_called"], ["rag_retrieve"])
        results = analyze_batch([self.payload()] * 2, e, max_lookup_calls=2, trusted_auth_results=True)
        self.assertEqual(len(e.calls), 6)

    def test_extracted_ioc_limit_marks_analysis_incomplete(self):
        body = " ".join("https://example.com/" + str(i) for i in range(400))
        e = Counting()
        v = analyze({"headers": AUTH, "body_text": body}, e, max_lookup_calls=0, trusted_auth_results=True)
        self.assertLessEqual(v["analysis_metadata"]["ioc_count"], 200)
        self.assertIn("IOC limit", v["analysis_metadata"]["processing_notes"])
        self.assertTrue(v["human_review_recommended"])

    def test_invalid_originating_ip_never_reaches_provider(self):
        e = Counting()
        analyze({"headers": dict(AUTH, x_originating_ip="not:an:ip")}, e, trusted_auth_results=True)
        self.assertEqual(e.calls, [])

if __name__ == "__main__":
    unittest.main()
