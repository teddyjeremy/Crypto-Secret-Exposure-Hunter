import unittest
from scanner.web_scan import safe_url, inspect_text


class WebScannerSafetyTests(unittest.TestCase):
    def test_rejects_non_http_schemes(self):
        self.assertIsNone(safe_url("file:///etc/passwd"))

    def test_rejects_credentials_in_url(self):
        self.assertIsNone(safe_url("https://user:pass@example.com"))

    def test_rejects_malformed_port(self):
        self.assertIsNone(safe_url("https://example.com:not-a-port"))

    def test_rejects_invalid_unicode_hostname(self):
        self.assertIsNone(safe_url("https://127.0.0.1:5000`，深色主题实时看板："))

    def test_exchange_api_secret_candidate_is_redacted(self):
        findings = []
        value = "SYNTHETIC_EXCHANGE_SECRET_VALUE_123"
        inspect_text('const OKX_API_SECRET = "' + value + '";', "https://example.com/app.js", findings)
        self.assertTrue(any(item["rule_id"] == "exchange_api_secret" for item in findings))
        self.assertNotIn(value, str(findings))
        self.assertNotIn("OKX_API_SECRET", str(findings))

    def test_exchange_api_key_candidate_is_redacted(self):
        findings = []
        value = "SYNTHETIC_BINANCE_KEY_VALUE_123"
        inspect_text('const BINANCE_API_KEY = "' + value + '";', "https://example.com/app.js", findings)
        self.assertTrue(any(item["rule_id"] == "exchange_api_key" for item in findings))
        self.assertNotIn(value, str(findings))

    def test_wallet_private_keys_are_out_of_scope(self):
        findings = []
        value = "0x" + ("a" * 64)
        inspect_text('const wallet_private_key = "' + value + '";', "https://example.com/app.js", findings)
        self.assertEqual(findings, [])

    def test_generic_service_tokens_are_out_of_scope(self):
        findings = []
        inspect_text('const x = "ghp_' + ('A' * 40) + '";', "https://example.com/app.js", findings)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
