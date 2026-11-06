import unittest
from scanner.web_scan import safe_url, inspect_text

class WebScannerSafetyTests(unittest.TestCase):
    def test_rejects_non_http_schemes(self):
        self.assertIsNone(safe_url("file:///etc/passwd"))
    def test_rejects_credentials_in_url(self):
        self.assertIsNone(safe_url("https://user:pass@example.com"))
    def test_rejects_malformed_port(self):
        self.assertIsNone(safe_url("https://example.com:not-a-port"))
    def test_evm_wallet_key_candidate_is_redacted(self):
        findings = []
        value = "0x" + ("a" * 64)
        inspect_text('const wallet_private_key = "' + value + '";', "https://example.com/app.js", findings)
        self.assertTrue(any(item["rule_id"] == "evm_wallet_private_key" for item in findings))
        self.assertNotIn(value, str(findings))

    def test_exchange_api_secret_candidate_is_redacted(self):
        findings = []
        value = "SYNTHETIC_EXCHANGE_SECRET_VALUE_123"
        inspect_text('const OKX_API_SECRET = "' + value + '";', "https://example.com/app.js", findings)
        self.assertTrue(any(item["rule_id"] == "exchange_api_secret" for item in findings))
        self.assertNotIn(value, str(findings))
        self.assertNotIn("OKX_API_SECRET", str(findings))

    def test_generic_service_tokens_are_out_of_scope(self):
        findings = []
        inspect_text('const x = "ghp_' + ('A' * 40) + '";', "https://example.com/app.js", findings)
        self.assertEqual(findings, [])

if __name__ == "__main__":
    unittest.main()
