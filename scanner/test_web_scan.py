import unittest
from scanner.web_scan import safe_url, inspect_text

class WebScannerSafetyTests(unittest.TestCase):
    def test_rejects_non_http_schemes(self):
        self.assertIsNone(safe_url("file:///etc/passwd"))
    def test_rejects_credentials_in_url(self):
        self.assertIsNone(safe_url("https://user:pass@example.com"))
    def test_secret_matches_are_redacted(self):
        findings = []
        inspect_text('const x = "ghp_' + ('A' * 40) + '";', "https://example.com/app.js", findings)
        self.assertTrue(findings)
        self.assertNotIn("ghp_", str(findings))
        self.assertNotIn("A" * 20, str(findings))

if __name__ == "__main__":
    unittest.main()
