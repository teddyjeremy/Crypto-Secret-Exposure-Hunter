import unittest
from scanner.scan import sanitize_report

class SanitizationTests(unittest.TestCase):
    def test_secret_material_is_never_returned(self):
        repo = {"full_name": "example/wallet-app", "ecosystem": "Solana"}
        raw = [{
            "RuleID": "generic-api-key",
            "Description": "Generic credential",
            "File": ".env",
            "Commit": "abcdef123456",
            "StartLine": 7,
            "Date": "2026-01-01T00:00:00Z",
            "Secret": "NEVER_STORE_THIS_PRIVATE_VALUE",
            "Match": "PRIVATE_KEY=NEVER_STORE_THIS_PRIVATE_VALUE",
            "Author": "developer@example.com",
            "Email": "developer@example.com",
        }]
        safe = sanitize_report(raw, repo)
        self.assertEqual(safe, [])
        serialized = str(safe)
        self.assertNotIn("NEVER_STORE_THIS_PRIVATE_VALUE", serialized)
        self.assertNotIn("developer@example.com", serialized)
        self.assertNotIn("Secret", safe[0])
        self.assertNotIn("Match", safe[0])
        self.assertEqual(safe[0]["file_path"], ".env")
        self.assertEqual(safe[0]["line_number"], 7)

    def test_gitleaks_rule_is_classified_as_secret_candidate(self):
        repo = {"full_name": "example/solana-app", "ecosystem": "Solana"}
        raw = [{"RuleID": "solana-keypair-json", "Description": "Solana keypair byte array", "File": "wallet.json", "Commit": "abcdef123456", "StartLine": 4}]
        finding = sanitize_report(raw, repo)[0]
        self.assertEqual(finding["classification"], "secret_candidate")
        self.assertEqual(finding["secret_type"], "solana_keypair")
        self.assertEqual(finding["confidence"], "high")
    def test_exchange_api_credentials_are_excluded(self):
        repo = {"full_name": "example/exchange-bot", "ecosystem": "Crypto Trading Bots"}
        raw = [{"RuleID": "exchange-api-secret", "Description": "Exchange API secret",
                "File": ".env", "Commit": "abcdef123456", "StartLine": 12,
                "Secret": "FAKE_SECRET", "Match": "OKX_API_SECRET=FAKE_SECRET"}]
        self.assertEqual(sanitize_report(raw, repo), [])

    def test_non_list_report_is_ignored(self):
        self.assertEqual(sanitize_report({"Secret": "do-not-store"}, {
            "full_name": "example/repo", "ecosystem": "Other Web3"
        }), [])

if __name__ == "__main__":
    unittest.main()
