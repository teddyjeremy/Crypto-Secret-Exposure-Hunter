import unittest
from scanner.scan import sanitize_report


class SanitizationTests(unittest.TestCase):
    def test_generic_credentials_are_excluded(self):
        repo = {"full_name": "example/app", "ecosystem": "OKX"}
        raw = [{
            "RuleID": "generic-api-key", "Description": "Generic credential",
            "File": ".env", "Commit": "abcdef123456", "StartLine": 7,
            "Secret": "NEVER_STORE_THIS_PRIVATE_VALUE",
            "Match": "API_KEY=NEVER_STORE_THIS_PRIVATE_VALUE",
        }]
        safe = sanitize_report(raw, repo)
        self.assertEqual(safe, [])
        self.assertNotIn("NEVER_STORE_THIS_PRIVATE_VALUE", str(safe))

    def test_wallet_signing_keys_are_excluded(self):
        repo = {"full_name": "example/wallet-app", "ecosystem": "OKX"}
        raw = [{
            "RuleID": "evm-private-key", "Description": "EVM private key",
            "File": ".env", "Commit": "abcdef123456", "StartLine": 4,
        }]
        self.assertEqual(sanitize_report(raw, repo), [])

    def test_exchange_api_credentials_are_reported_without_values(self):
        repo = {"full_name": "example/exchange-bot", "ecosystem": "OKX"}
        raw = [{
            "RuleID": "exchange-api-secret", "Description": "Exchange API secret",
            "File": ".env", "Commit": "abcdef123456", "StartLine": 12,
            "Secret": "FAKE_SECRET", "Match": "OKX_API_SECRET=FAKE_SECRET",
        }]
        finding = sanitize_report(raw, repo)[0]
        self.assertEqual(finding["secret_type"], "exchange_api_secret")
        self.assertIn("OKX", finding["description"])
        self.assertIn("permissions unknown", finding["description"])
        serialized = str(finding)
        self.assertNotIn("FAKE_SECRET", serialized)
        self.assertNotIn("OKX_API_SECRET=", serialized)

    def test_non_list_report_is_ignored(self):
        self.assertEqual(sanitize_report({"Secret": "do-not-store"}, {
            "full_name": "example/repo", "ecosystem": "OKX"
        }), [])


if __name__ == "__main__":
    unittest.main()
