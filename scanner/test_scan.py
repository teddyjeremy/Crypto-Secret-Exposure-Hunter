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
        self.assertEqual(len(safe), 1)
        serialized = str(safe[0])
        self.assertNotIn("NEVER_STORE_THIS_PRIVATE_VALUE", serialized)
        self.assertNotIn("developer@example.com", serialized)
        self.assertNotIn("Secret", safe[0])
        self.assertNotIn("Match", safe[0])
        self.assertEqual(safe[0]["file_path"], ".env")
        self.assertEqual(safe[0]["line_number"], 7)

    def test_non_list_report_is_ignored(self):
        self.assertEqual(sanitize_report({"Secret": "do-not-store"}, {
            "full_name": "example/repo", "ecosystem": "Other Web3"
        }), [])

if __name__ == "__main__":
    unittest.main()
