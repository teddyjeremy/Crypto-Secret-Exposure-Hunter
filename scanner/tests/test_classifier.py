import unittest
from scanner.classifier import classify_gitleaks_rule


class ClassificationTests(unittest.TestCase):
    def test_okx_exchange_key_is_classified(self):
        result = classify_gitleaks_rule("exchange-api-key")
        self.assertEqual(result.category, "secret_candidate")
        self.assertEqual(result.secret_type, "exchange_api_key")

    def test_exchange_secret_is_classified(self):
        result = classify_gitleaks_rule("exchange-api-secret")
        self.assertEqual(result.secret_type, "exchange_api_secret")
        self.assertEqual(result.confidence, "high")

    def test_exchange_passphrase_is_classified(self):
        result = classify_gitleaks_rule("exchange-api-passphrase")
        self.assertEqual(result.secret_type, "exchange_api_passphrase")

    def test_wallet_private_key_rule_is_ignored(self):
        result = classify_gitleaks_rule("evm-private-key")
        self.assertEqual(result.category, "ignored")
        self.assertIsNone(result.secret_type)

    def test_generic_api_rule_is_ignored(self):
        result = classify_gitleaks_rule("generic-api-key")
        self.assertEqual(result.category, "ignored")
        self.assertIsNone(result.secret_type)


if __name__ == "__main__":
    unittest.main()
