import unittest

from scanner.classifier import classify_gitleaks_rule, classify_text


class ChainClassificationTests(unittest.TestCase):
    def test_bitcoin_wif_rule_is_secret_candidate(self):
        result = classify_gitleaks_rule("bitcoin-wif")
        self.assertEqual(result.category, "secret_candidate")
        self.assertEqual(result.secret_type, "bitcoin_private_key")

    def test_cosmos_ecosystem_rule_is_classified(self):
        result = classify_gitleaks_rule("injective-mnemonic")
        self.assertEqual(result.category, "secret_candidate")
        self.assertEqual(result.secret_type, "mnemonic_or_seed_phrase")

    def test_tron_signing_key_rule_is_classified(self):
        result = classify_gitleaks_rule("tron-private-key")
        self.assertEqual(result.category, "secret_candidate")
        self.assertEqual(result.secret_type, "tron_signing_key")

    def test_public_evm_address_is_not_a_secret(self):
        result = classify_text("0x" + "a" * 40)
        self.assertEqual(result.category, "public_information")

    def test_unknown_value_is_not_promoted_to_secret(self):
        result = classify_text("not-a-key")
        self.assertEqual(result.category, "uncertain")


if __name__ == "__main__":
    unittest.main()
