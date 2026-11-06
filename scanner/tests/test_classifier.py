import unittest
from scanner.classifier import classify_text, classify_gitleaks_rule


class ClassificationTests(unittest.TestCase):
    def test_evm_address_is_public(self):
        result = classify_text("0x" + "a" * 40)
        self.assertEqual(result.category, "public_information")
        self.assertEqual(result.secret_type, "evm_address")

    def test_public_identifier_in_credential_context_is_uncertain(self):
        result = classify_text("0x" + "a" * 40, "PRIVATE_KEY = value")
        self.assertEqual(result.category, "uncertain")

    def test_secret_context_is_candidate_not_validated(self):
        result = classify_text("redacted", "WALLET_PRIVATE_KEY = value")
        self.assertEqual(result.category, "secret_candidate")

    def test_solana_rule_uses_metadata_only(self):
        result = classify_gitleaks_rule("solana-keypair")
        self.assertEqual(result.secret_type, "solana_keypair")

    def test_bitcoin_wif_rule_is_classified(self):
        result = classify_gitleaks_rule("bitcoin-wif")
        self.assertEqual(result.secret_type, "bitcoin_private_key")

    def test_tron_signing_key_rule_is_classified(self):
        result = classify_gitleaks_rule("tron-private-key")
        self.assertEqual(result.secret_type, "tron_signing_key")

    def test_substrate_signing_key_rule_is_classified(self):
        result = classify_gitleaks_rule("polkadot-private-key")
        self.assertEqual(result.secret_type, "substrate_signing_key")

    def test_public_identifier_is_not_promoted_to_secret(self):
        result = classify_text("not-a-key")
        self.assertEqual(result.category, "uncertain")


if __name__ == "__main__":
    unittest.main()
