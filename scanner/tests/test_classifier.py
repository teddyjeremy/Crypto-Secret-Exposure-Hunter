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

if __name__ == "__main__":
    unittest.main()
