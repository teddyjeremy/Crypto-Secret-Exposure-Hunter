"""Safe classification of private-key and exchange API detector metadata."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class Classification:
    category: str
    secret_type: Optional[str]
    confidence: str
    reason: str

RULE_TYPES = {
    "solana-keypair-json": ("solana_keypair", "high"),
    "solana-base58-private-key": ("solana_keypair", "medium"),
    "private-key-context-hex": ("evm_private_key", "medium"),
    "evm-private-key": ("evm_private_key", "high"),
    "bitcoin-wif-private-key": ("bitcoin_private_key", "high"),
    "extended-wallet-private-key": ("extended_wallet_private_key", "high"),
    "exchange-api-key": ("exchange_api_key", "high"),
    "exchange-api-secret": ("exchange_api_secret", "high"),
    "exchange-api-passphrase": ("exchange_api_passphrase", "high"),
}

def classify_gitleaks_rule(rule_id: str, description: str = "") -> Classification:
    """Classify rule metadata only; never inspect or return a matched credential."""
    rule = rule_id.strip().lower()
    if rule in RULE_TYPES:
        secret_type, confidence = RULE_TYPES[rule]
        if secret_type.startswith("exchange_api_"):
            reason = "Exchange API credential pattern; validity and permissions are unknown."
        else:
            reason = "Wallet private-key-like pattern; validity and control are unverified."
        return Classification("secret_candidate", secret_type, confidence, reason)
    return Classification("ignored", None, "low", "Outside the private-key and exchange API scope.")
