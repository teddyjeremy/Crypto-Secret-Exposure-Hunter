"""Safe offline classification of public blockchain identifiers vs secret candidates."""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class Classification:
    category: str
    secret_type: Optional[str]
    confidence: str
    reason: str

PUBLIC_PATTERNS = [
    ("evm_address", re.compile(r"(?i)^0x[a-f0-9]{40}$")),
    ("evm_uncompressed_public_key", re.compile(r"(?i)^0x04[a-f0-9]{128}$")),
    ("solana_public_address", re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")),
    ("bitcoin_legacy_address", re.compile(r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$")),
    ("bitcoin_bech32_address", re.compile(r"(?i)^bc1[ac-hj-np-z02-9]{11,71}$")),
]
ASSIGNMENT_HINT = re.compile(
    r"(?i)(private[_ -]?key|secret[_ -]?key|mnemonic|seed[_ -]?phrase|"
    r"wallet[_ -]?secret|api[_ -]?key|rpc[_ -]?token)"
)

def classify_text(value: str, context: str = "") -> Classification:
    """Return labels only. Never return the input or any substring of it."""
    candidate = value.strip()
    if not candidate:
        return Classification("uncertain", None, "low", "Empty value.")
    for label, pattern in PUBLIC_PATTERNS:
        if pattern.fullmatch(candidate):
            if ASSIGNMENT_HINT.search(context):
                return Classification("uncertain", None, "low",
                    "Public-looking identifier occurs in credential-labelled context; review manually.")
            return Classification("public_information", label, "high",
                "Matches a public identifier shape; not a private credential.")
    if ASSIGNMENT_HINT.search(context):
        return Classification("secret_candidate", "credential_assignment", "medium",
            "Credential-related assignment context; review sanitized detector metadata.")
    return Classification("uncertain", None, "low",
        "No reliable public-identifier or secret classification.")

def classify_gitleaks_rule(rule_id: str, description: str = "") -> Classification:
    """Map scanner rule metadata to a safe class without accessing the match."""
    key = (rule_id + " " + description).lower().replace("-", "_").replace(" ", "_")
    if "exchange_api_key" in key:
        return Classification("secret_candidate", "exchange_api_key", "high",
            "Rule indicates an exchange-specific API key assignment; permissions are unknown.")
    if "exchange_api_secret" in key:
        return Classification("secret_candidate", "exchange_api_secret", "high",
            "Rule indicates an exchange-specific API secret assignment; permissions are unknown.")
    if "exchange_api_passphrase" in key:
        return Classification("secret_candidate", "exchange_api_passphrase", "high",
            "Rule indicates an exchange-specific API passphrase assignment; permissions are unknown.")
    if any(x in key for x in ("mnemonic", "bip39", "seed_phrase", "seedphrase")):
        return Classification("secret_candidate", "mnemonic_or_seed_phrase", "high",
            "Rule indicates a mnemonic-like value.")
    if any(x in key for x in ("solana", "sol_keypair", "keypair")):
        return Classification("secret_candidate", "solana_keypair", "high",
            "Rule indicates Solana keypair-like material.")
    if any(x in key for x in ("ethereum", "eth_private", "evm_private")):
        return Classification("secret_candidate", "evm_private_key", "high",
            "Rule indicates EVM private-key-like material.")
    if any(x in key for x in ("bitcoin", "wif", "xprv", "extended_private_key")):
        return Classification("secret_candidate", "bitcoin_private_key", "high",
            "Rule indicates Bitcoin private-key or extended-private-key material.")
    if any(x in key for x in ("ton_wallet", "ton_private", "ton_secret")):
        return Classification("secret_candidate", "ton_wallet_secret", "high",
            "Rule indicates TON wallet signing material.")
    if any(x in key for x in ("sui", "aptos")) and any(x in key for x in ("private", "secret", "keypair")):
        return Classification("secret_candidate", "move_chain_signing_key", "high",
            "Rule indicates Sui or Aptos signing material.")
    if any(x in key for x in ("cosmos", "injective")) and any(x in key for x in ("private", "secret", "mnemonic", "key")):
        return Classification("secret_candidate", "cosmos_ecosystem_signing_key", "high",
            "Rule indicates Cosmos ecosystem signing material.")
    # Detection-only ecosystem registry. These labels classify detector metadata;
    # they do not validate, derive, authenticate with, or query discovered credentials.
    ecosystem_rules = (
        (("tron", "trx"), "tron_signing_key"),
        (("near",), "near_signing_key"),
        (("polkadot", "substrate", "kusama"), "substrate_signing_key"),
        (("cardano", "ada"), "cardano_signing_key"),
        (("xrpl", "ripple"), "xrpl_signing_key"),
        (("stellar", "xlm"), "stellar_signing_key"),
        (("algorand", "algo"), "algorand_signing_key"),
        (("hedera", "hbar"), "hedera_signing_key"),
        (("tezos", "xtz"), "tezos_signing_key"),
        (("filecoin", "fil"), "filecoin_signing_key"),
        (("zcash", "zec"), "zcash_signing_key"),
        (("monero", "xmr"), "monero_signing_key"),
        (("kaspa", "kas"), "kaspa_signing_key"),
        (("internet_computer", "icp"), "internet_computer_signing_key"),
        (("multiversx", "elrond", "egld"), "multiversx_signing_key"),
        (("litecoin", "ltc"), "litecoin_signing_key"),
        (("dogecoin", "doge"), "dogecoin_signing_key"),
        (("bitcoin_cash", "bitcoincash", "bch"), "bitcoin_cash_signing_key"),
        (("dash",), "dash_signing_key"),
        (("decred", "dcr"), "decred_signing_key"),
        (("zilliqa", "zil"), "zilliqa_signing_key"),
        (("aptos", "apt"), "aptos_signing_key"),
        (("sui",), "sui_signing_key"),
        (("ton", "the_open_network"), "ton_wallet_secret"),
        (("cosmos", "injective", "osmosis", "sei", "celestia", "atom"), "cosmos_ecosystem_signing_key"),
    )
    secret_context = any(x in key for x in ("private", "secret", "mnemonic", "seed", "key", "wallet", "signer"))
    if secret_context:
        for aliases, secret_type in ecosystem_rules:
            if any(alias in key for alias in aliases):
                return Classification("secret_candidate", secret_type, "medium",
                    "Rule metadata points to this ecosystem's signing material; manual review is required.")
    if secret_context and any(x in key for x in ("blockchain", "crypto", "web3", "wallet")):
        return Classification("secret_candidate", "blockchain_signing_key", "medium",
            "Rule indicates blockchain signing material; ecosystem mapping requires manual review.")
    if any(x in key for x in ("exchange_api_key", "exchange_api_secret", "exchange_api_passphrase")):
        return Classification("secret_candidate", "exchange_api_credential", "medium",
            "Rule indicates an exchange-specific API credential assignment; manual review is required.")
    if any(x in key for x in ("private_key", "privatekey", "wallet_secret")):
        return Classification("secret_candidate", "private_key", "high",
            "Rule indicates private-key-like material.")
    if any(x in key for x in ("api_key", "token", "rpc")):
        return Classification("secret_candidate", "service_credential", "medium",
            "Rule indicates a service credential.")
    return Classification("uncertain", None, "low", "Unmapped detector rule; manual review required.")
