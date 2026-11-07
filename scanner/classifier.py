"""Safe offline classification for exchange API credential detector metadata."""
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

EXCHANGE_RULES = {
    "exchange_api_key": "exchange_api_key",
    "exchange_api_secret": "exchange_api_secret",
    "exchange_api_passphrase": "exchange_api_passphrase",
}

def classify_gitleaks_rule(rule_id: str, description: str = "") -> Classification:
    """Classify rule metadata only; never inspect or return a matched credential."""
    key = (rule_id + " " + description).lower().replace("-", "_").replace(" ", "_")
    for marker, secret_type in EXCHANGE_RULES.items():
        if marker in key:
            return Classification(
                "secret_candidate", secret_type, "high",
                "Exchange API credential pattern; account permissions and validity are unknown."
            )
    return Classification("ignored", None, "low", "Not an exchange API credential rule.")
