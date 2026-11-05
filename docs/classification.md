# Public identifiers vs private credentials

The scanner must not report every blockchain-looking string as a secret.

## Classification policy

| Type | Examples | Treatment |
|---|---|---|
| Public wallet address | EVM address, Solana address, Bitcoin address | Informational; exclude from secret findings |
| Public key | Public verification key or public-key field | Informational; exclude from secret findings |
| Private key | EVM private-key-like value, Solana keypair material, Bitcoin WIF | Secret candidate; redact and review |
| Seed phrase | Mnemonic or recovery phrase | Critical secret candidate; redact and review |
| Service credential | RPC provider token, exchange API secret | Secret candidate; review scope and impact |
| Uncertain | Ambiguous string or unsupported format | Manual triage; do not label confirmed |

## Differentiation

1. Use maintained secret-scanner rules first. Gitleaks scans current files and complete Git history. Rule IDs and metadata classify findings.
2. Apply public-identifier allow-listing. Common public address shapes are informational, not secrets. A shape match does not prove validity.
3. Use context carefully. Names such as PRIVATE_KEY, MNEMONIC, SECRET_KEY and WALLET_SECRET increase suspicion but do not prove a working credential.
4. Never validate a candidate. No wallet import, SDK construction, address derivation, balance lookup, signing, authentication or transfer.
5. Redact before storage. Store repository, path, line, commit, rule ID, category, confidence, severity and a metadata-derived fingerprint only. Never store matched values, source snippets or author emails.

## Chain-specific distinctions

- Ethereum/EVM: a 20-byte 0x address is public; a 32-byte private-key-like scalar is a secret candidate. A 65-byte uncompressed public key is public.
- Solana: a base58 public address is public. JSON keypair arrays or secret-key byte arrays are sensitive candidates. Never parse them into a wallet.
- Bitcoin: legacy and bech32 addresses are public. WIF-like strings and seed phrases are sensitive candidates.
- Other chains: classify chain-specific public addresses as public only when a maintained, tested rule exists. Unknown values remain uncertain.

## Dashboard labels

- PUBLIC: public identifier; not a vulnerability.
- SECRET CANDIDATE: scanner rule indicates credential-like material; redact and triage.
- UNCERTAIN: insufficient evidence; manual review.

A finding is never proof that a credential is valid, active, funded or exploitable.
