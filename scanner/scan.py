from __future__ import annotations
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

try:
    from .classifier import classify_gitleaks_rule
except ImportError:  # Direct execution: python scanner/scan.py
    from classifier import classify_gitleaks_rule

API = "https://api.github.com"
USER_AGENT = "CryptoSecretExposureHunter/1.0 (defensive public repository research)"
ECOSYSTEMS = {
    "Solana": "topic:solana",
    "Ethereum / EVM": "topic:ethereum",
    "Base": "topic:base-chain",
    "Polygon": "topic:polygon",
    "Arbitrum": "topic:arbitrum",
    "Optimism": "topic:optimism",
    "BNB Chain": "topic:binance-smart-chain",
    "Avalanche": "topic:avalanche",
    "Bitcoin": "topic:bitcoin",
    "TON": "topic:ton",
    "Sui": "topic:sui",
    "Aptos": "topic:aptos",
    "Cosmos": "topic:cosmos-sdk",
    "Injective": "topic:injective",
    "Osmosis": "topic:osmosis",
    "Sei": "topic:sei",
    "Celestia": "topic:celestia",
    "TRON": "topic:tron",
    "NEAR": "topic:near-protocol",
    "Polkadot": "topic:polkadot",
    "Kusama": "topic:kusama",
    "Cardano": "topic:cardano",
    "XRP Ledger": "topic:xrpl",
    "Stellar": "topic:stellar",
    "Algorand": "topic:algorand",
    "Hedera": "topic:hedera",
    "Tezos": "topic:tezos",
    "Filecoin": "topic:filecoin",
    "Zcash": "topic:zcash",
    "Monero": "topic:monero",
    "Kaspa": "topic:kaspa",
    "Internet Computer": "topic:internet-computer",
    "MultiversX": "topic:multiversx",
    "Other Web3": "topic:web3",
}
MAX_REPO_SIZE_KB = int(os.getenv("MAX_REPO_SIZE_KB", "150000"))
REPO_TIMEOUT = int(os.getenv("REPO_TIMEOUT_SECONDS", "240"))
MAX_REPOS = min(max(int(os.getenv("MAX_REPOS", "40")), 1), 80)
PER_QUERY = int(os.getenv("PER_QUERY", "8"))
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
INGEST_URL = os.getenv("INGEST_URL", "").strip()
OIDC_AUDIENCE = "crypto-secret-exposure-hunter"
VERCEL_BYPASS = os.getenv("VERCEL_AUTOMATION_BYPASS_SECRET", "").strip()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def headers() -> dict[str, str]:
    result = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }
    if GITHUB_TOKEN:
        result["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return result


def github_oidc_token() -> str:
    request_url = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    request_token = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if not request_url or not request_token:
        raise RuntimeError("GitHub Actions OIDC token is unavailable; check id-token: write permission.")
    response = requests.get(request_url, headers={"Authorization": f"Bearer {request_token}"},
                            params={"audience": OIDC_AUDIENCE}, timeout=20)
    response.raise_for_status()
    value = response.json().get("value")
    if not isinstance(value, str) or not value:
        raise RuntimeError("GitHub Actions did not issue an OIDC token.")
    return value

def discover() -> list[dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    per_ecosystem = max(1, min(PER_QUERY, MAX_REPOS // max(1, len(ECOSYSTEMS))))
    for index, (ecosystem, query) in enumerate(ECOSYSTEMS.items()):
        if len(found) >= MAX_REPOS:
            break
        # Allocate a balanced quota so early chains do not starve later ecosystems.
        # Search API is rate-limited. Keep requests below approximately 10/minute.
        if index:
            time.sleep(6.5)
        response = requests.get(
            f"{API}/search/repositories",
            params={
                "q": f"{query} fork:false archived:false stars:>=0",
                "sort": "updated",
                "order": "desc",
                "per_page": min(per_ecosystem, 10),
            },
            headers=headers(),
            timeout=30,
        )
        if response.status_code in (403, 429):
            raise RuntimeError("GitHub search rate limit reached; stopping this run safely.")
        response.raise_for_status()
        for item in response.json().get("items", []):
            full_name = item.get("full_name", "")
            size_kb = int(item.get("size") or 0)
            if not full_name or full_name in found or size_kb > MAX_REPO_SIZE_KB:
                continue
            found[full_name] = {
                "full_name": full_name,
                "html_url": item.get("html_url", ""),
                "clone_url": item.get("clone_url", ""),
                "ecosystem": ecosystem,
                "description": (item.get("description") or "")[:300],
                "stars": int(item.get("stargazers_count") or 0),
                "default_branch": item.get("default_branch", ""),
                "size_kb": size_kb,
                "status": "pending",
            }
            if len(found) >= MAX_REPOS:
                break
    return list(found.values())


def classify(rule_id: str, description: str) -> str:
    value = f"{rule_id} {description}".lower()
    if any(term in value for term in ("private-key", "private_key", "mnemonic", "seed-phrase", "wallet", "keypair", "xprv", "wif")):
        return "critical"
    if any(term in value for term in ("token", "password", "api", "aws", "database", "generic")):
        return "high"
    return "medium"


def sanitize_report(raw: Any, repo: dict[str, Any]) -> list[dict[str, Any]]:
    safe: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return safe
    for item in raw:
        if not isinstance(item, dict):
            continue
        rule = str(item.get("RuleID") or "unknown")[:120]
        description = str(item.get("Description") or "")[:240]
        path = str(item.get("File") or "(path unavailable)")[:700]
        commit = str(item.get("Commit") or "")[:80]
        line_value = item.get("StartLine")
        line = line_value if isinstance(line_value, int) and line_value >= 0 else None
        # Fingerprint uses non-secret metadata only. Secret, Match and source lines are discarded.
        fingerprint = hashlib.sha256(
            f"{repo['full_name']}|{rule}|{path}|{commit}|{line}".encode("utf-8")
        ).hexdigest()
        classification = classify_gitleaks_rule(rule, description)
        safe.append({
            "fingerprint": fingerprint,
            "repository_full_name": repo["full_name"],
            "ecosystem": repo["ecosystem"],
            "severity": classify(rule, description),
            "classification": classification.category,
            "secret_type": classification.secret_type,
            "confidence": classification.confidence,
            "rule_id": rule,
            "description": description,
            "file_path": path,
            "line_number": line,
            "commit_sha": commit,
            "date": item.get("Date") if isinstance(item.get("Date"), str) else None,
        })
    return safe


def scan_repository(repo: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    if not shutil.which("gitleaks"):
        raise RuntimeError("Gitleaks binary is missing from PATH.")
    with tempfile.TemporaryDirectory(prefix="cseh-worker-") as temp:
        clone_path = Path(temp) / "repository"
        report_path = Path(temp) / "gitleaks-report.json"
        try:
            clone = subprocess.run(
                ["git", "clone", "--quiet", "--no-tags", repo["clone_url"], str(clone_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=REPO_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return "clone_timeout", []
        if clone.returncode != 0:
            return "clone_failed", []
        actual_size = sum(p.stat().st_size for p in clone_path.rglob("*") if p.is_file())
        if actual_size > MAX_REPO_SIZE_KB * 1024:
            return "skipped_size", []
        try:
            result = subprocess.run(
                [
                    "gitleaks", "detect", "--source", str(clone_path),
                    "--config", str(Path.cwd() / ".gitleaks.toml"),
                    "--redact", "--report-format", "json",
                    "--report-path", str(report_path), "--exit-code", "0",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=REPO_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return "scan_timeout", []
        if result.returncode != 0:
            return "scanner_error", []
        try:
            raw = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else []
        except (OSError, json.JSONDecodeError):
            raw = []
        return "completed", sanitize_report(raw, repo)


def main() -> None:
    if not INGEST_URL.startswith("https://"):
        raise RuntimeError("INGEST_URL must be an HTTPS endpoint.")
    if not VERCEL_BYPASS:
        raise RuntimeError("Add VERCEL_AUTOMATION_BYPASS_SECRET to GitHub Actions secrets.")
    run_id = str(uuid.uuid4())
    started = utc_now()
    print("Discovering public repositories by ecosystem metadata.")
    repositories = discover()
    all_findings: list[dict[str, Any]] = []
    scanned = 0
    errors: dict[str, int] = {}
    for index, repo in enumerate(repositories, start=1):
        print(f"[{index}/{len(repositories)}] Scanning {repo['full_name']} ({repo['ecosystem']})")
        try:
            status, findings = scan_repository(repo)
        except Exception:
            status, findings = "worker_error", []
        repo["status"] = status
        scanned += int(status == "completed")
        errors[status] = errors.get(status, 0) + 1
        all_findings.extend(findings)
        # Cap outgoing records to keep API requests bounded.
        if len(all_findings) >= 3000:
            all_findings = all_findings[:3000]
            break
    completed = utc_now()
    payload = {
        "run": {
            "id": run_id,
            "status": "completed",
            "trigger_source": "github-actions",
            "started_at": started,
            "completed_at": completed,
            "repositories_discovered": len(repositories),
            "repositories_scanned": scanned,
            "findings_total": len(all_findings),
            "summary": {"status_counts": errors, "ecosystems": list(ECOSYSTEMS.keys())},
        },
        "repositories": [
            {key: repo.get(key) for key in (
                "full_name", "html_url", "ecosystem", "description", "stars",
                "default_branch", "status"
            )}
            for repo in repositories
        ],
        "findings": all_findings,
    }
    # GitHub issues a short-lived OIDC JWT scoped to this workflow. The Vercel API
    # verifies issuer, audience, repository, branch, workflow path and event name.
    identity_token = github_oidc_token()
    response = requests.post(
        INGEST_URL,
        headers={
            "Authorization": f"Bearer {identity_token}",
            "Content-Type": "application/json",
            "x-vercel-protection-bypass": VERCEL_BYPASS,
        },
        json=payload,
        timeout=90,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Result ingestion failed with HTTP {response.status_code}; response body suppressed.")
    print(f"Completed: {scanned}/{len(repositories)} repositories scanned; {len(all_findings)} sanitized findings ingested.")


if __name__ == "__main__":
    main()
