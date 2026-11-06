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
WORKER_INGEST_TOKEN = os.getenv("WORKER_INGEST_TOKEN", "").strip()
WORKER_STATE_FILE = os.getenv("WORKER_STATE_FILE", "/var/data/scan-state.json")


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

def discover(progress_callback: Any | None = None) -> list[dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    # Prioritize bot-focused searches before the ecosystem topics. This also
    # includes archived bot repositories that may retain old exposed credentials.
    # Dedicated discovery for public crypto trading-bot repositories. Search includes
    # archived repositories too: abandoned bot projects can still expose old credentials.
    bot_queries = [
        ("Crypto Trading Bots", '"crypto trading bot"'),
        ("Crypto Trading Bots", '"cryptocurrency trading bot"'),
        ("Crypto Trading Bots", '"binance trading bot"'),
        ("Crypto Trading Bots", "ccxt"),
        ("Crypto Trading Bots", "freqtrade"),
        ("Crypto Trading Bots", "hummingbot"),
    ]
    # Search crypto project categories as well as chain ecosystems. These are
    # discovery labels only: every repository receives the same passive Gitleaks scan.
    project_queries = [
        ("Crypto Wallets", '"crypto wallet"'),
        ("Hardware / Self-Custody Wallets", '"self custody wallet"'),
        ("Crypto Exchanges", '"crypto exchange"'),
        ("Decentralized Exchanges", '"decentralized exchange"'),
        ("DeFi Protocols", '"DeFi protocol"'),
        ("Lending / Borrowing", '"crypto lending protocol"'),
        ("Yield / Farming", '"yield farming"'),
        ("Staking / Validators", '"staking validator"'),
        ("Token Launchpads", '"token launchpad"'),
        ("Memecoins", '"memecoin"'),
        ("NFT Projects", '"NFT marketplace"'),
        ("NFT Infrastructure", '"NFT protocol"'),
        ("Bridges / Interoperability", '"cross chain bridge"'),
        ("Oracles", '"blockchain oracle"'),
        ("Payments / Invoicing", '"crypto payments"'),
        ("Stablecoins", '"stablecoin"'),
        ("Blockchain Explorers", '"blockchain explorer"'),
        ("RPC / Node Infrastructure", '"blockchain RPC"'),
        ("Smart Contract Tooling", '"smart contract"'),
        ("DAO / Governance", '"DAO governance"'),
        ("Identity / Credentials", '"web3 identity"'),
        ("Gaming / Metaverse", '"web3 game"'),
        ("Privacy / ZK", '"zero knowledge blockchain"'),
        ("Crypto Analytics / Indexers", '"crypto analytics"'),
    ]
    discovery_queries = bot_queries + project_queries + list(ECOSYSTEMS.items())
    per_ecosystem = max(1, min(PER_QUERY, MAX_REPOS // max(1, len(discovery_queries))))
    for index, (ecosystem, query) in enumerate(discovery_queries):
        if len(found) >= MAX_REPOS:
            break
        # Allocate a balanced quota so early chains do not starve later ecosystems.
        # Search API is rate-limited. Keep requests below approximately 10/minute.
        if index:
            time.sleep(6.5)
        response = requests.get(
            f"{API}/search/repositories",
            params={
                # Bot discovery intentionally includes archived repositories.
                "q": f"{query} fork:false forks:<10" + ("" if ecosystem == "Crypto Trading Bots" else " archived:false"),
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
                "github_repo_id": int(item.get("id") or 0) or None,
                "html_url": item.get("html_url", ""),
                "clone_url": item.get("clone_url", ""),
                "ecosystem": ecosystem,
                "description": (item.get("description") or "")[:300],
                "stars": int(item.get("stargazers_count") or 0),
                "forks": int(item.get("forks_count") or 0),
                "default_branch": item.get("default_branch", ""),
                "size_kb": size_kb,
                "pushed_at": item.get("pushed_at"),
                "status": "pending",
            }
            if len(found) >= MAX_REPOS:
                break
        # Publish progress after each ecosystem query instead of leaving the dashboard frozen.
        if progress_callback:
            progress_callback(index + 1, len(discovery_queries), ecosystem, len(found))
    # Prefer low-fork repositories so discovery is less dominated by already-popular projects.
    return sorted(found.values(), key=lambda repo: (int(repo.get("forks") or 0), -int(repo.get("stars") or 0)))


def default_branch_head(repo: dict[str, Any]) -> str | None:
    """Resolve the exact commit scanned on the default branch."""
    branch = str(repo.get("default_branch") or "")
    if not branch:
        return None
    try:
        response = requests.get(
            f"{API}/repos/{repo['full_name']}/commits/{requests.utils.quote(branch, safe='')}",
            headers=headers(),
            timeout=20,
        )
        if response.status_code in (403, 429):
            return None
        response.raise_for_status()
        sha = response.json().get("sha")
        return str(sha)[:40] if isinstance(sha, str) and sha else None
    except (requests.RequestException, ValueError):
        return None


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


def send_event(event: str, run: dict[str, Any], summary: dict[str, Any],
               repo: dict[str, Any] | None = None,
               findings: list[dict[str, Any]] | None = None) -> None:
    """Send only sanitized scan metadata; obtain a fresh short-lived OIDC token per event."""
    payload = {
        "event": event,
        "run": run,
        "summary": summary,
        "repository": ({
            key: repo.get(key) for key in (
                "full_name", "github_repo_id", "html_url", "ecosystem", "description", "stars",
                "default_branch", "pushed_at", "head_sha", "status"
            )
        } if repo else None),
        "findings": (findings or [])[:500],
    }
    auth_headers = {"Content-Type": "application/json", "x-vercel-protection-bypass": VERCEL_BYPASS}
    if WORKER_INGEST_TOKEN:
        auth_headers["x-worker-token"] = WORKER_INGEST_TOKEN
    else:
        auth_headers["Authorization"] = f"Bearer {github_oidc_token()}"
    response = requests.post(INGEST_URL, headers=auth_headers,
        json=payload,
        timeout=60,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Progress ingestion failed with HTTP {response.status_code}; response body suppressed.")


def main() -> None:
    if not INGEST_URL.startswith("https://"):
        raise RuntimeError("INGEST_URL must be an HTTPS endpoint.")
    if not VERCEL_BYPASS:
        raise RuntimeError("Set VERCEL_AUTOMATION_BYPASS_SECRET for the protected Vercel ingestion endpoint.")
    if not WORKER_INGEST_TOKEN and not os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL"):
        raise RuntimeError("Set WORKER_INGEST_TOKEN for a hosted worker or run inside GitHub Actions.")

    run_id = str(uuid.uuid4())
    started = utc_now()
    run = {
        "id": run_id,
        "status": "running",
        "trigger_source": "hosted-worker" if WORKER_INGEST_TOKEN else "github-actions",
        "started_at": started,
        "completed_at": None,
        "repositories_discovered": 0,
        "repositories_scanned": 0,
        "findings_total": 0,
    }
    summary: dict[str, Any] = {
        "phase": "discovering",
        "message": "Searching public crypto project categories, blockchain ecosystems, and trading bots.",
        "progress_percent": 0,
        "current_repository": None,
        "status_counts": {},
        "repositories": [],
        "ecosystems": ["Crypto Trading Bots", *ECOSYSTEMS.keys()],
    }
    send_event("progress", run, summary)
    print("Discovering public repositories across crypto project categories and blockchain ecosystems.")

    def report_discovery_progress(index: int, total: int, ecosystem: str, found_count: int) -> None:
        summary["phase"] = "discovering"
        summary["message"] = f"Searching {ecosystem} ({index}/{total} ecosystems); {found_count} repositories found so far."
        summary["progress_percent"] = round((index / max(1, total)) * 10)
        send_event("progress", run, summary)

    repositories = discover(report_discovery_progress)
    for repository in repositories:
        repository["head_sha"] = default_branch_head(repository)
    registry_payload = {"event": "registry", "repository_names": [r["full_name"] for r in repositories]}
    registry_headers = {"Content-Type": "application/json", "x-vercel-protection-bypass": VERCEL_BYPASS}
    if WORKER_INGEST_TOKEN:
        registry_headers["x-worker-token"] = WORKER_INGEST_TOKEN
    else:
        registry_headers["Authorization"] = f"Bearer {github_oidc_token()}"
    registry_response = requests.post(INGEST_URL, headers=registry_headers, json=registry_payload, timeout=30)
    registry_response.raise_for_status()
    registry_rows = registry_response.json().get("repositories", [])
    previous = {r["full_name"]: r for r in registry_rows if isinstance(r, dict) and r.get("full_name")}
    discovered_count = len(repositories)
    repositories = [r for r in repositories if not (
        previous.get(r["full_name"], {}).get("latest_status") == "completed"
        and bool(r.get("head_sha"))
        and previous.get(r["full_name"], {}).get("last_scanned_commit") == r.get("head_sha")
    )]
    run["repositories_discovered"] = discovered_count
    summary.update({
        "phase": "scanning",
        "repositories_skipped_unchanged": discovered_count - len(repositories),
        "message": f"Discovered {discovered_count} repositories; {len(repositories)} are new or changed. Starting scans.",
        "progress_percent": 0,
        "repositories": [
            {
                "full_name": r["full_name"],
                "html_url": r["html_url"],
                "ecosystem": r["ecosystem"],
                "status": "pending",
            } for r in repositories
        ],
    })
    send_event("progress", run, summary)

    scanned = 0
    all_findings: list[dict[str, Any]] = []
    errors: dict[str, int] = {}
    for index, repo in enumerate(repositories, start=1):
        summary["phase"] = "scanning"
        summary["current_repository"] = repo["full_name"]
        summary["message"] = f"Scanning {repo['full_name']} ({index}/{len(repositories)})."
        summary["progress_percent"] = round(((index - 1) / max(1, len(repositories))) * 100)
        # Publish the in-flight repository before the clone and Gitleaks scan begin.
        send_event("progress", run, summary, repo)
        print(f"[{index}/{len(repositories)}] Scanning {repo['full_name']} ({repo['ecosystem']})")
        try:
            status, findings = scan_repository(repo)
        except Exception:
            status, findings = "worker_error", []
        repo["status"] = status
        if WORKER_INGEST_TOKEN and status == "completed":
            state[repo["full_name"]] = repo.get("pushed_at") or ""
            Path(WORKER_STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
            Path(WORKER_STATE_FILE).write_text(json.dumps(state), encoding="utf-8")
        scanned += int(status == "completed")
        errors[status] = errors.get(status, 0) + 1
        remaining = max(0, 3000 - len(all_findings))
        findings_to_send = findings[:remaining]
        all_findings.extend(findings_to_send)
        run["repositories_scanned"] = scanned
        run["findings_total"] = len(all_findings)
        summary["status_counts"] = errors
        summary["progress_percent"] = round((index / max(1, len(repositories))) * 100)
        summary["message"] = f"Finished {repo['full_name']}: {status}."
        for entry in summary["repositories"]:
            if entry["full_name"] == repo["full_name"]:
                entry["status"] = status
                entry["finding_count"] = len(findings)
                break
        # Persist each repository result immediately in bounded batches; findings contain metadata only.
        if findings_to_send:
            for offset in range(0, len(findings_to_send), 500):
                send_event("progress", run, summary, repo, findings_to_send[offset:offset + 500])
        else:
            send_event("progress", run, summary, repo)
        # Mark the end of this repository scan after every finding batch has arrived.
        if status == "completed":
            send_event("repository_complete", run, summary, repo)
    completed = utc_now()
    run["status"] = "completed"
    run["completed_at"] = completed
    summary["phase"] = "completed"
    summary["current_repository"] = None
    summary["progress_percent"] = 100
    summary["message"] = f"Scan completed: {scanned}/{len(repositories)} repositories scanned."
    send_event("complete", run, summary)
    print(f"Completed: {scanned}/{len(repositories)} repositories scanned; {len(all_findings)} sanitized findings ingested.")


if __name__ == "__main__":
    main()
