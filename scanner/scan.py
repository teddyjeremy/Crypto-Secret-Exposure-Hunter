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

API = "https://api.github.com"
USER_AGENT = "CryptoSecretExposureHunter/1.0 (defensive public repository research)"
ECOSYSTEMS = {
    "Solana": "topic:solana",
    "Ethereum / EVM": "topic:ethereum",
    "Bitcoin": "topic:bitcoin",
    "TON": "topic:ton",
    "Sui": "topic:sui",
    "Aptos": "topic:aptos",
    "Cosmos": "topic:cosmos-sdk",
    "TRON": "topic:tron",
    "NEAR": "topic:near-protocol",
    "Polkadot": "topic:polkadot",
    "Other Web3": "topic:web3",
}
MAX_REPO_SIZE_KB = int(os.getenv("MAX_REPO_SIZE_KB", "150000"))
REPO_TIMEOUT = int(os.getenv("REPO_TIMEOUT_SECONDS", "240"))
MAX_REPOS = min(max(int(os.getenv("MAX_REPOS", "30")), 1), 50)
PER_QUERY = int(os.getenv("PER_QUERY", "8"))
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
INGEST_URL = os.getenv("INGEST_URL", "").strip()
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "").strip()


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


def discover() -> list[dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for index, (ecosystem, query) in enumerate(ECOSYSTEMS.items()):
        if len(found) >= MAX_REPOS:
            break
        # Search API is rate-limited. Keep requests below approximately 10/minute.
        if index:
            time.sleep(6.5)
        response = requests.get(
            f"{API}/search/repositories",
            params={
                "q": f"{query} fork:false archived:false stars:>=0",
                "sort": "updated",
                "order": "desc",
                "per_page": min(PER_QUERY, 10),
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
    if any(term in value for term in ("private-key", "private_key", "mnemonic", "seed-phrase", "wallet")):
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
        safe.append({
            "fingerprint": fingerprint,
            "repository_full_name": repo["full_name"],
            "ecosystem": repo["ecosystem"],
            "severity": classify(rule, description),
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
                    "gitleaks", "git", str(clone_path),
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
    if not INGEST_URL.startswith("https://") or not INGEST_TOKEN:
        raise RuntimeError("INGEST_URL and INGEST_TOKEN GitHub Actions secrets are required.")
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
    response = requests.post(
        INGEST_URL,
        headers={"Authorization": f"Bearer {INGEST_TOKEN}", "Content-Type": "application/json"},
        json=payload,
        timeout=90,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Result ingestion failed with HTTP {response.status_code}; response body suppressed.")
    print(f"Completed: {scanned}/{len(repositories)} repositories scanned; {len(all_findings)} sanitized findings ingested.")


if __name__ == "__main__":
    main()
