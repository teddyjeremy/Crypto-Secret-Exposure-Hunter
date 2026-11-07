from __future__ import annotations
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
import queue
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
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
EXCHANGE_PROVIDERS = [
    "OKX", "Binance", "Coinbase", "Kraken", "Bybit", "KuCoin", "Gate.io",
    "Bitget", "MEXC", "HTX", "Crypto.com", "Gemini", "Bitfinex", "Deribit",
    "Bitstamp", "BingX", "CoinEx",
]

MAX_REPO_SIZE_KB = int(os.getenv("MAX_REPO_SIZE_KB", "50000"))
PRIORITY_CATEGORIES = [
    ("Ethereum / EVM", "topic:ethereum"),
    ("Solana", "topic:solana"),
    ("Bitcoin", "topic:bitcoin"),
    ("OKX API Integrations", '"OKX API"'),
    ("Binance API Integrations", '"Binance API"'),
    ("DeFi Protocols", '"DeFi protocol"'),
    ("Memecoins", '"memecoin"'),
    ("Crypto Trading Bots", '"crypto trading bot"'),
]
PRIORITY_REPO_SIZE_KB = 20_000
SEARCH_REQUEST_INTERVAL = 0.0
SEARCH_REMAINING = None
SEARCH_RESET_AT = 0
SEARCH_LIMIT = 30
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

def _search_rate_limit() -> tuple[int, int, int]:
    """Read the authenticated GitHub search budget and advertised limit."""
    response = requests.get(f"{API}/rate_limit", headers=headers(), timeout=20)
    response.raise_for_status()
    search = response.json().get("resources", {}).get("search", {})
    remaining = max(0, int(search.get("remaining") or 0))
    reset_at = int(search.get("reset") or time.time() + 60)
    limit = max(1, int(search.get("limit") or 30))
    return remaining, reset_at, limit


def _wait_for_search_budget() -> None:
    global SEARCH_REMAINING, SEARCH_RESET_AT, SEARCH_REQUEST_INTERVAL, SEARCH_LIMIT
    if SEARCH_REMAINING is None:
        SEARCH_REMAINING, SEARCH_RESET_AT, SEARCH_LIMIT = _search_rate_limit()
        SEARCH_REQUEST_INTERVAL = 60.0 / SEARCH_LIMIT * 1.10
    if not GITHUB_TOKEN:
        SEARCH_REQUEST_INTERVAL = max(SEARCH_REQUEST_INTERVAL, 10.0)
    now = time.time()
    if SEARCH_REMAINING <= 0:
        time.sleep(max(1.0, SEARCH_RESET_AT - now + 1.0))
        SEARCH_REMAINING, SEARCH_RESET_AT, SEARCH_LIMIT = _search_rate_limit()
        SEARCH_REQUEST_INTERVAL = 60.0 / SEARCH_LIMIT * 1.10
        if not GITHUB_TOKEN:
            SEARCH_REQUEST_INTERVAL = max(SEARCH_REQUEST_INTERVAL, 10.0)
        now = time.time()
    last = getattr(_wait_for_search_budget, "last_request", 0.0)
    elapsed = now - last
    if elapsed < SEARCH_REQUEST_INTERVAL:
        time.sleep(SEARCH_REQUEST_INTERVAL - elapsed)
    _wait_for_search_budget.last_request = time.time()


def discover(progress_callback: Any | None = None) -> list[dict[str, Any]]:
    """Discover public repositories integrating centralized exchange APIs."""
    global SEARCH_REMAINING, SEARCH_RESET_AT
    found: dict[str, dict[str, Any]] = {}
    discovery_queries = [
        ("OKX", '"OKX API" OR "okx-python" OR "okx-sdk"'),
        ("Binance", '"Binance API" OR "python-binance" OR "binance-connector"'),
        ("Coinbase", '"Coinbase API" OR "coinbase-advanced-py"'),
        ("Kraken", '"Kraken API" OR "krakenex"'),
        ("Bybit", '"Bybit API" OR "pybit"'),
        ("KuCoin", '"KuCoin API" OR "kucoin-python"'),
        ("Gate.io", '"Gate.io API" OR "gate-api"'),
        ("Bitget", '"Bitget API"'),
        ("MEXC", '"MEXC API"'),
        ("HTX", '"HTX API" OR "Huobi API"'),
        ("Other exchanges", '"Crypto.com API" OR "Gemini API" OR "Bitfinex API" OR "Deribit API" OR "Bitstamp API" OR "BingX API" OR "CoinEx API"'),
        ("Telegram swap and trading bots", '"Telegram swap bot" OR "Telegram trading bot" OR "DEX swap bot" -freqtrade -hummingbot -jesse -octobot -superalgos'),
        ("Token sniping and launch bots", '"Solana sniper bot" OR "token sniping bot" OR "launch trading bot" -freqtrade -hummingbot -jesse -octobot -superalgos'),
        ("Copy trading and wallet-follow bots", '"crypto copy trading bot" OR "wallet copy trading bot" OR "on-chain copy trader" -freqtrade -hummingbot -jesse -octobot -superalgos'),
        ("DEX swap execution bots", '"Uniswap swap bot" OR "Jupiter swap bot" OR "Raydium trading bot" OR "DEX trading bot" -freqtrade -hummingbot -jesse -octobot -superalgos'),
        ("Automated DeFi trading bots", '"DeFi trading automation bot" OR "on-chain trading bot" OR "automated token trader" -freqtrade -hummingbot -jesse -octobot -superalgos'),
    ]
    query_quota = max(1, min(PER_QUERY, MAX_REPOS // len(discovery_queries)))
    for index, (provider, query) in enumerate(discovery_queries):
        newly_added: list[dict[str, Any]] = []
        if len(found) >= MAX_REPOS:
            break
        _wait_for_search_budget()
        response = requests.get(
            f"{API}/search/repositories",
            params={
                "q": f"{query} fork:false",
                "sort": "updated",
                "order": "desc",
                "per_page": min(query_quota, 10),
            },
            headers=headers(),
            timeout=30,
        )
        if response.status_code in (403, 429):
            retry_after = int(response.headers.get("Retry-After") or 0)
            reset = int(response.headers.get("X-RateLimit-Reset") or time.time() + 60)
            SEARCH_REMAINING = 0
            SEARCH_RESET_AT = max(reset, time.time() + retry_after)
            raise RuntimeError("GitHub search rate limit reached; stopping this run safely.")
        response.raise_for_status()
        SEARCH_REMAINING = max(0, int(response.headers.get("X-RateLimit-Remaining", max(0, (SEARCH_REMAINING or 1) - 1))))
        SEARCH_RESET_AT = int(response.headers.get("X-RateLimit-Reset") or SEARCH_RESET_AT or time.time() + 60)
        SEARCH_LIMIT = max(1, int(response.headers.get("X-RateLimit-Limit") or SEARCH_LIMIT))
        SEARCH_REQUEST_INTERVAL = 60.0 / SEARCH_LIMIT * 1.10
        if not GITHUB_TOKEN:
            SEARCH_REQUEST_INTERVAL = max(SEARCH_REQUEST_INTERVAL, 10.0)
        for item in response.json().get("items", [])[:query_quota]:
            full_name = item.get("full_name", "")
            repo_key = full_name.casefold()
            size_kb = int(item.get("size") or 0)
            if not full_name or item.get("fork") is True or repo_key in found or size_kb > MAX_REPO_SIZE_KB:
                continue
            found[repo_key] = {
                "full_name": full_name,
                "github_repo_id": int(item.get("id") or 0) or None,
                "html_url": item.get("html_url", ""),
                "clone_url": item.get("clone_url", ""),
                "ecosystem": provider,
                "description": (item.get("description") or "")[:300],
                "stars": int(item.get("stargazers_count") or 0),
                "forks": int(item.get("forks_count") or 0),
                "default_branch": item.get("default_branch", ""),
                "size_kb": size_kb,
                "pushed_at": item.get("pushed_at"),
                "status": "pending",
            }
            newly_added.append(found[repo_key])
            if len(found) >= MAX_REPOS:
                break
        if progress_callback:
            progress_callback(index + 1, len(discovery_queries), provider, len(found), newly_added)

    def priority(repo: dict[str, Any]) -> tuple[int, int, int]:
        try:
            pushed_epoch = int(datetime.fromisoformat(
                str(repo.get("pushed_at") or "").replace("Z", "+00:00")
            ).timestamp())
        except (TypeError, ValueError, OverflowError):
            pushed_epoch = 0
        return (
            int(int(repo.get("size_kb") or 0) >= PRIORITY_REPO_SIZE_KB),
            -pushed_epoch,
            int(repo.get("forks") or 0),
        )
    return sorted(found.values(), key=priority)

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
    # Severity describes a detected exchange credential pattern, not its
    # permissions, validity, balance, or ability to withdraw funds.
    return "high" if rule_id in {
        "exchange-api-key", "exchange-api-secret", "exchange-api-passphrase"
    } else "ignored"


def sanitize_report(raw: Any, repo: dict[str, Any]) -> list[dict[str, Any]]:
    safe: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return safe
    # Exchange API credentials only. Wallet signing keys, seed phrases, generic
    # API tokens and unrelated credentials are intentionally excluded.
    allowed_rules = {
        "exchange-api-key", "exchange-api-secret", "exchange-api-passphrase",
    }
    for item in raw:
        if not isinstance(item, dict):
            continue
        rule = str(item.get("RuleID") or "unknown")[:120]
        if rule not in allowed_rules:
            continue
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
        if rule.startswith("exchange-api-"):
            # Extract only a provider label from the assignment name; never persist
            # the matched value, source line, or raw Gitleaks Match field.
            raw_match = str(item.get("Match") or "")
            provider_names = {
                "OKX": r"OKX", "Binance": r"BINANCE", "Coinbase": r"COINBASE",
                "Kraken": r"KRAKEN", "Bybit": r"BYBIT", "KuCoin": r"KUCOIN",
                "Gate.io": r"GATE[._ -]?IO", "Bitget": r"BITGET", "MEXC": r"MEXC",
                "HTX": r"HTX|HUOBI", "Crypto.com": r"CRYPTO[._ -]?COM",
                "Gemini": r"GEMINI", "Bitfinex": r"BITFINEX", "Deribit": r"DERIBIT",
                "Bitstamp": r"BITSTAMP", "BingX": r"BINGX", "CoinEx": r"COINEX",
            }
            provider = next((name for name, pattern in provider_names.items()
                             if re.search(pattern, raw_match, re.IGNORECASE)), "Exchange")
            kind = rule.removeprefix("exchange-api-")
            safe_description = f"{provider} exchange API {kind} candidate; permissions unknown."
            classification = type(classification)(
                classification.category, f"exchange_api_{kind}", classification.confidence,
                "Exchange-specific API credential pattern; permissions have not been verified."
            )
        else:
            safe_description = description
        safe.append({
            "fingerprint": fingerprint,
            "repository_full_name": repo["full_name"],
            "ecosystem": repo["ecosystem"],
            "severity": classify(rule, description),
            "classification": classification.category,
            "secret_type": classification.secret_type,
            "confidence": classification.confidence,
            "rule_id": rule,
            "description": safe_description,
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


def _post_event_with_retry(event: str, run: dict[str, Any], summary: dict[str, Any],
                          repo: dict[str, Any] | None = None,
                          findings: list[dict[str, Any]] | None = None) -> bool:
    for attempt in range(3):
        try:
            send_event(event, run, summary, repo, findings)
            return True
        except Exception as exc:
            print(f"Dashboard update attempt {attempt + 1}/3 failed ({type(exc).__name__}); scan continues.")
            if attempt < 2:
                time.sleep(2 ** attempt)
    return False


def _registry_lookup(repositories: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if not repositories:
        return {}
    payload = {"event": "registry", "repository_names": [r["full_name"] for r in repositories]}
    auth_headers = {"Content-Type": "application/json", "x-vercel-protection-bypass": VERCEL_BYPASS}
    if WORKER_INGEST_TOKEN:
        auth_headers["x-worker-token"] = WORKER_INGEST_TOKEN
    else:
        auth_headers["Authorization"] = f"Bearer {github_oidc_token()}"
    response = requests.post(INGEST_URL, headers=auth_headers, json=payload, timeout=30)
    response.raise_for_status()
    rows = response.json().get("repositories", [])
    return {r["full_name"]: r for r in rows if isinstance(r, dict) and r.get("full_name")}


def main() -> None:
    if not INGEST_URL.startswith("https://"):
        raise RuntimeError("INGEST_URL must be an HTTPS endpoint.")
    if not VERCEL_BYPASS:
        raise RuntimeError("Set VERCEL_AUTOMATION_BYPASS_SECRET for the protected Vercel ingestion endpoint.")
    if not WORKER_INGEST_TOKEN and not os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL"):
        raise RuntimeError("Set WORKER_INGEST_TOKEN for a hosted worker or run inside GitHub Actions.")

    run_id = str(uuid.uuid4())
    run = {"id": run_id, "status": "running",
           "trigger_source": "hosted-worker" if WORKER_INGEST_TOKEN else "github-actions",
           "started_at": utc_now(), "completed_at": None,
           "repositories_discovered": 0, "repositories_scanned": 0, "findings_total": 0}
    summary: dict[str, Any] = {
        "phase": "discovering",
        "message": "Discovering public crypto repositories; scans start as soon as each batch is found.",
        "progress_percent": 0, "current_repository": None, "status_counts": {},
        "repositories": [], "ecosystems": list(EXCHANGE_PROVIDERS),
        "repositories_skipped_unchanged": 0,
    }
    _post_event_with_retry("progress", run, summary)
    work_queue: queue.Queue[Any] = queue.Queue(maxsize=max(8, MAX_REPOS))
    discovery_errors: list[str] = []
    discovered_names: set[str] = set()
    state_lock = threading.Lock()
    counts: dict[str, int] = {}

    def publish_discovery(index: int, total: int, ecosystem: str, found_count: int,
                          newly_added: list[dict[str, Any]]) -> None:
        # Registry lookup is performed batch-by-batch, while workers continue
        # scanning repositories already queued from earlier search categories.
        changed: list[dict[str, Any]] = []
        try:
            previous = _registry_lookup(newly_added)
        except Exception as exc:
            previous = {}
            print(f"Registry lookup unavailable for {ecosystem} ({type(exc).__name__}); scanning candidates without skip.")
        for repo in newly_added:
            repo["head_sha"] = default_branch_head(repo)
            prior = previous.get(repo["full_name"], {})
            unchanged = (prior.get("latest_status") == "completed"
                         and bool(repo.get("head_sha"))
                         and prior.get("last_scanned_commit") == repo.get("head_sha"))
            if unchanged:
                with state_lock:
                    summary["repositories_skipped_unchanged"] += 1
                continue
            changed.append(repo)
            with state_lock:
                discovered_names.add(repo["full_name"])
                summary["repositories"].append({
                    "full_name": repo["full_name"], "html_url": repo["html_url"],
                    "ecosystem": repo["ecosystem"], "status": "pending",
                })
        for repo in changed:
            work_queue.put(repo)
        with state_lock:
            run["repositories_discovered"] = found_count
            summary["phase"] = "discovering_and_scanning"
            summary["message"] = (
                f"Searching {ecosystem} ({index}/{total}); {found_count} unique repositories found. "
                f"{work_queue.qsize()} waiting for scan workers."
            )
            summary["progress_percent"] = min(10, round(index / max(1, total) * 10))
        _post_event_with_retry("progress", run, summary)

    def producer() -> None:
        try:
            discover(publish_discovery)
        except Exception as exc:
            discovery_errors.append(type(exc).__name__)
            print(f"Repository discovery stopped safely ({type(exc).__name__}); queued work will finish.")
        finally:
            for _ in range(worker_count):
                work_queue.put(None)

    worker_count = min(4, max(1, int(os.getenv("SCAN_WORKERS", "3"))))
    producer_thread = threading.Thread(target=producer, name="repository-discovery", daemon=True)
    producer_thread.start()
    all_findings: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    completed_count = 0
    futures: dict[Any, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        sentinels = 0
        while sentinels < worker_count or futures:
            while sentinels < worker_count and len(futures) < worker_count:
                item = work_queue.get()
                if item is None:
                    sentinels += 1
                    continue
                futures[pool.submit(scan_repository, item)] = item
                item["status"] = "scanning"
                _post_event_with_retry("progress", run, summary, item)
                print(f"Started scanning {item['full_name']} ({item['ecosystem']}); workers={worker_count}.")
            if futures:
                done, _ = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    repo = futures.pop(future)
                    try:
                        status, findings = future.result()
                    except Exception as exc:
                        status, findings = "worker_error", []
                        print(f"Repository worker failed for {repo['full_name']} ({type(exc).__name__}).")
                    repo["status"] = status
                    completed_count += int(status == "completed")
                    status_counts[status] = status_counts.get(status, 0) + 1
                    remaining = max(0, 3000 - len(all_findings))
                    batch = findings[:remaining]
                    all_findings.extend(batch)
                    run["repositories_scanned"] = completed_count
                    run["findings_total"] = len(all_findings)
                    summary["status_counts"] = dict(status_counts)
                    total_known = max(1, len(summary["repositories"]))
                    summary["progress_percent"] = min(99, round(
                        completed_count / total_known * 100
                    ))
                    summary["message"] = f"Finished {repo['full_name']}: {status}."
                    for entry in summary["repositories"]:
                        if entry["full_name"] == repo["full_name"]:
                            entry["status"] = status
                            entry["finding_count"] = len(findings)
                            break
                    if batch:
                        for offset in range(0, len(batch), 250):
                            _post_event_with_retry("progress", run, summary, repo, batch[offset:offset + 250])
                    else:
                        _post_event_with_retry("progress", run, summary, repo)
                    if status == "completed":
                        _post_event_with_retry("repository_complete", run, summary, repo)
    producer_thread.join()
    finished = utc_now()
    run["status"] = "completed" if not discovery_errors else "partial"
    run["completed_at"] = finished
    summary["phase"] = "completed" if not discovery_errors else "partial"
    summary["current_repository"] = None
    summary["progress_percent"] = 100
    summary["message"] = (
        f"Scan finished: {completed_count} repositories scanned; "
        f"{summary['repositories_skipped_unchanged']} unchanged skipped."
    )
    if discovery_errors:
        summary["discovery_error"] = discovery_errors[0]
    _post_event_with_retry("complete", run, summary)
    print(summary["message"])


from concurrent.futures import FIRST_COMPLETED, wait


if __name__ == "__main__":
    main()
