from __future__ import annotations

"""Passive scanner for information intentionally or accidentally served to browsers.

Only fetches public HTTP(S) pages and assets linked from those pages. It does not
submit forms, connect wallets, call authenticated APIs, or test discovered values.
Raw response bodies and secret-like matches are never written to the report.
"""
import hashlib
import html
import ipaddress
import json
import os
import re
import socket
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag

import requests

USER_AGENT = "CryptoSecretExposureHunter-WebScanner/1.0 (+passive public asset review)"
MAX_ASSETS = min(12, max(1, int(os.getenv("WEB_MAX_ASSETS", "10"))))
MAX_BYTES = int(os.getenv("WEB_MAX_BYTES", "1500000"))
TIMEOUT = min(15, max(3, int(os.getenv("WEB_TIMEOUT_SECONDS", "8"))))
DELAY = max(0.2, float(os.getenv("WEB_REQUEST_DELAY", "0.25")))
CONCURRENCY = min(25, max(1, int(os.getenv("WEB_CONCURRENCY", "20"))))
MAX_SITES = min(1000, max(1, int(os.getenv("WEB_MAX_SITES", "1000"))))
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
OUTPUT = os.getenv("WEB_SCAN_OUTPUT", "web-scan-results.json")
WEB_INGEST_URL = os.getenv("WEB_INGEST_URL", "").strip()
VERCEL_BYPASS = os.getenv("VERCEL_AUTOMATION_BYPASS_SECRET", "").strip()

PATTERNS = [
    # Provider-labelled exchange API credentials only; matched values are never retained.
    ("exchange_api_key", re.compile(r"""(?i)(?:OKX|BINANCE|COINBASE|KRAKEN|BYBIT|KUCOIN|GATEIO|GATE\.IO|BITGET|MEXC|HTX|HUOBI|CRYPTO\.COM|GEMINI|BITFINEX|DERIBIT|BITSTAMP|BINGX|COINEX)[A-Z0-9_ .-]{0,40}(?:API[_ -]?(?:KEY|KEY_ID)|ACCESS[_ -]?KEY|APIKEY)\s*["']?\s*[:=]\s*["']?[A-Za-z0-9_./+=-]{12,160}"""), "high", "medium"),
    ("exchange_api_secret", re.compile(r"""(?i)(?:OKX|BINANCE|COINBASE|KRAKEN|BYBIT|KUCOIN|GATEIO|GATE\.IO|BITGET|MEXC|HTX|HUOBI|CRYPTO\.COM|GEMINI|BITFINEX|DERIBIT|BITSTAMP|BINGX|COINEX)[A-Z0-9_ .-]{0,40}(?:API[_ -]?SECRET|SECRET[_ -]?KEY|APISECRET)\s*["']?\s*[:=]\s*["']?[A-Za-z0-9_./+=-]{12,200}"""), "high", "medium"),
    ("exchange_api_passphrase", re.compile(r"""(?i)(?:OKX|BINANCE|COINBASE|KRAKEN|BYBIT|KUCOIN|GATEIO|GATE\.IO|BITGET|MEXC|HTX|HUOBI|CRYPTO\.COM|GEMINI|BITFINEX|DERIBIT|BITSTAMP|BINGX|COINEX)[A-Z0-9_ .-]{0,40}(?:API[_ -]?PASSPHRASE|PASSPHRASE)\s*["']?\s*[:=]\s*["']?[A-Za-z0-9_./+=-]{8,160}"""), "high", "medium"),

]

class AssetParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.assets = []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "script" and attrs.get("src"):
            self.assets.append(attrs["src"])
        elif tag == "link" and attrs.get("href"):
            rel = (attrs.get("rel") or "").lower()
            href = attrs["href"]
            if "preload" in rel or href.lower().endswith((".js", ".mjs")):
                self.assets.append(href)

def public_host(host: str) -> bool:
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        return bool(records) and all(
            (lambda ip: ip.is_global)(ipaddress.ip_address(record[4][0].split("%")[0]))
            for record in records
        )
    except (OSError, ValueError):
        return False

def safe_url(url: str, base_host: str | None = None) -> str | None:
    try:
        parsed = urlparse(url)
        port = parsed.port
        host_value = parsed.hostname
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not host_value:
        return None
    if parsed.username or parsed.password:
        return None
    if port not in (None, 80, 443):
        return None
    host = host_value.lower().rstrip(".")
    if base_host and host != base_host and not host.endswith("." + base_host):
        # Keep crawling within the registered site; do not follow arbitrary third-party URLs.
        return None
    if not public_host(host):
        return None
    return url

def fetch(url: str, root_host: str):
    current = url
    for _ in range(4):
        checked = safe_url(current, root_host)
        if not checked:
            return None
        try:
            response = requests.get(checked, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/javascript,application/json,*/*"},
                                    timeout=TIMEOUT, stream=True, allow_redirects=False)
        except requests.RequestException:
            return None
        if response.is_redirect:
            location = response.headers.get("Location")
            response.close()
            if not location:
                return None
            current = urljoin(current, location)
            continue
        if response.status_code != 200:
            response.close()
            return None
        content_type = response.headers.get("Content-Type", "").lower()
        chunks, size = [], 0
        try:
            for chunk in response.iter_content(65536):
                size += len(chunk)
                if size > MAX_BYTES:
                    return None
                chunks.append(chunk)
        finally:
            response.close()
        return b"".join(chunks), content_type, checked
    return None

def line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1

def inspect_text(text: str, asset_url: str, findings: list[dict]):
    for rule, pattern, severity, confidence in PATTERNS:
        for match in pattern.finditer(text):
            # Persist metadata only. Never persist matched text or surrounding source.
            line = line_for(text, match.start())
            fingerprint = hashlib.sha256(f"{asset_url}|{rule}|{line}".encode()).hexdigest()
            findings.append({
                "fingerprint": fingerprint,
                "rule_id": rule,
                "severity": severity,
                "confidence": confidence,
                "asset_url": asset_url,
                "line_number": line,
                "evidence": "redacted; source value intentionally not retained",
            })

def scan_site(site: str) -> dict:
    parsed = urlparse(site if "://" in site else "https://" + site)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host or not public_host(host):
        return {"site": site, "status": "skipped_invalid_or_nonpublic_host", "assets_checked": 0, "findings": []}
    start_url = safe_url(site if "://" in site else "https://" + site, host)
    if not start_url:
        return {"site": site, "status": "skipped_invalid_or_nonpublic_host", "assets_checked": 0, "findings": []}
    first = fetch(start_url, host)
    if not first:
        return {"site": site, "status": "unreachable_or_blocked", "assets_checked": 0, "findings": []}
    body, content_type, final_url = first
    findings, assets = [], [final_url]
    page = body.decode("utf-8", errors="replace")
    inspect_text(page, final_url, findings)
    parser = AssetParser()
    parser.feed(page)
    for raw in parser.assets:
        candidate = safe_url(urljoin(final_url, html.unescape(raw)), host)
        if candidate and candidate not in assets:
            assets.append(candidate)
    # Bound work even if a page includes hundreds of script tags.
    assets = assets[:MAX_ASSETS]
    assets_checked = 1
    source_maps = set()
    # Scan the selected JavaScript assets even when the asset list has reached
    # its cap; the cap limits selection, not whether those assets are fetched.
    for asset in assets[1:]:
        time.sleep(DELAY)
        result = fetch(asset, host)
        if not result:
            continue
        assets_checked += 1
        data, ctype, actual = result
        text = data.decode("utf-8", errors="replace")
        inspect_text(text, actual, findings)
        map_match = re.search(r'[#@]\s*sourceMappingURL=([^\s*]+)', text)
        if map_match:
            map_url = safe_url(urljoin(actual, map_match.group(1)), host)
            if map_url and map_url not in assets:
                source_maps.add(map_url)
    # Keep source-map inspection bounded independently from script discovery.
    for map_url in list(source_maps)[:3]:
        time.sleep(DELAY)
        result = fetch(map_url, host)
        if result:
            data, _, actual = result
            assets_checked += 1
            inspect_text(data.decode("utf-8", errors="replace"), actual, findings)
    unique = {f["fingerprint"]: f for f in findings}
    return {"site": host, "status": "completed", "assets_checked": assets_checked,
            "findings": list(unique.values())[:250]}

def discover_sites() -> list[str]:
    """Discover smaller/newer crypto and web3 project sites from public repo metadata.

    Low-fork searches improve discovery of less-copied projects; they do not
    imply that a project is vulnerable or that nobody else has reviewed it.
    """
    queries = [
        "OKX API integration", "OKX trading bot", "OKX exchange SDK",
        "Binance API integration", "Binance trading bot", "Binance connector",
        "Coinbase exchange API", "Kraken API integration", "Bybit API integration",
        "KuCoin API integration", "Gate.io API integration", "Bitget API integration",
        "MEXC API integration", "HTX Huobi API integration",
        "Crypto.com exchange API", "Gemini exchange API", "Bitfinex API integration",
        "Deribit API integration", "Bitstamp API integration", "BingX API integration",
        "CoinEx API integration", "ccxt exchange integration",
        "Freqtrade crypto trading bot exchange API",
        "Hummingbot exchange connector API keys",
        "Jesse trading bot exchange API",
        "OctoBot crypto trading bot exchange API",
        "Superalgos trading bot exchange API",
        "FreqAI trading bot exchange integration",
        "crypto arbitrage bot exchange API",
        "crypto market making bot exchange API",
        "open source crypto trading bot exchange connector",

    ]
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    domains = set()
    for index, query in enumerate(queries, 1):
        try:
            response = requests.get("https://api.github.com/search/repositories",
                params={"q": query + " fork:false archived:false forks:<10",
                        "sort": "updated", "order": "desc", "per_page": 100},
                headers=headers, timeout=20)
            if response.status_code in (403, 429):
                print(f"GitHub discovery rate-limited after {index - 1}/{len(queries)} searches.")
                break
            response.raise_for_status()
            items = response.json().get("items", [])
            added = 0
            for repo in items:
                candidates = [(repo.get("homepage") or "").strip()]
                # README links often contain the live app/docs URL even when the
                # repository homepage field is empty. Fetch only public README text.
                full_name = repo.get("full_name") or ""
                if full_name.count("/") == 1:
                    try:
                        readme = requests.get(
                            f"https://api.github.com/repos/{full_name}/readme",
                            headers={**headers, "Accept": "application/vnd.github.raw+json"},
                            timeout=12,
                        )
                        if readme.status_code == 200:
                            body = readme.text[:300000]
                            candidates.extend(re.findall(r"https?://[^\s\])>\"']+", body)[:12])
                    except requests.RequestException:
                        pass
                for candidate in candidates:
                    if not candidate:
                        continue
                    parsed = urlparse(candidate if "://" in candidate else "https://" + candidate)
                    host = (parsed.hostname or "").lower().rstrip(".")
                    if host and "." in host and public_host(host):
                        # Ignore GitHub itself and common source-hosting mirrors.
                        if host in {"github.com", "www.github.com", "raw.githubusercontent.com"}:
                            continue
                        domains.add("https://" + host)
                        added += 1
            print(f"Discovery {index}/{len(queries)}: {query}; {added} candidate domains.")
        except requests.RequestException as exc:
            print(f"Discovery search failed ({query}): {type(exc).__name__}")
        time.sleep(2.0 if GITHUB_TOKEN else 10.0)
    return sorted(domains)

def main():
    sites = discover_sites()
    try:
        with open("scanner/web_targets.txt", encoding="utf-8") as file:
            sites.extend(line.strip() for line in file if line.strip() and not line.lstrip().startswith("#"))
    except FileNotFoundError:
        pass
    # Normalize candidate hosts before checking the persistent scan registry.
    sites = list(dict.fromkeys(sites))
    discovered_total = len(sites)
    skipped_recent = 0
    if WEB_INGEST_URL and sites:
        request_url = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
        request_token = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
        if not request_url or not request_token or not VERCEL_BYPASS:
            raise RuntimeError("Website registry lookup requires GitHub Actions OIDC and Vercel bypass configuration.")
        token_response = requests.get(request_url, headers={"Authorization": f"Bearer {request_token}"},
                                      params={"audience": "crypto-secret-exposure-hunter"}, timeout=20)
        token_response.raise_for_status()
        oidc_token = token_response.json().get("value")
        if not isinstance(oidc_token, str) or not oidc_token:
            raise RuntimeError("GitHub Actions did not issue an OIDC token for registry lookup.")
        registry = requests.post(WEB_INGEST_URL,
            headers={"Authorization": f"Bearer {oidc_token}",
                     "x-vercel-protection-bypass": VERCEL_BYPASS,
                     "Content-Type": "application/json"},
            json={"event": "registry", "hosts": [urlparse(site).hostname for site in sites[:5000] if urlparse(site).hostname]}, timeout=30)
        registry.raise_for_status()
        visited = set(registry.json().get("recent_hosts", []))
        before = len(sites)
        sites = [site for site in sites if urlparse(site).hostname not in visited]
        skipped_recent = before - len(sites)
        print(f"Persistent deduplication: skipped {skipped_recent} sites scanned successfully in the last 7 days.")
    sites = sites[:MAX_SITES]
    results_by_index = {}
    print(f"Starting passive scan of {len(sites)} candidate websites with {CONCURRENCY} workers.")
    # Parallelize across separate websites; each site retains bounded requests,
    # timeouts, asset limits, same-host restrictions and a per-request delay.
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = {pool.submit(scan_site, site): index for index, site in enumerate(sites)}
        completed = 0
        for future in as_completed(futures):
            index = futures[future]
            try:
                results_by_index[index] = future.result()
            except Exception as exc:
                results_by_index[index] = {
                    "site": sites[index], "status": "scan_error",
                    "assets_checked": 0, "findings": [],
                    "error": type(exc).__name__,
                }
            completed += 1
            result = results_by_index[index]
            print(f"Website progress: {completed}/{len(sites)} completed; "
                  f"status={result['status']}; findings={len(result.get('findings', []))}.")
    results = [results_by_index[i] for i in sorted(results_by_index)]
    payload = {"scanner": "passive-public-web-v1", "sites_discovered": discovered_total,
               "sites_selected": len(sites), "sites_skipped_recent": skipped_recent,
               "sites_scanned": sum(r["status"] == "completed" for r in results),
               "results": results}
    with open(OUTPUT, "w", encoding="utf-8") as file:
        json.dump(payload, file, indent=2)
    print(json.dumps({k: v for k, v in payload.items() if k != "results"}))
    if WEB_INGEST_URL:
        request_url = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
        request_token = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
        if not request_url or not request_token or not VERCEL_BYPASS:
            raise RuntimeError("Website ingestion requires GitHub Actions OIDC and Vercel bypass configuration.")
        token_response = requests.get(request_url, headers={"Authorization": f"Bearer {request_token}"},
                                      params={"audience": "crypto-secret-exposure-hunter"}, timeout=20)
        token_response.raise_for_status()
        oidc_token = token_response.json().get("value")
        if not isinstance(oidc_token, str) or not oidc_token:
            raise RuntimeError("GitHub Actions did not issue an OIDC token.")
        ingest = requests.post(WEB_INGEST_URL,
            headers={"Authorization": f"Bearer {oidc_token}",
                     "x-vercel-protection-bypass": VERCEL_BYPASS,
                     "Content-Type": "application/json"},
            json={"run_id": str(uuid.uuid4()), "sites_discovered": payload["sites_discovered"],
                  "sites_scanned": payload["sites_scanned"], "sites_skipped_recent": skipped_recent, "results": results},
            timeout=60)
        if ingest.status_code != 200:
            raise RuntimeError(f"Website result ingestion failed with HTTP {ingest.status_code}.")
        print("Redacted website scan results ingested into the dashboard.")

if __name__ == "__main__":
    main()
