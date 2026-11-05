from __future__ import annotations

import os
import uuid
from typing import Any

import requests

from scan import (
    ECOSYSTEMS, INGEST_URL, VERCEL_BYPASS, discover, github_oidc_token,
    scan_repository, utc_now,
)

PROGRESS_URL = INGEST_URL.removesuffix("/api/ingest") + "/api/progress"


def post_json(url: str, payload: dict[str, Any]) -> requests.Response:
    token = github_oidc_token()
    return requests.post(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "x-vercel-protection-bypass": VERCEL_BYPASS,
        },
        json=payload,
        timeout=45,
    )


def update_progress(
    run_id: str,
    started: str,
    stage: str,
    discovered: int,
    processed: int,
    scanned: int,
    findings_total: int,
    status_counts: dict[str, int],
    current_repository: str | None = None,
    last_repository: str | None = None,
    repository: dict[str, Any] | None = None,
    status: str = "running",
) -> None:
    payload = {
        "run_id": run_id,
        "started_at": started,
        "stage": stage,
        "status": status,
        "discovered": discovered,
        "processed": processed,
        "scanned": scanned,
        "findings_total": findings_total,
        "status_counts": status_counts,
        "current_repository": current_repository,
        "last_repository": last_repository,
        "repository": {
            key: repository.get(key)
            for key in (
                "full_name", "html_url", "ecosystem", "description",
                "stars", "default_branch", "status",
            )
        } if repository else None,
    }
    try:
        response = post_json(PROGRESS_URL, payload)
        if response.status_code != 200:
            print(f"Progress update rejected (HTTP {response.status_code}); scan will continue.", flush=True)
    except Exception as exc:
        print(f"Progress update unavailable ({type(exc).__name__}); scan will continue.", flush=True)


def main() -> None:
    if not INGEST_URL.startswith("https://"):
        raise RuntimeError("INGEST_URL must be an HTTPS endpoint.")
    if not VERCEL_BYPASS:
        raise RuntimeError("Add VERCEL_AUTOMATION_BYPASS_SECRET to GitHub Actions secrets.")

    run_id = str(uuid.uuid4())
    started = utc_now()
    print("Starting defensive public-repository scan.", flush=True)
    update_progress(run_id, started, "discovering_repositories", 0, 0, 0, 0, {})

    repositories = discover()
    print(f"Discovered {len(repositories)} candidate repositories across {len(ECOSYSTEMS)} ecosystems.", flush=True)
    all_findings: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    scanned = 0
    processed = 0
    update_progress(
        run_id, started, "scanning_repositories", len(repositories), 0, 0, 0, status_counts
    )

    for index, repo in enumerate(repositories, start=1):
        name = repo["full_name"]
        print(f"[{index}/{len(repositories)}] Scanning {name} ({repo['ecosystem']})", flush=True)
        try:
            result_status, findings = scan_repository(repo)
        except Exception as exc:
            result_status, findings = "worker_error", []
            print(f"Repository scan failed for {name}: {type(exc).__name__}", flush=True)

        repo["status"] = result_status
        processed += 1
        scanned += int(result_status == "completed")
        status_counts[result_status] = status_counts.get(result_status, 0) + 1
        if len(all_findings) < 3000:
            all_findings.extend(findings[: 3000 - len(all_findings)])

        update_progress(
            run_id=run_id,
            started=started,
            stage="scanning_repositories",
            discovered=len(repositories),
            processed=processed,
            scanned=scanned,
            findings_total=len(all_findings),
            status_counts=status_counts,
            current_repository=None,
            last_repository=name,
            repository=repo,
        )
        print(
            f"Progress: {processed}/{len(repositories)} processed; "
            f"{scanned} completed; {len(all_findings)} sanitized candidates.",
            flush=True,
        )

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
            "summary": {"status_counts": status_counts, "ecosystems": list(ECOSYSTEMS.keys())},
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
    print("Uploading sanitized scan results to the dashboard.", flush=True)
    response = post_json(INGEST_URL, payload)
    if response.status_code != 200:
        update_progress(
            run_id, started, "result_ingestion_failed", len(repositories), processed,
            scanned, len(all_findings), status_counts, status="failed"
        )
        raise RuntimeError(
            f"Result ingestion failed with HTTP {response.status_code}; response body suppressed."
        )

    update_progress(
        run_id, started, "completed", len(repositories), processed, scanned,
        len(all_findings), status_counts, status="completed"
    )
    print(
        f"Completed: {scanned}/{len(repositories)} repositories scanned; "
        f"{len(all_findings)} sanitized findings ingested.",
        flush=True,
    )


if __name__ == "__main__":
    main()
