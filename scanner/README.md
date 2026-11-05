# Scanner worker

This worker runs in GitHub Actions, not inside Vercel serverless functions.

- Discovers public repositories using GitHub repository metadata search.
- Clones repositories into temporary directories with Git history.
- Runs Gitleaks locally with redaction enabled.
- Discards all raw reports and temporary clones.
- Sends only an allow-listed set of sanitized metadata to the authenticated ingestion API.

Required Actions secrets:
- `INGEST_URL`: Vercel `/api/ingest` endpoint.
- `INGEST_TOKEN`: same value as Vercel's sensitive `INGEST_TOKEN`.

The worker never imports or uses detected credentials, derives wallet addresses, checks balances, authenticates, signs transactions or transfers funds.
