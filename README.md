# Crypto Secret Exposure Hunter

A defensive research platform for discovering public repositories across 34 major blockchain ecosystem categories, scanning their complete Git history for accidentally committed secrets, and coordinating responsible disclosure.

## Architecture

- **Dashboard:** Next.js, TypeScript, responsive UI hosted on Vercel.
- **Discovery/scanning:** GitHub Actions scheduled worker. It searches public repository metadata and runs Gitleaks against temporary full-history clones.
- **Database:** Neon PostgreSQL. Stores repository metadata, sanitized findings, scan runs and disclosure status.
- **Ingestion:** Authenticated Vercel API endpoint. Only allow-listed metadata is accepted.
- **Safety:** Never stores matched credential values, source snippets, or author emails. Never imports, validates, derives addresses from, authenticates with, or uses a discovered credential.

## Local development

Requirements: Node.js 20+, Python 3.11+, Git, Go 1.23+ (for installing Gitleaks).

```powershell
npm install
Copy-Item .env.example .env.local
npm run dev
```

Set `DATABASE_URL` and `INGEST_TOKEN` in `.env.local`. The database schema is managed in Neon and is also documented in `database/schema.sql`.

## Required configuration

### Vercel environment variables

- `DATABASE_URL`: Neon PostgreSQL connection string (already provisioned for this project).
- Scan ingestion uses GitHub Actions OIDC; no shared ingestion secret is required.
- `GITHUB_DISPATCH_TOKEN`: optional fine-grained GitHub token with Actions: write and Metadata: read on this repository. Required for the dashboard's **Run scan** button.

### GitHub Actions repository secrets

Add these under **Settings → Secrets and variables → Actions → New repository secret**:

- `INGEST_TOKEN`: same value as the sensitive Vercel `INGEST_TOKEN`.
- `VERCEL_AUTOMATION_BYPASS_SECRET`: create a Vercel Deployment Protection → Automation Bypass secret for the project and store the same value here. The Vercel app is SSO-protected; this header allows only the trusted Actions worker to reach the ingestion endpoint.
- `INGEST_URL`: `https://crypto-secret-exposure-hunter.vercel.app/api/ingest`

The scheduled worker uses the workflow-scoped `github.token` for public repository discovery. No wallet credentials are needed.

**Important token setup:** Vercel's `INGEST_TOKEN` is stored as a sensitive, write-only environment variable. Generate a fresh value locally with `python -c "import secrets; print(secrets.token_urlsafe(48))"`, then overwrite `INGEST_TOKEN` with that value in Vercel Project Settings → Environment Variables and add the identical value as the GitHub Actions `INGEST_TOKEN` repository secret. Do not paste the token into issues, commits or chat. Set `INGEST_URL` to the endpoint above. The dashboard's Run scan button additionally requires `GITHUB_DISPATCH_TOKEN` in Vercel.

## Running scans

- The workflow runs daily at 04:17 UTC.
- It can also be started from the dashboard after `GITHUB_DISPATCH_TOKEN` is configured.
- It searches blockchain ecosystem repository topics, deduplicates results, clones each eligible public repository with history, and scans with Gitleaks.
- The worker enforces repository-count, repository-size and per-repository timeout limits.
- GitHub search is rate-limited and returns bounded results. This is not an exhaustive index of GitHub.

## Responsible disclosure

Findings are leads, not proof of a valid, active, funded or compromised wallet. Review repository context and bounty scope. Never test, import, use, publish or transmit credential values. Use the repository's SECURITY.md or private vulnerability reporting channel. The app generates redacted drafts; it does not automatically contact owners.

## Security model and limitations

- The ingestion API requires a bearer token and validates/limits incoming data.
- Only safe metadata is stored: repository, ecosystem, rule identifier, path, line, commit, severity, timestamps and a metadata-derived fingerprint.
- Raw Gitleaks reports and temporary clones are deleted by the worker.
- Secret scanning can produce false positives and may miss custom or unsupported formats.
- A public repository is not blanket authorization for intrusive testing.
- Do not run scans outside your program's scope. Respect GitHub API limits and repository terms.

## License

MIT
