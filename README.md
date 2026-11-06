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

Set `DATABASE_URL` in `.env.local`. The database schema is managed in Neon and is also documented in `database/schema.sql`.

## Required configuration

### Vercel environment variables

- `DATABASE_URL`: Neon PostgreSQL connection string (already provisioned for this project).
- `GITHUB_DISPATCH_TOKEN`: optional fine-grained GitHub token with Actions: write and Metadata: read on this repository. Required for the dashboard's **Run scan** button.

### GitHub Actions repository secrets

Add one secret under **Settings → Secrets and variables → Actions → New repository secret**:

- `VERCEL_AUTOMATION_BYPASS_SECRET`: create a Deployment Protection → Automation Bypass secret in the Vercel project and store the same value here. It allows the scheduled worker to reach the SSO-protected Vercel ingestion endpoint.

The workflow obtains a short-lived GitHub OIDC token at runtime. The Vercel API verifies the issuer, audience, repository, main branch, workflow path and allowed event. There is no shared static ingestion token. The ingestion URL is configured in the workflow file.

## Running scans

- The repository workflow also runs every 30 minutes; the website workflow runs weekly. Manual dashboard dispatch starts both concurrently.
- It can also be started from the dashboard after `GITHUB_DISPATCH_TOKEN` is configured.
- It searches blockchain ecosystem repository topics, deduplicates results, clones each eligible public repository with history, and scans with Gitleaks.
- The worker enforces repository-count, repository-size and per-repository timeout limits.
- GitHub search is rate-limited and returns bounded results. This is not an exhaustive index of GitHub.

## Responsible disclosure

Findings are leads, not proof of a valid, active, funded or compromised wallet. Review repository context and bounty scope. Never test, import, use, publish or transmit credential values. Use the repository's SECURITY.md or private vulnerability reporting channel. The app generates redacted drafts; it does not automatically contact owners.

## Security model and limitations

- The ingestion API verifies a short-lived GitHub Actions OIDC JWT and validates/limits incoming data.
- Only safe metadata is stored: repository, ecosystem, rule identifier, path, line, commit, severity, timestamps and a metadata-derived fingerprint.
- Raw Gitleaks reports and temporary clones are deleted by the worker.
- Secret scanning can produce false positives and may miss custom or unsupported formats.
- A public repository is not blanket authorization for intrusive testing.
- Do not run scans outside your program's scope. Respect GitHub API limits and repository terms.

## License

MIT
