# Scanner worker

This worker runs in GitHub Actions, not inside Vercel serverless functions.

- Discovers public repositories using GitHub repository metadata search.
- Clones repositories into temporary directories with Git history.
- Runs Gitleaks locally with redaction enabled.
- Discards all raw reports and temporary clones.
- Sends only an allow-listed set of sanitized metadata to the authenticated ingestion API.

Required Actions secrets:
- `VERCEL_AUTOMATION_BYPASS_SECRET`: Vercel Deployment Protection automation-bypass secret.

The worker requests a short-lived GitHub Actions OIDC token. The Vercel ingestion API validates its issuer, audience, repository, branch, workflow path and event. No static ingestion token is used.

The worker never imports or uses detected credentials, derives wallet addresses, checks balances, authenticates, signs transactions or transfers funds.
