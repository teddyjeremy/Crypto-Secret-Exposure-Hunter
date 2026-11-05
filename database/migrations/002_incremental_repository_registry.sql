-- Add durable fields used by the free incremental GitHub Actions scanner.
-- Safe additive migration: existing repository and finding records are preserved.
ALTER TABLE repositories
  ADD COLUMN IF NOT EXISTS github_repo_id BIGINT,
  ADD COLUMN IF NOT EXISTS last_pushed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_scanned_commit TEXT;

CREATE INDEX IF NOT EXISTS idx_repositories_last_pushed_at
  ON repositories(last_pushed_at);
