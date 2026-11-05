CREATE TABLE IF NOT EXISTS scan_runs (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'queued',
  trigger_source TEXT NOT NULL DEFAULT 'manual',
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  repositories_discovered INTEGER NOT NULL DEFAULT 0,
  repositories_scanned INTEGER NOT NULL DEFAULT 0,
  findings_total INTEGER NOT NULL DEFAULT 0,
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS repositories (
  full_name TEXT PRIMARY KEY,
  html_url TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  description TEXT,
  stars INTEGER NOT NULL DEFAULT 0,
  default_branch TEXT,
  last_scanned_at TIMESTAMPTZ,
  latest_status TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS findings (
  id BIGSERIAL PRIMARY KEY,
  fingerprint TEXT NOT NULL UNIQUE,
  repository_full_name TEXT NOT NULL REFERENCES repositories(full_name) ON DELETE CASCADE,
  ecosystem TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
  rule_id TEXT NOT NULL,
  description TEXT,
  file_path TEXT NOT NULL,
  line_number INTEGER,
  commit_sha TEXT,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','triaged','false_positive','disclosed','remediated')),
  triage_notes TEXT
);
CREATE INDEX IF NOT EXISTS findings_repo_idx ON findings(repository_full_name);
CREATE INDEX IF NOT EXISTS findings_severity_idx ON findings(severity);
CREATE INDEX IF NOT EXISTS findings_status_idx ON findings(status);
CREATE TABLE IF NOT EXISTS disclosures (
  id BIGSERIAL PRIMARY KEY,
  finding_fingerprint TEXT NOT NULL REFERENCES findings(fingerprint) ON DELETE CASCADE,
  channel TEXT NOT NULL DEFAULT 'private',
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','ready','sent','acknowledged','resolved','closed')),
  recipient TEXT,
  message TEXT NOT NULL,
  sent_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS disclosures_finding_idx ON disclosures(finding_fingerprint);
