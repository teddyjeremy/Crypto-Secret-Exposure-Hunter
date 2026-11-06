-- Persistent website scan deduplication.
-- Successfully scanned hosts are skipped for 30 days, then become eligible again.
CREATE TABLE IF NOT EXISTS public.website_scan_targets (
  host text PRIMARY KEY,
  last_scanned_at timestamptz NOT NULL DEFAULT NOW(),
  last_status text NOT NULL DEFAULT 'completed',
  last_run_id text,
  updated_at timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS website_scan_targets_last_scanned_idx
  ON public.website_scan_targets(last_scanned_at DESC);
