import { neon } from "@neondatabase/serverless";
export function getDb() {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL is not configured");
  return neon(url);
}
export async function getDashboardData() {
  const sql = getDb();
  const [stats] = await sql`SELECT
    (SELECT COUNT(*)::int FROM repositories) AS repositories,
    (SELECT COUNT(*)::int FROM findings WHERE classification='secret_candidate' AND status NOT IN ('false_positive','remediated')) AS open_findings,
    (SELECT COUNT(*)::int FROM findings WHERE severity='critical' AND classification='secret_candidate' AND status NOT IN ('false_positive','remediated')) AS critical,
    (SELECT COUNT(*)::int FROM scan_runs WHERE status='completed') AS completed_scans`;
  const runs = await sql`SELECT id,status,trigger_source,started_at,completed_at,repositories_discovered,repositories_scanned,findings_total,created_at FROM scan_runs ORDER BY created_at DESC LIMIT 8`;
  const findings = await sql`SELECT id,fingerprint,repository_full_name,ecosystem,severity,classification,secret_type,confidence,rule_id,file_path,line_number,commit_sha,status,last_seen_at FROM findings WHERE classification <> 'public_information' ORDER BY last_seen_at DESC LIMIT 8`;
  const ecosystems = await sql`SELECT ecosystem,COUNT(*)::int AS count FROM findings WHERE classification='secret_candidate' AND status NOT IN ('false_positive','remediated') GROUP BY ecosystem ORDER BY count DESC LIMIT 8`;
  return { stats, runs, findings, ecosystems };
}
export async function getFindings(filters?: {severity?: string; status?: string; search?: string}) {
  const sql = getDb();
  const rows = await sql`SELECT id,fingerprint,repository_full_name,ecosystem,severity,classification,secret_type,confidence,rule_id,description,file_path,line_number,commit_sha,status,first_seen_at,last_seen_at,triage_notes FROM findings WHERE classification <> 'public_information' ORDER BY last_seen_at DESC LIMIT 500`;
  return rows.filter((row:any) =>
    (!filters?.severity || row.severity===filters.severity) &&
    (!filters?.status || row.status===filters.status) &&
    (!filters?.search || String(row.repository_full_name+" "+row.file_path+" "+row.rule_id+" "+row.secret_type).toLowerCase().includes(filters.search.toLowerCase()))
  );
}
export async function getDisclosures() {
  const sql = getDb();
  return sql`SELECT d.id,d.finding_fingerprint,d.channel,d.status,d.recipient,d.message,d.created_at,d.updated_at,f.repository_full_name,f.file_path,f.severity,f.rule_id,f.secret_type,f.confidence FROM disclosures d JOIN findings f ON f.fingerprint=d.finding_fingerprint ORDER BY d.created_at DESC LIMIT 200`;
}