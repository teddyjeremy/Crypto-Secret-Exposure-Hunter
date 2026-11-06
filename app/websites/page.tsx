import { getDb } from "@/lib/db";

export const dynamic = "force-dynamic";

export default async function WebsitesPage() {
  let runs: any[] = [];
  let findings: any[] = [];
  let error = "";
  try {
    const sql = getDb();
    runs = await sql`SELECT id,status,sites_discovered,sites_scanned,findings_total,started_at,completed_at
      FROM website_scan_runs ORDER BY started_at DESC LIMIT 10`;
    findings = await sql`SELECT site_host,asset_url,rule_id,severity,confidence,line_number,status,last_seen_at
      FROM website_findings WHERE COALESCE(status,'open') NOT IN ('false_positive','remediated') ORDER BY last_seen_at DESC LIMIT 100`;
  } catch {
    error = "Website scan data is temporarily unavailable.";
  }
  return <main className="mx-auto w-full max-w-7xl space-y-8 px-5 py-10">
    <div className="space-y-2">
      <p className="text-sm font-medium text-cyan-400">PASSIVE WEB SCANNER</p>
      <h1 className="text-3xl font-semibold tracking-tight">Website exposure findings</h1>
      <p className="max-w-3xl text-sm text-muted-foreground">Only websites with an open detection are listed below. Websites scanned without a finding are intentionally hidden. Findings are heuristic candidates, not proof that a credential is valid or usable; secret values are never stored.</p>
    </div>
    {error && <p className="rounded-lg border p-4 text-sm">{error}</p>}
    <section className="grid gap-4 sm:grid-cols-3">
      <div className="rounded-xl border p-4"><p className="text-sm text-muted-foreground">Scans recorded</p><p className="mt-2 text-3xl font-semibold">{runs.length}</p></div>
      <div className="rounded-xl border p-4"><p className="text-sm text-muted-foreground">Websites scanned (latest)</p><p className="mt-2 text-3xl font-semibold">{runs[0]?.sites_scanned ?? 0}</p></div>
      <div className="rounded-xl border p-4"><p className="text-sm text-muted-foreground">Open website findings</p><p className="mt-2 text-3xl font-semibold">{findings.length}</p></div>
    </section>
    <section className="space-y-3">
      <h2 className="text-xl font-semibold">Recent scan runs</h2>
      <div className="overflow-x-auto rounded-xl border">
        <table className="w-full text-left text-sm"><thead><tr className="border-b text-muted-foreground"><th className="p-3">Started</th><th className="p-3">Status</th><th className="p-3">Discovered</th><th className="p-3">Scanned</th><th className="p-3">Findings</th></tr></thead>
          <tbody>{runs.map((r) => <tr key={r.id} className="border-b last:border-0"><td className="p-3">{new Date(r.started_at).toLocaleString()}</td><td className="p-3">{r.status}</td><td className="p-3">{r.sites_discovered}</td><td className="p-3">{r.sites_scanned}</td><td className="p-3">{r.findings_total}</td></tr>)}
          {!runs.length && <tr><td colSpan={5} className="p-5 text-muted-foreground">No website scan runs have been ingested yet.</td></tr>}</tbody>
        </table>
      </div>
    </section>
    <section className="space-y-3">
      <h2 className="text-xl font-semibold">Websites with vulnerability findings</h2>
      <div className="overflow-x-auto rounded-xl border">
        <table className="w-full text-left text-sm"><thead><tr className="border-b text-muted-foreground"><th className="p-3">Website</th><th className="p-3">Detection</th><th className="p-3">Severity</th><th className="p-3">Confidence</th><th className="p-3">Line</th><th className="p-3">Asset</th></tr></thead>
          <tbody>{findings.map((f, i) => <tr key={f.site_host + f.asset_url + f.rule_id + i} className="border-b last:border-0"><td className="p-3 font-medium">{f.site_host}</td><td className="p-3">{f.rule_id}</td><td className="p-3">{f.severity}</td><td className="p-3">{f.confidence}</td><td className="p-3">{f.line_number ?? "—"}</td><td className="max-w-xs truncate p-3"><a className="text-cyan-400 underline" href={f.asset_url} target="_blank" rel="noreferrer">Open public asset</a></td></tr>)}
          {!findings.length && <tr><td colSpan={6} className="p-5 text-muted-foreground">No open website findings. Clean websites and discovery-only candidates are hidden.</td></tr>}</tbody>
        </table>
      </div>
    </section>
    <p className="text-xs text-muted-foreground">This scanner only checks publicly accessible pages and linked assets. It does not inspect server-side secrets, connect wallets, submit transactions or verify credential validity.</p>
  </main>;
}
