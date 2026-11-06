import { getDb } from "@/lib/db";
import { ExternalLink, Globe, FileCode2 } from "lucide-react";

export const dynamic = "force-dynamic";

function safeHttpUrl(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    return url.toString();
  } catch {
    return null;
  }
}

function assetLabel(value: string): string {
  try {
    const url = new URL(value);
    const path = url.pathname.split("/").filter(Boolean);
    return path.slice(-2).join("/") || url.hostname;
  } catch {
    return value;
  }
}

export default async function WebsitesPage() {
  let runs: any[] = [];
  let findings: any[] = [];
  let error = "";
  try {
    const sql = getDb();
    runs = await sql`SELECT id,status,sites_discovered,sites_scanned,findings_total,started_at,completed_at
      FROM website_scan_runs ORDER BY started_at DESC LIMIT 10`;
    findings = await sql`SELECT fingerprint,site_host,asset_url,rule_id,severity,confidence,line_number,status,last_seen_at
      FROM website_findings WHERE COALESCE(status,'open') NOT IN ('false_positive','remediated','not_observed')
      ORDER BY last_seen_at DESC LIMIT 100`;
  } catch {
    error = "Website scan data is temporarily unavailable.";
  }
  return <main className="mx-auto w-full max-w-7xl space-y-8 px-5 py-10">
    <div className="space-y-2">
      <p className="text-sm font-medium text-cyan-400">PASSIVE WEB SCANNER</p>
      <h1 className="text-3xl font-semibold tracking-tight">Website exposure findings</h1>
      <p className="max-w-3xl text-sm text-muted-foreground">Each finding links to the affected website and the exact public asset inspected. The reported line is the scanner's detected line in that asset. Findings are heuristic candidates, not proof that a credential is valid or usable; secret values are never stored.</p>
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
      <div><h2 className="text-xl font-semibold">Affected websites and exposed items</h2>
        <p className="text-sm text-muted-foreground">Open the site to identify the project, or open the asset to inspect the exact public file.</p></div>
      <div className="overflow-x-auto rounded-xl border">
        <table className="w-full text-left text-sm"><thead><tr className="border-b text-muted-foreground">
          <th className="p-3">Affected website</th><th className="p-3">Detected item</th><th className="p-3">Severity</th><th className="p-3">Confidence</th><th className="p-3">Detected line</th><th className="p-3">Evidence asset</th>
        </tr></thead>
          <tbody>{findings.map((f, i) => {
            const siteUrl = safeHttpUrl(`https://${f.site_host}`);
            const assetUrl = safeHttpUrl(f.asset_url);
            return <tr key={f.fingerprint || f.site_host + f.asset_url + f.rule_id + i} className="border-b last:border-0 align-top">
              <td className="p-3 font-medium">
                {siteUrl ? <a className="text-cyan-400 underline underline-offset-2" href={siteUrl} target="_blank" rel="noopener noreferrer">
                  <Globe size={13} className="mr-1 inline"/> {f.site_host} <ExternalLink size={11} className="ml-1 inline"/>
                </a> : <span>{f.site_host}</span>}
              </td>
              <td className="p-3"><span className="font-medium">{f.rule_id}</span><div className="mt-1 text-xs text-muted-foreground">Potential exposed item</div></td>
              <td className="p-3">{f.severity}</td>
              <td className="p-3">{f.confidence}</td>
              <td className="p-3 font-mono">{f.line_number != null ? <a className="text-cyan-400 underline underline-offset-2" href={`/websites/source-viewer?asset=${encodeURIComponent(f.asset_url)}&line=${f.line_number}`}>Line {f.line_number} <ExternalLink size={11} className="ml-1 inline" /></a> : "Not available"}</td>
              <td className="max-w-sm p-3">
                {assetUrl && f.line_number != null ? <a className="break-all text-cyan-400 underline underline-offset-2" href={`/websites/source-viewer?asset=${encodeURIComponent(assetUrl)}&line=${f.line_number}`} title="Open the detected line in the source navigator">
                  <FileCode2 size={13} className="mr-1 inline"/>{assetLabel(f.asset_url)} — open at line {f.line_number} <ExternalLink size={11} className="ml-1 inline"/>
                </a> : assetUrl ? <a className="break-all text-cyan-400 underline underline-offset-2" href={assetUrl} target="_blank" rel="noopener noreferrer" title={f.asset_url}>
                  <FileCode2 size={13} className="mr-1 inline"/>{assetLabel(f.asset_url)} <ExternalLink size={11} className="ml-1 inline"/>
                </a> : <span className="text-muted-foreground">Asset URL unavailable</span>}
                <div className="mt-1 break-all text-xs text-muted-foreground">{f.asset_url}</div>
                {assetUrl && <a className="mt-1 inline-block text-xs text-muted-foreground underline" href={assetUrl} target="_blank" rel="noopener noreferrer">Open raw asset</a>}
              </td>
            </tr>;
          })}
          {!findings.length && <tr><td colSpan={6} className="p-5 text-muted-foreground">No open website findings. Clean websites and discovery-only candidates are hidden.</td></tr>}</tbody>
        </table>
      </div>
    </section>
    <p className="text-xs text-muted-foreground">Website line numbers identify the line detected by the scanner in the downloaded public asset. Unlike GitHub source files, ordinary website assets do not provide a universal line-number URL anchor, so the asset opens directly and the exact line is shown here. This scanner does not inspect server-side secrets, connect wallets, submit transactions or verify credential validity.</p>
  </main>;
}
