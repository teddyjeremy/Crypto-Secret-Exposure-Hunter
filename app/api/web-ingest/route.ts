import { NextRequest, NextResponse } from "next/server";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { getDb } from "@/lib/db";

export const runtime = "nodejs";
const ISSUER = "https://token.actions.githubusercontent.com";
const AUDIENCE = "crypto-secret-exposure-hunter";
const REPOSITORY = "teddyjeremy/Crypto-Secret-Exposure-Hunter";
const WORKFLOW = `${REPOSITORY}/.github/workflows/web-exposure-scan.yml@refs/heads/main`;
const JWKS = createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks`));
const clean = (v: unknown, max = 500) => typeof v === "string" ? v.slice(0, max) : "";
const integer = (v: unknown) => typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : null;

async function authorized(request: NextRequest) {
  const header = request.headers.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return false;
  try {
    const { payload } = await jwtVerify(token, JWKS, { issuer: ISSUER, audience: AUDIENCE });
    return payload.repository === REPOSITORY && payload.ref === "refs/heads/main"
      && payload.workflow_ref === WORKFLOW
      && ["schedule", "workflow_dispatch"].includes(String(payload.event_name));
  } catch { return false; }
}

export async function POST(request: NextRequest) {
  if (!await authorized(request)) return NextResponse.json({ error: "Unauthorized workflow identity" }, { status: 401 });
  const length = Number(request.headers.get("content-length") || 0);
  if (length > 4_000_000) return NextResponse.json({ error: "Payload too large" }, { status: 413 });
  let body: any;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Invalid JSON" }, { status: 400 }); }
  if (body?.event === "registry") {
    const hosts = Array.isArray(body?.hosts) ? [...new Set(body.hosts.slice(0, 5000)
      .map((v: unknown) => clean(v, 253).toLowerCase())
      .filter((v: string) => /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(v)))] : [];
    try {
      const sql = getDb();
      const rows = hosts.length
        ? await sql`SELECT host FROM website_scan_targets WHERE host = ANY(${hosts}::text[])
            AND last_status = 'completed' AND last_scanned_at >= NOW() - INTERVAL '30 days'`
        : [];
      return NextResponse.json({ ok: true, recent_hosts: rows.map((row: any) => row.host) },
        { headers: { "Cache-Control": "no-store" } });
    } catch {
      return NextResponse.json({ error: "Website scan registry unavailable" }, { status: 503 });
    }
  }
  if (!/^[a-f0-9-]{36}$/i.test(clean(body?.run_id, 36))) return NextResponse.json({ error: "Invalid run ID" }, { status: 400 });
  const results = Array.isArray(body?.results) ? body.results.slice(0, 1000) : [];
  const sitesDiscovered = integer(body?.sites_discovered) ?? 0;
  const sitesScanned = integer(body?.sites_scanned) ?? 0;
  const findings = results.flatMap((site: any) => {
    const host = clean(site?.site, 253).toLowerCase();
    if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) return [];
    return (Array.isArray(site?.findings) ? site.findings.slice(0, 250) : []).flatMap((f: any) => {
      const fingerprint = clean(f?.fingerprint, 64);
      const assetUrl = clean(f?.asset_url, 1000);
      let parsed: URL;
      try { parsed = new URL(assetUrl); } catch { return []; }
      if (!/^[a-f0-9]{64}$/i.test(fingerprint) || parsed.protocol !== "https:"
        || !(parsed.hostname === host || parsed.hostname.endsWith("." + host))) return [];
      const severity = ["critical", "high", "medium", "low"].includes(f?.severity) ? f.severity : "medium";
      const confidence = ["high", "medium", "low"].includes(f?.confidence) ? f.confidence : "low";
      return [{ fingerprint, host, assetUrl, rule: clean(f?.rule_id, 100) || "unknown",
        severity, confidence, line: integer(f?.line_number) }];
    });
  });
  try {
    const sql = getDb();
    const runId = clean(body.run_id, 36);
    await sql`INSERT INTO website_scan_runs(id,status,sites_discovered,sites_scanned,findings_total,completed_at,summary)
      VALUES(${runId},'completed',${sitesDiscovered},${sitesScanned},${findings.length},NOW(),${JSON.stringify({ scanner: "passive-public-web-v1" })}::jsonb)
      ON CONFLICT(id) DO UPDATE SET status='completed',sites_discovered=EXCLUDED.sites_discovered,
      sites_scanned=EXCLUDED.sites_scanned,findings_total=EXCLUDED.findings_total,completed_at=NOW(),summary=EXCLUDED.summary`;
    for (const site of results) {
      const host = clean(site?.site, 253).toLowerCase();
      if (site?.status === "completed" && /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)) {
        await sql`INSERT INTO website_scan_targets(host,last_scanned_at,last_status,last_run_id,updated_at)
          VALUES(${host},NOW(),'completed',${runId},NOW())
          ON CONFLICT(host) DO UPDATE SET last_scanned_at=NOW(),last_status='completed',
          last_run_id=EXCLUDED.last_run_id,updated_at=NOW()`;
        await sql`UPDATE website_findings SET status='not_observed' WHERE site_host=${host} AND status NOT IN ('false_positive','remediated')`;
      }
    }
    for (const f of findings) {
      await sql`INSERT INTO website_findings(fingerprint,site_host,asset_url,rule_id,severity,confidence,line_number,evidence,last_seen_at)
        VALUES(${f.fingerprint},${f.host},${f.assetUrl},${f.rule},${f.severity},${f.confidence},${f.line},
        'redacted; source value intentionally not retained',NOW())
        ON CONFLICT(fingerprint) DO UPDATE SET last_seen_at=NOW(),severity=EXCLUDED.severity,
        confidence=EXCLUDED.confidence,line_number=EXCLUDED.line_number,asset_url=EXCLUDED.asset_url,status=CASE WHEN website_findings.status IN ('not_observed','remediated') THEN 'new' ELSE website_findings.status END`;
    }
    return NextResponse.json({ ok: true, run_id: runId, sites_discovered: sitesDiscovered,
      sites_scanned: sitesScanned, findings_received: findings.length });
  } catch (error) {
    console.error("website scan ingestion failed", error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Could not persist website scan results" }, { status: 500 });
  }
}
