import { NextRequest, NextResponse } from "next/server";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { getDb } from "@/lib/db";

export const runtime = "nodejs";
const ISSUER = "https://token.actions.githubusercontent.com";
const AUDIENCE = "crypto-secret-exposure-hunter";
const REPOSITORY = "teddyjeremy/Crypto-Secret-Exposure-Hunter";
const WORKFLOW = `${REPOSITORY}/.github/workflows/crypto-scan.yml@refs/heads/main`;
const JWKS = createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks`));
const clean = (value: unknown, max = 500) => typeof value === "string" ? value.slice(0, max) : "";
const integer = (value: unknown) => typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : 0;

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
  if (length > 100_000) return NextResponse.json({ error: "Payload too large" }, { status: 413 });
  let body: any;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Invalid JSON" }, { status: 400 }); }
  const runId = clean(body?.run_id, 100);
  if (!/^[-a-zA-Z0-9_]{6,100}$/.test(runId)) return NextResponse.json({ error: "Invalid run id" }, { status: 400 });

  try {
    const sql = getDb();
    const status = ["running", "completed", "failed"].includes(body?.status) ? body.status : "running";
    const summary = {
      progress: {
        stage: clean(body?.stage, 60) || "starting",
        current_repository: clean(body?.current_repository, 200) || null,
        last_repository: clean(body?.last_repository, 200) || null,
        processed: integer(body?.processed),
        status_counts: body?.status_counts && typeof body.status_counts === "object" ? body.status_counts : {},
        updated_at: new Date().toISOString()
      }
    };
    await sql`INSERT INTO scan_runs(id,status,trigger_source,started_at,completed_at,repositories_discovered,repositories_scanned,findings_total,summary)
      VALUES(${runId},${status},'github-actions',${body?.started_at || new Date().toISOString()},${status === "completed" || status === "failed" ? new Date().toISOString() : null},${integer(body?.discovered)},${integer(body?.scanned)},${integer(body?.findings_total)},${JSON.stringify(summary)}::jsonb)
      ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,
      completed_at=EXCLUDED.completed_at,
      repositories_discovered=EXCLUDED.repositories_discovered,
      repositories_scanned=EXCLUDED.repositories_scanned,
      findings_total=EXCLUDED.findings_total,summary=EXCLUDED.summary`;

    const repo = body?.repository;
    if (repo && typeof repo === "object") {
      const fullName = clean(repo.full_name, 200);
      if (/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(fullName)) {
        await sql`INSERT INTO repositories(full_name,html_url,ecosystem,description,stars,default_branch,last_scanned_at,latest_status,updated_at)
          VALUES(${fullName},${clean(repo.html_url,500)},${clean(repo.ecosystem,80)||"Other Web3"},${clean(repo.description,300)||null},${integer(repo.stars)},${clean(repo.default_branch,120)||null},NOW(),${clean(repo.status,30)||"completed"},NOW())
          ON CONFLICT(full_name) DO UPDATE SET html_url=EXCLUDED.html_url,ecosystem=EXCLUDED.ecosystem,
          description=EXCLUDED.description,stars=EXCLUDED.stars,default_branch=EXCLUDED.default_branch,
          last_scanned_at=NOW(),latest_status=EXCLUDED.latest_status,updated_at=NOW()`;
      }
    }
    return NextResponse.json({ ok: true, run_id: runId, stage: summary.progress.stage });
  } catch (error) {
    console.error("progress update failed", error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "Could not persist scan progress." }, { status: 500 });
  }
}
