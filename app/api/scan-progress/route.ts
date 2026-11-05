import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const sql = getDb();
    await sql`UPDATE scan_runs SET status='failed',completed_at=NOW(),summary=summary || jsonb_build_object('phase','failed','message','The scan worker stopped reporting before completion.') WHERE status='running' AND started_at < NOW() - INTERVAL '4 hours'`;
    const rows = await sql`SELECT id,status,started_at,completed_at,repositories_discovered,repositories_scanned,findings_total,summary,created_at
      FROM scan_runs ORDER BY created_at DESC LIMIT 1`;
    if (!rows.length) return NextResponse.json({ run: null }, { headers: { "Cache-Control": "no-store" } });
    return NextResponse.json({ run: rows[0] }, { headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "Scan progress is temporarily unavailable." }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }
}
