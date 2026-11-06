import { NextRequest, NextResponse } from "next/server";
import { getDb } from "@/lib/db";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const OWNER = "teddyjeremy";
const REPOSITORY = "Crypto-Secret-Exposure-Hunter";
const API = `https://api.github.com/repos/${OWNER}/${REPOSITORY}/actions/workflows`;

async function dispatchWorkflow(token: string, workflow: string, inputs: Record<string, string>) {
  const response = await fetch(`${API}/${workflow}/dispatches`, {
    method: "POST",
    headers: {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ ref: "main", inputs }),
    cache: "no-store"
  });
  if (response.status !== 204) {
    const detail = await response.text().catch(() => "");
    return { queued: false, message: response.status === 404 || response.status === 403
      ? "GitHub rejected workflow dispatch. Check that GITHUB_DISPATCH_TOKEN has Actions: write and Metadata: read access."
      : `GitHub workflow dispatch failed (HTTP ${response.status}). ${detail.slice(0, 180)}` };
  }
  return { queued: true, message: "Workflow dispatch accepted by GitHub." };
}

export async function POST(request: NextRequest) {
  const origin = request.headers.get("origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  if (!origin || origin !== new URL(request.url).origin || (fetchSite && fetchSite !== "same-origin")) {
    return NextResponse.json({ error: "This action must be started from the dashboard." }, { status: 403 });
  }

  const token = process.env.GITHUB_DISPATCH_TOKEN;
  if (!token) {
    return NextResponse.json({
      error: "GITHUB_DISPATCH_TOKEN is missing from Vercel. Add a fine-grained GitHub token with Actions: write and Metadata: read access to this repository, then redeploy."
    }, { status: 503 });
  }

  try {
    const sql = getDb();
    const lock = await sql`INSERT INTO scan_dispatch_guard(id,last_requested_at)
      VALUES(1,NOW())
      ON CONFLICT(id) DO UPDATE SET last_requested_at=NOW()
      WHERE scan_dispatch_guard.last_requested_at < NOW() - INTERVAL '1 minute'
      RETURNING id`;
    if (!lock.length) {
      return NextResponse.json({ error: "A scan pair was requested in the last minute. Wait before starting another pair." }, { status: 429 });
    }

    const [repository, website] = await Promise.all([
      dispatchWorkflow(token, "crypto-scan.yml", { max_repos: "40" }),
      dispatchWorkflow(token, "web-exposure-scan.yml", { max_sites: "30" })
    ]);
    const ok = repository.queued && website.queued;
    return NextResponse.json({
      ok,
      repository,
      website,
      message: ok ? "Both scans were dispatched concurrently." : "Check each workflow result; one or both dispatches may have failed."
    }, { status: ok ? 202 : 502, headers: { "Cache-Control": "no-store" } });
  } catch {
    return NextResponse.json({ error: "The dispatcher could not reach GitHub or the scan database." }, { status: 502 });
  }
}
