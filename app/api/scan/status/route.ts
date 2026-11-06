import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const OWNER = "teddyjeremy";
const REPOSITORY = "Crypto-Secret-Exposure-Hunter";
const WORKFLOWS = ["crypto-scan.yml", "web-exposure-scan.yml"];

export async function GET() {
  const token = process.env.GITHUB_DISPATCH_TOKEN;
  if (!token) {
    return NextResponse.json({ available: false, active: false, error: "Workflow status is unavailable because GITHUB_DISPATCH_TOKEN is not configured." }, {
      status: 503, headers: { "Cache-Control": "no-store" }
    });
  }

  try {
    const headers = {
      "Accept": "application/vnd.github+json",
      "Authorization": `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28"
    };
    const responses = await Promise.all(WORKFLOWS.map(async (workflow) => {
      const response = await fetch(
        `https://api.github.com/repos/${OWNER}/${REPOSITORY}/actions/workflows/${workflow}/runs?per_page=10`,
        { headers, cache: "no-store", signal: AbortSignal.timeout(10000) }
      );
      if (!response.ok) throw new Error(`GitHub workflow status returned HTTP ${response.status}`);
      const body = await response.json() as { workflow_runs?: Array<{
        id: number; name: string; status: string; conclusion: string | null;
        html_url: string; created_at: string; run_started_at?: string | null;
      }> };
      const runs = body.workflow_runs || [];
      const active = runs.find((run) => run.status === "queued" || run.status === "in_progress" || run.status === "waiting" || run.status === "requested");
      return {
        workflow,
        active: active ? {
          id: active.id, name: active.name, status: active.status,
          url: active.html_url, created_at: active.created_at
        } : null
      };
    }));
    const active = responses.filter((item) => item.active !== null);
    return NextResponse.json({
      available: true,
      active: active.length > 0,
      workflows: responses
    }, { headers: { "Cache-Control": "no-store, max-age=0" } });
  } catch {
    return NextResponse.json({
      available: false,
      active: true,
      error: "Could not verify GitHub workflow status. Starting another scan is temporarily disabled for safety."
    }, { status: 503, headers: { "Cache-Control": "no-store" } });
  }
}
