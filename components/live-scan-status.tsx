"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Activity, Radio } from "lucide-react";

type Run = {
  id: string; status: string; started_at?: string | null;
  repositories_discovered?: number; repositories_scanned?: number;
  findings_total?: number; summary?: { progress?: {
    stage?: string; current_repository?: string | null; last_repository?: string | null;
    processed?: number; status_counts?: Record<string, number>; updated_at?: string;
  }};
};

export function LiveScanStatus({ run }: { run: Run | null }) {
  const router = useRouter();
  useEffect(() => {
    const timer = window.setInterval(() => router.refresh(), 10000);
    return () => window.clearInterval(timer);
  }, [router]);

  if (!run) return null;
  const progress = run.summary?.progress;
  const active = run.status === "running" || run.status === "queued";
  const discovered = Number(run.repositories_discovered || 0);
  const scanned = Number(run.repositories_scanned || 0);
  const processed = Number(progress?.processed || 0);
  const percent = discovered > 0 ? Math.min(100, Math.round(processed / discovered * 100)) : 0;
  const stage = progress?.stage || (active ? "Starting scanner" : run.status);
  const counts = progress?.status_counts || {};

  return <section className="panel" style={{ marginBottom: 20 }}>
    <div className="panel-head">
      <div>
        <div className="panel-title">Live scan monitor</div>
        <div className="panel-kicker" style={{ marginTop: 4 }}>AUTO-REFRESHES EVERY 10 SECONDS</div>
      </div>
      <span className={`badge ${active ? "medium" : run.status === "completed" ? "new" : "critical"}`}>
        {active ? "RUNNING" : run.status.toUpperCase()}
      </span>
    </div>
    <div style={{ display: "flex", alignItems: "center", gap: 9, color: "var(--muted)", fontSize: 12, marginBottom: 12 }}>
      {active ? <Radio size={15} /> : <Activity size={15} />}
      <span>{stage.replaceAll("_", " ")}</span>
      <span className="mono" style={{ marginLeft: "auto" }}>{String(run.id).slice(0, 8)}</span>
    </div>
    <div className="grid stats" style={{ marginBottom: 12 }}>
      <div className="stat-card"><div className="stat-head">Repositories processed</div><div className="stat-value">{processed}{discovered ? ` / ${discovered}` : ""}</div></div>
      <div className="stat-card"><div className="stat-head">Successful scans</div><div className="stat-value">{scanned}</div></div>
      <div className="stat-card"><div className="stat-head">Sanitized candidates</div><div className="stat-value">{run.findings_total || 0}</div></div>
    </div>
    <div className="bar-track" style={{ height: 7, marginBottom: 12 }}>
      <div className="bar-fill" style={{ width: `${percent}%`, height: "100%" }} />
    </div>
    <div style={{ display: "flex", flexWrap: "wrap", gap: 12, fontSize: 11, color: "var(--muted)" }}>
      {progress?.current_repository && <span>Scanning: <strong style={{ color: "#c7d4df" }}>{progress.current_repository}</strong></span>}
      {progress?.last_repository && !progress.current_repository && <span>Last checked: <strong style={{ color: "#c7d4df" }}>{progress.last_repository}</strong></span>}
      {Object.entries(counts).map(([key, value]) => <span key={key}>{key.replaceAll("_", " ")}: {value}</span>)}
    </div>
  </section>;
}
