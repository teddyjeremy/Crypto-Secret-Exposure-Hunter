"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

type ScanRun = {
  id: string;
  status: string;
  started_at?: string | null;
  completed_at?: string | null;
  repositories_discovered?: number;
  repositories_scanned?: number;
  findings_total?: number;
  summary?: {
    phase?: string;
    message?: string;
    progress_percent?: number;
    current_repository?: string | null;
    status_counts?: Record<string, number>;
    repositories?: Array<{full_name: string; html_url?: string; ecosystem?: string; status?: string; finding_count?: number}>;
  };
};

const label = (value?: string) => (value || "pending").replaceAll("_", " ");
const color = (status?: string) => status === "completed" ? "#34d399" : status === "running" ? "#60a5fa" : ["clone_failed","clone_timeout","scan_timeout","scanner_error","worker_error"].includes(status || "") ? "#fb7185" : "#94a3b8";

export function LiveScanProgress({ initialRun }: { initialRun?: ScanRun | null }) {
  const [run, setRun] = useState<ScanRun | null>(initialRun || null);
  const [updated, setUpdated] = useState("");
  const router = useRouter();
  useEffect(() => {
    let alive = true;
    const refresh = async () => {
      try {
        const response = await fetch("/api/scan-progress", { cache: "no-store" });
        if (!response.ok) return;
        const data = await response.json();
        if (alive && data.run) {
          setRun(data.run);
          setUpdated(new Date().toLocaleTimeString());
          router.refresh();
        }
      } catch { /* Keep the last successfully received progress snapshot. */ }
    };
    refresh();
    const timer = window.setInterval(refresh, 5000);
    return () => { alive = false; window.clearInterval(timer); };
  }, [router]);

  if (!run) return null;
  const summary = run.summary || {};
  const repos = summary.repositories || [];
  const scanned = Number(run.repositories_scanned || 0);
  const discovered = Number(run.repositories_discovered || 0);
  const percent = Math.max(0, Math.min(100, Number(summary.progress_percent ?? (run.status === "completed" ? 100 : 0))));
  const running = run.status === "running";
  return <section className="panel" style={{marginBottom:18}}>
    <div className="panel-head">
      <div><div className="panel-title">Live scan progress</div><div className="panel-kicker" style={{marginTop:4}}>AUTO-REFRESHES EVERY 5 SECONDS</div></div>
      <span className={`badge ${running ? "medium" : run.status === "completed" ? "new" : "low"}`}>{label(run.status)}</span>
    </div>
    <div style={{display:"flex",justifyContent:"space-between",gap:12,flexWrap:"wrap",fontSize:12,color:"var(--muted)"}}>
      <span>{summary.message || "Waiting for worker progress…"}</span>
      <strong style={{color:"var(--text)"}}>{scanned}/{discovered} repositories scanned · {Number(run.findings_total || 0)} findings</strong>
    </div>
    <div style={{height:7,background:"var(--surface-2)",borderRadius:99,overflow:"hidden",marginTop:12}}>
      <div style={{height:"100%",width:`${percent}%`,background:"var(--accent)",borderRadius:99,transition:"width .25s ease"}}/>
    </div>
    <div style={{display:"flex",justifyContent:"space-between",marginTop:6,fontSize:10,color:"var(--muted)"}}>
      <span>{label(summary.phase)} · {percent}%</span><span>{updated ? `Updated ${updated}` : "Connecting…"}</span>
    </div>
    {summary.current_repository && <div style={{marginTop:12,padding:10,borderRadius:8,background:"var(--surface-2)",fontSize:11}}>
      <span style={{color:"var(--muted)"}}>CURRENT REPOSITORY</span><div className="mono" style={{marginTop:4,color:"var(--text)"}}>{summary.current_repository}</div>
    </div>}
    {repos.length > 0 && <div style={{marginTop:14}}>
      <div className="panel-kicker" style={{marginBottom:8}}>REPOSITORIES IN THIS RUN ({repos.length})</div>
      <div style={{maxHeight:270,overflowY:"auto",display:"grid",gap:1}}>
        {repos.map((repo,index) => <div key={repo.full_name} style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:10,padding:"8px 2px",borderBottom:"1px solid var(--border)",fontSize:11}}>
          <div style={{minWidth:0}}><a href={repo.html_url || `https://github.com/${repo.full_name}`} target="_blank" rel="noreferrer" className="repo-name">{repo.full_name}</a><div style={{color:"var(--muted)",fontSize:10,marginTop:3}}>{repo.ecosystem || "Web3"}</div></div>
          <div style={{display:"flex",alignItems:"center",gap:10,flexShrink:0}}><span style={{color:"var(--muted)"}}>{repo.finding_count ?? 0} findings</span><span style={{color:color(repo.status),textTransform:"capitalize"}}>{label(repo.status)}</span></div>
        </div>)}
      </div>
    </div>}
    {Object.keys(summary.status_counts || {}).length > 0 && <div style={{display:"flex",gap:12,flexWrap:"wrap",marginTop:12,fontSize:10,color:"var(--muted)"}}>
      {Object.entries(summary.status_counts || {}).map(([status,count]) => <span key={status}>{label(status)}: <strong style={{color:color(status)}}>{count}</strong></span>)}
    </div>}
  </section>;
}
