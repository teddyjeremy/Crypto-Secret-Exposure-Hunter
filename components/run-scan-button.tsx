"use client";

import { useCallback, useEffect, useState } from "react";
import { ExternalLink, LoaderCircle, Play, CheckCircle2, AlertCircle, Lock } from "lucide-react";

type DispatchResult = {
  ok?: boolean;
  error?: string;
  message?: string;
  repository?: { queued?: boolean; message?: string };
  website?: { queued?: boolean; message?: string };
  active?: Array<{ workflow: string; id: number; status: string; html_url: string }>;
};

type WorkflowStatus = {
  available: boolean;
  active: boolean;
  error?: string;
  workflows?: Array<{
    workflow: string;
    active: { id: number; name: string; status: string; url: string; created_at: string } | null;
  }>;
};

export function RunScanButton() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DispatchResult | null>(null);
  const [workflowStatus, setWorkflowStatus] = useState<WorkflowStatus | null>(null);
  const [checking, setChecking] = useState(true);

  const refreshStatus = useCallback(async () => {
    try {
      const response = await fetch("/api/scan/status", { cache: "no-store" });
      if (!response.ok) throw new Error("Status request failed");
      const data = await response.json() as WorkflowStatus;
      setWorkflowStatus(data);
    } catch {
      // Fail closed: never enable a new scan when current workflow state is unknown.
      setWorkflowStatus({ available: false, active: true, error: "Could not verify GitHub workflow status." });
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    // Defer the initial network request until after the effect has completed.
    const initialTimer = window.setTimeout(() => { void refreshStatus(); }, 0);
    const intervalTimer = window.setInterval(() => { void refreshStatus(); }, 10000);
    return () => {
      window.clearTimeout(initialTimer);
      window.clearInterval(intervalTimer);
    };
  }, [refreshStatus]);

  async function startBothScans() {
    if (loading || checking || !workflowStatus?.available || workflowStatus.active) return;
    setLoading(true);
    setResult(null);
    try {
      const response = await fetch("/api/scan/dispatch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
        cache: "no-store"
      });
      const data = await response.json() as DispatchResult;
      setResult(data);
      if (response.status === 409) {
        await refreshStatus();
      } else if (response.ok) {
        setWorkflowStatus({ available: true, active: true });
        window.setTimeout(() => { void refreshStatus(); }, 2500);
      }
    } catch {
      setResult({ error: "Could not contact the scan dispatcher. Please try again." });
    } finally {
      setLoading(false);
      await refreshStatus();
    }
  }

  const bothQueued = Boolean(result?.repository?.queued && result?.website?.queued);
  const active = Boolean(workflowStatus?.active);
  const disabled = loading || checking || !workflowStatus?.available || active;

  return <div style={{display:"grid",justifyItems:"end",gap:6}}>
    <button className="btn" type="button" onClick={startBothScans} disabled={disabled}
      aria-busy={loading || checking} title={active ? "A repository or website workflow is already queued or running" : "Start repository and website scans concurrently"}
      style={disabled ? {opacity:0.55,cursor:"not-allowed"} : undefined}>
      {loading || checking ? <LoaderCircle size={14} className="spin"/> : active || !workflowStatus?.available ? <Lock size={14}/> : <Play size={14}/>}
      {checking ? "Checking workflow status…" : loading ? "Starting both scans…" : active ? "Scan already running" : !workflowStatus?.available ? "Scan status unavailable" : "Run both scans"}
    </button>
    {active && <div role="status" aria-live="polite" style={{maxWidth:340,fontSize:11,textAlign:"right",lineHeight:1.55,color:"var(--muted)"}}>
      <strong style={{color:"var(--green)"}}>New scans are locked while a workflow is queued or running.</strong>
      {workflowStatus?.workflows?.filter(w => w.active).map(w => <div key={w.workflow} style={{marginTop:3}}>
        {w.workflow.includes("crypto-scan") ? "Repository scan" : "Website scan"}: {w.active?.status}
        {w.active?.url && <> · <a href={w.active.url} target="_blank" rel="noreferrer">View run <ExternalLink size={10}/></a></>}
      </div>)}
      <div>Checking GitHub every 10 seconds.</div>
    </div>}
    {!workflowStatus?.available && !checking && <div role="status" aria-live="polite" style={{maxWidth:340,fontSize:11,textAlign:"right",color:"var(--red)"}}>
      {workflowStatus?.error || "Unable to confirm workflow status. Scan launch is disabled to prevent duplicate runs."}
    </div>}
    {result && <div role="status" aria-live="polite" style={{maxWidth:330,fontSize:11,textAlign:"right",lineHeight:1.55,color:bothQueued?"var(--green)":"var(--muted)"}}>
      {bothQueued ? <><CheckCircle2 size={13} style={{verticalAlign:"-2px",marginRight:5}}/>Repository and website scans queued concurrently.</> :
        <><AlertCircle size={13} style={{verticalAlign:"-2px",marginRight:5,color:"var(--red)"}/>{result.error || "One or more workflows could not be queued."}</>}
      {(result?.repository?.queued || result?.website?.queued) && <div style={{marginTop:3,display:"flex",gap:10,justifyContent:"end"}}>
        {result.repository?.queued && <a href="https://github.com/teddyjeremy/Crypto-Secret-Exposure-Hunter/actions/workflows/crypto-scan.yml" target="_blank" rel="noreferrer">Repository run <ExternalLink size={10}/></a>}
        {result.website?.queued && <a href="https://github.com/teddyjeremy/Crypto-Secret-Exposure-Hunter/actions/workflows/web-exposure-scan.yml" target="_blank" rel="noreferrer">Website run <ExternalLink size={10}/></a>}
      </div>}
    </div>}
  </div>;
}
