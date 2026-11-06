"use client";

import { useState } from "react";
import { ExternalLink, LoaderCircle, Play, CheckCircle2, AlertCircle } from "lucide-react";

type DispatchResult = {
  ok?: boolean;
  error?: string;
  message?: string;
  repository?: { queued?: boolean; message?: string };
  website?: { queued?: boolean; message?: string };
};

export function RunScanButton() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DispatchResult | null>(null);

  async function startBothScans() {
    if (loading) return;
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
    } catch {
      setResult({ error: "Could not contact the scan dispatcher. Please try again." });
    } finally {
      setLoading(false);
    }
  }

  const bothQueued = Boolean(result?.repository?.queued && result?.website?.queued);
  return <div style={{display:"grid",justifyItems:"end",gap:6}}>
    <button className="btn" type="button" onClick={startBothScans} disabled={loading}
      aria-busy={loading} title="Start repository and website scans concurrently">
      {loading ? <LoaderCircle size={14} className="spin"/> : <Play size={14}/>}
      {loading ? "Starting both scans…" : "Run both scans"}
    </button>
    {result && <div role="status" aria-live="polite" style={{maxWidth:330,fontSize:11,textAlign:"right",lineHeight:1.55,color:bothQueued?"var(--green)":"var(--muted)"}}>
      {bothQueued ? <><CheckCircle2 size={13} style={{verticalAlign:"-2px",marginRight:5}}/>Repository and website scans queued concurrently.</> :
        <><AlertCircle size={13} style={{verticalAlign:"-2px",marginRight:5,color:"var(--red)"}}/>{result.error || "One or more workflows could not be queued."}</>}
      {(result?.repository?.queued || result?.website?.queued) && <div style={{marginTop:3,display:"flex",gap:10,justifyContent:"end"}}>
        {result.repository?.queued && <a href="https://github.com/teddyjeremy/Crypto-Secret-Exposure-Hunter/actions/workflows/crypto-scan.yml" target="_blank" rel="noreferrer">Repository run <ExternalLink size={10}/></a>}
        {result.website?.queued && <a href="https://github.com/teddyjeremy/Crypto-Secret-Exposure-Hunter/actions/workflows/web-exposure-scan.yml" target="_blank" rel="noreferrer">Website run <ExternalLink size={10}/></a>}
      </div>}
    </div>}
  </div>;
}
