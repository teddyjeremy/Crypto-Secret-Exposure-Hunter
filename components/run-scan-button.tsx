"use client";
import { useState } from "react";
import { Play, Loader2 } from "lucide-react";
export function RunScanButton() {
 const [busy,setBusy]=useState(false); const [message,setMessage]=useState("");
 async function run(){
  setBusy(true);setMessage("");
  try { const r=await fetch("/api/scan",{method:"POST"}); const data=await r.json(); if(!r.ok) throw new Error(data.error||"Could not start scan"); setMessage("Scan queued in GitHub Actions."); }
  catch(e){setMessage(e instanceof Error?e.message:"Request failed");}
  finally{setBusy(false);}
 }
 return <div style={{display:"flex",gap:10,alignItems:"center",flexWrap:"wrap"}}><button className="btn" onClick={run} disabled={busy}>{busy?<Loader2 size={14} className="spin"/>:<Play size={14}/>} {busy?"Starting…":"Run scan"}</button>{message&&<span className="muted" style={{fontSize:11}}>{message}</span>}</div>;
}