"use client";
import { useState } from "react";
import { FileText, Check } from "lucide-react";
export function DisclosureCreate({fingerprint}:{fingerprint:string}) {
 const [busy,setBusy]=useState(false);const [done,setDone]=useState(false);
 async function create(){
  setBusy(true);
  try{const r=await fetch("/api/disclosures",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({fingerprint})});if(!r.ok)throw new Error("Could not create draft");setDone(true);}
  catch{alert("Could not create disclosure draft.");}
  finally{setBusy(false);}
 }
 return <button className="btn secondary" style={{padding:"7px 9px"}} disabled={busy||done} onClick={create}>{done?<Check size={13}/>:<FileText size={13}/>} {done?"Draft created":busy?"Creating…":"Create draft"}</button>;
}