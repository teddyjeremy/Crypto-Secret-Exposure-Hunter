"use client";
import { useState } from "react";
const options=["draft","ready","sent","acknowledged","resolved","closed"];
export function DisclosureStatusControl({id,initial}:{id:number;initial:string}){
 const [status,setStatus]=useState(initial);const [busy,setBusy]=useState(false);
 async function change(value:string){
  setBusy(true);
  try{const r=await fetch(`/api/disclosures/${id}`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({status:value})});if(!r.ok)throw new Error("Update failed");setStatus(value);}
  catch{alert("Could not update disclosure status.");}
  finally{setBusy(false);}
 }
 return <select className="select" style={{padding:"6px 8px",fontSize:11,minWidth:135}} disabled={busy} value={status} onChange={e=>change(e.target.value)}>{options.map(x=><option key={x} value={x}>{x}</option>)}</select>;
}