"use client";
import { useMemo,useState } from "react";
import { useRouter } from "next/navigation";
import { FileText,Loader2 } from "lucide-react";

type Finding={first_seen_at:string;id:number;fingerprint:string;repository_full_name:string;ecosystem:string;severity:string;classification:string;secret_type:string;confidence:string;rule_id:string;description:string;file_path:string;line_number:number|null;commit_sha:string|null;status:string};
const statuses=["new","triaged","false_positive","disclosed","remediated"];
const exchangeTypes=new Set(["exchange_api_key","exchange_api_secret","exchange_api_passphrase"]);
function fileUrl(f:Finding){
 if(!f.file_path||f.file_path==="(path unavailable)")return null;
 const path=String(f.file_path).split("/").map(part=>encodeURIComponent(part)).join("/");
 return `https://github.com/${f.repository_full_name}/blob/${f.commit_sha||"HEAD"}/${path}${f.line_number?`#L${f.line_number}`:""}`;
}
export function BulkFindings({rows}:{rows:Finding[]}){
 const router=useRouter();
 const [selected,setSelected]=useState<number[]>([]);
 const [status,setStatus]=useState("triaged");
 const [busy,setBusy]=useState<"status"|"draft"|null>(null);
 const [message,setMessage]=useState("");
 const [showDisclosureLink,setShowDisclosureLink]=useState(false);
 const selectableRows=rows.slice(0,500);
 const allSelected=selectableRows.length>0&&selectableRows.every(f=>selected.includes(f.id));
 const groups=useMemo(()=>{const m=new Map<string,Finding[]>();for(const f of rows){const k=f.repository_full_name||"Unknown repository";if(!m.has(k))m.set(k,[]);m.get(k)!.push(f);}return Array.from(m.entries()).sort((a,b)=>{
  const aNewest=Math.max(...a[1].map(f=>new Date(f.first_seen_at).getTime()||0));
  const bNewest=Math.max(...b[1].map(f=>new Date(f.first_seen_at).getTime()||0));
  return bNewest-aNewest;
 });},[rows]);
 function toggleMany(ids:number[]){
  if(ids.every(id=>selected.includes(id)))setSelected(old=>old.filter(id=>!ids.includes(id)));
  else setSelected(old=>Array.from(new Set([...old,...ids])).slice(0,500));
 }
 function toggle(id:number){toggleMany([id]);}
 function toggleAll(){toggleMany(selectableRows.map(f=>f.id));}
 async function updateStatus(){
  setBusy("status");setMessage("");
  try{const r=await fetch("/api/findings/bulk",{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({ids:selected,status})});const data=await r.json();if(!r.ok)throw new Error(data.error||"Update failed");setMessage(`Updated ${data.updated} finding(s) to “${status.replaceAll("_"," ")}”.`);setSelected([]);router.refresh();}
  catch(e){setMessage(e instanceof Error?e.message:"Bulk update failed.");}
  finally{setBusy(null);}
 }
 async function createDrafts(){
  setBusy("draft");setMessage("");setShowDisclosureLink(false);
  try{const fingerprints=rows.filter(f=>selected.includes(f.id)).map(f=>f.fingerprint);const r=await fetch("/api/disclosures/bulk",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({fingerprints})});const data=await r.json();if(!r.ok)throw new Error(data.error||"Draft creation failed");setMessage(`Created ${data.created} draft(s); skipped ${data.skipped} existing draft(s)${data.notFound?`; ${data.notFound} finding(s) were unavailable`:""}. Drafts are saved in the Disclosure Desk.`);setSelected([]);setShowDisclosureLink(data.created>0||data.skipped>0);router.refresh();}
  catch(e){setMessage(e instanceof Error?e.message:"Bulk draft creation failed.");}
  finally{setBusy(null);}
 }
 return <section>
  <div className="panel" style={{marginBottom:12}}>
   <div style={{display:"flex",alignItems:"center",gap:10,flexWrap:"wrap",padding:"12px 14px"}}>
    <label style={{display:"flex",alignItems:"center",gap:7,fontSize:12,cursor:"pointer"}}><input type="checkbox" checked={allSelected} onChange={toggleAll}/> Select first 500 shown</label>
    <span className="muted" style={{fontSize:12}}>{selected.length} selected{selected.length>=500?" · bulk limit reached":""}</span>
    <div style={{flex:1}}/>
    <select className="select" value={status} onChange={e=>setStatus(e.target.value)} disabled={!selected.length||!!busy} style={{padding:"7px 9px",fontSize:12}}>{statuses.map(s=><option key={s} value={s}>{s.replaceAll("_"," ")}</option>)}</select>
    <button className="btn secondary" disabled={!selected.length||!!busy} onClick={updateStatus}>{busy==="status"?<Loader2 size={13} className="spin"/>:""} Update status</button>
    <button className="btn" disabled={!selected.length||!!busy} onClick={createDrafts}>{busy==="draft"?<Loader2 size={13} className="spin"/>:<FileText size={13}/>} Create drafts ({selected.length})</button>
   </div>
   {message&&<div className="muted" role="status" style={{padding:"0 14px 12px",fontSize:12}}>{message}{showDisclosureLink&&<> <a className="repo-name" href="/disclosures">Open Disclosure Desk →</a></>}</div>}
  </div>
  {groups.length?<div style={{display:"grid",gap:10}}>{groups.map(([repo,findings],index)=>{
   const candidates=findings.filter(f=>f.classification==="secret_candidate").length;
   return <details key={repo} open={index===0} style={{border:"1px solid var(--border)",borderRadius:10,background:"rgba(255,255,255,.015)",overflow:"hidden"}}>
    <summary style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:12,padding:"14px 16px",cursor:"pointer",listStylePosition:"inside"}}>
     <span style={{display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}><a className="repo-name" href={`https://github.com/${repo}`} target="_blank" rel="noreferrer">{repo}</a><span className="badge medium">{findings.length} FINDINGS</span></span>
     <span className="muted" style={{fontSize:11,whiteSpace:"nowrap"}}>{candidates} candidates</span>
    </summary>
    <div className="table-wrap" style={{borderTop:"1px solid var(--border)"}}><table><thead><tr><th><input aria-label="Select all in repository" type="checkbox" checked={findings.slice(0,500).every(f=>selected.includes(f.id))} onChange={()=>toggleMany(findings.slice(0,500).map(f=>f.id))}/></th><th>Classification</th><th>Confidence</th><th>Exposed file / line</th><th>Chain</th><th>Secret type / rule</th><th>Commit</th><th>Status</th></tr></thead><tbody>{findings.map(f=>{
    const url=fileUrl(f);const exchange=exchangeTypes.has(String(f.secret_type||""));
    return <tr key={f.id}><td><input aria-label={`Select finding ${f.id}`} type="checkbox" checked={selected.includes(f.id)} onChange={()=>toggle(f.id)}/></td><td><span className={`badge ${f.classification==="secret_candidate"?"critical":"medium"}`}>{f.classification==="secret_candidate"?"SECRET CANDIDATE":"UNCERTAIN"}</span><div className="muted" style={{fontSize:10,marginTop:4}}>{f.severity}</div></td><td>{f.confidence}</td><td>{url?<a className="repo-name mono" href={url} target="_blank" rel="noreferrer" title="Open exact file and line on GitHub">{f.file_path}:{f.line_number||"?"}</a>:<span className="muted mono">{f.file_path||"Path unavailable"}:{f.line_number||"?"}</span>}</td><td><a className="repo-name" href={`/findings?chain=${encodeURIComponent(String(f.ecosystem||"unknown").toLowerCase())}`}>{f.ecosystem||"unknown"}</a></td><td className="mono">{exchange?"EXCHANGE · "+f.secret_type.replace("exchange_api_","").toUpperCase():(f.secret_type||f.rule_id)}<div className="muted" style={{marginTop:4}}>{exchange?"PERMISSIONS UNKNOWN · "+f.description:f.rule_id}</div></td><td className="mono">{f.commit_sha?String(f.commit_sha).slice(0,8):"—"}</td><td>{f.status?.replaceAll("_"," ")}</td></tr>;
   })}</tbody></table></div>
   </details>;
  })}</div>:<div className="empty"><strong style={{color:"#b8c8d5"}}>Nothing to triage</strong><div style={{marginTop:6}}>The first completed worker scan will populate these groups.</div></div>}
 </section>;
}
