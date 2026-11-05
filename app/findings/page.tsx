import { getFindings } from "@/lib/db";
import { StatusControl } from "@/components/status-control";
import { DisclosureCreate } from "@/components/disclosure-create";
import { Search } from "lucide-react";
export const dynamic="force-dynamic";
export default async function FindingsPage(){
 let rows:any[]=[];let failed=false;try{rows=await getFindings();}catch{failed=true;}
 return <><header className="topbar"><div><div className="eyebrow">INTELLIGENCE / TRIAGE</div><h1 className="page-title">Findings</h1><div className="page-subtitle">Sanitized detection metadata. Secret values and source snippets are never displayed.</div></div><span className="pill">{rows.length} RECORDS</span></header>
 {failed&&<div className="notice">Database unavailable. Verify DATABASE_URL and redeploy.</div>}
 <div className="notice"><strong>Review before disclosure.</strong> Severity is heuristic. A detected pattern does not prove that a credential is valid, active, funded or exploitable. Do not attempt to use it.</div>
 <div className="panel"><div className="panel-head"><div className="panel-title">Detection records</div><span className="panel-kicker">MAX 500 · NEWEST FIRST</span></div>
 {rows.length?<div className="table-wrap"><table><thead><tr><th>Severity</th><th>Repository / file</th><th>Chain</th><th>Rule</th><th>Commit</th><th>Status</th><th>Disclosure</th></tr></thead><tbody>{rows.map(f=><tr key={f.id}><td><span className={`badge ${f.severity}`}>{f.severity}</span></td><td><a className="repo-name" href={`https://github.com/${f.repository_full_name}`} target="_blank" rel="noreferrer">{f.repository_full_name}</a><div className="muted mono" style={{marginTop:4}}>{f.file_path}:{f.line_number||"?"}</div></td><td>{f.ecosystem}</td><td className="mono">{f.rule_id}</td><td className="mono">{f.commit_sha?String(f.commit_sha).slice(0,8):"—"}</td><td><StatusControl id={Number(f.id)} initial={f.status}/></td><td><DisclosureCreate fingerprint={f.fingerprint}/></td></tr>)}</tbody></table></div>:<div className="empty"><div className="empty-icon"><Search size={19}/></div><strong style={{color:"#b8c8d5"}}>Nothing to triage</strong><div style={{marginTop:6}}>The first completed worker scan will populate this table.</div></div>}</div>
 </>;
}