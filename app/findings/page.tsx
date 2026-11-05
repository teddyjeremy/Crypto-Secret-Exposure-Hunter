import { getFindings } from "@/lib/db";
import { StatusControl } from "@/components/status-control";
import { DisclosureCreate } from "@/components/disclosure-create";
import { Search } from "lucide-react";
export const dynamic="force-dynamic";

function fileUrl(f:any) {
 if (!f.commit_sha || !f.file_path || f.file_path==="(path unavailable)") return null;
 const filePath=String(f.file_path).split("/").map((part:string)=>encodeURIComponent(part)).join("/");
 return `https://github.com/${f.repository_full_name}/blob/${f.commit_sha}/${filePath}${f.line_number?`#L${f.line_number}`:""}`;
}

function FindingsTable({rows}:{rows:any[]}) {
 return <div className="table-wrap"><table><thead><tr><th>Classification</th><th>Confidence</th><th>File / line</th><th>Chain</th><th>Secret type / rule</th><th>Commit</th><th>Status</th><th>Disclosure</th></tr></thead><tbody>{rows.map(f=>{
 const url=fileUrl(f);
 return <tr key={f.id}><td><span className={`badge ${f.classification==="secret_candidate"?"critical":"medium"}`}>{f.classification==="secret_candidate"?"SECRET CANDIDATE":"UNCERTAIN"}</span><div className="muted" style={{fontSize:10,marginTop:4}}>{f.severity}</div></td><td>{f.confidence}</td><td>{url?<a className="repo-name mono" href={url} target="_blank" rel="noreferrer">{f.file_path}:{f.line_number||"?"}</a>:<span className="muted mono">{f.file_path||"Path unavailable"}:{f.line_number||"?"}</span>}</td><td>{f.ecosystem}</td><td className="mono">{f.secret_type||f.rule_id}<div className="muted" style={{marginTop:4}}>{f.rule_id}</div></td><td className="mono">{f.commit_sha?String(f.commit_sha).slice(0,8):"—"}</td><td><StatusControl id={Number(f.id)} initial={f.status}/></td><td><DisclosureCreate fingerprint={f.fingerprint}/></td></tr>;
 })}</tbody></table></div>;
}

export default async function FindingsPage(){
 let rows:any[]=[];let failed=false;try{rows=await getFindings();}catch{failed=true;}
 const groups=new Map<string,any[]>();
 for(const finding of rows){const repo=String(finding.repository_full_name||"Unknown repository");if(!groups.has(repo))groups.set(repo,[]);groups.get(repo)!.push(finding);}
 const repositories=Array.from(groups.entries()).sort((a,b)=>a[0].localeCompare(b[0]));
 return <><header className="topbar"><div><div className="eyebrow">INTELLIGENCE / TRIAGE</div><h1 className="page-title">Findings by repository</h1><div className="page-subtitle">Each public repository has its own group. Expand a repository to inspect its file-level findings.</div></div><span className="pill">{rows.length} RECORDS · {repositories.length} REPOS</span></header>
 {failed&&<div className="notice">Database unavailable. Verify DATABASE_URL and redeploy.</div>}
 <div className="notice"><strong>Review before disclosure.</strong> Severity is heuristic. A detected pattern does not prove that a credential is valid, active, funded or exploitable. Do not attempt to use it.</div>
 <div className="panel"><div className="panel-head"><div className="panel-title">Repository groups</div><span className="panel-kicker">MAX 500 · NEWEST FIRST WITHIN EACH REPOSITORY</span></div>
 {repositories.length?<div style={{display:"grid",gap:10,padding:14}}>{repositories.map(([repo,findings],index)=>{
 const candidates=findings.filter(f=>f.classification==="secret_candidate").length;
 return <details key={repo} open={index===0} style={{border:"1px solid var(--border)",borderRadius:10,background:"rgba(255,255,255,.015)",overflow:"hidden"}}>
 <summary style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:12,padding:"14px 16px",cursor:"pointer",listStylePosition:"inside"}}>
 <span style={{display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}><a className="repo-name" href={`https://github.com/${repo}`} target="_blank" rel="noreferrer" onClick={(event)=>event.stopPropagation()}>{repo}</a><span className="badge medium">{findings.length} FINDINGS</span></span>
 <span className="muted" style={{fontSize:11,whiteSpace:"nowrap"}}>{candidates} candidates</span>
 </summary>
 <div style={{borderTop:"1px solid var(--border)"}}><FindingsTable rows={findings}/></div>
 </details>;
 })}</div>:<div className="empty"><div className="empty-icon"><Search size={19}/></div><strong style={{color:"#b8c8d5"}}>Nothing to triage</strong><div style={{marginTop:6}}>The first completed worker scan will populate these repository groups.</div></div>}</div>
 </>;
}
