import { getFindings } from "@/lib/db";
import { StatusControl } from "@/components/status-control";
import { DisclosureCreate } from "@/components/disclosure-create";
import { Search } from "lucide-react";
export const dynamic="force-dynamic";

function fileUrl(f:any) {
 if (!f.file_path || f.file_path==="(path unavailable)") return null;
 const filePath=String(f.file_path).split("/").map((part:string)=>encodeURIComponent(part)).join("/");
 const ref=f.commit_sha?String(f.commit_sha):"HEAD";
 return `https://github.com/${f.repository_full_name}/blob/${ref}/${filePath}${f.line_number?`#L${f.line_number}`:""}`;
}

const EXCHANGE_TYPES = new Set(["exchange_api_key","exchange_api_secret","exchange_api_passphrase"]);
function categoryOf(f:any):"exchange" {
 return EXCHANGE_TYPES.has(String(f.secret_type||"")) ? "exchange" : "exchange";
}
const CATEGORY_LABELS = {exchange:"Exchange API credentials"};

function FindingsTable({rows}:{rows:any[]}) {
 return <div className="table-wrap"><table><thead><tr><th>Classification</th><th>Confidence</th><th>Exposed file / line</th><th>Chain</th><th>Secret type / rule</th><th>Commit</th><th>Status</th><th>Disclosure</th></tr></thead><tbody>{rows.map(f=>{
 const url=fileUrl(f);
 const chain=String(f.ecosystem||"unknown").toLowerCase();
 return <tr key={f.id}><td><span className={`badge ${f.classification==="secret_candidate"?"critical":"medium"}`}>{f.classification==="secret_candidate"?"SECRET CANDIDATE":"UNCERTAIN"}</span><div className="muted" style={{fontSize:10,marginTop:4}}>{f.severity}</div></td><td>{f.confidence}</td><td>{url?<a className="repo-name mono" href={url} target="_blank" rel="noreferrer" title="Open exact file and line on GitHub">{f.file_path}:{f.line_number||"?"}</a>:<span className="muted mono">{f.file_path||"Path unavailable"}:{f.line_number||"?"}</span>}</td><td><a className="repo-name" href={`/findings?chain=${encodeURIComponent(chain)}`} title={`Show only ${chain} findings`}>{f.ecosystem||"unknown"}</a></td><td className="mono">{f.secret_type?.startsWith("exchange_api_")?"EXCHANGE · "+f.secret_type.replace("exchange_api_","").toUpperCase():(f.secret_type||f.rule_id)}<div className="muted" style={{marginTop:4}}>{f.secret_type?.startsWith("exchange_api_")?"PERMISSIONS UNKNOWN · "+f.description:f.rule_id}</div></td><td className="mono">{f.commit_sha?String(f.commit_sha).slice(0,8):"—"}</td><td><StatusControl id={Number(f.id)} initial={f.status}/></td><td><DisclosureCreate fingerprint={f.fingerprint}/></td></tr>;
 })}</tbody></table></div>;
}

export default async function FindingsPage({searchParams}:{searchParams:Promise<{chain?:string;category?:string}>}){
 let rows:any[]=[];let failed=false;try{rows=await getFindings();}catch{failed=true;}
 const params=await searchParams;
 const selectedChain=String(params?.chain||"").trim().toLowerCase();
 const chains=Array.from(new Set(rows.map(f=>String(f.ecosystem||"unknown").toLowerCase()))).sort();
 const categoryRows=rows.filter(f=>categoryOf(f)==="exchange");
 const filteredRows=selectedChain?categoryRows.filter(f=>String(f.ecosystem||"unknown").toLowerCase()===selectedChain):categoryRows;
 const groups=new Map<string,any[]>();
 for(const finding of filteredRows){const repo=String(finding.repository_full_name||"Unknown repository");if(!groups.has(repo))groups.set(repo,[]);groups.get(repo)!.push(finding);}
 const repositories=Array.from(groups.entries()).sort((a,b)=>a[0].localeCompare(b[0]));
 const displayChain=chains.find(c=>c===selectedChain);
 const categoryCounts={exchange:categoryRows.length};
 const title=displayChain?`${displayChain.toUpperCase()} exchange API findings`:CATEGORY_LABELS.exchange;
 return <><header className="topbar"><div><div className="eyebrow">INTELLIGENCE / TRIAGE</div><h1 className="page-title">{title}</h1><div className="page-subtitle">Only repositories with open secret-candidate findings are shown. Clean scans and discovery-only repositories are hidden.</div></div><span className="pill">{filteredRows.length} RECORDS · {repositories.length} REPOS</span></header>
 {failed&&<div className="notice">Database unavailable. Verify DATABASE_URL and redeploy.</div>}
 <div className="notice"><strong>Review before disclosure.</strong> Severity is heuristic. A detected pattern does not prove that a credential is valid, active, funded or exploitable. Exchange API permissions are always marked unknown unless the owner independently confirms them. Never authenticate with discovered credentials or test withdrawals.</div>
 <div className="panel"><div className="panel-head"><div className="panel-title">Credential category</div><span className="panel-kicker">EXCHANGE API KEYS ONLY</span></div>
 <div style={{display:"flex",gap:8,flexWrap:"wrap",padding:"12px 14px"}}>
 <span className="btn">Exchange API credentials ({categoryRows.length})</span>
 </div></div>
 <div className="panel"><div className="panel-head"><div className="panel-title">Filter by exchange provider</div><span className="panel-kicker">{chains.length} EXCHANGES / PROVIDERS</span></div>
 <div style={{display:"flex",gap:8,flexWrap:"wrap",padding:"12px 14px"}}>
 <a className={`btn ${!selectedChain?"":"secondary"}`} href="/findings">All providers ({categoryRows.length})</a>
 {chains.map(chain=><a key={chain} className={`btn ${selectedChain===chain?"":"secondary"}`} href={`/findings?chain=${encodeURIComponent(chain)}`}>{chain.toUpperCase()} ({categoryRows.filter(f=>String(f.ecosystem||"unknown").toLowerCase()===chain).length})</a>)}
 </div></div>
 <div className="panel"><div className="panel-head"><div className="panel-title">{displayChain?`${displayChain.toUpperCase()} exchange API repository groups`:"Exchange API findings grouped by repository"}</div><span className="panel-kicker">UP TO 100 LATEST FINDINGS PER REPOSITORY · FILE PATHS AND LINES</span></div>
 {repositories.length?<div style={{display:"grid",gap:10,padding:14}}>{repositories.map(([repo,findings],index)=>{
 const candidates=findings.filter(f=>f.classification==="secret_candidate").length;
 return <details key={repo} open={index===0} style={{border:"1px solid var(--border)",borderRadius:10,background:"rgba(255,255,255,.015)",overflow:"hidden"}}>
 <summary style={{display:"flex",alignItems:"center",justifyContent:"space-between",gap:12,padding:"14px 16px",cursor:"pointer",listStylePosition:"inside"}}>
 <span style={{display:"flex",alignItems:"center",gap:10,flexWrap:"wrap"}}><a className="repo-name" href={`https://github.com/${repo}`} target="_blank" rel="noreferrer">{repo}</a><span className="badge medium">{findings.length} FINDINGS</span></span>
 <span className="muted" style={{fontSize:11,whiteSpace:"nowrap"}}>{candidates} candidates</span>
 </summary>
 <div style={{borderTop:"1px solid var(--border)"}}><FindingsTable rows={findings}/></div>
 </details>;
 })}</div>:<div className="empty"><div className="empty-icon"><Search size={19}/></div><strong style={{color:"#b8c8d5"}}>{selectedChain?"No exchange API findings for this provider":"No exchange API findings to triage"}</strong><div style={{marginTop:6}}>{selectedChain?"Try another provider or select All providers.":"The first completed exchange-only scan will populate these groups."}</div></div>}</div>
 </>;
}
