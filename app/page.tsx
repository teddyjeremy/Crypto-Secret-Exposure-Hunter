import Link from "next/link";
import { Activity, AlertTriangle, Database, GitBranch, ShieldCheck, ArrowUpRight, Clock3 } from "lucide-react";
import { getDashboardData } from "@/lib/db";
import { RunScanButton } from "@/components/run-scan-button";
import { LiveScanProgress } from "@/components/live-scan-progress";
export const dynamic = "force-dynamic";
const fmt=(v:any)=>v?new Date(v).toLocaleString():"—";
export default async function Home(){
 let data:any=null;let dbError=false;
 try{data=await getDashboardData();}catch{dbError=true;}
 const stats=data?.stats||{};
 const ecosystems=data?.ecosystems||[];
 const max=Math.max(1,...ecosystems.map((x:any)=>Number(x.count)));
 return <>
  <header className="topbar"><div><div className="eyebrow">SECURITY OPERATIONS / OVERVIEW</div><h1 className="page-title">Exposure intelligence</h1><div className="page-subtitle">Public blockchain repository monitoring and responsible disclosure.</div></div><div className="top-actions"><span className="pill">ALL CHAINS · PUBLIC REPOS</span><RunScanButton/></div></header>
  {dbError&&<div className="notice"><strong>Database connection unavailable.</strong> Check DATABASE_URL in Vercel project settings and redeploy.</div>}
  <LiveScanProgress initialRun={data?.runs?.[0] || null}/>
  <section className="grid stats">
   <div className="stat-card"><div className="stat-head">Repositories with findings <span className="stat-icon"><GitBranch size={15}/></span></div><div className="stat-value">{stats.repositories??"—"}</div><div className="stat-foot">Distinct repositories with open vulnerability candidates</div></div>
   <div className="stat-card"><div className="stat-head">Open findings <span className="stat-icon"><AlertTriangle size={15}/></span></div><div className="stat-value">{stats.open_findings??"—"}</div><div className="stat-foot">Excluding false positives and remediated</div></div>
   <div className="stat-card"><div className="stat-head">Critical candidates <span className="stat-icon"><ShieldCheck size={15}/></span></div><div className="stat-value" style={{color:"var(--red)"}}>{stats.critical??"—"}</div><div className="stat-foot">Requires human review; not proof of compromise</div></div>
   <div className="stat-card"><div className="stat-head">Exchange API candidates <span className="stat-icon"><Database size={15}/></span></div><div className="stat-value">{stats.exchange_api_candidates??"—"}</div><div className="stat-foot">Keys, secrets and passphrases · permissions unknown</div></div>
   <div className="stat-card"><div className="stat-head">Completed scans <span className="stat-icon"><Activity size={15}/></span></div><div className="stat-value">{stats.completed_scans??"—"}</div><div className="stat-foot">Completed scan runs (default branch history)</div></div>
  </section>
  <section className="grid content-grid">
   <div>
    <div className="panel"><div className="panel-head"><div><div className="panel-title">Recent findings</div><div className="panel-kicker" style={{marginTop:4}}>REDACTED METADATA ONLY</div></div><Link href="/findings" className="muted" style={{fontSize:11}}>View all <ArrowUpRight size={13} style={{verticalAlign:"middle"}}/></Link></div>
     {data?.findings?.length?<div className="table-wrap"><table><thead><tr><th>Severity</th><th>Repository</th><th>Chain</th><th>Rule</th><th>Status</th></tr></thead><tbody>{data.findings.map((f:any)=><tr key={f.id}><td><span className={`badge ${f.severity}`}>{f.severity}</span></td><td className="repo-name">{f.repository_full_name}</td><td>{f.ecosystem}</td><td className="mono">{f.rule_id}</td><td><span className={`badge ${f.status}`}>{f.status}</span></td></tr>)}</tbody></table></div>:<div className="empty"><div className="empty-icon"><ShieldCheck size={19}/></div><strong style={{color:"#b8c8d5"}}>No findings yet</strong><div style={{marginTop:6}}>Start a scan to discover public repositories and review redacted candidates.</div></div>}
    </div>
    <div className="panel"><div className="panel-head"><div className="panel-title">Scan activity</div><span className="panel-kicker">LATEST RUNS</span></div>
     {data?.runs?.length?<div className="table-wrap"><table><thead><tr><th>Run</th><th>Started</th><th>Repositories</th><th>Findings</th><th>Status</th></tr></thead><tbody>{data.runs.map((r:any)=><tr key={r.id}><td className="mono">{String(r.id).slice(0,10)}</td><td>{fmt(r.started_at||r.created_at)}</td><td>{r.repositories_scanned}/{r.repositories_discovered}</td><td>{r.findings_total}</td><td><span className={`badge ${r.status==="completed"?"new":"medium"}`}>{r.status}</span></td></tr>)}</tbody></table></div>:<div className="empty">No scan activity recorded.</div>}
    </div>
   </div>
   <div>
    <div className="panel"><div className="panel-head"><div className="panel-title">Findings by ecosystem</div><span className="panel-kicker">OPEN</span></div>
     {ecosystems.length?<div className="bar-list">{ecosystems.map((e:any)=><div className="bar-row" key={e.ecosystem}><span>{e.ecosystem}</span><div className="bar-track"><div className="bar-fill" style={{width:`${Number(e.count)/max*100}%`}}/></div><span className="mono">{e.count}</span></div>)}</div>:<div className="empty">Ecosystem distribution will appear after the first scan.</div>}
    </div>
    <div className="panel"><div className="panel-head"><div className="panel-title">Safety controls</div><ShieldCheck size={16} color="var(--green)"/></div>
     <div style={{display:"grid",gap:13}}>
      {["No private-key values stored","No wallet imports or authentication","No address derivation or balance checks","No signing or fund transfers","Private disclosure drafts only"].map((x,i)=><div key={x} style={{display:"flex",gap:9,alignItems:"center",fontSize:11,color:"#a9b8c5"}}><span style={{color:"var(--green)"}}>✓</span>{x}</div>)}
     </div>
    </div>
    <div className="panel"><div className="panel-head"><div className="panel-title">Scheduled scanning</div><span className="badge new">FREE WORKFLOW</span></div><div style={{fontSize:11,color:"var(--muted)",lineHeight:1.7}}>GitHub Actions checks for new or changed public repositories every 30 minutes. Previously scanned repositories with no new pushes are skipped. Results stream into Neon as each repository finishes.</div><Link href="/settings" className="btn secondary" style={{marginTop:13}}>View setup <ArrowUpRight size={13}/></Link></div>
   </div>
  </section>
  <div className="footer-note">Defensive research only · Findings are heuristic leads, not proof of wallet compromise · Last page refresh: {new Date().toLocaleString()}</div>
 </>;
}