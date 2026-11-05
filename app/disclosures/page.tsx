import { getDisclosures } from "@/lib/db";
import { CopyButton } from "@/components/copy-button";
import { DisclosureStatusControl } from "@/components/disclosure-status-control";
export const dynamic="force-dynamic";
export default async function DisclosuresPage(){
 let rows:any[]=[];let failed=false;try{rows=await getDisclosures();}catch{failed=true;}
 return <><header className="topbar"><div><div className="eyebrow">RESPONSIBLE DISCLOSURE / CASES</div><h1 className="page-title">Disclosure desk</h1><div className="page-subtitle">Prepare private, redacted reports and track owner responses.</div></div><span className="pill">{rows.length} DRAFTS / CASES</span></header>
 <div className="notice"><strong>Manual review required.</strong> This tool does not send messages automatically. Never include private keys, seed phrases, raw matches or exploit instructions in a disclosure.</div>
 {failed&&<div className="notice">Database unavailable. Verify DATABASE_URL and redeploy.</div>}
 {rows.length?rows.map(d=><article className="panel" key={d.id}><div className="panel-head"><div><div className="panel-title">{d.repository_full_name}</div><div className="panel-kicker" style={{marginTop:5}}>{d.file_path} · {d.rule_id} · {d.severity}</div></div><DisclosureStatusControl id={Number(d.id)} initial={d.status}/></div><pre style={{whiteSpace:"pre-wrap",fontSize:11,lineHeight:1.7,color:"#aebdca",fontFamily:"DM Mono,monospace"}}>{d.message}</pre><div style={{display:"flex",justifyContent:"space-between",alignItems:"center",gap:10}}><span className="muted" style={{fontSize:10}}>Created {new Date(d.created_at).toLocaleString()}</span><CopyButton text={d.message}/></div></article>):<div className="panel empty">No disclosure drafts yet. Create one from a finding after reviewing it.</div>}
 </>;
}