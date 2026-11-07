import { getFindings } from "@/lib/db";
import { BulkFindings } from "@/components/bulk-findings";
import { Search } from "lucide-react";
export const dynamic="force-dynamic";
const EXCHANGE_TYPES=new Set(["exchange_api_key","exchange_api_secret","exchange_api_passphrase"]);
function categoryOf(f:any):"exchange"|"wallet"{return EXCHANGE_TYPES.has(String(f.secret_type||""))?"exchange":"wallet";}
const CATEGORY_LABELS={exchange:"Exchange API credentials",wallet:"Wallet private keys"};
export default async function FindingsPage({searchParams}:{searchParams:Promise<{chain?:string;category?:string}>}){
 let rows:any[]=[];let failed=false;try{rows=await getFindings();}catch{failed=true;}
 const params=await searchParams;
 const selectedChain=String(params?.chain||"").trim().toLowerCase();
 const selectedCategory=["exchange","wallet"].includes(String(params?.category||""))?String(params.category) as "exchange"|"wallet":"";
 const chains=Array.from(new Set(rows.map(f=>String(f.ecosystem||"unknown").toLowerCase()))).sort();
 const categoryRows=selectedCategory?rows.filter(f=>categoryOf(f)===selectedCategory):rows;
 const filteredRows=selectedChain?categoryRows.filter(f=>String(f.ecosystem||"unknown").toLowerCase()===selectedChain):categoryRows;
 const displayChain=chains.find(c=>c===selectedChain);
 const categoryCounts={exchange:rows.filter(f=>categoryOf(f)==="exchange").length,wallet:rows.filter(f=>categoryOf(f)==="wallet").length};
 const title=selectedCategory?CATEGORY_LABELS[selectedCategory]:displayChain?`${displayChain.toUpperCase()} findings`:"Findings by credential category";
 return <><header className="topbar"><div><div className="eyebrow">INTELLIGENCE / TRIAGE</div><h1 className="page-title">{title}</h1><div className="page-subtitle">Select individual findings or all shown findings to update status or create private disclosure drafts in bulk.</div></div><span className="pill">{filteredRows.length} RECORDS</span></header>
 {failed&&<div className="notice">Database unavailable. Verify DATABASE_URL and redeploy.</div>}
 <div className="notice"><strong>Review before disclosure.</strong> Severity is heuristic. A detected pattern does not prove that a credential is valid, active, funded or exploitable. Exchange API permissions are always marked unknown unless the owner independently confirms them. Never authenticate with discovered credentials or test withdrawals.</div>
 <div className="panel"><div className="panel-head"><div className="panel-title">Credential category</div><span className="panel-kicker">SEPARATE FINDING TYPES</span></div>
 <div style={{display:"flex",gap:8,flexWrap:"wrap",padding:"12px 14px"}}>
 <a className={`btn ${!selectedCategory?"":"secondary"}`} href="/findings">All credentials ({rows.length})</a>
 {(["exchange","wallet"] as const).map(category=><a key={category} className={`btn ${selectedCategory===category?"":"secondary"}`} href={`/findings?category=${category}`}>{CATEGORY_LABELS[category]} ({categoryCounts[category]})</a>)}
 </div></div>
 <div className="panel"><div className="panel-head"><div className="panel-title">Filter by chain</div><span className="panel-kicker">{chains.length} ECOSYSTEMS</span></div>
 <div style={{display:"flex",gap:8,flexWrap:"wrap",padding:"12px 14px"}}>
 <a className={`btn ${!selectedChain?"":"secondary"}`} href={selectedCategory?`/findings?category=${selectedCategory}`:"/findings"}>All chains ({categoryRows.length})</a>
 {chains.map(chain=><a key={chain} className={`btn ${selectedChain===chain?"":"secondary"}`} href={`/findings?chain=${encodeURIComponent(chain)}${selectedCategory?`&category=${selectedCategory}`:""}`}>{chain.toUpperCase()} ({categoryRows.filter(f=>String(f.ecosystem||"unknown").toLowerCase()===chain).length})</a>)}
 </div></div>
 <div className="panel"><div className="panel-head"><div className="panel-title">{selectedCategory?CATEGORY_LABELS[selectedCategory]:displayChain?`${displayChain.toUpperCase()} findings`:"Findings grouped by repository"}</div><span className="panel-kicker">SELECT · BULK UPDATE · BULK DRAFT</span></div><div style={{padding:14}}><BulkFindings rows={filteredRows}/></div></div>
 </>;
}
