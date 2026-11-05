import { NextRequest,NextResponse } from "next/server";
import { createRemoteJWKSet,jwtVerify } from "jose";
import { getDb } from "@/lib/db";
export const runtime="nodejs";
const clean=(v:unknown,max=500)=>typeof v==="string"?v.slice(0,max):"";
const integer=(v:unknown)=>typeof v==="number"&&Number.isInteger(v)&&v>=0?v:null;
const GITHUB_ISSUER="https://token.actions.githubusercontent.com";
const GITHUB_AUDIENCE="crypto-secret-exposure-hunter";
const EXPECTED_REPOSITORY="teddyjeremy/Crypto-Secret-Exposure-Hunter";
const EXPECTED_WORKFLOW=`${EXPECTED_REPOSITORY}/.github/workflows/crypto-scan.yml@refs/heads/main`;
const JWKS=createRemoteJWKSet(new URL(`${GITHUB_ISSUER}/.well-known/jwks`));
async function authorized(request:NextRequest):Promise<boolean>{
 const header=request.headers.get("authorization")||"";
 const token=header.startsWith("Bearer ")?header.slice(7):"";
 if(!token)return false;
 try{
  const {payload}=await jwtVerify(token,JWKS,{issuer:GITHUB_ISSUER,audience:GITHUB_AUDIENCE});
  return payload.repository===EXPECTED_REPOSITORY&&payload.ref==="refs/heads/main"
   &&payload.workflow_ref===EXPECTED_WORKFLOW
   &&["schedule","workflow_dispatch"].includes(String(payload.event_name));
 }catch{return false;}
}
export async function POST(request:NextRequest){
 if(!await authorized(request))return NextResponse.json({error:"Unauthorized workflow identity"},{status:401});
 const length=Number(request.headers.get("content-length")||0);
 if(length>2_000_000)return NextResponse.json({error:"Payload too large"},{status:413});
 let body:any;try{body=await request.json();}catch{return NextResponse.json({error:"Invalid JSON"},{status:400});}
 const run=body?.run;const repositories=Array.isArray(body?.repositories)?body.repositories.slice(0,100):[];const findings=Array.isArray(body?.findings)?body.findings.slice(0,3000):[];
 if(!run||!/^[-a-zA-Z0-9_]{6,100}$/.test(clean(run.id,100)))return NextResponse.json({error:"Invalid scan run metadata"},{status:400});
 try{
  const sql=getDb();
  await sql`INSERT INTO scan_runs(id,status,trigger_source,started_at,completed_at,repositories_discovered,repositories_scanned,findings_total,summary,error_message)
   VALUES(${clean(run.id,100)},${clean(run.status,20)||"completed"},${clean(run.trigger_source,30)||"github-actions"},${run.started_at||null},${run.completed_at||new Date().toISOString()},${integer(run.repositories_discovered)||0},${integer(run.repositories_scanned)||0},${findings.length},${JSON.stringify(run.summary||{})}::jsonb,${clean(run.error_message,500)||null})
   ON CONFLICT(id) DO UPDATE SET status=EXCLUDED.status,completed_at=EXCLUDED.completed_at,repositories_discovered=EXCLUDED.repositories_discovered,repositories_scanned=EXCLUDED.repositories_scanned,findings_total=EXCLUDED.findings_total,summary=EXCLUDED.summary,error_message=EXCLUDED.error_message`;
  for(const repo of repositories){
   const fullName=clean(repo.full_name,200);if(!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(fullName))continue;
   await sql`INSERT INTO repositories(full_name,html_url,ecosystem,description,stars,default_branch,last_scanned_at,latest_status,updated_at)
    VALUES(${fullName},${clean(repo.html_url,500)},${clean(repo.ecosystem,80)||"Other Web3"},${clean(repo.description,300)||null},${integer(repo.stars)||0},${clean(repo.default_branch,120)||null},NOW(),${clean(repo.status,30)||"completed"},NOW())
    ON CONFLICT(full_name) DO UPDATE SET html_url=EXCLUDED.html_url,ecosystem=EXCLUDED.ecosystem,description=EXCLUDED.description,stars=EXCLUDED.stars,default_branch=EXCLUDED.default_branch,last_scanned_at=NOW(),latest_status=EXCLUDED.latest_status,updated_at=NOW()`;
  }
  let inserted=0;
  for(const f of findings){
   const fingerprint=clean(f.fingerprint,80);const fullName=clean(f.repository_full_name,200);
   if(!/^[a-f0-9]{32,64}$/i.test(fingerprint)||!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(fullName))continue;
   const severity=["critical","high","medium","low"].includes(f.severity)?f.severity:"medium";
   const classification=["public_information","secret_candidate","uncertain"].includes(f.classification)?f.classification:"uncertain";
   const confidence=["low","medium","high"].includes(f.confidence)?f.confidence:"low";
   const secretType=clean(f.secret_type,120)||null;
   const line=integer(f.line_number);
   await sql`INSERT INTO findings(fingerprint,repository_full_name,ecosystem,severity,classification,secret_type,confidence,rule_id,description,file_path,line_number,commit_sha,first_seen_at,last_seen_at)
    VALUES(${fingerprint},${fullName},${clean(f.ecosystem,80)||"Other Web3"},${severity},${classification},${secretType},${confidence},${clean(f.rule_id,120)||"unknown"},${clean(f.description,240)||null},${clean(f.file_path,700)||"(path unavailable)"},${line},${clean(f.commit_sha,80)||null},COALESCE(${f.date||null}::timestamptz,NOW()),NOW())
    ON CONFLICT(fingerprint) DO UPDATE SET last_seen_at=NOW(),classification=EXCLUDED.classification,secret_type=EXCLUDED.secret_type,confidence=EXCLUDED.confidence,description=EXCLUDED.description,file_path=EXCLUDED.file_path,line_number=EXCLUDED.line_number,commit_sha=EXCLUDED.commit_sha`;
   inserted++;
  }
  return NextResponse.json({ok:true,run_id:run.id,repositories_received:repositories.length,findings_received:findings.length,findings_upserted:inserted});
 }catch(error){console.error("ingest failed",error instanceof Error?error.message:"unknown");return NextResponse.json({error:"Could not persist sanitized scan results."},{status:500});}
}