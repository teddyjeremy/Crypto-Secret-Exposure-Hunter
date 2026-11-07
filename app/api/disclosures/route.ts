import { NextRequest,NextResponse } from "next/server";
import { getDb } from "@/lib/db";
export const runtime="nodejs";
export async function POST(request:NextRequest){
 let body:any;try{body=await request.json();}catch{return NextResponse.json({error:"Invalid JSON"},{status:400});}
 const fingerprint=typeof body.fingerprint==="string"?body.fingerprint.slice(0,80):"";
 if(!/^[a-f0-9]{32,64}$/i.test(fingerprint))return NextResponse.json({error:"Invalid finding fingerprint"},{status:400});
 try{
  const sql=getDb();const rows=await sql`SELECT fingerprint,repository_full_name,file_path,line_number,rule_id,severity FROM findings WHERE fingerprint=${fingerprint} AND classification='secret_candidate' LIMIT 1`;
  if(!rows.length)return NextResponse.json({error:"Finding not found"},{status:404});
  const f=rows[0];
  const existing=await sql`SELECT id,status FROM disclosures WHERE finding_fingerprint=${fingerprint} AND status NOT IN ('closed','resolved') ORDER BY created_at DESC LIMIT 1`;
  if(existing.length)return NextResponse.json({ok:true,alreadyExists:true,disclosure:existing[0]});
  const message=[
   "Subject: Potential exposed credential in public repository","",
   "Hello repository maintainers,","",
   "I identified a potential secret exposure during a defensive review of public repository content.",
   "I have not used, tested, imported, or authenticated with the value, and have not accessed or moved funds.","",
   `Repository: ${f.repository_full_name}`,
   `Location: ${f.file_path} (line ${f.line_number||"unknown"})`,
   `Detection: ${f.rule_id} (${f.severity})`,"",
   "Suggested remediation: treat the value as compromised, rotate or revoke it using your normal trusted procedures, remove it from the working tree and review Git history. Move secrets into a dedicated secrets manager or protected environment variables.",
   "This report intentionally omits the credential value. Please advise if you have a preferred private reporting channel.","",
   "Regards,","Security researcher"
  ].join("\n");
  const result=await sql`INSERT INTO disclosures(finding_fingerprint,channel,status,message) VALUES(${fingerprint},'private','draft',${message}) RETURNING id,status,created_at`;
  return NextResponse.json({ok:true,disclosure:result[0]},{status:201});
 }catch{return NextResponse.json({error:"Could not create disclosure draft"},{status:500});}
}