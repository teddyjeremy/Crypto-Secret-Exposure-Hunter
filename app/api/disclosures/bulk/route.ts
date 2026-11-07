import { NextRequest,NextResponse } from "next/server";
import { getDb } from "@/lib/db";
export const runtime="nodejs";
export async function POST(request:NextRequest){
 let body:any;try{body=await request.json();}catch{return NextResponse.json({error:"Invalid JSON"},{status:400});}
 const fingerprints=Array.isArray(body.fingerprints)?Array.from(new Set(body.fingerprints.filter((x:any)=>typeof x==="string"&&/^[a-f0-9]{32,64}$/i.test(x)).map((x:string)=>x.slice(0,80))):[];
 if(!fingerprints.length||fingerprints.length>500)return NextResponse.json({error:"Select between 1 and 500 findings"},{status:400});
 try{
  const sql=getDb();
  const findings=await sql`SELECT fingerprint,repository_full_name,file_path,line_number,rule_id,severity FROM findings WHERE fingerprint = ANY(${fingerprints}::text[])`;
  let created=0;let skipped=0;
  for(const f of findings){
   const existing=await sql`SELECT id FROM disclosures WHERE finding_fingerprint=${f.fingerprint} AND status NOT IN ('closed','resolved') LIMIT 1`;
   if(existing.length){skipped++;continue;}
   const message=[
    "Subject: Potential exposed credential in public repository","","Hello repository maintainers,","",
    "I identified a potential secret exposure during a defensive review of public repository content.",
    "I have not used, tested, imported, or authenticated with the value, and have not accessed or moved funds.","",
    `Repository: ${f.repository_full_name}`,
    `Location: ${f.file_path} (line ${f.line_number||"unknown"})`,
    `Detection: ${f.rule_id} (${f.severity})`,"",
    "Suggested remediation: treat the value as compromised, rotate or revoke it using your normal trusted procedures, remove it from the working tree and review Git history. Move secrets into a dedicated secrets manager or protected environment variables.",
    "This report intentionally omits the credential value. Please advise if you have a preferred private reporting channel.","","Regards,","Security researcher"
   ].join("\\n");
   await sql`INSERT INTO disclosures(finding_fingerprint,channel,status,message) VALUES(${f.fingerprint},'private','draft',${message})`;
   created++;
  }
  return NextResponse.json({ok:true,created,skipped,notFound:fingerprints.length-findings.length},{status:201});
 }catch{return NextResponse.json({error:"Could not create bulk disclosure drafts"},{status:500});}
}
