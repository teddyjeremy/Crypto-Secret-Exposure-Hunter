import { NextRequest,NextResponse } from "next/server";
import { getDb } from "@/lib/db";
export const runtime="nodejs";
export async function POST(request:NextRequest){
 let body:any;try{body=await request.json();}catch{return NextResponse.json({error:"Invalid JSON"},{status:400});}
 const fingerprints=Array.isArray(body.fingerprints)?Array.from(new Set(body.fingerprints.filter((x:any)=>typeof x==="string"&&/^[a-f0-9]{32,64}$/i.test(x)).map((x:string)=>x.slice(0,80)))):[];
 if(!fingerprints.length||fingerprints.length>500)return NextResponse.json({error:"Select between 1 and 500 findings"},{status:400});
 try{
  const sql=getDb();
  const findings=await sql`SELECT fingerprint FROM findings WHERE fingerprint = ANY(${fingerprints}::text[])`;
  const foundFingerprints=findings.map((f:any)=>String(f.fingerprint));
  const existing=foundFingerprints.length?await sql`SELECT DISTINCT finding_fingerprint FROM disclosures WHERE finding_fingerprint = ANY(${foundFingerprints}::text[]) AND status NOT IN ('closed','resolved')`:[];
  const existingSet=new Set(existing.map((d:any)=>String(d.finding_fingerprint)));
  const pending=foundFingerprints.filter((fingerprint:string)=>!existingSet.has(fingerprint));
  const inserted=pending.length?await sql`
   INSERT INTO disclosures(finding_fingerprint,channel,status,message)
   SELECT f.fingerprint,'private','draft',
    concat_ws(chr(10),\\n',
     'Subject: Potential exposed credential in public repository',
     '',
     'Hello repository maintainers,',
     '',
     'I identified a potential secret exposure during a defensive review of public repository content.',
     'I have not used, tested, imported, or authenticated with the value, and have not accessed or moved funds.',
     '',
     'Repository: ' || f.repository_full_name,
     'Location: ' || f.file_path || ' (line ' || COALESCE(f.line_number::text,'unknown') || ')',
     'Detection: ' || f.rule_id || ' (' || f.severity || ')',
     '',
     'Suggested remediation: treat the value as compromised, rotate or revoke it using your normal trusted procedures, remove it from the working tree and review Git history. Move secrets into a dedicated secrets manager or protected environment variables.',
     'This report intentionally omits the credential value. Please advise if you have a preferred private reporting channel.',
     '',
     'Regards,',
     'Security researcher'
    )
   FROM findings f
   WHERE f.fingerprint = ANY(${pending}::text[])
    AND NOT EXISTS (
     SELECT 1 FROM disclosures d
     WHERE d.finding_fingerprint=f.fingerprint AND d.status NOT IN ('closed','resolved')
    )
   RETURNING finding_fingerprint`:[];
  const created=inserted.length;
  const skipped=existingSet.size+(pending.length-created);
  return NextResponse.json({ok:true,created,skipped,notFound:fingerprints.length-findings.length},{status:201});
 }catch{return NextResponse.json({error:"Could not create bulk disclosure drafts"},{status:500});}
}
