import { NextRequest,NextResponse } from "next/server";
import { getDb } from "@/lib/db";
export const runtime="nodejs";
const allowed=["draft","ready","sent","acknowledged","resolved","closed"];
export async function PATCH(request:NextRequest,{params}:{params:Promise<{id:string}>}){
 const {id}=await params;const numeric=Number(id);
 if(!Number.isSafeInteger(numeric)||numeric<1)return NextResponse.json({error:"Invalid disclosure ID"},{status:400});
 let body:any;try{body=await request.json();}catch{return NextResponse.json({error:"Invalid JSON"},{status:400});}
 if(!allowed.includes(body.status))return NextResponse.json({error:"Invalid disclosure status"},{status:400});
 try{
  const sql=getDb();
  const rows=await sql`UPDATE disclosures SET status=${body.status},sent_at=CASE WHEN ${body.status}='sent' THEN COALESCE(sent_at,NOW()) ELSE sent_at END,updated_at=NOW() WHERE id=${numeric} RETURNING id,status,sent_at`;
  if(!rows.length)return NextResponse.json({error:"Disclosure not found"},{status:404});
  return NextResponse.json({ok:true,disclosure:rows[0]});
 }catch{return NextResponse.json({error:"Could not update disclosure status"},{status:500});}
}