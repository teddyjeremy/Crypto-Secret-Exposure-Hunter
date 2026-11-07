import { NextRequest,NextResponse } from "next/server";
import { getDb } from "@/lib/db";
export const runtime="nodejs";
const allowed=["new","triaged","false_positive","disclosed","remediated"];
export async function PATCH(request:NextRequest){
 let body:any;try{body=await request.json();}catch{return NextResponse.json({error:"Invalid JSON"},{status:400});}
 const ids=Array.isArray(body.ids)?Array.from(new Set(body.ids.map(Number).filter((n:number)=>Number.isSafeInteger(n)&&n>0))):[];
 if(!ids.length||ids.length>500)return NextResponse.json({error:"Select between 1 and 500 findings"},{status:400});
 if(!allowed.includes(body.status))return NextResponse.json({error:"Invalid status"},{status:400});
 try{
  const sql=getDb();
  const rows=await sql`UPDATE findings SET status=${body.status} WHERE id = ANY(${ids}::int[]) AND classification='secret_candidate' RETURNING id,status`;
  return NextResponse.json({ok:true,updated:rows.length,findings:rows});
 }catch{return NextResponse.json({error:"Bulk status update failed"},{status:500});}
}
