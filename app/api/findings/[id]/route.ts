import { NextRequest,NextResponse } from "next/server";
import { getDb } from "@/lib/db";
export const runtime="nodejs";
const allowed=["new","triaged","false_positive","disclosed","remediated"];
export async function PATCH(request:NextRequest,{params}:{params:Promise<{id:string}>}){
 const {id}=await params;const numeric=Number(id);
 if(!Number.isSafeInteger(numeric)||numeric<1)return NextResponse.json({error:"Invalid finding ID"},{status:400});
 let body:any;try{body=await request.json();}catch{return NextResponse.json({error:"Invalid JSON"},{status:400});}
 if(!allowed.includes(body.status))return NextResponse.json({error:"Invalid status"},{status:400});
 try{const sql=getDb();const rows=await sql`UPDATE findings SET status=${body.status},triage_notes=${typeof body.notes==="string"?body.notes.slice(0,1000):null} WHERE id=${numeric} RETURNING id,status`;
 if(!rows.length)return NextResponse.json({error:"Finding not found"},{status:404});
 return NextResponse.json({ok:true,finding:rows[0]});}catch{return NextResponse.json({error:"Database update failed"},{status:500});}
}