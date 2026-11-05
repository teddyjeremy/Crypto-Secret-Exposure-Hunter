import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
export const runtime="nodejs";
export async function GET(){
 try{const sql=getDb();await sql`SELECT 1 AS ok`;return NextResponse.json({ok:true,database:"connected",timestamp:new Date().toISOString()});}
 catch{return NextResponse.json({ok:false,database:"unavailable"},{status:503});}
}