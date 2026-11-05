import { NextResponse } from "next/server";
export const runtime="nodejs";
export async function POST(){
 const token=process.env.GITHUB_DISPATCH_TOKEN;
 const repository=process.env.GITHUB_REPOSITORY||"teddyjeremy/Crypto-Secret-Exposure-Hunter";
 if(!token)return NextResponse.json({error:"GITHUB_DISPATCH_TOKEN is not configured in Vercel. Add a fine-grained token with Actions: write and Metadata: read."},{status:503});
 const [owner,name]=repository.split("/");
 if(!owner||!name)return NextResponse.json({error:"GITHUB_REPOSITORY must use owner/repository format."},{status:500});
 const response=await fetch(`https://api.github.com/repos/${owner}/${name}/actions/workflows/crypto-scan.yml/dispatches`,{
  method:"POST",headers:{Authorization:`Bearer ${token}`,Accept:"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","Content-Type":"application/json"},
  body:JSON.stringify({ref:"main",inputs:{max_repos:"40"}}),cache:"no-store"
 });
 if(!response.ok){const body=await response.text();return NextResponse.json({error:`GitHub rejected workflow dispatch (HTTP ${response.status}). Check token permissions and workflow file.`,detail:body.slice(0,300)},{status:502});}
 return NextResponse.json({ok:true,message:"Scan workflow queued. Live repository progress will appear on the dashboard."});
}