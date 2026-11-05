"use client";
import { useState } from "react";
import { Copy, Check } from "lucide-react";
export function CopyButton({text}:{text:string}){const [copied,setCopied]=useState(false);return <button className="btn secondary" onClick={async()=>{await navigator.clipboard.writeText(text);setCopied(true);setTimeout(()=>setCopied(false),1600);}}>{copied?<Check size={13}/>:<Copy size={13}/>} {copied?"Copied":"Copy draft"}</button>;}