"use client";

import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ExternalLink, FileCode2, Loader2, ShieldCheck } from "lucide-react";

export default function WebsiteSourceViewer() {
  const params = useSearchParams();
  const asset = params.get("asset") || "";
  const line = Math.max(1, Number(params.get("line")) || 1);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [lineCount, setLineCount] = useState(0);
  const [message, setMessage] = useState("");

  const safeAsset = useMemo(() => {
    try {
      const url = new URL(asset);
      if (!["https:", "http:"].includes(url.protocol)) return null;
      const host = url.hostname.toLowerCase();
      if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")
        || host === "0.0.0.0" || host === "::1" || /^127\./.test(host)
        || /^10\./.test(host) || /^192\.168\./.test(host)
        || /^169\.254\./.test(host)
        || /^172\.(1[6-9]|2\d|3[01])\./.test(host)) return null;
      return url.toString();
    } catch { return null; }
  }, [asset]);

  useEffect(() => {
    if (!safeAsset) {
      setStatus("error");
      setMessage("This asset URL is not allowed.");
      return;
    }
    let active = true;
    fetch(safeAsset, { method: "GET", mode: "cors", credentials: "omit" })
      .then(async (response) => {
        if (!response.ok) throw new Error("The asset returned an error.");
        const text = await response.text();
        if (!active) return;
        setLineCount(text.split(/\r\n|\n|\r/).length);
        setStatus("ready");
      })
      .catch(() => {
        if (!active) return;
        setStatus("error");
        setMessage("This website does not allow browser access to its source (CORS), or the asset is no longer available. Open the asset directly and use the displayed line number with your editor's Go to Line command.");
      });
    return () => { active = false; };
  }, [safeAsset]);

  return <main className="mx-auto w-full max-w-4xl space-y-6 px-5 py-10">
    <div className="space-y-2">
      <p className="text-sm font-medium text-cyan-400">WEBSITE FINDING LOCATION</p>
      <h1 className="text-3xl font-semibold tracking-tight">Source line navigator</h1>
      <p className="text-sm text-muted-foreground">The detected source line is highlighted below. Source text is intentionally not displayed, so a potentially exposed credential is never revealed in the dashboard.</p>
    </div>
    <div className="rounded-xl border p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0"><p className="text-sm text-muted-foreground">Evidence asset</p><p className="break-all text-sm">{safeAsset || "Invalid asset URL"}</p></div>
        {safeAsset && <a className="shrink-0 text-cyan-400 underline" href={safeAsset} target="_blank" rel="noopener noreferrer">Open asset <ExternalLink size={12} className="inline" /></a>}
      </div>
      <div className="mt-4 flex items-center gap-2 text-sm">
        <FileCode2 size={16} />
        <span className="font-mono">Line {line}</span>
        {status === "loading" && <><Loader2 size={14} className="animate-spin" /> Counting lines…</>}
        {status === "ready" && <span className="text-muted-foreground">of {lineCount.toLocaleString()} lines</span>}
      </div>
    </div>
    {status === "ready" && <div className="overflow-hidden rounded-xl border">
      <div className="border-b bg-muted/40 px-4 py-2 text-xs text-muted-foreground">LOCATION IN FILE</div>
      <div className="max-h-[55vh] overflow-auto py-2 font-mono text-sm">
        {Array.from({ length: Math.min(lineCount, 5000) }, (_, i) => i + 1)
          .filter((n) => n >= Math.max(1, line - 5) && n <= Math.min(lineCount, line + 5))
          .map((n) => <div key={n} id={n === line ? "detected-line" : undefined}
            className={n === line ? "flex items-center gap-4 border-y border-amber-500/40 bg-amber-500/10 px-4 py-3 text-amber-200" : "flex gap-4 px-4 py-2 text-muted-foreground"}>
            <span className="w-12 shrink-0 select-none text-right opacity-60">{n}</span>
            <span>{n === line ? "→ Potential exposure detected on this line. Content hidden for safety." : "· · ·"}</span>
          </div>)}
      </div>
      <div className="border-t px-4 py-3 text-xs text-muted-foreground">Only the location is shown. The scanner does not store or display the matched secret.</div>
    </div>}
    {status === "error" && <div className="rounded-xl border p-4 text-sm"><p>{message}</p></div>}
    <div className="flex items-start gap-2 rounded-xl border p-4 text-sm text-muted-foreground"><ShieldCheck size={17} className="mt-0.5 shrink-0" /><p>To inspect the actual source safely, use the line number in a local text editor. Do not copy, test, or use any credential you encounter.</p></div>
  </main>;
}
