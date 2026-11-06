"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
import { ExternalLink, FileCode2, Loader2, ShieldCheck } from "lucide-react";

function WebsiteSourceViewerContent() {
  const params = useSearchParams();
  const asset = params.get("asset") || "";
  const line = Math.max(1, Number(params.get("line")) || 1);
  const [status, setStatus] = useState<"loading" | "ready" | "error">("loading");
  const [lineCount, setLineCount] = useState(0);
  const [sourceLines, setSourceLines] = useState<string[]>([]);
  const [message, setMessage] = useState("");
  const [loadedAsset, setLoadedAsset] = useState("");

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
    if (!safeAsset) return;
    let active = true;
    fetch(safeAsset, { method: "GET", mode: "cors", credentials: "omit" })
      .then(async (response) => {
        if (!response.ok) throw new Error("The asset returned an error.");
        const text = await response.text();
        if (!active) return;
        const lines = text.split(/\r\n|\n|\r/);
        setLineCount(lines.length);
        setSourceLines(lines);
        setStatus("ready");
        setLoadedAsset(safeAsset);
      })
      .catch(() => {
        if (!active) return;
        setStatus("error");
        setMessage("This website does not allow browser access to its source (CORS), or the asset is no longer available. Open the asset directly and use the displayed line number with your editor's Go to Line command.");
        setLoadedAsset(safeAsset);
      });
    return () => { active = false; };
  }, [safeAsset]);

  const viewStatus = !safeAsset ? "error" : loadedAsset === safeAsset ? status : "loading";
  const viewMessage = !safeAsset ? "This asset URL is not allowed." : message;

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
        {viewStatus === "loading" && <><Loader2 size={14} className="animate-spin" /> Counting lines…</>}
        {viewStatus === "ready" && <span className="text-muted-foreground">of {lineCount.toLocaleString()} lines</span>}
      </div>
    </div>
    {viewStatus === "ready" && <div className="overflow-hidden rounded-xl border">
      <div className="border-b bg-muted/40 px-4 py-2 text-xs text-muted-foreground">DETECTED LINE AND NEARBY CONTEXT · SHOWING UP TO 5 LINES EACH SIDE</div>
      <div className="max-h-[65vh] overflow-auto py-2 font-mono text-xs sm:text-sm">
        {Array.from({ length: Math.max(0, Math.min(lineCount, line + 5) - Math.max(1, line - 5) + 1) }, (_, i) => Math.max(1, line - 5) + i)
          .map((n) => {
            const raw = sourceLines[n - 1] ?? "";
            const sensitive = /(private.?key|secret|token|password|mnemonic|seed.?phrase|api.?key|authorization|bearer|access.?key|client.?secret|credential|wallet.?key)/i.test(raw)
              || /-----BEGIN [A-Z ]*PRIVATE KEY-----|-----END [A-Z ]*PRIVATE KEY-----/i.test(raw)
              || /(?:0x)?[a-fA-F0-9]{64,}/.test(raw)
              || /[1-9A-HJ-NP-Za-km-z]{50,}/.test(raw);
            const display = n === line || sensitive
              ? (raw.trim() ? "[potentially sensitive source line redacted]" : "")
              : raw.slice(0, 500);
            return <div key={n} id={n === line ? "detected-line" : undefined}
              className={n === line ? "flex gap-3 border-y border-amber-500/40 bg-amber-500/10 px-3 py-2 text-amber-200" : "flex gap-3 px-3 py-1.5 text-muted-foreground"}>
              <span className="w-12 shrink-0 select-none text-right opacity-60">{n}</span>
              <span className="min-w-0 whitespace-pre-wrap break-all">{n === line ? "→ " : ""}{display}</span>
            </div>;
          })}
      </div>
      <div className="border-t px-4 py-3 text-xs text-muted-foreground">Showing only nearby lines, not the entire file. The detected line and lines that look sensitive are redacted; other nearby source lines are shown for context. No source text is saved to the database.</div>
    </div>}
    {viewStatus === "error" && <div className="rounded-xl border p-4 text-sm"><p>{viewMessage}</p></div>}
    <div className="flex items-start gap-2 rounded-xl border p-4 text-sm text-muted-foreground"><ShieldCheck size={17} className="mt-0.5 shrink-0" /><p>To inspect the actual source safely, use the line number in a local text editor. Do not copy, test, or use any credential you encounter.</p></div>
  </main>;
}


export default function WebsiteSourceViewer() {
  return <Suspense fallback={<main className="mx-auto max-w-4xl px-5 py-10 text-sm text-muted-foreground">Loading source location…</main>}><WebsiteSourceViewerContent /></Suspense>;
}
