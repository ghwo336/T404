// Web Worker: runs the engine off the main thread and streams one report per file.
import { analyze, Parsed } from "../src/engine";
import type { FileReport } from "../src/types";

self.onmessage = (ev: MessageEvent) => {
  const msg = ev.data;
  if (msg?.type !== "analyze") return;
  const sources = new Map<string, string>(msg.sources as [string, string][]);
  const files = [...sources.keys()].filter((f) => f.endsWith(".sol")).sort();
  const cache = new Map<string, Parsed>();
  const reports: FileReport[] = [];
  const t0 = Date.now();
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    let r: FileReport;
    try {
      r = analyze(f, sources, cache);
    } catch (e: any) {
      r = { file: f, verdict: "Uncertain", score: 0, parseErrors: [String(e?.message ?? e)], imports: { resolved: [], unresolved: [] }, contracts: [], findings: [], summary: "analysis failed" };
    }
    reports.push(r);
    (self as any).postMessage({ type: "file", index: i, total: files.length, report: r });
  }
  const imported = new Set<string>();
  for (const r of reports) for (const i of r.imports.resolved) imported.add(i);
  for (const r of reports) r.role = imported.has(r.file) ? "library" : "entry";
  (self as any).postMessage({ type: "done", reports, ms: Date.now() - t0 });
};
