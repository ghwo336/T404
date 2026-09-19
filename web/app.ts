// Browser UI: drop .sol files / a folder -> verdicts, findings, attack paths, checks, highlighted source.
// Bundled by web/build.ts into a single offline HTML (web/noexit.html).
import { analyzeAll, VERSION } from "../src/engine";
import type { FileReport, Finding } from "../src/types";

declare const __SAMPLES__: Record<string, string>; // injected at build time: sample path -> source

const $ = (s: string) => document.querySelector(s) as HTMLElement;
const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));

let sources = new Map<string, string>();
let reports: FileReport[] = [];
let selected: string | null = null;

function setStatus(msg: string) { $("#status").textContent = msg; }

async function readDropped(items: DataTransferItemList | null, files: FileList | null): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const readFile = (f: File, path: string) => new Promise<void>((res) => { const r = new FileReader(); r.onload = () => { out.set(path, String(r.result)); res(); }; r.onerror = () => res(); r.readAsText(f); });
  const walkEntry = async (entry: any, prefix: string): Promise<void> => {
    if (entry.isFile) {
      if (!entry.name.endsWith(".sol")) return;
      const f: File = await new Promise((res) => entry.file(res));
      await readFile(f, prefix + entry.name);
    } else if (entry.isDirectory) {
      if (/^(node_modules|\.git|out|cache|artifacts|build)$/.test(entry.name)) return;
      const reader = entry.createReader();
      const entries: any[] = await new Promise((res) => { const acc: any[] = []; const step = () => reader.readEntries((es: any[]) => { if (!es.length) res(acc); else { acc.push(...es); step(); } }); step(); });
      for (const e of entries) await walkEntry(e, prefix + entry.name + "/");
    }
  };
  if (items) {
    const entries = [...items].map((i) => (i as any).webkitGetAsEntry?.()).filter(Boolean);
    if (entries.length) { for (const e of entries) await walkEntry(e, ""); return out; }
  }
  if (files) for (const f of [...files]) if (f.name.endsWith(".sol")) await readFile(f, (f as any).webkitRelativePath || f.name);
  return out;
}

function run(src: Map<string, string>) {
  sources = src;
  const t0 = performance.now();
  reports = analyzeAll(sources);
  const ms = Math.round(performance.now() - t0);
  const m = reports.filter((r) => r.verdict === "Malicious").length, u = reports.filter((r) => r.verdict === "Uncertain").length, b = reports.filter((r) => r.verdict === "Benign").length;
  setStatus(`${reports.length} file(s) in ${ms} ms — ${m} Malicious · ${u} Uncertain · ${b} Benign`);
  $("#empty").style.display = "none";
  $("#main").style.display = "grid";
  renderList();
  const first = reports.find((r) => r.verdict === "Malicious") ?? reports[0];
  if (first) select(first.file);
}

function badge(v: string) { return `<span class="badge ${v.toLowerCase()}">${v}</span>`; }

function renderList() {
  const order = { Malicious: 0, Uncertain: 1, Benign: 2 } as any;
  const rows = [...reports].sort((a, b) => order[a.verdict] - order[b.verdict] || b.score - a.score);
  $("#files").innerHTML = rows.map((r) => `
    <div class="file ${r.file === selected ? "sel" : ""}" data-file="${esc(r.file)}">
      <div class="file-top">${badge(r.verdict)}<span class="score">${r.score}</span></div>
      <div class="file-name" title="${esc(r.file)}">${esc(r.file.split("/").pop()!)}${r.role === "library" ? ' <span class="lib">imported</span>' : ""}</div>
      <div class="file-sum">${esc(r.summary)}</div>
    </div>`).join("");
  $("#files").querySelectorAll(".file").forEach((el) => el.addEventListener("click", () => select((el as HTMLElement).dataset.file!)));
}

function select(file: string) {
  selected = file;
  renderList();
  const r = reports.find((x) => x.file === file)!;
  const shown = r.findings.filter((f) => f.severity !== "info");
  const info = r.findings.filter((f) => f.severity === "info");
  $("#detail").innerHTML = `
    <div class="head">
      <div>${badge(r.verdict)} <span class="big">${r.score}<span class="dim">/100</span></span></div>
      <div class="path">${esc(r.file)}</div>
      ${r.imports.resolved.length || r.imports.unresolved.length ? `<div class="dim small">imports: ${r.imports.resolved.length} resolved${r.imports.unresolved.length ? `, unresolved: ${esc(r.imports.unresolved.join(", "))}` : ""}</div>` : ""}
      ${r.parseErrors.length ? `<div class="warn small">parse: ${esc(r.parseErrors[0])}</div>` : ""}
    </div>
    ${shown.map(findingHtml).join("")}
    ${r.contracts.map((c) => c.checks.length ? `<div class="checks"><div class="checks-title">checks for ${esc(c.name)}</div>${c.checks.map((k) => `<div class="check ${k.status}"><span class="mark">${k.status === "pass" ? "✓" : "✗"}</span><b>${esc(k.id)}</b><span class="dim">${esc(k.note)}</span></div>`).join("")}</div>` : "").join("")}
    ${info.length ? `<div class="dim small" style="margin-top:12px">${info.map((f) => esc(f.title)).join(" · ")}</div>` : ""}
  `;
  $("#detail").querySelectorAll("[data-jump]").forEach((el) => el.addEventListener("click", () => { const [f, l] = (el as HTMLElement).dataset.jump!.split("::"); showSource(f, Number(l)); }));
  const lines = shown.map((f) => f.location.line);
  showSource(r.file, lines[0] ?? 1, new Map(shown.map((f) => [`${f.location.file}::${f.location.line}`, f.severity])));
}

function findingHtml(f: Finding) {
  return `<div class="finding ${f.severity}">
    <div class="f-top"><span class="sev ${f.severity}">${f.severity}</span><span class="id">${esc(f.id)}</span><span class="dim">conf ${Math.round(f.confidence * 100)}%</span>
      <a class="jump" data-jump="${esc(f.location.file)}::${f.location.line}">${esc(f.location.contract ?? "")}${f.location.function ? "." + esc(f.location.function) + "()" : ""} L${f.location.line}</a></div>
    <div class="f-title">${esc(f.title)}</div>
    ${f.location.snippet ? `<pre class="snip">${esc(f.location.snippet)}</pre>` : ""}
    <div class="f-why">${esc(f.reasoning)}</div>
    ${f.attackPath ? `<ol class="path">${f.attackPath.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>` : ""}
    ${f.related?.length ? `<div class="small">related: ${f.related.map((l) => `<a class="jump" data-jump="${esc(l.file)}::${l.line}">${esc(l.function ?? l.contract ?? "")}() L${l.line}</a>`).join(", ")}</div>` : ""}
  </div>`;
}

let marks = new Map<string, string>();
function showSource(file: string, line: number, m?: Map<string, string>) {
  if (m) marks = m;
  const src = sources.get(file) ?? "";
  const lines = src.split(/\r?\n/);
  $("#src-name").textContent = file;
  $("#src").innerHTML = lines.map((l, i) => {
    const n = i + 1; const sev = marks.get(`${file}::${n}`);
    return `<div class="ln ${sev ? "mark " + sev : ""} ${n === line ? "cur" : ""}" id="L${n}"><span class="no">${n}</span><span class="code">${esc(l) || " "}</span></div>`;
  }).join("");
  const el = document.getElementById(`L${line}`);
  const pane = $("#src");
  if (el) pane.scrollTop = Math.max(0, el.offsetTop - pane.clientHeight / 2);
}

function exportJson() {
  const blob = new Blob([JSON.stringify({ tool: "noexit", version: VERSION, generatedAt: new Date().toISOString(), files: reports }, null, 2)], { type: "application/json" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "noexit-report.json"; a.click();
}

function init() {
  $("#ver").textContent = "v" + VERSION;
  const drop = document.body;
  drop.addEventListener("dragover", (e) => { e.preventDefault(); $("#empty").classList.add("over"); });
  drop.addEventListener("dragleave", () => $("#empty").classList.remove("over"));
  drop.addEventListener("drop", async (e) => { e.preventDefault(); $("#empty").classList.remove("over"); setStatus("reading…"); const s = await readDropped(e.dataTransfer?.items ?? null, e.dataTransfer?.files ?? null); if (s.size) run(s); else setStatus("no .sol files found"); });
  ($("#pick") as HTMLInputElement).addEventListener("change", async (e) => { const s = await readDropped(null, (e.target as HTMLInputElement).files); if (s.size) run(s); });
  ($("#pickdir") as HTMLInputElement).addEventListener("change", async (e) => { const s = await readDropped(null, (e.target as HTMLInputElement).files); if (s.size) run(s); });
  $("#samples").addEventListener("click", () => run(new Map(Object.entries(__SAMPLES__))));
  $("#export").addEventListener("click", exportJson);
  $("#reset").addEventListener("click", () => { $("#main").style.display = "none"; $("#empty").style.display = "flex"; setStatus(""); });
}
init();
