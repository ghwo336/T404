// noexit web UI: landing -> streaming scan -> dashboard. Engine runs in a Blob Web Worker (see worker.ts);
// the source pane is virtualized so multi-thousand-line contracts stay smooth. Bundled by build.mjs into one HTML.
import { VERSION } from "../src/engine";
import type { FileReport, Finding } from "../src/types";

declare const __SAMPLES__: Record<string, string>;
declare const __WORKER__: string;

const $ = <T extends HTMLElement = HTMLElement>(s: string) => document.querySelector(s) as T;
const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]!));
const VORDER: Record<string, number> = { Malicious: 0, Uncertain: 1, Benign: 2 };

let sources = new Map<string, string>();
let reports: FileReport[] = [];
let selected: string | null = null;
let filter = "All";
let worker: Worker | null = null;

// ---------------------------------------------------------------- input
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

// ---------------------------------------------------------------- scan (worker)
function getWorker(): Worker {
  if (worker) return worker;
  const blob = new Blob([__WORKER__], { type: "application/javascript" });
  worker = new Worker(URL.createObjectURL(blob));
  return worker;
}

function run(src: Map<string, string>) {
  sources = src;
  reports = [];
  selected = null;
  show("scan");
  const total = [...src.keys()].filter((f) => f.endsWith(".sol")).length;
  $("#scan-total").textContent = String(total);
  $("#scan-done").textContent = "0";
  $("#scan-bar").style.width = "0%";
  $("#scan-list").innerHTML = "";
  const counts = { Malicious: 0, Uncertain: 0, Benign: 0 };
  const w = getWorker();
  w.onmessage = (ev: MessageEvent) => {
    const m = ev.data;
    if (m.type === "file") {
      const r: FileReport = m.report;
      reports.push(r);
      counts[r.verdict]++;
      $("#scan-done").textContent = String(m.index + 1);
      $("#scan-bar").style.width = `${((m.index + 1) / m.total) * 100}%`;
      $("#c-mal").textContent = String(counts.Malicious); $("#c-unc").textContent = String(counts.Uncertain); $("#c-ben").textContent = String(counts.Benign);
      const row = document.createElement("div");
      row.className = `scan-row ${r.verdict.toLowerCase()}`;
      row.innerHTML = `<span class="scan-name">${esc(r.file)}</span><span class="scan-sum">${esc(r.summary)}</span>${badge(r.verdict)}`;
      const list = $("#scan-list");
      list.prepend(row);
      while (list.children.length > 14) list.removeChild(list.lastChild!);
    } else if (m.type === "done") {
      reports = m.reports;
      const ms = m.ms;
      setTimeout(() => { show("results"); renderDashboard(ms); renderList(); const first = sortedReports().find((r) => r.verdict === "Malicious" && r.role !== "library") ?? sortedReports()[0]; if (first) select(first.file); }, 350);
    }
  };
  w.postMessage({ type: "analyze", sources: [...src.entries()] });
}

function show(view: "landing" | "scan" | "results") {
  for (const v of ["landing", "scan", "results"]) $("#view-" + v).classList.toggle("active", v === view);
  $("#nav-actions").style.visibility = view === "results" ? "visible" : "hidden";
}

// ---------------------------------------------------------------- results
function badge(v: string) { return `<span class="badge ${v.toLowerCase()}">${v}</span>`; }

function sortedReports() {
  return [...reports].sort((a, b) => (a.role === "library" ? 1 : 0) - (b.role === "library" ? 1 : 0) || VORDER[a.verdict] - VORDER[b.verdict] || b.score - a.score || a.file.localeCompare(b.file));
}

function renderDashboard(ms: number) {
  const m = reports.filter((r) => r.verdict === "Malicious").length, u = reports.filter((r) => r.verdict === "Uncertain").length, b = reports.filter((r) => r.verdict === "Benign").length;
  const n = reports.length || 1;
  $("#d-files").textContent = String(reports.length);
  $("#d-ms").textContent = `${ms} ms`;
  $("#d-mal").textContent = String(m); $("#d-unc").textContent = String(u); $("#d-ben").textContent = String(b);
  // donut
  const R = 40, C = 2 * Math.PI * R;
  const segs = [["#FF6B6B", m], ["#F5C451", u], ["#3DD68C", b]] as [string, number][];
  let off = 0;
  $("#donut").innerHTML = `<circle cx="50" cy="50" r="${R}" fill="none" stroke="#242a33" stroke-width="12"/>` + segs.map(([col, v]) => {
    const len = (v / n) * C; const s = `<circle cx="50" cy="50" r="${R}" fill="none" stroke="${col}" stroke-width="12" stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-off}" transform="rotate(-90 50 50)" class="seg"/>`; off += len; return s;
  }).join("") + `<text x="50" y="54" text-anchor="middle" class="donut-n">${reports.length}</text>`;
  // rule histogram (top 8)
  const cnt = new Map<string, number>();
  for (const r of reports) for (const f of r.findings) if (f.severity !== "info" && f.severity !== "low") cnt.set(f.id, (cnt.get(f.id) ?? 0) + 1);
  const top = [...cnt.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  const max = top[0]?.[1] ?? 1;
  $("#rules-bars").innerHTML = top.length ? top.map(([id, v]) => `<div class="bar-row"><span class="bar-id">${esc(id)}</span><div class="bar"><div class="bar-fill" style="width:${(v / max) * 100}%"></div></div><span class="bar-v">${v}</span></div>`).join("") : `<div class="dim small">no high-severity findings</div>`;
}

function renderList() {
  const q = ($("#search") as HTMLInputElement).value.toLowerCase();
  const rows = sortedReports().filter((r) => (filter === "All" || r.verdict === filter) && (!q || r.file.toLowerCase().includes(q)));
  $("#files").innerHTML = rows.map((r) => `
    <div class="file ${r.file === selected ? "sel" : ""} ${r.verdict.toLowerCase()}" data-file="${esc(r.file)}">
      <div class="file-top">${badge(r.verdict)}<span class="score">${r.score}<span class="dim">/100</span></span></div>
      <div class="file-name" title="${esc(r.file)}">${esc(r.file.split("/").pop()!)}${r.role === "library" ? ' <span class="lib">imported</span>' : ""}</div>
      <div class="file-sum">${esc(r.summary)}</div>
    </div>`).join("") || `<div class="dim small" style="padding:16px">no files match</div>`;
  $("#files").querySelectorAll(".file").forEach((el) => el.addEventListener("click", () => select((el as HTMLElement).dataset.file!, true)));
  document.querySelectorAll("#filters button").forEach((b) => b.classList.toggle("on", (b as HTMLElement).dataset.f === filter));
}

function isMobile() { return window.matchMedia("(max-width: 760px)").matches; }
function setPane(p: string) { $("#main").dataset.pane = p; document.querySelectorAll("#mtabs button").forEach((b) => b.classList.toggle("on", (b as HTMLElement).dataset.pane === p)); if (p === "src") renderVisible(); }

function select(file: string, fromUser = false) {
  selected = file;
  renderList();
  if (fromUser && isMobile()) setPane("detail");
  const r = reports.find((x) => x.file === file)!;
  const shown = r.findings.filter((f) => f.severity !== "info");
  const info = r.findings.filter((f) => f.severity === "info");
  $("#detail").innerHTML = `
    <div class="head ${r.verdict.toLowerCase()}">
      <div class="head-row">${badge(r.verdict)}<span class="big">${r.score}<span class="dim">/100</span></span><span class="sp"></span><span class="dim small">${r.contracts.map((c) => esc(c.name)).join(", ")}</span></div>
      <div class="path">${esc(r.file)}</div>
      ${r.imports.resolved.length || r.imports.unresolved.length ? `<div class="dim small">imports: ${r.imports.resolved.length} resolved${r.imports.unresolved.length ? `, unresolved: ${esc(r.imports.unresolved.join(", "))}` : ""}</div>` : ""}
      ${r.parseErrors.length ? `<div class="warn small">parse: ${esc(r.parseErrors[0])}</div>` : ""}
    </div>
    ${shown.map(findingHtml).join("")}
    ${r.contracts.map((c) => c.checks.length ? `<div class="checks"><div class="checks-title">verified for ${esc(c.name)}</div>${c.checks.map((k) => `<div class="check ${k.status}"><span class="mark">${k.status === "pass" ? "✓" : "✗"}</span><b>${esc(k.id)}</b><span class="dim">${esc(k.note)}</span></div>`).join("")}</div>` : "").join("")}
    ${info.length ? `<div class="dim small" style="margin-top:12px">${info.map((f) => esc(f.title)).join(" · ")}</div>` : ""}
  `;
  $("#detail").scrollTop = 0;
  $("#detail").querySelectorAll("[data-jump]").forEach((el) => el.addEventListener("click", () => { const [f, l] = (el as HTMLElement).dataset.jump!.split("::"); if (isMobile()) setPane("src"); showSource(f, Number(l)); }));
  const marks = new Map<string, string>();
  for (const f of shown) { marks.set(`${f.location.file}::${f.location.line}`, f.severity); for (const rel of f.related ?? []) marks.set(`${rel.file}::${rel.line}`, "related"); }
  showSource(r.file, shown[0]?.location.line ?? 1, marks);
}

function findingHtml(f: Finding) {
  return `<div class="finding ${f.severity}">
    <div class="f-top"><span class="sev ${f.severity}">${f.severity}</span><span class="id">${esc(f.id)}</span><span class="dim">conf ${Math.round(f.confidence * 100)}%</span>
      <a class="jump" data-jump="${esc(f.location.file)}::${f.location.line}">${esc(f.location.contract ?? "")}${f.location.function ? "." + esc(f.location.function) + "()" : ""} L${f.location.line}</a></div>
    <div class="f-title">${esc(f.title)}</div>
    ${f.location.snippet ? `<pre class="snip">${esc(f.location.snippet)}</pre>` : ""}
    <div class="f-why">${esc(f.reasoning)}</div>
    ${f.attackPath ? `<div class="steps">${f.attackPath.map((s, i) => `<div class="step"><span class="step-n">${i + 1}</span><span>${esc(s)}</span></div>`).join("")}</div>` : ""}
    ${f.related?.length ? `<div class="small">trigger: ${f.related.map((l) => `<a class="jump" data-jump="${esc(l.file)}::${l.line}">${esc(l.function ?? l.contract ?? "")}() L${l.line}</a>`).join(", ")}</div>` : ""}
  </div>`;
}

// ---------------------------------------------------------------- virtualized source view
const LINE_H = 21;
let srcLines: string[] = [];
let srcFile = "";
let srcMarks = new Map<string, string>();
let curLine = 0;

function showSource(file: string, line: number, marks?: Map<string, string>) {
  if (marks) srcMarks = marks;
  srcFile = file;
  srcLines = (sources.get(file) ?? "").split(/\r?\n/);
  curLine = line;
  $("#src-name").textContent = file;
  $("#src-lines").textContent = `${srcLines.length} lines`;
  const pane = $("#src");
  $("#src-spacer").style.height = `${srcLines.length * LINE_H}px`;
  pane.scrollTop = Math.max(0, (line - 1) * LINE_H - pane.clientHeight / 2 + LINE_H);
  renderVisible();
  const el = document.getElementById("cur-line");
  if (el) { el.classList.remove("pulse"); void el.offsetWidth; el.classList.add("pulse"); }
}

function renderVisible() {
  const pane = $("#src");
  const first = Math.max(0, Math.floor(pane.scrollTop / LINE_H) - 10);
  const last = Math.min(srcLines.length, Math.ceil((pane.scrollTop + pane.clientHeight) / LINE_H) + 10);
  const w = String(srcLines.length).length;
  let html = "";
  for (let i = first; i < last; i++) {
    const n = i + 1; const sev = srcMarks.get(`${srcFile}::${n}`);
    html += `<div class="ln ${sev ? "mark " + sev : ""} ${n === curLine ? "cur" : ""}" style="top:${i * LINE_H}px" ${n === curLine ? 'id="cur-line"' : ""}><span class="no">${String(n).padStart(w, " ")}</span><span class="code">${hl(srcLines[i])}</span></div>`;
  }
  $("#src-body").innerHTML = html;
}

const KW = /\b(pragma|solidity|contract|interface|library|abstract|function|modifier|event|emit|constructor|returns?|return|require|revert|assert|if|else|for|while|do|break|continue|public|private|internal|external|view|pure|payable|virtual|override|memory|storage|calldata|mapping|address|uint\d*|int\d*|bool|string|bytes\d*|true|false|is|new|delete|import|using|constant|immutable|indexed|msg|block|tx|this|super|selfdestruct|delegatecall)\b/g;
function hl(l: string): string {
  if (!l) return " ";
  let s = esc(l);
  s = s.replace(/(\/\/.*$)/, '<span class="c-cm">$1</span>');
  if (!s.includes("c-cm")) s = s.replace(/("[^"]*")/g, '<span class="c-str">$1</span>').replace(KW, '<span class="c-kw">$1</span>').replace(/\b(\d+(?:e\d+)?|0x[0-9a-fA-F]+)\b/g, '<span class="c-num">$1</span>');
  return s;
}

// ---------------------------------------------------------------- misc
function exportJson() {
  const blob = new Blob([JSON.stringify({ tool: "noexit", version: VERSION, generatedAt: new Date().toISOString(), files: reports }, null, 2)], { type: "application/json" });
  const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "noexit-report.json"; a.click();
}

function countUp(el: HTMLElement, to: number, suffix = "", decimals = 0) {
  const t0 = performance.now(); const dur = 1100;
  const step = (t: number) => { const p = Math.min(1, (t - t0) / dur); const e = 1 - Math.pow(1 - p, 3); el.textContent = (to * e).toFixed(decimals) + suffix; if (p < 1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}

function init() {
  document.querySelectorAll(".ver").forEach((e) => (e.textContent = "v" + VERSION));
  document.querySelectorAll<HTMLElement>("[data-count]").forEach((el) => countUp(el, Number(el.dataset.count), el.dataset.suffix ?? "", Number(el.dataset.dec ?? 0)));
  const body = document.body;
  body.addEventListener("dragover", (e) => { e.preventDefault(); $("#drop").classList.add("over"); });
  body.addEventListener("dragleave", (e) => { if (!(e as DragEvent).relatedTarget) $("#drop").classList.remove("over"); });
  body.addEventListener("drop", async (e) => { e.preventDefault(); $("#drop").classList.remove("over"); const s = await readDropped(e.dataTransfer?.items ?? null, e.dataTransfer?.files ?? null); if (s.size) run(s); else toast("No .sol files found in the drop"); });
  document.querySelectorAll<HTMLInputElement>("input.pick").forEach((inp) => inp.addEventListener("change", async () => { const s = await readDropped(null, inp.files); if (s.size) run(s); inp.value = ""; }));
  document.querySelectorAll(".samples").forEach((b) => b.addEventListener("click", () => run(new Map(Object.entries(__SAMPLES__)))));
  $("#export").addEventListener("click", exportJson);
  $("#reset").addEventListener("click", () => show("landing"));
  $("#search").addEventListener("input", renderList);
  document.querySelectorAll("#filters button").forEach((b) => b.addEventListener("click", () => { filter = (b as HTMLElement).dataset.f!; renderList(); }));
  document.querySelectorAll("#mtabs button").forEach((b) => b.addEventListener("click", () => setPane((b as HTMLElement).dataset.pane!)));
  $("#src").addEventListener("scroll", () => requestAnimationFrame(renderVisible));
  window.addEventListener("resize", () => renderVisible());
  show("landing");
}

function toast(msg: string) { const t = $("#toast"); t.textContent = msg; t.classList.add("on"); setTimeout(() => t.classList.remove("on"), 2200); }

init();
