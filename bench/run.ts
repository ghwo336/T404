// Real-world benchmark: downloads verified source from Etherscan (V2 API, free key) for
//   bench/malicious.tsv  - 189 ERC-20 backdoor contracts labeled by the Pied-Piper study (TOSEM'22)
//   bench/benign.tsv     - 30 blue-chip tokens
// then runs noexit on each and prints a confusion matrix + per-category recall.
// Sources are cached under bench/src/, so re-runs are offline.
//
//   ETHERSCAN_API_KEY=... npx tsx bench/run.ts            (or put the key in .env)
//   npx tsx bench/run.ts --offline                        (use cache only)
import * as fs from "node:fs";
import * as path from "node:path";
import { scanFile } from "../src/scan";
import { Resolver } from "../src/resolve";

const ROOT = fs.existsSync(path.join(__dirname, "malicious.tsv")) ? __dirname : path.resolve(__dirname, "..", "..");
const SRC = path.join(ROOT, "src");
const offline = process.argv.includes("--offline");

function loadEnv() {
  const p = path.join(ROOT, "..", ".env");
  if (!fs.existsSync(p)) return;
  for (const line of fs.readFileSync(p, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*"?([^"]*)"?\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
}
loadEnv();
const KEY = process.env.ETHERSCAN_API_KEY;

interface Entry { address: string; label: string; category: string; }
function readList(file: string, label: string): Entry[] {
  return fs.readFileSync(path.join(ROOT, file), "utf8").split(/\r?\n/).filter(Boolean).map((l) => {
    const [address, category] = l.split("\t");
    return { address: address.toLowerCase(), label, category: category ?? "" };
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function fetchSource(address: string, dir: string): Promise<{ entry: string | null; note: string }> {
  const meta = path.join(dir, "meta.json");
  if (fs.existsSync(meta)) {
    const m = JSON.parse(fs.readFileSync(meta, "utf8"));
    return { entry: m.entry, note: m.note };
  }
  if (offline || !KEY) return { entry: null, note: offline ? "not cached" : "no ETHERSCAN_API_KEY" };
  fs.mkdirSync(dir, { recursive: true });
  const url = `https://api.etherscan.io/v2/api?chainid=1&module=contract&action=getsourcecode&address=${address}&apikey=${KEY}`;
  let json: any;
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await fetch(url);
    json = await res.json();
    if (json.status === "1" && json.result?.[0]) break;
    if (/rate limit/i.test(json.result ?? "")) { await sleep(1200); continue; }
    break;
  }
  await sleep(250); // 5 calls/s on the free plan
  const r = json?.result?.[0];
  if (!r || !r.SourceCode) {
    fs.writeFileSync(meta, JSON.stringify({ entry: null, note: "source not verified" }));
    return { entry: null, note: "source not verified" };
  }
  let entry: string | null = null;
  let note = "";
  let src: string = r.SourceCode;
  if (src.startsWith("{{")) src = src.slice(1, -1); // etherscan wraps multi-file JSON in {{ }}
  if (src.trim().startsWith("{")) {
    let obj: any;
    try { obj = JSON.parse(src); } catch { obj = null; }
    const sources = obj?.sources ?? obj;
    if (sources && typeof sources === "object") {
      for (const [p, v] of Object.entries<any>(sources)) {
        const safe = p.replace(/^\/+/, "").replace(/\.\./g, "_");
        const fp = path.join(dir, safe);
        fs.mkdirSync(path.dirname(fp), { recursive: true });
        fs.writeFileSync(fp, typeof v === "string" ? v : v.content ?? "");
        if (!entry && new RegExp(`contract\\s+${r.ContractName}\\b`).test(typeof v === "string" ? v : v.content ?? "")) entry = fp;
      }
      note = `multi-file (${Object.keys(sources).length})`;
    }
  } else {
    entry = path.join(dir, `${r.ContractName || "Contract"}.sol`);
    fs.writeFileSync(entry, src);
  }
  if (r.Proxy === "1" && r.Implementation) note += ` proxy->${r.Implementation}`;
  fs.writeFileSync(meta, JSON.stringify({ entry: entry ? path.relative(dir, entry) : null, note, contractName: r.ContractName, compiler: r.CompilerVersion, proxy: r.Proxy, implementation: r.Implementation }, null, 2));
  return { entry: entry ? path.relative(dir, entry) : null, note };
}

async function main() {
  const entries = [...readList("malicious.tsv", "Malicious"), ...readList("benign.tsv", "Benign")];
  const rows: any[] = [];
  let i = 0;
  for (const e of entries) {
    i++;
    const dir = path.join(SRC, e.label.toLowerCase(), e.address);
    let src;
    try { src = await fetchSource(e.address, dir); } catch (err: any) { src = { entry: null, note: "fetch error: " + err.message }; }
    if (!src.entry) { rows.push({ ...e, verdict: "n/a", score: 0, note: src.note, top: "" }); process.stderr.write(`[${i}/${entries.length}] ${e.address} skipped: ${src.note}\n`); continue; }
    const file = path.join(dir, src.entry);
    let rep;
    try { rep = scanFile(file, new Resolver([dir])); } catch (err: any) { rows.push({ ...e, verdict: "error", score: 0, note: err.message, top: "" }); continue; }
    const top = rep.findings.filter((f) => f.severity !== "info").slice(0, 2).map((f) => f.id).join(",");
    rows.push({ ...e, verdict: rep.verdict, score: rep.score, note: src.note, top, parseErrors: rep.parseErrors.length });
    process.stderr.write(`[${i}/${entries.length}] ${e.label.padEnd(9)} ${e.category.padEnd(17)} -> ${rep.verdict.padEnd(9)} ${top}\n`);
  }
  fs.writeFileSync(path.join(ROOT, "results.json"), JSON.stringify(rows, null, 2));

  // metrics: Malicious label vs verdict; Uncertain counted separately
  const ok = rows.filter((r) => r.verdict !== "n/a" && r.verdict !== "error");
  const mal = ok.filter((r) => r.label === "Malicious"), ben = ok.filter((r) => r.label === "Benign");
  const tp = mal.filter((r) => r.verdict === "Malicious").length, malUnc = mal.filter((r) => r.verdict === "Uncertain").length, fn = mal.filter((r) => r.verdict === "Benign").length;
  const tn = ben.filter((r) => r.verdict === "Benign").length, benUnc = ben.filter((r) => r.verdict === "Uncertain").length, fp = ben.filter((r) => r.verdict === "Malicious").length;
  const precision = tp / Math.max(1, tp + fp), recall = tp / Math.max(1, mal.length), f1 = (2 * precision * recall) / Math.max(1e-9, precision + recall);
  const md: string[] = [];
  md.push(`# noexit real-world benchmark`, ``, `Sources: Pied-Piper backdoor list (TOSEM 2022, ${entries.filter((e) => e.label === "Malicious").length} Ethereum ERC-20 contracts) + ${entries.filter((e) => e.label === "Benign").length} blue-chip tokens. ${rows.filter((r) => r.verdict === "n/a").length} skipped (source not verified / not cached).`, ``);
  md.push(`| label \\ verdict | Malicious | Uncertain | Benign | total |`, `|---|---|---|---|---|`);
  md.push(`| Malicious (backdoor) | **${tp}** | ${malUnc} | ${fn} | ${mal.length} |`);
  md.push(`| Benign (blue-chip) | ${fp} | ${benUnc} | **${tn}** | ${ben.length} |`);
  md.push(``, `- recall (Malicious flagged as Malicious): **${(recall * 100).toFixed(1)}%**; counting Uncertain as a flag: ${(((tp + malUnc) / Math.max(1, mal.length)) * 100).toFixed(1)}%`);
  md.push(`- precision: **${(precision * 100).toFixed(1)}%**, F1: **${f1.toFixed(3)}**`, ``);
  md.push(`## Recall by backdoor category`, ``, `| category | n | Malicious | Uncertain | Benign |`, `|---|---|---|---|---|`);
  for (const cat of [...new Set(mal.map((r) => r.category))]) {
    const rs = mal.filter((r) => r.category === cat);
    md.push(`| ${cat} | ${rs.length} | ${rs.filter((r) => r.verdict === "Malicious").length} | ${rs.filter((r) => r.verdict === "Uncertain").length} | ${rs.filter((r) => r.verdict === "Benign").length} |`);
  }
  md.push(``, `## Blue-chip tokens`, ``, `| token | verdict | score | top findings | note |`, `|---|---|---|---|---|`);
  for (const r of rows.filter((r) => r.label === "Benign")) md.push(`| ${r.category} | ${r.verdict} | ${r.score} | ${r.top} | ${r.note} |`);
  md.push(``, `## Missed / uncertain backdoors`, ``, `| address | category | verdict | top findings |`, `|---|---|---|---|`);
  for (const r of mal.filter((r) => r.verdict !== "Malicious")) md.push(`| ${r.address} | ${r.category} | ${r.verdict} | ${r.top} |`);
  fs.writeFileSync(path.join(ROOT, "RESULTS.md"), md.join("\n") + "\n");
  console.log(md.slice(0, 12).join("\n"));
  console.log(`\nfull report: bench/RESULTS.md, raw: bench/results.json`);
}
main();
