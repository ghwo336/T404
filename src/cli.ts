#!/usr/bin/env node
import * as fs from "node:fs";
import * as path from "node:path";
import { Command } from "commander";
import { scan, scanFile, listSolFiles, VERSION } from "./scan";
import { Resolver } from "./resolve";
import { FileReport, ScanReport } from "./types";

const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", yellow: "\x1b[33m", green: "\x1b[32m", cyan: "\x1b[36m", magenta: "\x1b[35m", gray: "\x1b[90m",
};
const SEV_COLOR: Record<string, string> = { critical: C.red + C.bold, high: C.red, medium: C.yellow, low: C.cyan, info: C.gray };
const VERDICT_COLOR: Record<string, string> = { Malicious: C.red + C.bold, Uncertain: C.yellow + C.bold, Benign: C.green + C.bold };

function pretty(r: ScanReport, color: boolean, verbose: boolean): string {
  const c = (s: string, code: string) => (color ? code + s + C.reset : s);
  const lines: string[] = [];
  lines.push(c(`noexit v${r.version}`, C.bold) + c(`  offline Solidity threat scanner`, C.dim));
  lines.push("");
  for (const f of r.files) lines.push(...prettyFile(f, c, verbose));
  lines.push(c("─".repeat(72), C.dim));
  lines.push(`${r.totals.files} file(s): ` + c(`${r.totals.malicious} Malicious`, C.red) + `, ` + c(`${r.totals.uncertain} Uncertain`, C.yellow) + `, ` + c(`${r.totals.benign} Benign`, C.green) + (r.totals.errors ? c(`, ${r.totals.errors} with parse errors`, C.magenta) : ""));
  return lines.join("\n");
}

function prettyFile(f: FileReport, c: (s: string, code: string) => string, verbose: boolean): string[] {
  const out: string[] = [];
  out.push(`${c(f.verdict.toUpperCase().padEnd(9), VERDICT_COLOR[f.verdict])} ${c(String(f.score).padStart(3), C.bold)}/100  ${f.file}${f.role === "library" ? c("  (imported by another file)", C.dim) : ""}`);
  if (f.parseErrors.length) for (const e of f.parseErrors.slice(0, 3)) out.push(`         ${c("parse: " + e, C.magenta)}`);
  if (f.imports.resolved.length || f.imports.unresolved.length) out.push(`           ${c(`imports: ${f.imports.resolved.length} resolved${f.imports.unresolved.length ? `, unresolved: ${f.imports.unresolved.join(", ")}` : ""}`, C.dim)}`);
  const shown = f.findings.filter((x) => verbose || x.severity !== "info");
  for (const x of shown) {
    const where = `${x.location.contract ?? ""}${x.location.function ? "." + x.location.function + "()" : ""} L${x.location.line}`;
    out.push(`  ${c(x.severity.toUpperCase().padEnd(8), SEV_COLOR[x.severity])} ${c(x.id, C.bold)}  ${x.title}  ${c("@ " + where, C.dim)}`);
    if (verbose) {
      out.push(`           ${c("evidence: ", C.dim)}${x.evidence}`);
      out.push(`           ${c("why:      ", C.dim)}${x.reasoning}`);
    } else if (x.location.snippet) {
      out.push(`           ${c(x.location.snippet, C.dim)}`);
    }
    if (x.attackPath && (verbose || x.severity === "critical" || x.severity === "high")) {
      x.attackPath.forEach((step, i) => out.push(`           ${c(`${i + 1}. `, C.magenta)}${step}`));
    }
  }
  if (!shown.length) out.push(`           ${c(f.summary, C.dim)}`);
  if (verbose || f.verdict === "Benign") {
    for (const ct of f.contracts) {
      if (!ct.checks.length) continue;
      out.push(`           ${c(`checks for ${ct.name}:`, C.dim)}`);
      for (const k of ct.checks) out.push(`           ${k.status === "pass" ? c("✓", C.green) : c("✗", C.red)} ${k.id.padEnd(30)} ${c(k.note, C.dim)}`);
    }
  }
  out.push("");
  return out;
}

function toSarif(r: ScanReport) {
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "noexit", version: r.version, rules: [...new Set(r.files.flatMap((f) => f.findings.map((x) => x.id)))].map((id) => ({ id, name: id })) } },
      results: r.files.flatMap((f) => f.findings.map((x) => ({
        ruleId: x.id,
        level: x.severity === "critical" || x.severity === "high" ? "error" : x.severity === "medium" ? "warning" : "note",
        message: { text: `${x.title}. ${x.reasoning}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file }, region: { startLine: Math.max(1, x.location.line), startColumn: x.location.column + 1 } } }],
        properties: { confidence: x.confidence, evidence: x.evidence, verdict: f.verdict },
      }))),
    }],
  };
}

process.stdout.on("error", (e: NodeJS.ErrnoException) => { if (e.code === "EPIPE") process.exit(0); throw e; });

const program = new Command();
program.name("noexit").description("Offline static analysis of Solidity sources for honeypot / rug-pull / hidden-privilege patterns.").version(VERSION);

program
  .command("scan", { isDefault: true })
  .argument("<paths...>", "directories or .sol files to analyze (directories are scanned recursively)")
  .option("-o, --out <file>", "write the JSON report to this file")
  .option("-f, --format <fmt>", "stdout format: pretty | json | sarif | summary", "pretty")
  .option("-v, --verbose", "show evidence and reasoning for every finding, incl. info", false)
  .option("--no-color", "disable ANSI colors")
  .option("--fail-on <verdict>", "exit code 1 if any file reaches this verdict: malicious | uncertain")
  .action((paths: string[], opts) => {
    for (const p of paths) if (!fs.existsSync(p)) { console.error(`noexit: path not found: ${p}`); process.exit(2); }
    const report = scan(paths);
    if (opts.out) {
      fs.mkdirSync(path.dirname(path.resolve(opts.out)), { recursive: true });
      fs.writeFileSync(opts.out, JSON.stringify(report, null, 2));
    }
    switch (opts.format) {
      case "json": process.stdout.write(JSON.stringify(report, null, 2) + "\n"); break;
      case "sarif": process.stdout.write(JSON.stringify(toSarif(report), null, 2) + "\n"); break;
      case "summary":
        for (const f of report.files) process.stdout.write(`${f.verdict}\t${f.score}\t${f.file}\t${f.summary}\n`);
        break;
      default: process.stdout.write(pretty(report, opts.color !== false && process.stdout.isTTY !== false, opts.verbose) + "\n");
    }
    if (opts.failOn) {
      const want = String(opts.failOn).toLowerCase();
      const bad = report.files.some((f) => f.verdict === "Malicious" || (want === "uncertain" && f.verdict === "Uncertain"));
      if (bad) process.exit(1);
    }
  });

// ---------------------------------------------------------------- TRUST404 Track 1 grading entry point
// `noexit judge <dir>`: every *.sol directly in <dir> (no recursion) -> one JSON array on stdout matching the
// track's schema.json; all logs on stderr; exit code 0 even if some files fail (they become UNCERTAIN).
function t404Object(r: FileReport, fileName: string, totalLines: number, src?: string) {
  const verdict = r.verdict.toUpperCase() as "MALICIOUS" | "BENIGN" | "UNCERTAIN";
  const inFile = (l: { file: string; line: number }) => path.basename(l.file) === fileName && l.line >= 1 && l.line <= totalLines;
  const strong = r.findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const shown = (verdict === "MALICIOUS" ? strong : r.findings).filter((f) => f.severity !== "info");
  const reasons: string[] = [];
  const evidence: { function?: string; line?: number }[] = [];
  const seen = new Set<string>();
  const addEv = (fn: string | undefined, line: number | undefined) => {
    const ev: { function?: string; line?: number } = {};
    if (fn) ev.function = fn;
    if (line) ev.line = line;
    if (!ev.function && !ev.line) return;
    const k = `${ev.function ?? ""}:${ev.line ?? ""}`;
    if (seen.has(k)) return; seen.add(k); evidence.push(ev);
  };
  const declLine = (fn?: string) => { if (!fn || !src) return undefined; const m = src.match(new RegExp(`^[^\\n]*\\bfunction\\s+${fn.replace(/[$]/g, "\\$")}\\s*\\(`, "m")); return m ? src.slice(0, m.index).split(/\r?\n/).length : undefined; };
  for (const f of shown) {
    reasons.push(`[${f.severity.toUpperCase()} ${f.id}] ${f.title}. ${f.reasoning}${f.attackPath ? " Steps: " + f.attackPath.map((s, i) => `(${i + 1}) ${s}`).join(" ") : ""}`);
    addEv(f.location.function, inFile(f.location) ? f.location.line : declLine(f.location.function));
    for (const rel of f.related ?? []) addEv(rel.function, inFile(rel) ? rel.line : declLine(rel.function));
    if (f.location.function && inFile(f.location)) addEv(f.location.function, declLine(f.location.function));
  }
  if (verdict !== "MALICIOUS") {
    for (const c of r.contracts) for (const k of c.checks) if (k.status === "pass") reasons.push(`[OK ${k.id}] ${k.note}`);
    for (const f of r.findings.filter((x) => x.severity === "low" || x.severity === "medium")) reasons.push(`[NOTE ${f.id}] ${f.title}. ${f.reasoning}`);
    if (r.parseErrors.length) reasons.push(`[PARSE] ${r.parseErrors[0]}`);
    if (!r.contracts.length && !r.parseErrors.length) reasons.push("No deployable contract in this file (interfaces / libraries / abstract only).");
  }
  const ids = new Set(r.findings.map((f) => f.id));
  const risk_type = verdict === "BENIGN" ? (r.findings.some((f) => f.severity === "low" || f.severity === "medium") ? "CENTRALIZATION" : "NONE")
    : [...ids].some((i) => /^(OPEN_DRAIN|OPEN_MINT|OPEN_OWNER_TAKEOVER)$/.test(i)) ? "VULNERABILITY" : verdict === "MALICIOUS" ? "BACKDOOR" : "CENTRALIZATION";
  const risk_level = r.findings.some((f) => f.severity === "critical") ? "CRITICAL" : r.findings.some((f) => f.severity === "high") ? "HIGH" : r.findings.some((f) => f.severity === "medium") ? "MEDIUM" : "LOW";
  const confidence = verdict === "UNCERTAIN" ? 0.5 : Math.max(0.5, Math.min(0.99, shown.length ? Math.max(...shown.map((f) => f.confidence)) : 0.9));
  return { file: fileName, verdict, reasons, evidence, risk_level, risk_type, confidence: Math.round(confidence * 100) / 100 };
}

program
  .command("judge")
  .description("TRUST404 Track 1 grading mode: process every *.sol directly inside <dir>, print one JSON array (schema.json) to stdout, logs to stderr, exit 0")
  .argument("<dir>", "directory containing .sol files")
  .option("--recursive", "also include subdirectories (grading uses top-level files only)", false)
  .action((dir: string, opts) => {
    const log = (m: string) => process.stderr.write(m + "\n");
    const out: any[] = [];
    let files: string[] = [];
    try {
      if (!fs.existsSync(dir)) throw new Error(`path not found: ${dir}`);
      files = opts.recursive ? listSolFiles([dir]) : fs.readdirSync(dir).filter((f) => f.endsWith(".sol") && fs.statSync(path.join(dir, f)).isFile()).sort().map((f) => path.join(dir, f));
    } catch (e: any) { log(`noexit: ${e.message}`); }
    const resolver = files.length ? new Resolver([dir]) : undefined;
    const seenNames = new Set<string>();
    for (const file of files) {
      const name = path.basename(file);
      if (seenNames.has(name)) { log(`skip duplicate name ${file}`); continue; }
      seenNames.add(name);
      const t0 = Date.now();
      try {
        const r = scanFile(file, resolver);
        const text = fs.readFileSync(file, "utf8");
        const o = t404Object(r, name, text.split(/\r?\n/).length, text);
        if (o.verdict === "MALICIOUS" && !o.evidence.length) { o.verdict = "UNCERTAIN"; o.reasons.unshift("Downgraded to UNCERTAIN: no in-file evidence location could be attached."); }
        out.push(o);
        log(`${o.verdict.padEnd(9)} ${name} (${Date.now() - t0} ms)`);
      } catch (e: any) {
        out.push({ file: name, verdict: "UNCERTAIN", reasons: [`analysis failed: ${e?.message ?? e}`], evidence: [], risk_level: "LOW", risk_type: "NONE", confidence: 0 });
        log(`UNCERTAIN ${name} (error: ${e?.message ?? e})`);
      }
    }
    if (!out.length) { out.push({ file: "no-input.sol", verdict: "UNCERTAIN", reasons: ["no .sol files found in the input directory"], evidence: [] }); }
    process.stdout.write(JSON.stringify(out, null, 2) + "\n");
    process.exitCode = 0;
  });

program.parse();
