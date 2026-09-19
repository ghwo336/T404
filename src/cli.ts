#!/usr/bin/env node
import * as fs from "node:fs";
import * as path from "node:path";
import { Command } from "commander";
import { scan, VERSION } from "./scan";
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

program.parse();
