import * as fs from "node:fs";
import * as path from "node:path";
import parser from "@solidity-parser/parser";
import { buildModels, mainContracts } from "./model";
import { runRules } from "./rules";
import { Finding, FileReport, ScanReport, Verdict, ContractReport, Severity } from "./types";

export const VERSION = "0.1.0";
const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const WEIGHT: Record<Severity, number> = { critical: 45, high: 22, medium: 8, low: 2, info: 0 };

export function verdictFor(findings: Finding[]): { verdict: Verdict; score: number; summary: string } {
  let score = 0;
  let crit = 0, high = 0, med = 0;
  for (const f of findings) {
    const eff = f.confidence >= 0.75 ? f.severity : downgrade(f.severity);
    score += WEIGHT[eff] * (0.5 + f.confidence / 2);
    if (eff === "critical") crit++;
    else if (eff === "high") high++;
    else if (eff === "medium") med++;
  }
  score = Math.min(100, Math.round(score));
  const unresolved = findings.some((f) => f.id === "UNRESOLVED_BASE");
  let verdict: Verdict;
  if (crit >= 1 || high >= 2) verdict = "Malicious";
  else if (high >= 1 || med >= 2 || (unresolved && med >= 1)) verdict = "Uncertain";
  else verdict = "Benign";
  const top = findings.filter((f) => f.severity !== "info").sort(bySeverity).slice(0, 3).map((f) => f.title);
  const summary = verdict === "Benign"
    ? (findings.length ? `No malicious logic found; ${findings.length} informational note(s).` : "No malicious logic or hidden privilege paths found.")
    : `${verdict}: ${top.join("; ")}`;
  return { verdict, score, summary };
}

function downgrade(s: Severity): Severity {
  const i = SEV_ORDER.indexOf(s);
  return SEV_ORDER[Math.min(i + 1, SEV_ORDER.length - 1)];
}

export function bySeverity(a: Finding, b: Finding): number {
  const d = SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity);
  return d !== 0 ? d : b.confidence - a.confidence;
}

export function listSolFiles(inputs: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const visit = (p: string) => {
    const st = fs.statSync(p);
    if (st.isDirectory()) {
      const base = path.basename(p);
      if (/^(node_modules|lib|\.git|out|cache|artifacts|build)$/.test(base) && p !== inputs[0]) return;
      for (const e of fs.readdirSync(p).sort()) visit(path.join(p, e));
    } else if (st.isFile() && p.endsWith(".sol")) {
      const r = path.resolve(p);
      if (!seen.has(r)) { seen.add(r); out.push(p); }
    }
  };
  for (const i of inputs) visit(i);
  return out;
}

export function scanFile(file: string): FileReport {
  const source = fs.readFileSync(file, "utf8");
  const parseErrors: string[] = [];
  let ast: any;
  try {
    ast = parser.parse(source, { loc: true, range: true, tolerant: true });
    for (const e of ast.errors ?? []) parseErrors.push(`${e.message} (line ${e.line ?? "?"})`);
  } catch (e: any) {
    const errs = e?.errors ?? [e];
    for (const x of errs) parseErrors.push(x.message ?? String(x));
    return { file, verdict: "Uncertain", score: 0, parseErrors, contracts: [], findings: [], summary: "Could not parse file." };
  }
  const models = buildModels([{ file, ast }]);
  const targets = mainContracts(models);
  const contracts: ContractReport[] = [];
  const all: Finding[] = [];
  for (const c of targets) {
    const findings = runRules({ file, source, c }).sort(bySeverity);
    contracts.push({
      name: c.name,
      kind: c.kind,
      bases: c.bases,
      privilegedFunctions: c.privilegedFunctions.map((f) => `${f.name} [${f.privilegeReason}]`),
      transferPath: [...c.transferPath],
      findings,
    });
    all.push(...findings);
  }
  all.sort(bySeverity);
  const v = verdictFor(all);
  return { file, verdict: v.verdict, score: v.score, parseErrors, contracts, findings: all, summary: v.summary };
}

export function scan(inputs: string[]): ScanReport {
  const files = listSolFiles(inputs);
  const reports = files.map(scanFile);
  return {
    tool: "noexit",
    version: VERSION,
    generatedAt: new Date().toISOString(),
    inputs,
    totals: {
      files: reports.length,
      malicious: reports.filter((r) => r.verdict === "Malicious").length,
      uncertain: reports.filter((r) => r.verdict === "Uncertain").length,
      benign: reports.filter((r) => r.verdict === "Benign").length,
      errors: reports.filter((r) => r.parseErrors.length).length,
    },
    files: reports,
  };
}
