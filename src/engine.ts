// Filesystem-free core: analyze in-memory sources. Used by the browser UI and usable as a library.
import parser from "@solidity-parser/parser";
import { Node, walk } from "./ast";
import { buildModels, mainContracts, Contract } from "./model";
import { runRules } from "./rules";
import { attackPath, checklist } from "./explain";
import { deployable } from "./deployable";
import { Finding, FileReport, Verdict, ContractReport, Severity } from "./types";

export const VERSION = "0.1.0";
const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const WEIGHT: Record<Severity, number> = { critical: 45, high: 22, medium: 8, low: 2, info: 0 };

export function verdictFor(findings: Finding[]): { verdict: Verdict; score: number; summary: string } {
  let score = 0;
  let crit = 0, high = 0, med = 0, vuln = 0;
  for (const f of findings) {
    const eff = f.confidence >= 0.75 ? f.severity : downgrade(f.severity);
    score += WEIGHT[eff] * (0.5 + f.confidence / 2);
    if (f.vulnerability) { if (eff === "critical" || eff === "high") vuln++; else if (eff === "medium") med++; continue; }
    if (eff === "critical") crit++;
    else if (eff === "high") high++;
    else if (eff === "medium") med++;
  }
  score = Math.min(100, Math.round(score));
  const unresolved = findings.some((f) => f.id === "UNRESOLVED_BASE");
  let verdict: Verdict;
  if (crit >= 1 || high >= 1) verdict = "Malicious"; // any confident critical/high finding is an asset-loss or asymmetric-control path
  else if (vuln >= 1 || med >= 2 || (unresolved && med >= 1)) verdict = "Uncertain"; // an exploitable bug puts funds at risk without proving intent
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

export interface Parsed { file: string; source: string; ast: Node | null; errors: string[]; imports: string[] }

export function parseSource(file: string, source: string): Parsed {
  const pf: Parsed = { file, source, ast: null, errors: [], imports: [] };
  try {
    pf.ast = parser.parse(source, { loc: true, range: true, tolerant: true });
    for (const e of (pf.ast as any).errors ?? []) pf.errors.push(`${e.message} (line ${e.line ?? "?"})`);
  } catch (e: any) {
    for (const x of e?.errors ?? [e]) pf.errors.push(x.message ?? String(x));
    return pf;
  }
  walk(pf.ast, (n) => { n.__file = file; });
  for (const c of pf.ast.children ?? []) if (c?.type === "ImportDirective" && typeof c.path === "string") pf.imports.push(c.path);
  return pf;
}

function normalize(p: string): string {
  const out: string[] = [];
  for (const seg of p.replace(/\\/g, "/").split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") out.pop(); else out.push(seg);
  }
  return out.join("/");
}

/** resolve an import against an in-memory file set: relative path, then any file whose tail matches, then same basename */
export function resolveInMemory(raw: string, fromFile: string, files: Iterable<string>): string | null {
  const all = [...files];
  if (raw.startsWith(".")) {
    const dir = normalize(fromFile).split("/").slice(0, -1).join("/");
    const target = normalize((dir ? dir + "/" : "") + raw);
    const hit = all.find((f) => normalize(f) === target);
    if (hit) return hit;
  }
  const segs = normalize(raw).split("/");
  let best: string | null = null, bestScore = 0;
  for (const f of all) {
    const fs = normalize(f).split("/");
    let s = 0;
    while (s < segs.length && s < fs.length && fs[fs.length - 1 - s] === segs[segs.length - 1 - s]) s++;
    if (s > bestScore) { bestScore = s; best = f; }
  }
  return bestScore > 0 ? best : null;
}

export interface AnalyzeOptions { cwd?: string }

/** Analyze one entry file given every available source (entry included). */
export function analyze(entry: string, sources: Map<string, string>, cache?: Map<string, Parsed>, sink?: { contracts: Contract[] }): FileReport {
  const parsed = cache ?? new Map<string, Parsed>();
  const get = (f: string) => { let p = parsed.get(f); if (!p) { p = parseSource(f, sources.get(f) ?? ""); parsed.set(f, p); } return p; };
  const closure: Parsed[] = [];
  const seen = new Set<string>();
  const unresolved: string[] = [];
  const visit = (f: string) => {
    if (seen.has(f)) return; seen.add(f);
    const p = get(f); closure.push(p);
    for (const raw of p.imports) {
      const r = resolveInMemory(raw, f, sources.keys());
      if (r) visit(r); else if (!unresolved.includes(raw)) unresolved.push(raw);
    }
  };
  visit(entry);
  const e = closure[0];
  const parseErrors = [...e.errors];
  if (!e.ast) return { file: entry, verdict: "Uncertain", score: 0, parseErrors, imports: { resolved: [], unresolved }, contracts: [], findings: [], summary: "Could not parse file." };
  const srcMap = new Map<string, string>();
  for (const p of closure) srcMap.set(p.file, p.source);
  const models = buildModels(closure.filter((p) => p.ast).map((p) => ({ file: p.file, ast: p.ast })));
  const targets = mainContracts(models.filter((m) => m.file === entry));
  if (sink) sink.contracts = targets;
  const contracts: ContractReport[] = [];
  const all: Finding[] = [];
  for (const c of targets) {
    const findings = runRules({ file: entry, source: e.source, sources: srcMap, c }).sort(bySeverity);
    for (const f of findings) { const ap = attackPath(f); if (ap) f.attackPath = ap; }
    contracts.push({ checks: checklist(c, findings), name: c.name, kind: c.kind, bases: c.bases, privilegedFunctions: c.privilegedFunctions.map((f) => `${f.name} [${f.privilegeReason}]`), transferPath: [...c.transferPath], findings });
    all.push(...findings);
  }
  all.sort(bySeverity);
  const v = verdictFor(all);
  if (v.verdict === "Benign" && parseErrors.length) { v.verdict = "Uncertain"; v.summary = `Could not fully parse the file (${parseErrors[0]}); no verdict.`; }
  const allC = new Map<string, any>(); for (const p of closure) for (const ch of p.ast?.children ?? []) if (ch?.type === "ContractDefinition") allC.set(ch.name, ch);
  const dep = deployable(e.ast, allC, unresolved.length > 0);
  if (!dep.ok) { parseErrors.push(...dep.reasons.map((r) => `compile: ${r}`)); v.verdict = "Uncertain"; v.summary = `Source cannot compile (${dep.reasons[0]}), so it cannot be deployed as written; ${all.length ? `${all.length} finding(s) noted but not judged` : "no verdict"}.`; }
  return { file: entry, verdict: v.verdict, score: v.score, parseErrors, imports: { resolved: closure.slice(1).map((p) => p.file), unresolved }, contracts, findings: all, summary: targets.length ? v.summary : "No deployable contract in this file (interfaces / libraries / abstract only)." };
}

/** Analyze every .sol in the set; files imported by others are marked role=library. */
export function analyzeAll(sources: Map<string, string>): FileReport[] {
  const cache = new Map<string, Parsed>();
  const reports = [...sources.keys()].filter((f) => f.endsWith(".sol")).sort().map((f) => analyze(f, sources, cache));
  const imported = new Set<string>();
  for (const r of reports) for (const i of r.imports.resolved) imported.add(i);
  for (const r of reports) r.role = imported.has(r.file) ? "library" : "entry";
  return reports;
}
