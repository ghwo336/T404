import * as fs from "node:fs";
import * as path from "node:path";
import { Resolver } from "./resolve";
import { buildModels, mainContracts } from "./model";
import { runRules } from "./rules";
import { attackPath, checklist } from "./explain";
import { Finding, FileReport, ScanReport, ContractReport } from "./types";

export { VERSION, verdictFor, bySeverity } from "./engine";
import { VERSION, verdictFor, bySeverity } from "./engine";

export function listSolFiles(inputs: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const visit = (p: string) => {
    const st = fs.statSync(p);
    if (st.isDirectory()) {
      const base = path.basename(p);
      if (/^(node_modules|\.git|out|cache|artifacts|build)$/.test(base) && p !== inputs[0]) return;
      for (const e of fs.readdirSync(p).sort()) visit(path.join(p, e));
    } else if (st.isFile() && p.endsWith(".sol")) {
      const r = path.resolve(p);
      if (!seen.has(r)) { seen.add(r); out.push(p); }
    }
  };
  for (const i of inputs) visit(i);
  return out;
}

export function scanFile(file: string, resolver?: Resolver): FileReport {
  const res = resolver ?? new Resolver([file]);
  const closure = res.closure(file);
  const entry = closure[0];
  const parseErrors = [...entry.errors];
  const unresolvedImports = res.unresolved(file);
  if (!entry.ast) {
    return { file, verdict: "Uncertain", score: 0, parseErrors, imports: { resolved: [], unresolved: unresolvedImports }, contracts: [], findings: [], summary: "Could not parse file." };
  }
  const sources = new Map<string, string>();
  for (const pf of closure) sources.set(pf.file, pf.source);
  const models = buildModels(closure.filter((pf) => pf.ast).map((pf) => ({ file: pf.file, ast: pf.ast })));
  const own = models.filter((m) => m.file === entry.file);
  const targets = mainContracts(own);
  const contracts: ContractReport[] = [];
  const all: Finding[] = [];
  for (const c of targets) {
    const findings = runRules({ file: entry.file, source: entry.source, sources, c }).sort(bySeverity);
    for (const f of findings) { const ap = attackPath(f); if (ap) f.attackPath = ap; }
    contracts.push({
      checks: checklist(c, findings),
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
  const summary = targets.length ? v.summary : "No deployable contract in this file (interfaces / libraries / abstract only).";
  return {
    file, verdict: v.verdict, score: v.score, parseErrors,
    imports: { resolved: closure.slice(1).map((pf) => path.relative(process.cwd(), pf.file)), unresolved: unresolvedImports },
    contracts, findings: all, summary,
  };
}

export function scan(inputs: string[]): ScanReport {
  const files = listSolFiles(inputs);
  const resolver = new Resolver(inputs);
  const reports = files.map((f) => scanFile(f, resolver));
  // mark files that only exist to be imported by other scanned files
  const imported = new Set<string>();
  for (const r of reports) for (const i of r.imports.resolved) imported.add(path.resolve(i));
  for (const r of reports) r.role = imported.has(path.resolve(r.file)) ? "library" : "entry";
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
