// Adapter for the team's BAYBENCH harness (github.com/sdh2222/trust404):
//   node dist/baybench.js <input-dir> <output.json>
// Emits results.json in baybench/schema/result.schema.json shape, mapping noexit rule ids onto the
// catalog ids/families from docs/research/track1-malice-patterns.md §7.
import * as fs from "node:fs";
import * as path from "node:path";
import { scan, VERSION } from "./scan";
import { Finding, FileReport } from "./types";

type Family = "A" | "B" | "C" | "D" | "E" | "F" | "G";
interface Cat { id: string; family: Family }

/** noexit rule id -> baybench catalog rule id + family */
const MAP: Record<string, Cat> = {
  SELL_RESTRICTION: { id: "EXIT_SELL_ONLY", family: "A" },
  SELL_FEE_UNCAPPED: { id: "FEE_UNBOUNDED", family: "A" },
  UNCAPPED_FEE: { id: "FEE_UNBOUNDED", family: "A" },
  BLACKLIST_GATE: { id: "EXIT_ADDR_GATE", family: "A" },
  ALLOWLIST_GATE: { id: "EXIT_ADDR_GATE", family: "A" },
  AUTO_BLACKLIST: { id: "EXIT_ADDR_GATE", family: "A" },
  TRADING_GATE: { id: "EXIT_GLOBAL_SWITCH", family: "A" },
  OWNER_LIMIT_TO_ZERO: { id: "EXIT_AMOUNT_LIMIT", family: "A" },
  EXIT_TIME_GATE: { id: "EXIT_TIME_GATE", family: "A" },
  EXIT_CALLBACK_CYCLE: { id: "EXIT_CALLBACK_CYCLE", family: "A" },
  FEE_ADDR_MUTABLE: { id: "FEE_ADDR_MUTABLE", family: "C" },
  HIDDEN_MINT: { id: "BAL_PRIV_MINT", family: "B" },
  OWNER_MINT: { id: "BAL_PRIV_MINT", family: "B" },
  OPEN_MINT: { id: "BAL_PRIV_MINT", family: "B" },
  HIDDEN_CALLER_BRANCH: { id: "BAL_TRANSFER_HIDDEN_MINT", family: "B" },
  BALANCE_MANIPULATION: { id: "BAL_DIRECT_SET", family: "B" },
  VIEW_CALLER_DEPENDENT: { id: "VIEW_CALLER_DEPENDENT", family: "B" },
  APPROVAL_BYPASS: { id: "LEAK_ARBITRARY_TRANSFERFROM", family: "C" },
  LEAK_EXEMPT_PATH: { id: "LEAK_EXEMPT_PATH", family: "C" },
  CUSTODY_SWEEP: { id: "LEAK_PRIV_SWEEP", family: "C" },
  PRIVILEGED_WITHDRAW: { id: "LEAK_PRIV_SWEEP", family: "C" },
  OPEN_DRAIN: { id: "LEAK_PRIV_SWEEP", family: "C" },
  WITHDRAW_REDIRECT: { id: "LEAK_PRIV_SWEEP", family: "C" },
  OBFUSCATED_RECIPIENT: { id: "FEE_ADDR_MUTABLE", family: "C" },
  FAKE_RENOUNCE: { id: "OWN_FAKE_RENOUNCE", family: "D" },
  HIDDEN_OWNER_TRANSFER: { id: "OWN_HIDDEN_ROLE", family: "D" },
  OPEN_OWNER_TAKEOVER: { id: "OWN_REASSIGN_NONSTD", family: "D" },
  TX_ORIGIN_AUTH: { id: "OWN_TX_ORIGIN", family: "D" },
  TX_ORIGIN_VALUE: { id: "OWN_TX_ORIGIN", family: "D" },
  EXTERNAL_TRANSFER_HOOK: { id: "STRUCT_EXTERNAL_GATE", family: "E" },
  OPAQUE_DEPENDENCY: { id: "STRUCT_EXTERNAL_GATE", family: "E" },
  DELEGATECALL: { id: "STRUCT_DELEGATECALL_SETTABLE", family: "E" },
  UPGRADEABLE_PROXY: { id: "STRUCT_PROXY_EOA_ADMIN", family: "E" },
  SELFDESTRUCT: { id: "STRUCT_SELFDESTRUCT", family: "E" },
  DRAIN_APPROVAL_PULL: { id: "DRAIN_APPROVAL_PULL", family: "F" },
  APPROVAL_HARVEST: { id: "DRAIN_APPROVAL_PULL", family: "F" },
  RIGGED_PAYOUT: { id: "HONEYPOT_LEGACY", family: "F" },
  UNSATISFIABLE_PAYOUT: { id: "HONEYPOT_LEGACY", family: "F" },
  PAYMENT_HIJACK: { id: "HONEYPOT_LEGACY", family: "F" },
  REENTRANCY: { id: "SLITHER_HIGH_OVERLAY", family: "C" },
  TRANSFER_INFLATION: { id: "BAL_TRANSFER_HIDDEN_MINT", family: "B" },
  HIDDEN_ROLE: { id: "OWN_HIDDEN_ROLE", family: "D" },
  SHADOWED_AUTH: { id: "OWN_HIDDEN_ROLE", family: "D" },
  PONZI_SHAPE: { id: "PONZI_SHAPE", family: "G" },
  HIDDEN_CODE_LAYOUT: { id: "HONEYPOT_LEGACY", family: "F" },
  PREEMPTIVE_DRAIN: { id: "HONEYPOT_LEGACY", family: "F" },
  UNRESOLVED_BASE: { id: "STRUCT_EXTERNAL_GATE", family: "E" },
};

function sev(f: Finding): "HIGH" | "MED" | "INFO" {
  const eff = f.confidence >= 0.75 ? f.severity : ({ critical: "high", high: "medium", medium: "low", low: "info", info: "info" } as const)[f.severity];
  if (eff === "critical" || eff === "high") return "HIGH";
  if (eff === "medium") return "MED";
  return "INFO";
}

export function toBaybench(reports: FileReport[], root: string) {
  const results = reports.filter((r) => r.role !== "library").map((r) => {
    const findings = r.findings.map((f) => {
      const m = MAP[f.id] ?? { id: f.id, family: "E" as Family };
      const lines = [f.location.line, ...(f.related ?? []).map((l) => l.line)].filter((l) => l > 0);
      return { rule_id: m.id, family: m.family, severity: sev(f), contract: f.location.contract ?? "", function: f.location.function ?? "", lines, reasoning: `${f.id}: ${f.title}` };
    });
    // the privileged setter that arms a gate is evidence too: emit it as its own function so expected_functions can match
    for (const f of r.findings) for (const l of f.related ?? []) if (l.function && !findings.some((x) => x.function === l.function && x.rule_id === (MAP[f.id]?.id ?? f.id))) {
      const m = MAP[f.id] ?? { id: f.id, family: "E" as Family };
      findings.push({ rule_id: m.id, family: m.family, severity: sev(f), contract: l.contract ?? "", function: l.function, lines: [l.line], reasoning: `${f.id}: arms ${f.title}` });
    }
    return { file: path.relative(root, r.file).split(path.sep).join("/"), verdict: r.verdict, reason: r.parseErrors.length ? `parse: ${r.parseErrors[0]}` : r.summary, findings };
  });
  return { tool: { name: "noexit", version: VERSION }, results };
}

if (require.main === module) {
  const [input, output] = process.argv.slice(2);
  if (!input || !output) { console.error("usage: baybench <input-dir> <output.json>"); process.exit(2); }
  const root = path.resolve(input);
  const report = scan([root]);
  const out = toBaybench(report.files, root);
  fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
  fs.writeFileSync(output, JSON.stringify(out, null, 2));
  console.error(`noexit baybench: ${out.results.length} files -> ${output}`);
}
