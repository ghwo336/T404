// Optional compile confirmation with solc-js (pure wasm, fully offline, bundled as optional dependencies).
// The analysis never depends on it: it only answers "can this source compile at all?" so that a file with
// intrinsic errors (undeclared identifiers, type errors, duplicate declarations) is judged Uncertain rather than
// confidently Malicious/Benign. Missing imports and unknown base contracts are NOT compile failures here -
// the file may simply have been submitted without its dependencies, and the analysis handles that on its own.
import { createRequire } from "node:module";

const req = createRequire(__filename);
const VERSIONS: Record<string, string> = { "0.4": "solc-0.4.26", "0.5": "solc-0.5.17", "0.6": "solc-0.6.12", "0.7": "solc-0.7.6", "0.8": "solc" };
const cache = new Map<string, any>();

function load(pkg: string): any | null {
  if (cache.has(pkg)) return cache.get(pkg);
  let s: any = null;
  try { s = req(pkg); } catch { s = null; }
  cache.set(pkg, s);
  return s;
}

export function available(): boolean { return Object.values(VERSIONS).some((p) => load(p)); }

/** major.minor from the first version literal in the file's pragma(s), else null */
export function pragmaMinor(source: string): string | null {
  const m = /pragma\s+solidity\s+([^;]+);/.exec(source);
  if (!m) return null;
  const v = /(\d+)\.(\d+)(?:\.\d+)?/.exec(m[1]);
  return v ? `${v[1]}.${v[2]}` : null;
}

export interface CompileCheck { ran: boolean; ok: boolean; version?: string; errors: string[]; skipped?: string }

/** Ignore errors that come from the environment, not from the source itself. */
const ENVIRONMENTAL = /Source "[^"]*" not found|File not found|File import callback not supported|not found: File|requires different compiler version|Multiple SPDX/i;

export function compileCheck(entry: string, sources: Map<string, string>, hasUnresolvedImports: boolean): CompileCheck {
  const src = sources.get(entry);
  if (!src) return { ran: false, ok: true, errors: [], skipped: "no source" };
  if (hasUnresolvedImports) return { ran: false, ok: true, errors: [], skipped: "unresolved imports" };
  const minor = pragmaMinor(src);
  // preferred version first (from the pragma), then every other bundled compiler: a source is only "non-compiling"
  // when NO bundled solc accepts it - ranges like >=0.4.22 <0.6.0 often need the higher end
  const all = ["solc-0.4.26", "solc-0.5.17", "solc-0.6.12", "solc-0.7.6", "solc"];
  const pref = minor && VERSIONS[minor] ? VERSIONS[minor] : null;
  const order = pref ? [pref, ...all.filter((x) => x !== pref)] : ["solc-0.4.26", "solc-0.5.17", "solc", "solc-0.6.12", "solc-0.7.6"];
  const relax = (s: string) => s.replace(/pragma\s+solidity\s+[^;]+;/g, "pragma solidity >=0.4.0;").replace(/pragma\s+experimental\s+ABIEncoderV2\s*;/g, (x) => x);
  let last: CompileCheck = { ran: false, ok: true, errors: [], skipped: "no solc-js installed" };
  for (const pkg of order) {
    const solc = load(pkg);
    if (!solc) continue;
    const input = { language: "Solidity", sources: Object.fromEntries([...sources.entries()].map(([k, v]) => [k, { content: relax(v) }])), settings: { outputSelection: { "*": { "*": [] } }, optimizer: { enabled: false } } };
    let out: any;
    try {
      const findImports = (p: string) => ({ error: `File not found: ${p}` });
      const raw = typeof solc.compileStandardWrapper === "function" ? solc.compileStandardWrapper(JSON.stringify(input), findImports) : solc.compile(JSON.stringify(input), { import: findImports });
      out = JSON.parse(raw);
    } catch (e: any) { last = { ran: true, ok: true, version: pkg, errors: [], skipped: `solc crashed: ${String(e?.message ?? e).slice(0, 80)}` }; continue; }
    const errs: string[] = (out.errors ?? []).filter((x: any) => x.severity === "error").map((x: any) => (x.formattedMessage ?? x.message ?? "").replace(/\s+/g, " ").trim());
    const intrinsic = errs.filter((m) => !ENVIRONMENTAL.test(m));
    const version = String(solc.version?.() ?? pkg);
    if (!errs.length) return { ran: true, ok: true, version, errors: [] };
    if (!intrinsic.length) return { ran: true, ok: true, version, errors: [], skipped: "only environmental errors" };
    // keep the preferred version's message (most meaningful), keep trying the others
    if (!last.ran || last.ok) last = { ran: true, ok: false, version, errors: intrinsic.slice(0, 5) };
  }
  return last;
}
