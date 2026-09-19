// Import resolution: follows `import` directives inside the analyzed tree so that
// inheritance (Ownable, ERC20, ...) is modeled from the real source instead of guessed by name.
// Fully offline: only looks at the filesystem under the input roots / their ancestors.
import * as fs from "node:fs";
import * as path from "node:path";
import parser from "@solidity-parser/parser";
import { Node, walk } from "./ast";

export interface ParsedFile {
  file: string; // absolute path
  source: string;
  ast: Node | null;
  errors: string[];
  imports: string[]; // raw import strings
  resolved: Map<string, string | null>; // raw -> absolute path or null if unresolved
}

export class Resolver {
  private cache = new Map<string, ParsedFile>();
  private remappings: { from: string; to: string }[] = [];
  private searchRoots: string[] = [];
  private indexByBase = new Map<string, string[]>(); // basename -> absolute paths (lazy)
  private indexed = false;

  constructor(private roots: string[]) {
    // search roots: each input root and up to 4 ancestors (for node_modules / lib / remappings.txt)
    const seen = new Set<string>();
    for (const r of roots) {
      let d = fs.statSync(r).isDirectory() ? path.resolve(r) : path.dirname(path.resolve(r));
      for (let i = 0; i < 5; i++) {
        if (!seen.has(d)) { seen.add(d); this.searchRoots.push(d); }
        const parent = path.dirname(d);
        if (parent === d) break;
        d = parent;
      }
    }
    for (const d of this.searchRoots) {
      const rm = path.join(d, "remappings.txt");
      if (fs.existsSync(rm)) {
        for (const line of fs.readFileSync(rm, "utf8").split(/\r?\n/)) {
          const m = line.trim().match(/^([^=]+)=(.+)$/);
          if (m) this.remappings.push({ from: m[1].trim(), to: path.resolve(d, m[2].trim()) });
        }
      }
    }
  }

  parse(file: string): ParsedFile {
    const abs = path.resolve(file);
    const hit = this.cache.get(abs);
    if (hit) return hit;
    const source = fs.readFileSync(abs, "utf8");
    const pf: ParsedFile = { file: abs, source, ast: null, errors: [], imports: [], resolved: new Map() };
    this.cache.set(abs, pf);
    try {
      pf.ast = parser.parse(source, { loc: true, range: true, tolerant: true });
      for (const e of (pf.ast as any).errors ?? []) pf.errors.push(`${e.message} (line ${e.line ?? "?"})`);
    } catch (e: any) {
      for (const x of e?.errors ?? [e]) pf.errors.push(x.message ?? String(x));
      return pf;
    }
    walk(pf.ast, (n) => { n.__file = abs; });
    for (const c of pf.ast.children ?? []) {
      if (c.type === "ImportDirective" && typeof c.path === "string") {
        pf.imports.push(c.path);
        pf.resolved.set(c.path, this.resolveImport(c.path, abs));
      }
    }
    return pf;
  }

  /** entry + transitive closure of resolvable imports (entry first) */
  closure(file: string): ParsedFile[] {
    const out: ParsedFile[] = [];
    const seen = new Set<string>();
    const visit = (f: string) => {
      const abs = path.resolve(f);
      if (seen.has(abs)) return;
      seen.add(abs);
      const pf = this.parse(abs);
      out.push(pf);
      for (const r of pf.resolved.values()) if (r) visit(r);
    };
    visit(file);
    return out;
  }

  unresolved(file: string): string[] {
    const out: string[] = [];
    for (const pf of this.closure(file)) for (const [raw, r] of pf.resolved) if (!r) out.push(raw);
    return [...new Set(out)];
  }

  private resolveImport(raw: string, fromFile: string): string | null {
    const tryFile = (p: string) => (fs.existsSync(p) && fs.statSync(p).isFile() ? path.resolve(p) : null);
    // 1. relative
    if (raw.startsWith(".")) return tryFile(path.resolve(path.dirname(fromFile), raw));
    // 2. remappings (longest prefix first)
    for (const rm of [...this.remappings].sort((a, b) => b.from.length - a.from.length)) {
      if (raw.startsWith(rm.from)) {
        const r = tryFile(path.join(rm.to, raw.slice(rm.from.length)));
        if (r) return r;
      }
    }
    // 3. node_modules / lib / root-relative in every search root
    for (const d of this.searchRoots) {
      for (const sub of ["node_modules", "lib", ""]) {
        const r = tryFile(path.join(d, sub, raw));
        if (r) return r;
      }
      // forge-style: lib/<pkg>/src/...  or  lib/<pkg>/contracts/...
      const first = raw.split("/")[0];
      const rest = raw.split("/").slice(1).join("/");
      for (const sub of ["src", "contracts", ""]) {
        const r = tryFile(path.join(d, "lib", first, sub, rest));
        if (r) return r;
      }
      // @openzeppelin/contracts -> lib/openzeppelin-contracts/contracts
      if (raw.startsWith("@openzeppelin/contracts/")) {
        for (const pkg of ["openzeppelin-contracts", "openzeppelin"]) {
          const r = tryFile(path.join(d, "lib", pkg, "contracts", raw.slice("@openzeppelin/contracts/".length)));
          if (r) return r;
        }
      }
    }
    // 4. last resort: a file with the same basename somewhere under the input roots
    this.buildIndex();
    const cands = this.indexByBase.get(path.basename(raw)) ?? [];
    if (cands.length === 1) return cands[0];
    if (cands.length > 1) {
      // prefer one whose tail matches more of the import path
      const segs = raw.split("/").filter((x) => x !== "." && x !== "..");
      let best: string | null = null, bestScore = 0;
      for (const c of cands) {
        const cs = c.split(path.sep);
        let score = 0;
        while (score < segs.length && cs[cs.length - 1 - score] === segs[segs.length - 1 - score]) score++;
        if (score > bestScore) { bestScore = score; best = c; }
      }
      return best;
    }
    return null;
  }

  private buildIndex() {
    if (this.indexed) return;
    this.indexed = true;
    const visit = (p: string, depth: number) => {
      if (depth > 8) return;
      let st: fs.Stats;
      try { st = fs.statSync(p); } catch { return; }
      if (st.isDirectory()) {
        if (/^(\.git|out|cache|artifacts|build|dist)$/.test(path.basename(p))) return;
        for (const e of fs.readdirSync(p)) visit(path.join(p, e), depth + 1);
      } else if (p.endsWith(".sol")) {
        const b = path.basename(p);
        const arr = this.indexByBase.get(b) ?? [];
        arr.push(path.resolve(p));
        this.indexByBase.set(b, arr);
      }
    };
    for (const r of this.roots) visit(path.resolve(r), 0);
  }
}
