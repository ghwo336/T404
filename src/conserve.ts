// Balance conservation on the transfer path with local arithmetic followed.
// Every credit must be paid for by a debit or by a supply increase: sum(credits) - sum(debits) - (mint - burn) == 0.
// A positive residual means some slot is credited with tokens nobody paid - a hidden mint on every transfer.
import { Node, walk, collect, baseName, calleeName, isCallTo, snippet, line, endLine } from "./ast";
import { Contract, Func } from "./model";
import { Finding, Location } from "./types";
import type { Ctx } from "./rules";

type Lin = Map<string, number>; // atom -> coefficient; atom "1" = constants

const add = (a: Lin, b: Lin, k = 1): Lin => { const o = new Map(a); for (const [x, c] of b) o.set(x, (o.get(x) ?? 0) + k * c); return o; };
const one = (atom: string, k = 1): Lin => new Map([[atom, k]]);

function key(ctx: Ctx, n: Node): string { return snippet(ctx.sources.get(n?.__file) ?? ctx.source, n, 400).replace(/\s+/g, ""); }

class Env {
  locals = new Map<string, Lin>();
  unknown = false; // something we could not follow (call with side effects on balances, overwrite, loop)
  constructor(public ctx: Ctx, public c: Contract) {}
  lin(n: Node): Lin {
    if (!n) return new Map();
    switch (n.type) {
      case "NumberLiteral": return one("1", Number(n.number.replace(/_/g, "")) || 0);
      case "Identifier": return this.locals.get(n.name) ?? one(n.name);
      case "TupleExpression": return n.components?.length === 1 ? this.lin(n.components[0]) : one(key(this.ctx, n));
      case "BinaryOperation":
        if (n.operator === "+") return add(this.lin(n.left), this.lin(n.right));
        if (n.operator === "-") return add(this.lin(n.left), this.lin(n.right), -1);
        return one(key(this.ctx, n));
      case "FunctionCall": {
        const cn = calleeName(n);
        const args: Node[] = n.arguments ?? [];
        if (n.expression?.type === "MemberAccess" && /^(add|safeAdd)$/i.test(cn ?? "")) return add(this.lin(n.expression.expression), this.lin(args[0]));
        if (n.expression?.type === "MemberAccess" && /^(sub|safeSub)$/i.test(cn ?? "")) return add(this.lin(n.expression.expression), this.lin(args[0]), -1);
        if (n.expression?.type === "Identifier" && /^(add|safeAdd)$/i.test(cn ?? "") && args.length >= 2) return add(this.lin(args[0]), this.lin(args[1]));
        if (n.expression?.type === "Identifier" && /^(sub|safeSub)$/i.test(cn ?? "") && args.length >= 2) return add(this.lin(args[0]), this.lin(args[1]), -1);
        if (n.expression?.type === "ElementaryTypeName" && args.length === 1) return this.lin(args[0]); // uint256(x)
        return one(key(this.ctx, n));
      }
      default: return one(key(this.ctx, n));
    }
  }
}

export interface Ledger { credits: Lin; debits: Lin; supply: Lin; creditNodes: Node[]; unknown: boolean; hadDebit: boolean; hadCredit: boolean }

/** Walk statements in order (branches included, loops make it unknown) and book every balance / supply effect. */
export function ledger(ctx: Ctx, c: Contract, f: Func): Ledger {
  const env = new Env(ctx, c);
  let credits: Lin = new Map(), debits: Lin = new Map(), supply: Lin = new Map();
  const creditNodes: Node[] = [];
  let hadDebit = false, hadCredit = false;
  const isBal = (t: Node) => c.balanceVars.has(baseName(t) ?? "");
  const isSup = (t: Node) => c.supplyVars.has(baseName(t) ?? "");
  const stmt = (n: Node) => {
    if (!n || env.unknown) return;
    switch (n.type) {
      case "Block": for (const s of n.statements ?? []) stmt(s); return;
      case "IfStatement": stmt(n.trueBody); stmt(n.falseBody); return;
      case "ForStatement": case "WhileStatement": case "DoWhileStatement": env.unknown = true; return;
      case "VariableDeclarationStatement": {
        const v = n.variables?.[0];
        if (v?.name) env.locals.set(v.name, n.initialValue ? env.lin(n.initialValue) : one("1", 0));
        return;
      }
      case "ExpressionStatement": expr(n.expression); return;
      case "EmitStatement": case "ReturnStatement": return;
      default: return;
    }
  };
  const expr = (e: Node) => {
    if (!e) return;
    if (e.type === "BinaryOperation" && /^(=|\+=|-=)$/.test(e.operator)) {
      const t = e.left;
      if (t.type === "Identifier" && !c.stateVars.has(t.name)) { // local
        const rhs = env.lin(e.right);
        if (e.operator === "=") env.locals.set(t.name, rhs);
        else env.locals.set(t.name, add(env.locals.get(t.name) ?? one(t.name), rhs, e.operator === "+=" ? 1 : -1));
        return;
      }
      if (isBal(t) || isSup(t)) {
        let delta: Lin | null = null;
        if (e.operator === "+=") delta = env.lin(e.right);
        else if (e.operator === "-=") delta = add(new Map(), env.lin(e.right), -1);
        else { // x = x + d / x.add(d) / x - d / x.sub(d) : the lin of the rhs contains the slot itself once
          const rhs = env.lin(e.right); const self = key(ctx, t); const selfName = t.type === "Identifier" ? t.name : self;
          const coef = (rhs.get(self) ?? 0) + (selfName !== self ? (rhs.get(selfName) ?? 0) : 0);
          if (Math.abs(coef - 1) < 1e-9) { delta = new Map(rhs); delta.delete(self); delta.delete(selfName); }
          else { env.unknown = true; return; } // overwrite: cannot be booked
        }
        const pos = [...delta.values()].some((v) => v > 0), neg = [...delta.values()].some((v) => v < 0);
        if (isBal(t)) {
          credits = add(credits, delta); // negative coefficients act as debits automatically
          if (pos) { hadCredit = true; creditNodes.push(e); }
          if (neg) hadDebit = true;
        } else supply = add(supply, delta);
      }
      return;
    }
    if (e.type === "FunctionCall") {
      const cn = calleeName(e) ?? ""; const args: Node[] = e.arguments ?? [];
      if (/^_?burn(From)?$/i.test(cn) && args.length >= 1 && e.expression?.type === "Identifier") { const amt = env.lin(args[args.length - 1]); credits = add(credits, amt, -1); supply = add(supply, amt, -1); hadDebit = true; return; }
      if (/^_?mint$/i.test(cn) && args.length >= 1 && e.expression?.type === "Identifier") { const amt = env.lin(args[args.length - 1]); credits = add(credits, amt); supply = add(supply, amt); hadCredit = true; creditNodes.push(e); return; }
      if (/^(require|assert|emit|_approve|_spendAllowance|_beforeTokenTransfer|_afterTokenTransfer|_beforeTransfer|_afterTransfer|revert)$/.test(cn)) return;
      // any other internal call that receives an amount-looking argument may move balances: give up
      if (e.expression?.type === "Identifier" && c.functions.has(cn)) { const g = c.functions.get(cn)!; if (g.writes.some((w) => c.balanceVars.has(w.base) || c.supplyVars.has(w.base)) || [...g.calls].some((x) => /_?burn|_?mint|_?transfer/i.test(x))) env.unknown = true; }
      return;
    }
  };
  stmt(f.node.body);
  return { credits, debits, supply, creditNodes, unknown: env.unknown, hadDebit, hadCredit };
}

function loc(ctx: Ctx, node: Node, fn?: Func): Location {
  return { file: node?.__file ?? fn?.file ?? ctx.c.file, line: line(node), column: node?.loc?.start?.column ?? 0, endLine: endLine(node), contract: fn?.contract ?? ctx.c.name, function: fn?.name, snippet: snippet(ctx.sources.get(node?.__file) ?? ctx.source, node) };
}

/** credits - debits - supply change, with tiny coefficients dropped */
export function ruleTransferConservation(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  if (c.balanceVars.size !== 1) return out; // reflection tokens keep two ledgers in different units; not a linear question
  // balanceOf() must return the mapping slot itself; a scaled getter (_rOwned * _tTotal / _rTotal) means the ledger is in another unit
  const bal = [...c.balanceVars][0];
  const getter = c.functions.get("balanceOf");
  if (getter?.node.body) {
    const ret = collect(getter.node.body, (n) => n.type === "ReturnStatement")[0];
    if (!ret || !(ret.expression?.type === "IndexAccess" && baseName(ret.expression) === bal)) return out;
  }
  for (const fname of c.coreTransferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body || f.visibility === "public" && /^transfer(From)?$/.test(f.name) && [...f.calls].some((x) => c.coreTransferPath.has(x))) continue; // wrapper; the worker will be analysed
    const L = ledger(ctx, c, f);
    if (L.unknown || !L.hadDebit || !L.hadCredit) continue;
    const residual = add(L.credits, L.supply, -1);
    const pos = [...residual.entries()].filter(([k, v]) => v > 1e-9 && k !== "1");
    const neg = [...residual.entries()].filter(([k, v]) => v < -1e-9 && k !== "1");
    // only a one-sided residual is conclusive: a leftover positive AND negative opaque term may simply be the same
    // quantity written two ways (reflection maths, rate conversions) that a linear view cannot equate
    if (!pos.length || neg.length) continue;
    const atoms = pos.map(([k]) => k);
    // point at the credit whose amount mentions the unpaid atom
    const node = L.creditNodes.find((n) => atoms.some((a) => key(ctx, n).includes(a))) ?? L.creditNodes[L.creditNodes.length - 1];
    out.push({ id: "TRANSFER_INFLATION", title: `Transfer path credits ${atoms.map((a) => `'${a.slice(0, 40)}'`).join(" + ")} that no debit pays for`, severity: "critical", confidence: 0.85, location: loc(ctx, node, f),
      evidence: `credits − debits − Δsupply = ${pos.map(([k, v]) => `${v === 1 ? "" : v + "·"}${k.slice(0, 60)}`).join(" + ")} in ${f.name}()`,
      reasoning: `Following the local arithmetic of ${f.name}() (fees subtracted from 'amount', burns, mints), the balances written add up to more than what the sender loses: ${atoms.map((a) => `'${a.slice(0, 60)}'`).join(", ")} is credited without being debited anywhere and totalSupply is not raised to match. Every transfer manufactures that much for the credited slot - a hidden mint disguised as fee accounting.` });
  }
  return out;
}
