import { Node, walk, collect, baseName, identifiers, isCallTo, calleeName, numberValue, isZeroAddress, line, endLine, snippet, isMsgSender, isTxOrigin, indexChain, isOwnerGetterCall, ownerGetters } from "./ast";
import { Contract, Func, Assign, PAIR_NAME } from "./model";
import { Finding, Severity, Location } from "./types";
import { RULES2 } from "./rules2";
import { RULES3 } from "./rules3";

export interface Ctx {
  file: string; // entry file being judged
  source: string; // entry file source
  sources: Map<string, string>; // every resolved file -> source
  c: Contract;
}

/** snippet from whichever file the node was parsed from (nodes are tagged with __file at parse time) */
function sn(ctx: Ctx, node: Node): string {
  return snippet(ctx.sources.get(node?.__file) ?? ctx.source, node);
}

export const TO_NAMES = /^(to|_to|recipient|_recipient|dst|receiver|target|_receiver)$/i;
export const FROM_NAMES = /^(from|_from|sender|_sender|src|owner_|holder)$/i;
export const AMOUNT_NAMES = /^(amount|_amount|value|_value|tAmount|amt|tokens|quantity)$/i;
const EXEMPT_NAME = /(exclud|exempt|whitelist|isFeeExempt|isTxLimitExempt|noFee|isVIP|allowed|authorized|privileged)/i;
const BLACKLIST_NAME = /(blacklist|blocklist|blocked|banned|bots?$|isBot|_isBot|sniper|frozen|freeze|restricted|denylist|cannotSell|canSell|isBlack|locked|jail)/i;
const FEE_NAME = /(fee|tax|rate|percent|pct|bps|burn|liquidity|marketing|dev|reflect|charity|team|slippage|cut|commission)/i;
const WITHDRAW_NAME = /(withdraw|rescue|recover|claim|sweep|clear|emergency|manual|sendETH|sendEth|drain|collect|stuck|forward|payout|distribute)/i;
const OWNERSHIP_FN = /^_?(transferOwnership|_transferOwnership|renounceOwnership|acceptOwnership|_setOwner|setOwner|changeOwner|updateOwner|transferAdmin|setAdmin|changeAdmin|_setAdmin|initialize|init|__Ownable_init|__Ownable_init_unchained|_checkOwner|pushManagement|pullManagement|renounceManagement|initializeOwner|setGovernor|transferGovernance|acceptGovernance|_initialize|initializer|setup|configure)$/i;

function loc(ctx: Ctx, node: Node, fn?: Func): Location {
  return {
    file: node?.__file ?? fn?.file ?? ctx.c.file,
    line: line(node),
    column: node?.loc?.start?.column ?? 0,
    endLine: endLine(node),
    contract: fn?.contract ?? ctx.c.name,
    function: fn?.name,
    snippet: sn(ctx, node),
  };
}

function mk(ctx: Ctx, id: string, title: string, severity: Severity, confidence: number, node: Node, fn: Func | undefined, evidence: string, reasoning: string, related?: Location[]): Finding {
  return { id, title, severity, confidence, location: loc(ctx, node, fn), evidence, reasoning, related };
}

function hasRevert(body: Node): boolean {
  if (!body) return false;
  return collect(body, (x) => x.type === "RevertStatement" || x.type === "ThrowStatement" || isCallTo(x, ["revert"]) || (isCallTo(x, ["require", "assert"]) && x.arguments?.[0]?.type === "BooleanLiteral" && x.arguments[0].value === false)
    || (x.type === "ReturnStatement" && x.expression?.type === "BooleanLiteral" && x.expression.value === false)).length > 0; // `return false` = silent block (pre-0.4.22 style)
}

export interface Gate { fn: Func; node: Node; cond: Node; kind: "require" | "if-revert" | "if"; body?: Node; enclosing: Node[] }

/** All guards in the transfer path: require(cond), if(cond) revert, plain if(cond){...} */
export function transferGates(c: Contract): Gate[] {
  const out: Gate[] = [];
  for (const fname of c.transferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body) continue;
    const visit = (n: Node, enclosing: Node[]) => {
      if (!n || typeof n !== "object") return;
      if (Array.isArray(n)) { for (const x of n) visit(x, enclosing); return; }
      if (isCallTo(n, ["require", "assert"]) && n.arguments?.[0] && n.arguments[0].type !== "BooleanLiteral") out.push({ fn: f, node: n, cond: n.arguments[0], kind: "require", enclosing });
      if (n.type === "IfStatement") {
        const rv = hasRevert(n.trueBody) && !n.falseBody ? "if-revert" : hasRevert(n.falseBody) && !hasRevert(n.trueBody) ? "if" : hasRevert(n.trueBody) ? "if-revert" : "if";
        out.push({ fn: f, node: n, cond: n.condition, kind: rv, body: n.trueBody, enclosing });
        visit(n.condition, enclosing);
        visit(n.trueBody, [...enclosing, n.condition]);
        visit(n.falseBody, enclosing);
        return;
      }
      for (const k of Object.keys(n)) { if (k === "loc" || k === "range") continue; const v = n[k]; if (v && typeof v === "object") visit(v, enclosing); }
    };
    visit(f.node.body, []);
    // guards that live in the function's modifiers (canTransfer(msg.sender), whenNotPaused, inNormalState ...)
    for (const mname of f.modifiers) {
      const m = c.modifiers.get(mname);
      if (m?.node?.body && !m.privileged) visit(m.node.body, []);
    }
  }
  return out;
}

export function refsPair(c: Contract, expr: Node): boolean {
  const ids = identifiers(expr);
  if (ids.some((i) => c.pairVars.has(i) || c.pairMaps.has(i))) return true;
  let found = false;
  walk(expr, (n) => {
    if (n.type === "FunctionCall" && /^(isPair|_isPair|isMarketPair|isAMM|automatedMarketMakerPairs|isDexPair|isLP)$/i.test(calleeName(n) ?? "")) found = true;
    if (n.type === "MemberAccess" && PAIR_NAME.test(n.memberName) && !/router|factory/i.test(n.memberName)) found = true;
    if (n.type === "Identifier" && /^(uniswapV2Pair|uniswapPair|pancakePair|pair|lpPair|_pair|dexPair)$/i.test(n.name)) found = true;
  });
  return found;
}

export function paramNamed(f: Func, re: RegExp, pos: number): string | null {
  const byName = f.params.find((p) => re.test(p));
  if (byName) return byName;
  return f.params[pos] ?? null;
}

export function refsIdent(expr: Node, name: string | null): boolean {
  return !!name && identifiers(expr).includes(name);
}

export function refsExemption(c: Contract, expr: Node): boolean {
  const ids = identifiers(expr);
  if (ids.some((i) => c.ownerVars.has(i))) return true;
  if (ids.some((i) => (EXEMPT_NAME.test(i) && c.stateVars.has(i)) || c.exemptMaps.has(i))) return true;
  let found = false;
  walk(expr, (n) => {
    if (isOwnerGetterCall(n) || (n.type === "FunctionCall" && /^(isExcluded|isExempt|_isExcludedFromFee|isFeeExempt)/i.test(calleeName(n) ?? ""))) found = true;
    if (n.type === "IndexAccess" && EXEMPT_NAME.test(baseName(n.base) ?? "")) found = true;
    if (n.type === "MemberAccess" && n.memberName === "sender" && false) found = true;
  });
  return found;
}

/** Is a state var written by a privileged, non-constructor function with a value derived from a parameter or a literal? */
export function privilegedSetters(c: Contract, varName: string): { fn: Func; w: Assign }[] {
  const out: { fn: Func; w: Assign }[] = [];
  for (const f of c.functions.values()) {
    if (!f.privileged || f.isConstructor || c.transferPath.has(f.name)) continue;
    for (const w of f.writes) if (w.base === varName) out.push({ fn: f, w });
  }
  return out;
}

function unprivilegedPublicWriters(c: Contract, varName: string): { fn: Func; w: Assign }[] {
  const out: { fn: Func; w: Assign }[] = [];
  for (const f of c.functions.values()) {
    if (f.privileged || f.isConstructor || c.transferPath.has(f.name)) continue;
    if (!/^(public|external|default)$/.test(f.visibility)) continue;
    for (const w of f.writes) if (w.base === varName) out.push({ fn: f, w });
  }
  return out;
}

export function valueFromParam(f: Func, w: Assign): boolean {
  if (!w.value) return w.operator === "++" || w.operator === "--";
  const ids = identifiers(w.value);
  return ids.some((i) => f.params.includes(i));
}

function assignsLiteral(w: Assign, v: boolean): boolean {
  return w.value?.type === "BooleanLiteral" && w.value.value === v;
}

/** does the function bound `paramOrVar` with a `<`/`<=` against a number?  returns bound or null */
function resolveNum(c: Contract, n: Node): number | null {
  const direct = numberValue(n);
  if (direct !== null) return direct;
  if (n?.type === "Identifier") {
    const sv = c.stateVars.get(n.name);
    if (sv?.isConstant && sv.node?.expression) return numberValue(sv.node.expression);
  }
  if (n?.type === "BinaryOperation") {
    const l = resolveNum(c, n.left), r = resolveNum(c, n.right);
    if (l !== null && r !== null) {
      switch (n.operator) { case "+": return l + r; case "-": return l - r; case "*": return l * r; case "/": return r ? l / r : null; }
    }
  }
  return null;
}

export function upperBound(c: Contract, f: Func, names: string[]): number | null | "unbounded" {
  let bound: number | null = null;
  let any = false;
  walk(f.node.body, (n) => {
    const conds: Node[] = [];
    if (isCallTo(n, ["require"]) && n.arguments?.[0]) conds.push(n.arguments[0]);
    if (n.type === "IfStatement" && hasRevert(n.trueBody)) conds.push(n.condition);
    for (const cnd of conds) {
      walk(cnd, (b) => {
        if (b.type !== "BinaryOperation") return;
        const ops = ["<", "<=", ">", ">="];
        if (!ops.includes(b.operator)) return;
        const L = b.left, R = b.right;
        const lIds = identifiers(L), rIds = identifiers(R);
        const lHas = lIds.some((i) => names.includes(i)), rHas = rIds.some((i) => names.includes(i));
        let num: number | null = null;
        // form: x <= N  or  N >= x   (also x + y <= N)
        if (lHas && !rHas && (b.operator === "<" || b.operator === "<=")) num = resolveNum(c, R) ?? (rIds.length ? -1 : null);
        if (rHas && !lHas && (b.operator === ">" || b.operator === ">=")) num = resolveNum(c, L) ?? (lIds.length ? -1 : null);
        if (num !== null) { any = true; bound = bound === null ? num : Math.min(bound, num); }
      });
    }
  });
  if (!any) return "unbounded";
  return bound;
}

/** Guess the fee denominator used in the transfer path (100, 1000, 10000...) */
function feeDenominator(c: Contract): number | null {
  let denom: number | null = null;
  for (const fname of c.transferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body) continue;
    walk(f.node.body, (n) => {
      if (n.type === "BinaryOperation" && n.operator === "/") {
        const v = numberValue(n.right);
        if (v && [100, 1000, 10000, 100000, 1e6].includes(v)) denom = denom ? Math.max(denom, v) : v;
        const id = n.right?.type === "Identifier" ? n.right.name : null;
        if (id) {
          const sv = c.stateVars.get(id);
          const init = sv?.node?.expression ? numberValue(sv.node.expression) : null;
          if (init && [100, 1000, 10000, 100000, 1e6].includes(init)) denom = denom ? Math.max(denom, init) : init;
        }
      }
      if (n.type === "FunctionCall" && /^(div)$/.test(calleeName(n) ?? "") && n.arguments?.[0]) {
        const v = numberValue(n.arguments[0]);
        if (v && [100, 1000, 10000].includes(v)) denom = denom ? Math.max(denom, v) : v;
      }
    });
  }
  return denom;
}

/** State vars that feed the transfer arithmetic, directly or via a local (`uint f = sellFee; amount * f / 100`). */
export function feeStateVars(c: Contract): Set<string> {
  const direct = new Set<string>();
  const localFrom = new Map<string, Set<string>>(); // local -> state vars assigned into it
  const arithLocals = new Set<string>();
  for (const fname of c.transferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body) continue;
    walk(f.node.body, (n) => {
      const arith = (n.type === "BinaryOperation" && (n.operator === "*" || n.operator === "/")) || isCallTo(n, ["mul", "div"]);
      if (arith) for (const i of identifiers(n)) { if (c.stateVars.has(i) && !c.stateVars.get(i)!.isMapping) direct.add(i); else arithLocals.add(i); }
      if ((n.type === "BinaryOperation" && n.operator === "=") || n.type === "VariableDeclarationStatement") {
        const target = n.type === "VariableDeclarationStatement" ? n.variables?.[0]?.name : baseName(n.left);
        const value = n.type === "VariableDeclarationStatement" ? n.initialValue : n.right;
        if (target && value && !c.stateVars.has(target)) {
          const set = localFrom.get(target) ?? new Set<string>();
          for (const i of identifiers(value)) if (c.stateVars.has(i) && !c.stateVars.get(i)!.isMapping && /^uint/.test(c.stateVars.get(i)!.typeStr)) set.add(i);
          localFrom.set(target, set);
        }
      }
    });
  }
  for (const [local, svs] of localFrom) if (arithLocals.has(local)) for (const v of svs) direct.add(v);
  // interprocedural, 2 rounds: state var (or local derived from one) passed as an argument to an internal function whose
  // matching parameter is used in arithmetic; and state var assigned from another state var inside the path.
  const paramArith = (f: Func, idx: number) => f.params[idx] && arithLocals.has(f.params[idx]);
  for (let round = 0; round < 2; round++) {
    for (const fname of c.transferPath) {
      const f = c.functions.get(fname);
      if (!f?.node.body) continue;
      walk(f.node.body, (n) => {
        if (n.type === "FunctionCall" && n.expression?.type === "Identifier") {
          const callee = c.functions.get(n.expression.name);
          if (!callee) return;
          (n.arguments ?? []).forEach((a: Node, i: number) => {
            if (!paramArith(callee, i)) return;
            for (const id of identifiers(a)) {
              if (c.stateVars.has(id) && !c.stateVars.get(id)!.isMapping) direct.add(id);
              for (const v of localFrom.get(id) ?? []) direct.add(v);
            }
          });
        }
        if (n.type === "BinaryOperation" && n.operator === "=") {
          const b = baseName(n.left);
          if (b && c.stateVars.has(b) && direct.has(b)) for (const i of identifiers(n.right)) if (c.stateVars.has(i) && !c.stateVars.get(i)!.isMapping) direct.add(i);
        }
      });
    }
  }
  return direct;
}

/** State vars that are assigned inside a sell-conditioned branch of the transfer path (name-independent "sell fee" detection). */
function sellBranchAssigned(c: Contract): Set<string> {
  const out = new Set<string>();
  for (const g of transferGates(c)) {
    if (g.kind !== "if" || !g.body || !inSellBranch(c, g)) continue;
    walk(g.body, (n) => {
      if (n.type === "BinaryOperation" && n.operator === "=") for (const i of identifiers(n.right)) if (c.stateVars.has(i) && /^uint/.test(c.stateVars.get(i)!.typeStr)) out.add(i);
    });
  }
  return out;
}

export function inSellBranch(c: Contract, gate: Gate): boolean {
  if (sellCond(c, gate.fn, gate.cond)) return true;
  return gate.enclosing.some((e) => sellCond(c, gate.fn, e));
}

export function sellCond(c: Contract, fn: Func, cond: Node): boolean {
  const to = paramNamed(fn, TO_NAMES, 1);
  const from = paramNamed(fn, FROM_NAMES, 0);
  if (!refsPair(c, cond)) return false;
  // `to == pair`  or `from != pair`  or  automatedMarketMakerPairs[to]
  let sell = false;
  walk(cond, (n) => {
    if (n.type === "BinaryOperation" && (n.operator === "==" || n.operator === "!=")) {
      const [L, R] = [n.left, n.right];
      const pairSide = refsPair(c, L) ? R : refsPair(c, R) ? L : null;
      if (pairSide) {
        if (n.operator === "==" && refsIdent(pairSide, to)) sell = true;
        if (n.operator === "!=" && refsIdent(pairSide, from)) sell = true;
      }
    }
    if (n.type === "IndexAccess" && refsPair(c, n.base) && refsIdent(n.index, to)) sell = true;
    if (n.type === "FunctionCall" && refsPair(c, n.expression) && n.arguments?.some((a: Node) => refsIdent(a, to))) sell = true;
  });
  return sell;
}

// ---------------------------------------------------------------- rules

export function ruleSellRestriction(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const g of transferGates(c)) {
    const isSell = inSellBranch(c, g);
    if (!isSell) continue;
    const to = paramNamed(g.fn, TO_NAMES, 1);
    const from = paramNamed(g.fn, FROM_NAMES, 0);
    const exempt = refsExemption(c, g.cond);
    if (g.kind === "if-revert") {
      out.push(mk(ctx, "SELL_RESTRICTION", "Sell path reverts (buy allowed, sell blocked)", "critical", exempt ? 0.95 : 0.85, g.node, g.fn,
        `Transfer to the liquidity pair is rejected: ${sn(ctx, g.cond)}`,
        `Inside the token transfer logic, a transfer whose destination is the DEX pair (i.e. a sell) hits a revert${exempt ? " unless the sender is owner/exempt" : ""}. Buying (pair -> user) passes through. This is the canonical honeypot: users can acquire the token but cannot exit.`));
      continue;
    }
    if (g.kind === "require") {
      // require(to != pair || exempt) / require(!(to == pair) ...)
      const exemptOrToggle = exempt || identifiers(g.cond).some((i) => c.stateVars.get(i)?.typeStr === "bool");
      out.push(mk(ctx, "SELL_RESTRICTION", "Sell path guarded by require that ordinary holders cannot satisfy", exempt ? "critical" : "high", exempt ? 0.9 : 0.6, g.node, g.fn,
        `require in transfer path references the pair and the recipient: ${sn(ctx, g.cond)}`,
        `A require() in the transfer path distinguishes sells (recipient == pair) from other transfers${exempt ? " and only owner/exempt addresses satisfy it" : exemptOrToggle ? " and depends on an owner-controlled flag" : ""}. Ordinary holders may be unable to sell.`));
      continue;
    }
    // plain if (sell) { ... }: inspect the body for diversions
    const body = g.body;
    if (!body) continue;
    const writes = collect(body, (n) => n.type === "BinaryOperation" && ["=", "+=", "-="].includes(n.operator));
    const diverted = writes.filter((w) => {
      const b = baseName(w.left);
      if (!b || !c.balanceVars.has(b)) return false;
      const idx = indexChain(w.left)[0];
      return idx && !refsIdent(idx, to) && !refsIdent(idx, from) && w.operator !== "-=";
    });
    const hasReturn = collect(body, (n) => n.type === "ReturnStatement").length > 0;
    if (diverted.length && hasReturn) {
      out.push(mk(ctx, "SELL_RESTRICTION", "Sell proceeds diverted: on sell, tokens are credited to another address and the function returns", "critical", 0.75, diverted[0], g.fn,
        sn(ctx, diverted[0]),
        `In the sell branch, balances are written to an address other than the recipient (${to}) and the function returns early, so the pair never receives the tokens - the sell silently fails or is confiscated.`));
    }
    // sell-only amount limit / fee variables handled by other rules, but flag sell branch that sets fee from an owner-set var
    const feeVars = feeStateVars(c);
    const feeAssign = collect(body, (n) => n.type === "BinaryOperation" && n.operator === "=" && identifiers(n.right).some((i) => c.stateVars.has(i) && (FEE_NAME.test(i) || feeVars.has(i))));
    for (const fa of feeAssign) {
      const vars = identifiers(fa.right).filter((i) => c.stateVars.has(i) && (FEE_NAME.test(i) || feeVars.has(i)) && /^uint/.test(c.stateVars.get(i)!.typeStr));
      for (const v of vars) {
        const setters = privilegedSetters(c, v);
        if (!setters.length) continue;
        const b = upperBound(c, setters[0].fn, [v, ...setters[0].fn.params]);
        const denom = feeDenominator(c) ?? 100;
        if (b === "unbounded" || (typeof b === "number" && (b < 0 || b >= denom * 0.5))) {
          out.push(mk(ctx, "SELL_FEE_UNCAPPED", "Sell-side fee is owner-settable without an effective cap", "critical", 0.85, fa, g.fn,
            `${sn(ctx, fa)}  |  setter ${setters[0].fn.name}() ${b === "unbounded" ? "has no upper bound" : `allows up to ${b}/${denom}`}`,
            `The fee applied specifically when selling comes from ${v}, which ${setters[0].fn.name}() (privileged) can set ${b === "unbounded" ? "to any value, including 100%" : `as high as ${b}/${denom}`}. Owner can turn every sell into a total loss after launch.`,
            [loc(ctx, setters[0].w.node, setters[0].fn)]));
        }
      }
    }
  }
  return dedupe(out);
}

export function ruleBlacklistGate(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const gates = transferGates(c).filter((g) => g.kind !== "if");
  for (const v of c.stateVars.values()) {
    if (!v.isMapping || v.valueType !== "bool" || v.keyType !== "address" || c.pairMaps.has(v.name)) continue;
    const readInGate = gates.filter((g) => identifiers(g.cond).includes(v.name));
    if (!readInGate.length) continue;
    // is the mapping used as a *restriction* (blocked when true) rather than an exemption (skips a limit when true)?
    const asRestriction = readInGate.some((g) => {
      let restrict = false;
      walk(g.cond, (n) => {
        if (n.type === "IndexAccess" && baseName(n.base) === v.name) {
          // require(!bl[x])  or  if (bl[x]) revert
          if (g.kind === "if-revert") restrict = true;
        }
        if (n.type === "UnaryOperation" && n.operator === "!" && n.subExpression?.type === "IndexAccess" && baseName(n.subExpression.base) === v.name && g.kind === "require") restrict = true;
        if (n.type === "BinaryOperation" && n.operator === "==" && n.right?.type === "BooleanLiteral" && !n.right.value && baseName(n.left) === v.name && g.kind === "require") restrict = true;
      });
      return restrict || (BLACKLIST_NAME.test(v.name) && !EXEMPT_NAME.test(v.name));
    });
    // allow-list form: require(allowed[x]) as the whole condition or one side of &&, i.e. everyone NOT on the list is blocked
    const asAllowlist = !asRestriction && readInGate.some((g) => {
      if (g.kind !== "require") return false;
      const isM = (n: Node) => (n?.type === "IndexAccess" && baseName(n.base) === v.name) || (n?.type === "BinaryOperation" && n.operator === "==" && n.right?.type === "BooleanLiteral" && n.right.value && baseName(n.left) === v.name);
      if (isM(g.cond)) return true;
      if (g.cond?.type === "BinaryOperation" && g.cond.operator === "&&") {
        const parts: Node[] = []; const flat = (n: Node) => { if (n?.type === "BinaryOperation" && n.operator === "&&") { flat(n.left); flat(n.right); } else parts.push(n); }; flat(g.cond);
        return parts.some(isM);
      }
      return false;
    });
    if (!asRestriction && !asAllowlist) continue;
    const setters = privilegedSetters(c, v.name).filter(({ fn, w }) => valueFromParam(fn, w) || assignsLiteral(w, true));
    const openSetters = unprivilegedPublicWriters(c, v.name);
    const gate = readInGate[0];
    const sellOnly = inSellBranch(c, gate) || refsPair(c, gate.cond);
    if (setters.length) {
      const s = setters[0];
      const arbitrary = s.fn.params.length > 0 && identifiers(s.w.target).some((i) => s.fn.params.includes(i));
      if (asAllowlist) {
        out.push(mk(ctx, "ALLOWLIST_GATE", `Only owner-approved addresses can ${sellOnly ? "sell" : "transfer"}`, "critical", /whitelist|allow|approved|permitted|canTransfer|authorized/i.test(v.name) ? 0.95 : 0.85, gate.node, gate.fn,
          `${sn(ctx, gate.cond)}  |  ${v.name} is written in ${s.fn.name}() [${s.fn.privilegeReason}]`,
          `The transfer path requires ${v.name}[sender] to be true, and only a privileged function can set it. Every holder who is not on the list (i.e. everyone the owner has not approved) cannot move the tokens they received. The owner ${c.exemptMaps.has(v.name) ? "puts itself on the list in the constructor, so the restriction is asymmetric: " : ""}decides who may exit - a honeypot by permission.`,
          [loc(ctx, s.w.node, s.fn)]));
      } else
      out.push(mk(ctx, "BLACKLIST_GATE", `Owner-controlled address blacklist blocks ${sellOnly ? "selling" : "transfers"}`, arbitrary ? "critical" : "high", BLACKLIST_NAME.test(v.name) ? 0.95 : 0.8, gate.node, gate.fn,
        `${sn(ctx, gate.cond)}  |  ${v.name} is written in ${s.fn.name}() [${s.fn.privilegeReason}]`,
        `The transfer path refuses when ${v.name}[addr] is set, and a privileged function can set it for ${arbitrary ? "any address passed as a parameter" : "addresses"} at any time. The owner can therefore freeze any holder's tokens after they buy - a targeted honeypot / rug mechanism that never shows up on-chain until the victim tries to sell.`,
        [loc(ctx, s.w.node, s.fn)]));
    } else if (openSetters.length) {
      out.push(mk(ctx, "BLACKLIST_GATE", "Publicly writable blacklist gates transfers", "critical", 0.7, openSetters[0].w.node, openSetters[0].fn,
        sn(ctx, openSetters[0].w.node), `Anyone can write ${v.name}, which the transfer path uses as a block condition.`));
    } else {
      const autoWriters = [...c.functions.values()].filter((f) => c.transferPath.has(f.name) && f.writes.some((w) => w.base === v.name));
      if (autoWriters.length) {
        out.push(mk(ctx, "AUTO_BLACKLIST", "Addresses are auto-blacklisted inside the transfer path (sniper/bot trap)", "medium", 0.6, gate.node, gate.fn,
          `${v.name} written in ${autoWriters[0].name}() and checked as a block condition`,
          `Buyers matching some in-transfer condition (usually early blocks) are permanently marked and later refused. There is no privileged setter, so it cannot be undone, but it is still a hidden exit restriction.`));
      }
    }
  }
  return out;
}

export function ruleTradingGate(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const gates = transferGates(c).filter((g) => g.kind !== "if");
  for (const v of c.stateVars.values()) {
    if (v.isMapping || v.typeStr !== "bool") continue;
    if (/(swap|inSwap|swapping|lock|reentr|guard|entered|distributing|liquif|autoLp|autoLiq)/i.test(v.name)) continue;
    const readInGate = gates.filter((g) => identifiers(g.cond).includes(v.name));
    if (!readInGate.length) continue;
    const setters = privilegedSetters(c, v.name);
    if (!setters.length) continue;
    const gate = readInGate[0];
    // which value of the flag blocks transfers?  require(v) / if(!v) revert  -> false blocks;  require(!v) / if(v) revert -> true blocks
    let blocking = gate.kind === "require" ? false : true;
    walk(gate.cond, (n) => {
      if (n.type === "UnaryOperation" && n.operator === "!" && identifiers(n.subExpression).includes(v.name)) blocking = !blocking;
      if (n.type === "BinaryOperation" && n.operator === "==" && n.right?.type === "BooleanLiteral" && identifiers(n.left).includes(v.name)) blocking = gate.kind === "require" ? !n.right.value : n.right.value;
    });
    const canDisable = setters.some(({ fn, w }) => valueFromParam(fn, w) || assignsLiteral(w, blocking) || (w.value?.type === "UnaryOperation" && w.value.operator === "!"));
    const sellOnly = refsPair(c, gate.cond);
    const stdPausable = /^_?paused$/i.test(v.name) && setters.every(({ fn }) => /^_?(pause|unpause|_pause|_unpause|setPaused|emergencyPause|emergencyUnpause)$/i.test(fn.name)) && !sellOnly;
    if (canDisable && stdPausable) {
      out.push(mk(ctx, "TRADING_GATE", "Standard emergency pause (owner can halt all transfers)", "medium", 0.8, gate.node, gate.fn,
        `${sn(ctx, gate.cond)}  |  ${v.name} toggled by ${setters.map((x) => x.fn.name + "()").join(", ")}`,
        `OpenZeppelin-style Pausable: transfers stop while paused. This is a well-known centralisation control rather than a hidden trap, but holders depend on the pauser to unpause.`,
        [loc(ctx, setters[0].w.node, setters[0].fn)]));
    } else if (canDisable && !sellOnly && !refsExemption(c, gate.cond) && !gate.enclosing.some((e) => refsExemption(c, e))) {
      out.push(mk(ctx, "TRADING_GATE", "Owner can pause all transfers (applies to the owner too)", "low", 0.8, gate.node, gate.fn,
        `${sn(ctx, gate.cond)}  |  ${v.name} set in ${setters[0].fn.name}() [${setters[0].fn.privilegeReason}]`,
        `A privileged function can halt transfers, but the check is symmetric: nothing exempts the owner or a whitelist, so no asset moves to the owner's side. Availability / centralisation risk, not a theft path.`,
        [loc(ctx, setters[0].w.node, setters[0].fn)]));
    } else if (canDisable) {
      out.push(mk(ctx, "TRADING_GATE", sellOnly ? "Owner can switch selling off at any time" : "Owner can pause transfers while exempting itself", "critical", 0.85, gate.node, gate.fn,
        `${sn(ctx, gate.cond)}  |  ${v.name} set in ${setters[0].fn.name}() [${setters[0].fn.privilegeReason}]`,
        `The transfer path requires ${v.name}, and a privileged function can flip it back to false. ${sellOnly ? "Because the check only applies to transfers into the pair, buys keep working while sells are halted - a switchable honeypot." : "Holders can be locked in indefinitely."}`,
        [loc(ctx, setters[0].w.node, setters[0].fn)]));
    } else if (identifiers(gate.cond).some((i) => i !== v.name && c.stateVars.get(i)?.isMapping && /bool/.test(c.stateVars.get(i)!.valueType ?? "") && privilegedSetters(c, i).some(({ fn, w }) => valueFromParam(fn, w) || indexChain(w.target).some((ix) => identifiers(ix).some((p) => fn.params.includes(p)))))) {
      const lst = identifiers(gate.cond).find((i) => i !== v.name && c.stateVars.get(i)?.isMapping)!;
      out.push(mk(ctx, "ALLOWLIST_GATE", `Until the owner releases trading, only addresses on '${lst}' can transfer`, "high", 0.75, gate.node, gate.fn,
        `${sn(ctx, gate.cond)}  |  ${lst} written by ${privilegedSetters(c, lst).map((x) => x.fn.name + "()").join(", ")}; ${v.name} flipped in ${setters[0].fn.name}()`,
        `A launch lock is symmetric only if nobody can move. Here a privileged list exempts chosen addresses (the deployer's own wallets, a 'crowdsale' contract) while every other holder is frozen until a release that the same insiders control and may never trigger. Asymmetric by construction.`,
        [loc(ctx, setters[0].w.node, setters[0].fn)]));
    } else {
      out.push(mk(ctx, "TRADING_GATE", "One-way launch gate (owner enables trading once)", "low", 0.7, gate.node, gate.fn,
        `${sn(ctx, gate.cond)}  |  ${v.name} is only ever set to its non-blocking value in ${setters[0].fn.name}()`,
        `Transfers are blocked until the owner enables trading, and the flag can only be set to true. Common launch pattern; risk is limited to a pre-launch lock.`));
    }
  }
  return out;
}

export function ruleUncappedFee(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const denom = feeDenominator(c);
  const arithVars = feeStateVars(c);
  const sellAssigned = sellBranchAssigned(c);
  const feeVarsRead = new Set<string>(arithVars);
  for (const fname of c.transferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body) continue;
    walk(f.node.body, (n) => {
      if (n.type === "Identifier" && c.stateVars.has(n.name) && FEE_NAME.test(n.name) && /^uint/.test(c.stateVars.get(n.name)!.typeStr)) feeVarsRead.add(n.name);
    });
  }
  for (const v of feeVarsRead) {
    const sv = c.stateVars.get(v)!;
    if (!/^uint/.test(sv.typeStr) || sv.isConstant) continue;
    if (!FEE_NAME.test(v) && !/(denominator|divisor|base)/i.test(v)) { /* arithmetic var w/o fee-ish name: still check but lower confidence */ }
    if (/(denominator|divisor|max(Tx|Wallet|Sell|Buy)|limit|threshold|supply|decimals|launch|block|time|cooldown|min)/i.test(v)) continue;
    const setters = privilegedSetters(c, v).filter(({ fn, w }) => valueFromParam(fn, w));
    if (!setters.length) continue;
    const s = setters[0];
    const b = upperBound(c, s.fn, [v, ...identifiers(s.w.value).filter((i) => s.fn.params.includes(i))]);
    const d = denom ?? 100;
    const sellCtx = /sell/i.test(v) || sellAssigned.has(v);
    let sev: Severity | null = null, why = "";
    if (b === "unbounded") { sev = "high"; why = "has no upper bound at all"; }
    else if (typeof b === "number" && b < 0) { sev = "medium"; why = "is bounded only by another owner-settable variable"; }
    else if (typeof b === "number" && b >= d * 0.5) { sev = "medium"; why = `may be set as high as ${b}/${d} (${Math.round((b / d) * 100)}%)`; }
    else if (typeof b === "number" && b >= d * 0.25) { sev = "low"; why = `may be set as high as ${b}/${d} (${Math.round((b / d) * 100)}%)`; }
    if (!sev) continue;
    if (sellCtx && sev === "high") sev = "critical";
    else if (sellCtx && sev === "medium") sev = "high";
    out.push(mk(ctx, "UNCAPPED_FEE", `${sellCtx ? "Sell" : "Transfer"} fee ${v} is owner-settable and ${b === "unbounded" ? "uncapped" : "weakly capped"}`, sev, FEE_NAME.test(v) ? 0.85 : arithVars.has(v) ? 0.8 : 0.55, s.w.node, s.fn,
      `${sn(ctx, s.w.node)} in ${s.fn.name}() [${s.fn.privilegeReason}]; ${v} is used in the transfer arithmetic`,
      `${v} feeds the amount deducted on ${sellCtx ? "sells" : "transfers"}. Its setter ${why}, so the owner can raise the fee post-launch to confiscate most or all of every ${sellCtx ? "sell" : "transfer"}. A fee that can reach ~100% is a delayed honeypot.`));
  }
  return out;
}

/** classify a write to a mapping slot: same-slot arithmetic update vs. plain overwrite */
export function writeKind(w: Assign): "increase" | "decrease" | "overwrite" | "other" {
  if (w.operator === "+=" || w.operator === "++") return "increase";
  if (w.operator === "-=" || w.operator === "--") return "decrease";
  if (w.operator === "delete") return "overwrite";
  if (w.operator !== "=" || !w.value) return "other";
  const target = sn0(w.target);
  const refsSelf = collect(w.value, (n) => (n.type === "IndexAccess" || n.type === "Identifier") && sn0(n) === target).length > 0;
  const v = w.value;
  const addLike = (n: Node) => (n.type === "BinaryOperation" && n.operator === "+") || (n.type === "FunctionCall" && /^(add|safeAdd|add96|add128|add256|_add)$/i.test(calleeName(n) ?? ""));
  const subLike = (n: Node) => (n.type === "BinaryOperation" && n.operator === "-") || (n.type === "FunctionCall" && /^(sub|safeSub|sub96|sub128|sub256|_sub|subtract)$/i.test(calleeName(n) ?? ""));
  if (refsSelf && addLike(v)) return "increase";
  if (refsSelf && subLike(v)) return "decrease";
  if (refsSelf) return "other";
  return "overwrite";
}
/** structural key for an lvalue: base + index identifiers */
function sn0(n: Node): string {
  return `${baseName(n)}[${indexChain(n).map((i) => identifiers(i).join(".") || (i?.type ?? "?")).join("][")}]`;
}

function isMintLike(c: Contract, f: Func): { kind: "call" | "balance"; node: Node } | null {
  let hit: { kind: "call" | "balance"; node: Node } | null = null;
  walk(f.node.body, (n) => {
    if (hit) return false;
    if (isCallTo(n, ["_mint", "mint", "_mintTokens", "_issue", "issue"])) hit = { kind: "call", node: n };
  });
  if (hit) return hit;
  const balInc = f.writes.find((w) => c.balanceVars.has(w.base) && writeKind(w) === "increase");
  const supInc = f.writes.find((w) => c.supplyVars.has(w.base) && writeKind(w) === "increase");
  if (balInc && supInc) return { kind: "balance", node: balInc.node };
  return null;
}

export function ruleHiddenMint(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const f of c.functions.values()) {
    if (f.isConstructor || c.transferPath.has(f.name) || /^(_mint|mint|_mintTokens)$/i.test(f.name) && f.visibility === "internal") continue;
    if (!/^(public|external|default)$/.test(f.visibility)) continue;
    const m = isMintLike(c, f);
    if (!m) continue;
    const named = /mint|issue|airdrop|reward|distribute|emit/i.test(f.name);
    const cappedBase = c.bases.some((b) => /^ERC20Capped(Upgradeable)?$/.test(b)) || c.unknownBases.some((b) => /^ERC20Capped(Upgradeable)?$/.test(b)); // cap enforced in the (standard) base _mint/_update
    const capped = named && (cappedBase || upperBound(c, f, [...f.params, ...c.supplyVars]) !== "unbounded");
    if (f.privileged && capped) {
      out.push(mk(ctx, "OWNER_MINT", "Owner can mint within a hard cap", "low", 0.8, m.node, f, `${sn(ctx, m.node)} in ${f.name}() [${f.privilegeReason}]`, `Minting is privileged but bounded by a supply cap check in the same function.`));
      continue;
    }
    if (f.privileged) {
      out.push(mk(ctx, "HIDDEN_MINT", named ? `Owner can mint unlimited supply via '${f.name}()' (no cap check)` : `Supply inflation hidden in '${f.name}()'`, "critical", named ? 0.8 : 0.85, m.node, f,
        `${sn(ctx, m.node)} in ${f.name}() [${f.privilegeReason}]`,
        named ? `A privileged function mints new tokens with no cap. The owner can dilute holders or dump freshly minted supply into the pool.` : `A function whose name does not suggest minting (${f.name}) increases balances and total supply under owner control. This is a disguised inflation backdoor - the owner can print tokens and dump them.`));
    } else if (f.mutability !== "payable") {
      out.push(mk(ctx, "OPEN_MINT", `Anyone can mint via '${f.name}()'`, "critical", 0.75, m.node, f,
        sn(ctx, m.node), `A public, non-payable, unguarded function creates new tokens. Either a critical bug or an intentional backdoor for a co-conspirator address.`));
    }
  }
  return out;
}

export function ruleBalanceManipulation(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const f of c.functions.values()) {
    if (f.isConstructor || c.transferPath.has(f.name) || !f.privileged) continue;
    if (isMintLike(c, f)) continue; // reported by HIDDEN_MINT
    for (const w of f.writes) {
      if (!c.balanceVars.has(w.base)) continue;
      const idx = indexChain(w.target)[0];
      const arbitrary = !!idx && identifiers(idx).some((i) => f.params.includes(i));
      const kind = writeKind(w);
      const readsAllowance = [...f.reads].some((r) => c.allowanceVars.has(r)) || [...f.calls].some((x) => /allowance|_spendAllowance/i.test(x));
      const selfIdx = !!idx && isMsgSender(idx);
      if (kind === "overwrite") {
        out.push(mk(ctx, "BALANCE_MANIPULATION", `Owner can overwrite ${arbitrary ? "any holder's" : "a"} balance`, arbitrary ? "critical" : "high", 0.9, w.node, f,
          `${sn(ctx, w.node)} in ${f.name}() [${f.privilegeReason}]`,
          `A privileged function assigns the balance mapping directly${arbitrary ? " for an address supplied as a parameter" : " for a fixed address"}, bypassing transfer/allowance logic. Holdings can be zeroed or reassigned at will.`));
      } else if (kind === "decrease") {
        if (selfIdx || readsAllowance) continue; // self-burn or burnFrom-with-allowance: consented
        out.push(mk(ctx, "BALANCE_MANIPULATION", `Owner can burn tokens from ${arbitrary ? "any address" : "holders"} without consent`, arbitrary ? "critical" : "medium", 0.85, w.node, f,
          `${sn(ctx, w.node)} in ${f.name}()`,
          `A privileged function reduces another address's balance without an allowance or signature. Combined with a mint this becomes arbitrary confiscation.`));
      } else if (kind === "increase") {
        const selfCredit = !!idx && (identifiers(idx).some((i) => c.ownerVars.has(i)) || isMsgSender(idx) || isOwnerGetterCall(idx));
        if (selfCredit) {
          out.push(mk(ctx, "BALANCE_MANIPULATION", `Owner credits their own balance in '${f.name}()' without minting`, "critical", 0.85, w.node, f,
            `${sn(ctx, w.node)} in ${f.name}() [${f.privilegeReason}]`,
            `A privileged function adds an arbitrary amount to the owner's own balance while totalSupply stays untouched. This is a disguised mint: the owner can dump tokens that never appear in the supply figure.`));
          continue;
        }
        out.push(mk(ctx, "BALANCE_MANIPULATION", "Balance increased under owner control without supply accounting", arbitrary ? "high" : "medium", 0.7, w.node, f,
          `${sn(ctx, w.node)} in ${f.name}()`,
          `Tokens are credited without touching total supply - a stealth mint that keeps totalSupply() looking unchanged.`));
      }
    }
  }
  return out;
}

export function ruleApprovalBypass(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  // (a) privileged writes to allowance mapping outside approve-like functions
  for (const f of c.functions.values()) {
    if (f.isConstructor || /^(_?approve|_?spendAllowance|increaseAllowance|decreaseAllowance|permit|_useAllowance|_?setAllowance)$/i.test(f.name)) continue;
    for (const w of f.writes) {
      if (!c.allowanceVars.has(w.base)) continue;
      const [ownerIdx] = indexChain(w.target);
      if (ownerIdx && isMsgSender(ownerIdx)) continue;
      const k = writeKind(w);
      if (k === "decrease") continue; // spending an allowance can never grant one
      if (k === "other") continue;
      if (c.transferPath.has(f.name) && [...f.reads].some((r) => c.allowanceVars.has(r)) && k !== "overwrite") continue;
      if (c.transferPath.has(f.name) && k === "overwrite" && w.value && identifiers(w.value).some((id) => !f.params.includes(id) && !c.stateVars.has(id))) continue; // allowances[src][spender] = newAllowance (local computed from the old allowance)
      if (f.privileged || /^(public|external|default)$/.test(f.visibility)) {
        out.push(mk(ctx, "APPROVAL_BYPASS", "Allowance mapping written on behalf of other holders", "critical", 0.85, w.node, f,
          `${sn(ctx, w.node)} in ${f.name}()${f.privileged ? ` [${f.privilegeReason}]` : " (unprivileged)"}`,
          `The allowance of an arbitrary token owner is set outside approve(). Whoever controls this can grant themselves spending rights over every wallet and drain holders with transferFrom.`));
      }
    }
  }
  // (b) transferFrom that never consults allowance
  const tf = c.functions.get("transferFrom");
  if (tf && tf.node.body && !tf.callsSuper) {
    const ids = identifiers(tf.node.body);
    const usesAllowance = ids.some((i) => c.allowanceVars.has(i)) || [...tf.calls].some((x) => /allowance|_approve|_spendAllowance|_transferFrom|_useAllowance/i.test(x));
    if (!usesAllowance) {
      out.push(mk(ctx, "APPROVAL_BYPASS", "transferFrom() ignores allowances", "critical", 0.8, tf.node, tf,
        `transferFrom body references no allowance mapping and no allowance helper`,
        `Anyone can move tokens out of any wallet without approval. In malicious tokens this is often paired with an owner-only check so only the deployer can drain.`));
    } else {
      // (c) allowance check skipped for a privileged caller
      walk(tf.node.body, (n) => {
        if (n.type === "IfStatement" && identifiers(n.condition).some((i) => c.ownerVars.has(i)) && collect(n.condition, (x) => isMsgSender(x)).length) {
          out.push(mk(ctx, "APPROVAL_BYPASS", "transferFrom skips allowance check for the owner", "critical", 0.75, n, tf,
            sn(ctx, n.condition), `When the caller is the owner, the allowance branch is bypassed - the deployer can pull tokens from any holder.`));
        }
      });
    }
  }
  return out;
}

export function ruleOwnership(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const ownerWritten = (f: Func) => f.writes.filter((w) => c.ownerVars.has(w.base) && !/^(_previousOwner|previousOwner|_pendingOwner|pendingOwner)$/i.test(w.base));
  const ren = c.functions.get("renounceOwnership");
  if (ren && ren.node.body && !ren.callsSuper) {
    const w = ownerWritten(ren);
    const setsZero = w.some((x) => x.value && isZeroAddress(x.value)) || [...ren.calls].some((x) => /_transferOwnership|_setOwner/i.test(x));
    const backup = ren.writes.find((x) => !c.ownerVars.has(x.base) || /previous/i.test(x.base)) ;
    const backsUpOwner = ren.writes.some((x) => x.value && identifiers(x.value).some((i) => c.ownerVars.has(i)) && x.base !== "_owner" && !isZeroAddress(x.value));
    if (!setsZero) {
      out.push(mk(ctx, "FAKE_RENOUNCE", "renounceOwnership() does not actually remove the owner", "high", 0.85, ren.node, ren,
        `no assignment of an owner variable to address(0) in renounceOwnership()`,
        `The function exists to make the token look renounced on explorers, but the owner variable is never cleared. Every onlyOwner backdoor stays live.`));
    } else if (backsUpOwner && backup) {
      out.push(mk(ctx, "FAKE_RENOUNCE", "Owner is backed up before renouncing (re-claimable ownership)", "high", 0.85, backup.node, ren,
        sn(ctx, backup.node),
        `The previous owner address is stashed before ownership is set to zero. A companion function (typically lock()/unlock()/getUnlockTime) can restore it, so 'renounced' is cosmetic.`));
    }
  }
  // authority variables: every state address the privilege checks compare msg.sender against
  const authorityVars = new Set<string>();
  for (const f of c.functions.values()) for (const m of f.privilegeReason.matchAll(/msg\.sender vs ([A-Za-z_$][\w$]*)(?!\()/g)) if (c.stateVars.has(m[1])) authorityVars.add(m[1]);
  if (ren && ren.node.body && !ren.callsSuper) {
    const zeroed = new Set(ren.writes.filter((w) => w.value && isZeroAddress(w.value)).map((w) => w.base));
    const touched = new Set(ren.writes.map((w) => w.base));
    const clears = zeroed.size > 0 || [...ren.calls].some((x) => /_transferOwnership|_setOwner/i.test(x));
    const survivors = [...authorityVars].filter((v) => !touched.has(v) && !(clears && zeroed.size === 0 && c.ownerVars.has(v) && /owner/i.test(v)));
    const users = [...c.functions.values()].filter((f) => f.name !== ren.name && survivors.some((v) => f.privilegeReason.includes(`msg.sender vs ${v}`)));
    if (survivors.length && users.length && clears) {
      out.push(mk(ctx, "FAKE_RENOUNCE", `renounceOwnership() clears the owner but '${survivors[0]}' keeps its powers`, "critical", 0.85, ren.node, ren,
        `zeroed: ${[...zeroed].join(", ")}; still authorising ${users.map((f) => f.name + "()").join(", ")}: ${survivors.join(", ")}`,
        `Explorers will show the token as renounced, yet a second authority variable that the renounce never touches still gates ${users.map((f) => f.name + "()").join(", ")}. The 'renounce' is cosmetic - the deployer keeps the backdoor.`, users.map((f) => loc(ctx, f.node, f))));
    }
  }
  // hidden role: a visible owner that authorises nothing, while a private/internal address gates privileged functions
  {
    const visibleOwners = [...c.ownerVars].filter((v) => /^(public)$/.test(c.stateVars.get(v)?.node?.visibility ?? "") && !/^_/.test(v));
    const ownerUsed = [...c.functions.values()].some((f) => visibleOwners.some((v) => f.privilegeReason.includes(`msg.sender vs ${v}`)) || /owner\(\)|_checkOwner|onlyOwner/i.test(f.privilegeReason));
    const hidden = [...authorityVars].filter((v) => !visibleOwners.includes(v) && /^(private|internal|default)$/.test(c.stateVars.get(v)?.node?.visibility ?? "default"));
    if (visibleOwners.length && !ownerUsed && hidden.length) {
      const users = [...c.functions.values()].filter((f) => hidden.some((v) => f.privilegeReason.includes(`msg.sender vs ${v}`)));
      if (users.length) out.push(mk(ctx, "HIDDEN_ROLE", `Public '${visibleOwners[0]}' is decorative; the real authority is hidden '${hidden[0]}'`, "high", 0.8, c.stateVars.get(hidden[0])!.node, users[0],
        `${users.map((f) => f.name + "()").join(", ")} gated by ${hidden.join(", ")}; ${visibleOwners.join(", ")} authorises nothing`,
        `The contract exposes an owner variable that explorers and holders will check, but no privileged function actually uses it. Control sits in a non-public address that renounce/transferOwnership never touch - a hidden role designed to survive scrutiny.`, users.map((f) => loc(ctx, f.node, f))));
    }
  }
  const INIT_FN = /^_?(initialize|init|initializer|setup|configure|_initialize|__Ownable_init|__Ownable_init_unchained)$/i;
  for (const f of c.functions.values()) {
    if (f.isConstructor) continue;
    if (OWNERSHIP_FN.test(f.name)) {
      // post-deploy initializer that hands the owner slot to msg.sender with no initializer guard = open takeover
      if (!INIT_FN.test(f.name) || f.privileged || !/^(public|external|default)$/.test(f.visibility) || f.modifiers.some((m) => /initializer|onlyInitializing|reinitializer/i.test(m))) continue;
      const w = ownerWritten(f).find((x) => x.value && (isMsgSender(x.value) || identifiers(x.value).some((i) => f.params.includes(i))));
      if (!w) continue;
      const guarded = collect(f.node.body, (x) => isCallTo(x, ["require"]) && x.arguments?.[0] && identifiers(x.arguments[0]).some((i) => /init|setup|configured|owner|_owner/i.test(i) || c.ownerVars.has(i))).length > 0;
      if (guarded) continue;
      out.push(mk(ctx, "OPEN_OWNER_TAKEOVER", `Anyone can become owner via '${f.name}()' (unguarded re-initializer)`, "critical", 0.85, w.node, f, `${sn(ctx, w.node)} in ${f.name}()`,
        `A public initializer writes the owner slot and nothing stops it from being called again after deployment - no 'initialized' flag, no initializer modifier, no owner check. Whoever calls it next owns every privileged function.`));
      continue;
    }
    for (const w of ownerWritten(f)) {
      const fromBackup = w.value && identifiers(w.value).some((i) => /previous|_prev|backup|old/i.test(i) || (c.stateVars.get(i)?.typeStr === "address" && !c.ownerVars.has(i)));
      const open = !f.privileged && /^(public|external|default)$/.test(f.visibility);
      // renounce / transferOwnership by shape: privileged, value is address(0) or a parameter
      const literalAddr = w.value?.type === "NumberLiteral" || (w.value?.type === "FunctionCall" && w.value.arguments?.[0]?.type === "NumberLiteral" && !isZeroAddress(w.value));
      if (f.privileged && w.value && !literalAddr && (isZeroAddress(w.value) || identifiers(w.value).every((i) => f.params.includes(i)))) continue;
      out.push(mk(ctx, open ? "OPEN_OWNER_TAKEOVER" : "HIDDEN_OWNER_TRANSFER", open ? `Anyone can become owner via '${f.name}()'` : literalAddr ? `Owner silently set to a hard-coded address inside '${f.name}()'` : fromBackup ? `Ownership restored from backup in '${f.name}()'` : `Owner reassigned in unexpected function '${f.name}()'`, open || literalAddr ? "critical" : "high", literalAddr ? 0.9 : 0.8, w.node, f,
        `${sn(ctx, w.node)} in ${f.name}()${f.privileged ? ` [${f.privilegeReason}]` : ""}`,
        open ? `An unguarded public function writes the owner variable. Any address can seize control.` : fromBackup ? `This is the second half of a fake renounce: a stashed address is written back into the owner slot.` : `Ownership changes outside transferOwnership/renounceOwnership are hidden from anyone auditing the standard functions.`));
    }
  }
  return out;
}

export function ruleDangerousOps(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const f of c.functions.values()) {
    if (!f.node.body) continue;
    walk(f.node.body, (n) => {
      // inline-assembly proxy: delegatecall(gas(), impl, ...) where impl is a local loaded from a state slot
      if (n.type === "AssemblyCall" && n.functionName === "delegatecall") {
        const tgt = n.arguments?.[1];
        const tname: string | null = tgt?.type === "AssemblyCall" && !tgt.arguments?.length ? tgt.functionName : tgt?.type === "Identifier" ? tgt.name : null;
        let sv: string | null = tname && c.stateVars.has(tname) ? tname : null;
        if (!sv && tname) {
          const decl = collect(f.node.body, (x) => x.type === "VariableDeclarationStatement" && (x.variables ?? []).some((v: Node) => v?.name === tname))[0];
          const from = decl?.initialValue && identifiers(decl.initialValue).find((i) => c.stateVars.has(i));
          if (from) sv = from;
        }
        const adminSettable = !!sv && privilegedSetters(c, sv).length > 0;
        const pf = mk(ctx, "UPGRADEABLE_PROXY", adminSettable ? "Upgradeable proxy whose implementation a single privileged key can swap" : "Upgradeable proxy: logic lives in another contract", adminSettable ? "high" : "low", 0.8, n, f,
          `${sn(ctx, n)} in ${f.name}()${sv ? `; target from ${sv}` : ""}`, `Assembly delegatecall proxy. The implementation decides the real behaviour and is not part of this source${adminSettable ? "; a single key can replace it at any time, so nothing about the contract's behaviour is fixed" : ""}.`);
        if (adminSettable) pf.vulnerability = true;
        out.push(pf);
        return;
      }
      if (isCallTo(n, ["selfdestruct", "suicide"])) {
        const open = !f.privileged && /^(public|external|default)$/.test(f.visibility);
        out.push(mk(ctx, "SELFDESTRUCT", open ? "Unguarded selfdestruct" : "Owner can selfdestruct the contract", open ? "critical" : "high", 0.9, n, f,
          `${sn(ctx, n)} in ${f.name}()`, `selfdestruct removes the contract and sends its ETH to the target address; every holder's balance becomes unreachable.`));
      }
      if (n.type === "FunctionCall" && n.expression?.type === "MemberAccess" && n.expression.memberName === "delegatecall") {
        const target = n.expression.expression;
        const tid = baseName(target);
        const settable = tid && (privilegedSetters(c, tid).length > 0 || f.params.includes(tid));
        const isThis = target?.type === "FunctionCall" && target.arguments?.[0]?.type === "Identifier" && target.arguments[0].name === "this";
        const proxyShape = f.name === "fallback" || /^_?(delegate|fallback|_implementation|delegateTo|_delegateTo)$/i.test(f.name) || (target?.type === "FunctionCall" && /implementation/i.test(calleeName(target) ?? "")) || (tid && /implementation|logic/i.test(tid));
        if (!isThis && proxyShape) {
          const adminSettable = tid && privilegedSetters(c, tid).length > 0;
          const pf = mk(ctx, "UPGRADEABLE_PROXY", adminSettable ? "Upgradeable proxy whose implementation a single privileged key can swap" : "Upgradeable proxy: logic can be replaced by the proxy admin", adminSettable ? "high" : "low", 0.8, n, f,
            `${sn(ctx, n)} in ${f.name}()`, `Standard delegatecall proxy pattern. The implementation behind this address decides the real behaviour and is not part of this source; ${adminSettable ? "a single key can replace it at any time, so nothing about the token's behaviour is fixed" : "analyze the implementation contract as well"}.`);
          if (adminSettable) pf.vulnerability = true; // cannot be judged from this file alone -> Uncertain, not Malicious
          out.push(pf);
        } else if (!isThis) {
          out.push(mk(ctx, "DELEGATECALL", settable ? "delegatecall to an owner-controlled address" : "delegatecall to external code", settable ? "critical" : "high", settable ? 0.85 : 0.6, n, f,
            `${sn(ctx, n)} in ${f.name}()`, `delegatecall executes foreign code in this contract's storage context. ${settable ? "Because the target is settable, the owner can swap in arbitrary logic (including balance rewrites) after launch." : "Any logic in the target can rewrite balances and ownership."}`));
        }
      }
    });
  }
  return out;
}

export function ruleExternalGateInTransfer(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const ROUTER_FN = /^(swapExactTokensForETH|swapExactTokensForETHSupportingFeeOnTransferTokens|swapExactTokensForTokens|swapExactTokensForTokensSupportingFeeOnTransferTokens|addLiquidity|addLiquidityETH|WETH|factory|getPair|createPair|sync|skim|getReserves|balanceOf|transfer|transferFrom|approve|allowance|totalSupply|decimals|token0|token1|getAmountsOut|sendValue|call|delegatecall|staticcall|send|push|pop|add|sub|mul|div|mod|min|max|toString|sqrt|encode|decode|encodePacked|keccak256|_msgSender|require|revert|assert|emit|super|owner)$/;
  for (const fname of c.coreTransferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body) continue;
    walk(f.node.body, (n) => {
      if (n.type !== "FunctionCall" || n.expression?.type !== "MemberAccess") return;
      const member = n.expression.memberName;
      if (ROUTER_FN.test(member)) return;
      if (/^(current|increment|decrement|latest|length|toString|min|max|abs|pow|sqrt|mulDiv|wrap|unwrap)$/.test(member)) return;
      const recv = n.expression.expression;
      // I(addr).fn(...) or addr.fn(...)
      let addrId: string | null = null;
      if (recv?.type === "FunctionCall" && recv.arguments?.length === 1) addrId = baseName(recv.arguments[0]);
      else addrId = baseName(recv);
      if (!addrId || addrId === "this" || addrId === "super" || addrId === "msg" || addrId === "address") return;
      const sv = c.stateVars.get(addrId);
      if (!sv || sv.isConstant || sv.isMapping) return;
      if (!(sv.typeStr === "address" || sv.typeStr === "address payable" || /^[A-Z]/.test(sv.typeStr))) return; // must be an address or contract-typed var, not a struct/library
      if (/^(Counters?\.Counter|Checkpoints?|EnumerableSet|EnumerableMap|BitMaps?|Strings|SafeMath|Math)/.test(sv.typeStr)) return;
      if (c.pairVars.has(addrId) || /router|factory|weth/i.test(addrId)) return;
      const setters = privilegedSetters(c, addrId);
      const argsRefFromTo = n.arguments?.some((a: Node) => identifiers(a).some((i) => f.params.includes(i)));
      const sev: Severity = setters.length ? "critical" : "medium";
      out.push(mk(ctx, "EXTERNAL_TRANSFER_HOOK", setters.length ? "Transfer logic delegated to an owner-replaceable external contract" : "Transfer logic depends on an external contract", sev, argsRefFromTo ? 0.8 : 0.6, n, f,
        `${sn(ctx, n)} in ${f.name}()${setters.length ? `; ${addrId} set in ${setters[0].fn.name}()` : ""}`,
        `The transfer path calls out to ${addrId}.${member}(). The rules that decide whether a transfer succeeds live in code that is not in this file${setters.length ? " and can be swapped by the owner at any time" : ""}. This is how honeypots hide the sell-block: the visible token looks clean, the external 'checker' does the blocking.`,
        setters.length ? [loc(ctx, setters[0].w.node, setters[0].fn)] : undefined));
    });
  }
  return dedupe(out);
}

export function ruleHiddenWithdraw(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const f of c.functions.values()) {
    if (f.isConstructor || !f.privileged || c.transferPath.has(f.name)) continue;
    let node: Node | null = null, what = "";
    walk(f.node.body, (n) => {
      if (node) return false;
      if (n.type === "FunctionCall" && n.expression?.type === "MemberAccess") {
        const m = n.expression.memberName;
        const recv = n.expression.expression;
        const recvIsThis = recv?.type === "FunctionCall" && recv.expression?.type === "ElementaryTypeName" && recv.arguments?.[0]?.name === "this";
        if ((m === "transfer" || m === "send") && (recvIsThis || isMsgSender(recv) || identifiers(recv).some((i) => c.ownerVars.has(i)) || (recv?.type === "FunctionCall" && /^(payable|owner)$/.test(calleeName(recv) ?? "")))) {
          if (recv?.type === "FunctionCall" && calleeName(recv) === "payable" || isMsgSender(recv) || identifiers(recv).some((i) => c.ownerVars.has(i))) { node = n; what = "ETH sent to owner/caller"; }
        }
        if (m === "call" && n.expression?.type === "MemberAccess" && (n as Node).arguments && (identifiers(recv).some((i) => c.ownerVars.has(i)) || isMsgSender(recv))) { node = n; what = "ETH sent via call to owner/caller"; }
        if (m === "transfer" && recv?.type === "FunctionCall" && /^I?ERC20|IBEP20|IToken/i.test(calleeName(recv) ?? "")) { node = n; what = "ERC20 tokens moved out of the contract"; }
      }
      if (n.type === "FunctionCall" && n.expression?.type === "FunctionCallOptions" && n.expression.expression?.type === "MemberAccess" && n.expression.expression.memberName === "call") {
        const recv = n.expression.expression.expression;
        if (identifiers(recv).some((i) => c.ownerVars.has(i)) || isMsgSender(recv)) { node = n; what = "ETH sent via call{value} to owner/caller"; }
      }
    });
    if (!node) continue;
    const honest = WITHDRAW_NAME.test(f.name);
    out.push(mk(ctx, "PRIVILEGED_WITHDRAW", honest ? `Owner can withdraw contract funds via '${f.name}()'` : `Funds are sent to the owner inside '${f.name}()' (name does not suggest a withdrawal)`, honest ? "low" : "medium", honest ? 0.8 : 0.7, node, f,
      `${what}: ${sn(ctx, node)} [${f.privilegeReason}]`,
      honest ? `Centralisation risk: ETH/tokens held by the contract (e.g. collected fees, presale funds) can be pulled by the owner at any time.` : `A function whose name hides its purpose moves contract funds to the owner. Hidden withdrawal paths are a classic rug component.`));
  }
  return out;
}

export function ruleMisc(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  // tx.origin used for privilege
  for (const f of c.functions.values()) {
    if (!f.node.body) continue;
    walk(f.node.body, (n) => {
      if (n.type === "BinaryOperation" && (n.operator === "==" || n.operator === "!=") && (isTxOrigin(n.left) || isTxOrigin(n.right)) && !(isMsgSender(n.left) || isMsgSender(n.right))) {
        // is this check the gate of a state write? (in this function, or in a public function that calls this helper)
        const callers = [...c.functions.values()].filter((g) => g === f || g.calls.has(f.name));
        const guardsWrite = callers.some((g) => g.writes.length > 0 && /^(public|external|default)$/.test(g.visibility));
        const tf = mk(ctx, "TX_ORIGIN_AUTH", guardsWrite ? "tx.origin is the only authorization on a privileged state change" : "tx.origin used for authorization", guardsWrite ? "high" : "low", guardsWrite ? 0.8 : 0.7, n, f, sn(ctx, n),
          guardsWrite ? `The owner check compares tx.origin, so any contract the owner is tricked into calling can perform this privileged write on their behalf. Not proof of intent, but the privilege is phishable.` : `tx.origin checks are phishable and often used to whitelist the deployer's EOA in a way that is hard to spot.`);
        if (guardsWrite) tf.vulnerability = true;
        out.push(tf);
      }
    });
  }
  // sell/tx limit that the owner can shrink to zero
  const gates = transferGates(c);
  for (const g of gates) {
    if (g.kind === "if") continue;
    const f = g.fn;
    const amt = paramNamed(f, AMOUNT_NAMES, 2);
    walk(g.cond, (n) => {
      if (n.type !== "BinaryOperation" || !["<", "<=", ">", ">="].includes(n.operator)) return;
      const sides = [n.left, n.right];
      const amtSide = sides.findIndex((s) => refsIdent(s, amt));
      if (amtSide < 0) return;
      const other = sides[1 - amtSide];
      const lim = identifiers(other).find((i) => c.stateVars.has(i) && !c.stateVars.get(i)!.isConstant && !c.stateVars.get(i)!.isMapping);
      if (!lim) return;
      const setters = privilegedSetters(c, lim).filter(({ fn, w }) => valueFromParam(fn, w));
      if (!setters.length) return;
      const s = setters[0];
      // lower bound present?
      let lower = false;
      walk(s.fn.node.body, (x) => {
        if (isCallTo(x, ["require"]) && x.arguments?.[0]) {
          const cnd = x.arguments[0];
          if (cnd.type === "BinaryOperation" && [">", ">="].includes(cnd.operator) && identifiers(cnd.left).some((i) => s.fn.params.includes(i) || i === lim)) lower = true;
          if (cnd.type === "BinaryOperation" && ["<", "<="].includes(cnd.operator) && identifiers(cnd.right).some((i) => s.fn.params.includes(i) || i === lim)) lower = true;
        }
      });
      if (lower) return;
      const sell = inSellBranch(c, g) || refsPair(c, g.cond);
      const asym = sell || refsExemption(c, g.cond) || g.enclosing.some((e) => refsExemption(c, e));
      out.push(mk(ctx, "OWNER_LIMIT_TO_ZERO", `${sell ? "Sell" : "Transfer"} amount limit ${lim} can be set to zero by the owner${asym ? "" : " (applies to the owner too)"}`, sell ? "critical" : asym ? "high" : "low", sell ? 0.8 : 0.7, g.node, f,
        `${sn(ctx, g.cond)}  |  ${lim} set in ${s.fn.name}() without a lower bound`,
        `Transfers are rejected when amount exceeds ${lim}. The setter has no minimum, so the owner can set it to 0 (or 1 wei) and effectively stop ${sell ? "sells" : "all transfers"} while the code still looks like a harmless anti-whale limit.`,
        [loc(ctx, s.w.node, s.fn)]));
    });
  }
  // anyone can drain: unprivileged function sending the whole contract balance (or ERC20 holdings) to the caller
  for (const f of c.functions.values()) {
    if (f.isConstructor || f.privileged || !/^(public|external|default)$/.test(f.visibility) || !f.node.body) continue;
    walk(f.node.body, (n) => {
      let hit: string | null = null;
      const isThisBal = (x: Node) => x?.type === "MemberAccess" && x.memberName === "balance" && ((x.expression?.type === "FunctionCall" && x.expression.arguments?.[0]?.name === "this") || (x.expression?.type === "Identifier" && x.expression.name === "this"));
      if (n.type === "FunctionCall" && n.expression?.type === "MemberAccess" && (n.expression.memberName === "transfer" || n.expression.memberName === "send") && isMsgSender(n.expression.expression) && n.arguments?.some(isThisBal)) hit = "ETH";
      if (n.type === "FunctionCall" && n.expression?.type === "FunctionCallOptions" && n.expression.expression?.memberName === "call" && isMsgSender(n.expression.expression.expression) && n.expression.arguments?.some?.(isThisBal)) hit = "ETH";
      if (n.type === "FunctionCall" && n.expression?.type === "MemberAccess" && n.expression.memberName === "transfer" && n.arguments?.length === 2 && isMsgSender(n.arguments[0]) && collect(n.arguments[1], (x) => x.type === "MemberAccess" && x.memberName === "balanceOf").length) hit = "ERC20";
      if (hit) out.push(mk(ctx, "OPEN_DRAIN", `Anyone can drain the contract's ${hit} via '${f.name}()'`, "critical", 0.8, n, f, sn(ctx, n), `An unguarded function transfers the contract's entire ${hit} balance to whoever calls it. Either a fatal bug or a backdoor for a pre-arranged address.`));
    });
  }
  // unresolved non-standard base contracts => note
  const std = /^(ERC20|ERC20Upgradeable|BEP20|IERC20|IBEP20|Ownable|Ownable2Step|OwnableUpgradeable|Context|ContextUpgradeable|ReentrancyGuard|Pausable|ERC20Burnable|ERC20Permit|ERC20Votes|ERC165|Initializable|AccessControl|SafeMath|Address|IUniswapV2Router02|IUniswapV2Factory|IUniswapV2Pair|IERC20Metadata|ERC20Capped|Auth|Owned)$/i;
  const unk = c.unknownBases.filter((b) => !std.test(b));
  if (unk.length) {
    out.push(mk(ctx, "UNRESOLVED_BASE", `Inherits from contracts not present in the analyzed files: ${unk.join(", ")}`, "info", 0.9, c.node, undefined,
      `bases: ${c.bases.join(", ")}`, `Transfer/ownership logic may live in ${unk.join(", ")}, which could not be analyzed. Verdict confidence is reduced.`));
  }
  return out;
}

function dedupe(fs: Finding[]): Finding[] {
  const seen = new Set<string>();
  return fs.filter((f) => {
    const k = `${f.id}:${f.location.line}:${f.title}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}


// ================================================================ additional families (research-note §7)

/** does this function (or anything it calls inside the transfer path) decrease a balance-mapping slot? */
function debitsBalance(c: Contract, f: Func, seen = new Set<string>()): boolean {
  if (seen.has(f.name)) return false; seen.add(f.name);
  if (f.writes.some((w) => c.balanceVars.has(w.base) && writeKind(w) === "decrease")) return true;
  for (const callee of f.calls) { const g = c.functions.get(callee); if (g && debitsBalance(c, g, seen)) return true; }
  return f.callsSuper; // super._transfer debits in the base
}

export function ruleTimeGate(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const isTime = (n: Node) => (n.type === "MemberAccess" && (n.memberName === "timestamp" || n.memberName === "number") && n.expression?.name === "block") || (n.type === "Identifier" && n.name === "now");
  for (const g of transferGates(c)) {
    if (g.kind === "if") continue;
    if (!collect(g.cond, isTime).length) continue;
    const vars = identifiers(g.cond).filter((i) => c.stateVars.has(i) && !c.stateVars.get(i)!.isMapping && !c.stateVars.get(i)!.isConstant);
    const settable = vars.map((v) => ({ v, s: privilegedSetters(c, v).filter(({ fn, w }) => valueFromParam(fn, w)) })).filter((x) => x.s.length);
    const asym = refsExemption(c, g.cond) || g.enclosing.some((e) => refsExemption(c, e));
    if (settable.length) {
      const { v, s } = settable[0];
      out.push(mk(ctx, "EXIT_TIME_GATE", asym ? "Owner-adjustable time lock on transfers with an owner exemption" : "Owner can move the transfer time lock (applies to the owner too)", asym ? "critical" : "low", 0.8, g.node, g.fn,
        `${sn(ctx, g.cond)}  |  ${v} set in ${s[0].fn.name}() [${s[0].fn.privilegeReason}]`,
        `Transfers are gated on block time against ${v}, and a privileged function can push that boundary arbitrarily far into the future. ${asym ? "The owner/exempt path is not subject to it, so holders are locked while the owner trades." : "Holders can be locked indefinitely under a cover story of 'vesting' or 'launch protection'."}`,
        [loc(ctx, s[0].w.node, s[0].fn)]));
    } else if (vars.length === 0 || vars.every((v) => c.stateVars.get(v)!.isConstant)) {
      out.push(mk(ctx, "EXIT_TIME_GATE", "Fixed time window on transfers", "low", 0.7, g.node, g.fn, sn(ctx, g.cond), `Transfers depend on block time against a constant or immutable bound - a launch/vesting schedule that nobody can change after deployment.`));
    }
  }
  return out;
}

export function ruleCallbackCycle(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const path = [...c.coreTransferPath];
  for (const a of path) {
    const fa = c.functions.get(a);
    if (!fa) continue;
    for (const b of fa.calls) {
      if (b === a || !c.coreTransferPath.has(b)) continue;
      const fb = c.functions.get(b);
      if (!fb || !fb.calls.has(a)) continue; // a -> b -> a cycle
      // does the re-entering call pass a controlled address (state var / address(this)) as a transfer argument?
      let node: Node | null = null;
      walk(fb.node.body, (n) => {
        if (node) return false;
        if (n.type === "FunctionCall" && calleeName(n) === a) {
          const args: Node[] = n.arguments ?? [];
          if (args.some((x) => (x.type === "FunctionCall" && x.arguments?.[0]?.name === "this") || (x.type === "Identifier" && c.stateVars.get(x.name)?.typeStr === "address"))) node = n;
        }
      });
      if (!node) continue;
      const gated = transferGates(c).some((g) => g.kind !== "if" && g.fn.name === a);
      out.push(mk(ctx, "EXIT_CALLBACK_CYCLE", "Transfer re-enters itself with a contract-controlled address", gated ? "high" : "medium", 0.6, node, fb,
        `${a}() -> ${b}() -> ${a}(${sn(ctx, node)})`,
        `The transfer path calls itself again with an address the contract controls. If the gate in ${a}() compares sender/receiver with a stored address, the nested call can be made to always fail for ordinary sellers while the seller never appears in any list (the 'invalid callback' trapdoor).`));
    }
  }
  return out;
}

export function ruleFeeAddrMutable(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  // address state vars that receive value inside the transfer path
  const receivers = new Set<string>();
  for (const fname of c.transferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body) continue;
    for (const w of f.writes) if (c.balanceVars.has(w.base) && writeKind(w) === "increase") { const idx = indexChain(w.target)[0]; const id = idx?.type === "Identifier" ? idx.name : null; if (id && c.stateVars.get(id)?.typeStr.startsWith("address")) receivers.add(id); }
    walk(f.node.body, (n) => {
      if (n.type === "FunctionCall" && /^(_transfer|_basicTransfer|_tokenTransfer|_transferStandard|transfer|_update|_send)$/.test(calleeName(n) ?? "")) {
        const to = n.arguments?.[n.arguments.length === 3 ? 1 : 0];
        if (to?.type === "Identifier" && c.stateVars.get(to.name)?.typeStr.startsWith("address")) receivers.add(to.name);
      }
      if (n.type === "FunctionCall" && n.expression?.type === "MemberAccess" && (n.expression.memberName === "transfer" || n.expression.memberName === "send")) {
        const recv = n.expression.expression; const id = recv?.type === "Identifier" ? recv.name : recv?.type === "FunctionCall" && recv.arguments?.[0]?.type === "Identifier" ? recv.arguments[0].name : null;
        if (id && c.stateVars.get(id)?.typeStr.startsWith("address")) receivers.add(id);
      }
    });
  }
  for (const v of receivers) {
    if (c.pairVars.has(v) || c.routerVars.has(v)) continue;
    const setters = privilegedSetters(c, v).filter(({ fn, w }) => valueFromParam(fn, w));
    if (!setters.length) continue;
    out.push(mk(ctx, "FEE_ADDR_MUTABLE", `Fee recipient ${v} can be redirected by the owner`, "medium", 0.75, setters[0].w.node, setters[0].fn,
      `${sn(ctx, setters[0].w.node)} in ${setters[0].fn.name}() [${setters[0].fn.privilegeReason}]; ${v} receives value inside the transfer path`,
      `Every fee deducted on transfer is sent to ${v}, and a privileged function can point it at any address. On its own this is centralisation; combined with an uncapped fee it is the second half of a drain.`));
  }
  return out;
}

export function ruleViewCallerDependent(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const f of c.functions.values()) {
    if (!/^(balanceOf|totalSupply|allowance|decimals|name|symbol)$/.test(f.name) || !f.node.body) continue;
    walk(f.node.body, (n) => {
      const cond = n.type === "IfStatement" ? n.condition : n.type === "Conditional" ? n.condition : null;
      if (!cond) return;
      const dep = collect(cond, (x) => isMsgSender(x) || isTxOrigin(x)).length > 0 || identifiers(cond).some((i) => c.ownerVars.has(i)) || collect(cond, (x) => x.type === "IndexAccess" && isMsgSender(x.index)).length > 0;
      if (dep) out.push(mk(ctx, "VIEW_CALLER_DEPENDENT", `${f.name}() answers differently depending on who asks`, "high", 0.85, n, f, sn(ctx, cond),
        `A standard view function branches on msg.sender/owner. Explorers, wallets and DEX front-ends are shown one number while the transfer logic uses another - the 'balanceOf that lies' class (TokenScope). Used to fake liquidity, balances or supply.`));
    });
  }
  return out;
}

export function ruleExemptPath(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const fname of c.coreTransferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body || !debitsBalance(c, f)) continue;
    walk(f.node.body, (n) => {
      if (n.type !== "IfStatement") return;
      if (!refsExemption(c, n.condition) && !collect(n.condition, (x) => isMsgSender(x)).some(() => identifiers(n.condition).some((i) => c.ownerVars.has(i)))) return;
      const body = n.trueBody;
      const hasReturn = collect(body, (x) => x.type === "ReturnStatement").length > 0;
      if (!hasReturn) return;
      // the branch credits someone or calls a transfer helper but never debits (directly or via callees)
      const credits = collect(body, (x) => x.type === "BinaryOperation" && ["=", "+="].includes(x.operator) && c.balanceVars.has(baseName(x.left) ?? "") && writeKind({ node: x, target: x.left, base: baseName(x.left)!, operator: x.operator, value: x.right }) === "increase").length > 0;
      const debits = collect(body, (x) => x.type === "BinaryOperation" && ["=", "-="].includes(x.operator) && c.balanceVars.has(baseName(x.left) ?? "") && writeKind({ node: x, target: x.left, base: baseName(x.left)!, operator: x.operator, value: x.right }) === "decrease").length > 0
        || collect(body, (x) => x.type === "FunctionCall" && c.functions.has(calleeName(x) ?? "") && debitsBalance(c, c.functions.get(calleeName(x)!)!)).length > 0
        || collect(body, (x) => isSuperCallNode(x)).length > 0;
      if (credits && !debits) {
        out.push(mk(ctx, "LEAK_EXEMPT_PATH", "Privileged sender is credited without being debited", "critical", 0.8, n, f, sn(ctx, n.condition),
          `Inside the transfer path, a branch taken only for the owner/exempt sender credits the recipient and returns without reducing the sender's balance. The privileged account can 'transfer' tokens it does not have - supply is created on every such call, unaccounted in totalSupply.`));
      }
    });
  }
  return out;
}
function isSuperCallNode(n: Node): boolean { return n?.type === "FunctionCall" && n.expression?.type === "MemberAccess" && n.expression.expression?.type === "Identifier" && n.expression.expression.name === "super"; }

export function ruleApprovalDrain(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const f of c.functions.values()) {
    if (f.isConstructor || !f.node.body || !/^(public|external|default)$/.test(f.visibility)) continue;
    walk(f.node.body, (n) => {
      if (n.type !== "FunctionCall" || n.expression?.type !== "MemberAccess" || !/^(transferFrom|safeTransferFrom|permitTransferFrom)$/.test(n.expression.memberName)) return;
      const args: Node[] = n.arguments ?? [];
      const fromArg = args[0], toArg = args[1];
      if (!fromArg || !toArg || !isMsgSender(fromArg)) return;
      const toIsThis = toArg.type === "FunctionCall" && toArg.arguments?.[0]?.name === "this";
      if (toIsThis) return; // deposit into this contract: normal
      const toIsParam = toArg.type === "Identifier" && f.params.includes(toArg.name);
      if (toIsParam) return; // caller chooses the destination
      const toId = baseName(toArg);
      const hard = toArg.type === "NumberLiteral" || (toArg.type === "FunctionCall" && toArg.arguments?.[0]?.type === "NumberLiteral");
      const toOwner = (toId && (c.ownerVars.has(toId) || c.stateVars.has(toId))) || (toArg.type === "FunctionCall" && isOwnerGetterCall(toArg));
      if (!hard && !toOwner) return;
      // is the caller credited in return (a swap/deposit)?  any write to a mapping indexed by msg.sender in this function
      const credited = f.writes.some((w) => { const idx = indexChain(w.target)[0]; return idx && isMsgSender(idx) && writeKind(w) === "increase"; });
      if (credited) return;
      out.push(mk(ctx, "DRAIN_APPROVAL_PULL", `'${f.name}()' pulls the caller's approved tokens to ${hard ? "a hard-coded address" : toId ?? "the owner"}`, "critical", 0.85, n, f, sn(ctx, n),
        `The function moves tokens from msg.sender (who must have approved this contract) to an address the caller does not choose and receives nothing in return. This is the on-chain half of an approval-phishing / 'claim airdrop' drainer.`));
    });
  }
  return out;
}

export function ruleCustodySweep(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  // does the contract custody user funds? a payable function that credits a per-user mapping with msg.value
  let custody: Func | null = null;
  for (const f of c.functions.values()) {
    if (f.mutability !== "payable" || f.isConstructor) continue;
    if (f.writes.some((w) => { const sv = c.stateVars.get(w.base); const idx = indexChain(w.target)[0]; return sv?.isMapping && idx && isMsgSender(idx) && writeKind(w) === "increase"; })) { custody = f; break; }
  }
  if (!custody) return out;
  for (const f of c.functions.values()) {
    if (!f.privileged || f.isConstructor || !f.node.body) continue;
    walk(f.node.body, (n) => {
      const isThisBal = (x: Node) => x?.type === "MemberAccess" && x.memberName === "balance" && ((x.expression?.type === "FunctionCall" && x.expression.arguments?.[0]?.name === "this") || (x.expression?.type === "Identifier" && x.expression.name === "this"));
      const sendsWhole = (n.type === "FunctionCall" && n.expression?.type === "MemberAccess" && /^(transfer|send)$/.test(n.expression.memberName) && n.arguments?.some(isThisBal))
        || (n.type === "FunctionCall" && n.expression?.type === "FunctionCallOptions" && n.expression.expression?.memberName === "call" && (n.expression.arguments ?? []).some?.(isThisBal))
        || (n.type === "FunctionCall" && n.expression?.type === "NameValueExpression" && collect(n.expression, isThisBal).length > 0);
      if (!sendsWhole) return;
      out.push(mk(ctx, "CUSTODY_SWEEP", `Owner can sweep user deposits via '${f.name}()'`, "critical", 0.85, n, f, `${sn(ctx, n)} [${f.privilegeReason}]; deposits are recorded in ${custody!.name}()`,
        `Users deposit ETH through ${custody!.name}() and the contract tracks their balances, yet a privileged function sends the entire contract balance out. Those are user funds, not fees - this is a rug path, whatever the function is called.`));
    });
  }
  return out;
}

export const RULES: ((ctx: Ctx) => Finding[])[] = [
  ruleTimeGate,
  ruleCallbackCycle,
  ruleFeeAddrMutable,
  ruleViewCallerDependent,
  ruleExemptPath,
  ruleApprovalDrain,
  ruleCustodySweep,
  ruleSellRestriction,
  ruleBlacklistGate,
  ruleTradingGate,
  ruleUncappedFee,
  ruleHiddenMint,
  ruleBalanceManipulation,
  ruleApprovalBypass,
  ruleOwnership,
  ruleDangerousOps,
  ruleExternalGateInTransfer,
  ruleHiddenWithdraw,
  ruleMisc,
  ...RULES2,
  ...RULES3,
];

export function runRules(ctx: Ctx): Finding[] {
  const out: Finding[] = [];
  for (const r of RULES) {
    try {
      out.push(...r(ctx));
    } catch (e) {
      out.push({ id: "RULE_ERROR", title: `rule ${r.name} crashed: ${(e as Error).message}`, severity: "info", confidence: 1, location: { file: ctx.file, line: 0, column: 0, contract: ctx.c.name }, evidence: "", reasoning: "" });
    }
  }
  return dedupe(out);
}
