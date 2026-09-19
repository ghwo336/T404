import { Node, walk, collect, baseName, identifiers, isCallTo, calleeName, numberValue, isZeroAddress, line, endLine, snippet, isMsgSender, isTxOrigin, indexChain } from "./ast";
import { Contract, Func, Assign, PAIR_NAME } from "./model";
import { Finding, Severity, Location } from "./types";

export interface Ctx {
  file: string;
  source: string;
  c: Contract;
}

const TO_NAMES = /^(to|_to|recipient|_recipient|dst|receiver|target|_receiver)$/i;
const FROM_NAMES = /^(from|_from|sender|_sender|src|owner_|holder)$/i;
const AMOUNT_NAMES = /^(amount|_amount|value|_value|tAmount|amt|tokens|quantity)$/i;
const EXEMPT_NAME = /(exclud|exempt|whitelist|isFeeExempt|isTxLimitExempt|noFee|isVIP|allowed|authorized|privileged)/i;
const BLACKLIST_NAME = /(blacklist|blocklist|blocked|banned|bots?$|isBot|_isBot|sniper|frozen|freeze|restricted|denylist|cannotSell|canSell|isBlack|locked|jail)/i;
const FEE_NAME = /(fee|tax|rate|percent|pct|bps|burn|liquidity|marketing|dev|reflect|charity|team|slippage|cut|commission)/i;
const WITHDRAW_NAME = /(withdraw|rescue|recover|claim|sweep|clear|emergency|manual|sendETH|sendEth|drain|collect|stuck|forward|payout|distribute)/i;
const OWNERSHIP_FN = /^(transferOwnership|_transferOwnership|renounceOwnership|acceptOwnership|_setOwner|setOwner|changeOwner|updateOwner|transferAdmin|setAdmin|changeAdmin|_setAdmin|initialize|init|__Ownable_init|__Ownable_init_unchained|_checkOwner|pushManagement|pullManagement|renounceManagement)$/i;

function loc(ctx: Ctx, node: Node, fn?: Func): Location {
  return {
    file: ctx.file,
    line: line(node),
    column: node?.loc?.start?.column ?? 0,
    endLine: endLine(node),
    contract: ctx.c.name,
    function: fn?.name,
    snippet: snippet(ctx.source, node),
  };
}

function mk(ctx: Ctx, id: string, title: string, severity: Severity, confidence: number, node: Node, fn: Func | undefined, evidence: string, reasoning: string, related?: Location[]): Finding {
  return { id, title, severity, confidence, location: loc(ctx, node, fn), evidence, reasoning, related };
}

function hasRevert(body: Node): boolean {
  if (!body) return false;
  return collect(body, (x) => x.type === "RevertStatement" || x.type === "ThrowStatement" || isCallTo(x, ["revert"]) || (isCallTo(x, ["require", "assert"]) && x.arguments?.[0]?.type === "BooleanLiteral" && x.arguments[0].value === false)).length > 0;
}

interface Gate { fn: Func; node: Node; cond: Node; kind: "require" | "if-revert" | "if"; body?: Node; enclosing: Node[] }

/** All guards in the transfer path: require(cond), if(cond) revert, plain if(cond){...} */
function transferGates(c: Contract): Gate[] {
  const out: Gate[] = [];
  for (const fname of c.transferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body) continue;
    const visit = (n: Node, enclosing: Node[]) => {
      if (!n || typeof n !== "object") return;
      if (Array.isArray(n)) { for (const x of n) visit(x, enclosing); return; }
      if (isCallTo(n, ["require"]) && n.arguments?.[0]) out.push({ fn: f, node: n, cond: n.arguments[0], kind: "require", enclosing });
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
  }
  return out;
}

function refsPair(c: Contract, expr: Node): boolean {
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

function paramNamed(f: Func, re: RegExp, pos: number): string | null {
  const byName = f.params.find((p) => re.test(p));
  if (byName) return byName;
  return f.params[pos] ?? null;
}

function refsIdent(expr: Node, name: string | null): boolean {
  return !!name && identifiers(expr).includes(name);
}

function refsExemption(c: Contract, expr: Node): boolean {
  const ids = identifiers(expr);
  if (ids.some((i) => c.ownerVars.has(i))) return true;
  if (ids.some((i) => EXEMPT_NAME.test(i) && c.stateVars.has(i))) return true;
  let found = false;
  walk(expr, (n) => {
    if (n.type === "FunctionCall" && /^(owner|_owner|getOwner|isExcluded|isExempt|_isExcludedFromFee|isFeeExempt)/i.test(calleeName(n) ?? "")) found = true;
    if (n.type === "IndexAccess" && EXEMPT_NAME.test(baseName(n.base) ?? "")) found = true;
    if (n.type === "MemberAccess" && n.memberName === "sender" && false) found = true;
  });
  return found;
}

/** Is a state var written by a privileged, non-constructor function with a value derived from a parameter or a literal? */
function privilegedSetters(c: Contract, varName: string): { fn: Func; w: Assign }[] {
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

function valueFromParam(f: Func, w: Assign): boolean {
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

function upperBound(c: Contract, f: Func, names: string[]): number | null | "unbounded" {
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

function inSellBranch(c: Contract, gate: Gate): boolean {
  if (sellCond(c, gate.fn, gate.cond)) return true;
  return gate.enclosing.some((e) => sellCond(c, gate.fn, e));
}

function sellCond(c: Contract, fn: Func, cond: Node): boolean {
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
        `Transfer to the liquidity pair is rejected: ${snippet(ctx.source, g.cond)}`,
        `Inside the token transfer logic, a transfer whose destination is the DEX pair (i.e. a sell) hits a revert${exempt ? " unless the sender is owner/exempt" : ""}. Buying (pair -> user) passes through. This is the canonical honeypot: users can acquire the token but cannot exit.`));
      continue;
    }
    if (g.kind === "require") {
      // require(to != pair || exempt) / require(!(to == pair) ...)
      const exemptOrToggle = exempt || identifiers(g.cond).some((i) => c.stateVars.get(i)?.typeStr === "bool");
      out.push(mk(ctx, "SELL_RESTRICTION", "Sell path guarded by require that ordinary holders cannot satisfy", exempt ? "critical" : "high", exempt ? 0.9 : 0.6, g.node, g.fn,
        `require in transfer path references the pair and the recipient: ${snippet(ctx.source, g.cond)}`,
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
        snippet(ctx.source, diverted[0]),
        `In the sell branch, balances are written to an address other than the recipient (${to}) and the function returns early, so the pair never receives the tokens - the sell silently fails or is confiscated.`));
    }
    // sell-only amount limit / fee variables handled by other rules, but flag sell branch that sets fee from an owner-set var
    const feeAssign = collect(body, (n) => n.type === "BinaryOperation" && n.operator === "=" && identifiers(n.right).some((i) => c.stateVars.has(i) && FEE_NAME.test(i)));
    for (const fa of feeAssign) {
      const vars = identifiers(fa.right).filter((i) => c.stateVars.has(i) && FEE_NAME.test(i));
      for (const v of vars) {
        const setters = privilegedSetters(c, v);
        if (!setters.length) continue;
        const b = upperBound(c, setters[0].fn, [v, ...setters[0].fn.params]);
        const denom = feeDenominator(c) ?? 100;
        if (b === "unbounded" || (typeof b === "number" && (b < 0 || b >= denom * 0.5))) {
          out.push(mk(ctx, "SELL_FEE_UNCAPPED", "Sell-side fee is owner-settable without an effective cap", "critical", 0.85, fa, g.fn,
            `${snippet(ctx.source, fa)}  |  setter ${setters[0].fn.name}() ${b === "unbounded" ? "has no upper bound" : `allows up to ${b}/${denom}`}`,
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
    if (!asRestriction) continue;
    const setters = privilegedSetters(c, v.name).filter(({ fn, w }) => valueFromParam(fn, w) || assignsLiteral(w, true));
    const openSetters = unprivilegedPublicWriters(c, v.name);
    const gate = readInGate[0];
    const sellOnly = inSellBranch(c, gate) || refsPair(c, gate.cond);
    if (setters.length) {
      const s = setters[0];
      const arbitrary = s.fn.params.length > 0 && identifiers(s.w.target).some((i) => s.fn.params.includes(i));
      out.push(mk(ctx, "BLACKLIST_GATE", `Owner-controlled address blacklist blocks ${sellOnly ? "selling" : "transfers"}`, arbitrary ? "critical" : "high", BLACKLIST_NAME.test(v.name) ? 0.95 : 0.8, gate.node, gate.fn,
        `${snippet(ctx.source, gate.cond)}  |  ${v.name} is written in ${s.fn.name}() [${s.fn.privilegeReason}]`,
        `The transfer path refuses when ${v.name}[addr] is set, and a privileged function can set it for ${arbitrary ? "any address passed as a parameter" : "addresses"} at any time. The owner can therefore freeze any holder's tokens after they buy - a targeted honeypot / rug mechanism that never shows up on-chain until the victim tries to sell.`,
        [loc(ctx, s.w.node, s.fn)]));
    } else if (openSetters.length) {
      out.push(mk(ctx, "BLACKLIST_GATE", "Publicly writable blacklist gates transfers", "critical", 0.7, openSetters[0].w.node, openSetters[0].fn,
        snippet(ctx.source, openSetters[0].w.node), `Anyone can write ${v.name}, which the transfer path uses as a block condition.`));
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
    const canDisable = setters.some(({ fn, w }) => valueFromParam(fn, w) || assignsLiteral(w, false) || (w.value?.type === "UnaryOperation" && w.value.operator === "!"));
    const gate = readInGate[0];
    const sellOnly = refsPair(c, gate.cond);
    if (canDisable) {
      out.push(mk(ctx, "TRADING_GATE", sellOnly ? "Owner can switch selling off at any time" : "Owner can pause all transfers at any time", sellOnly ? "critical" : "high", 0.8, gate.node, gate.fn,
        `${snippet(ctx.source, gate.cond)}  |  ${v.name} set in ${setters[0].fn.name}() [${setters[0].fn.privilegeReason}]`,
        `The transfer path requires ${v.name}, and a privileged function can flip it back to false. ${sellOnly ? "Because the check only applies to transfers into the pair, buys keep working while sells are halted - a switchable honeypot." : "Holders can be locked in indefinitely."}`,
        [loc(ctx, setters[0].w.node, setters[0].fn)]));
    } else {
      out.push(mk(ctx, "TRADING_GATE", "One-way launch gate (owner enables trading once)", "low", 0.7, gate.node, gate.fn,
        `${snippet(ctx.source, gate.cond)}  |  ${v.name} set only to true in ${setters[0].fn.name}()`,
        `Transfers are blocked until the owner enables trading, and the flag can only be set to true. Common launch pattern; risk is limited to a pre-launch lock.`));
    }
  }
  return out;
}

export function ruleUncappedFee(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const denom = feeDenominator(c);
  const feeVarsRead = new Set<string>();
  for (const fname of c.transferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body) continue;
    walk(f.node.body, (n) => {
      if (n.type === "BinaryOperation" && (n.operator === "*" || n.operator === "/")) for (const i of identifiers(n)) if (c.stateVars.has(i) && !c.stateVars.get(i)!.isMapping) feeVarsRead.add(i);
      if (isCallTo(n, ["mul", "div"])) for (const i of identifiers(n)) if (c.stateVars.has(i) && !c.stateVars.get(i)!.isMapping) feeVarsRead.add(i);
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
    const sellCtx = /sell/i.test(v);
    let sev: Severity | null = null, why = "";
    if (b === "unbounded") { sev = "high"; why = "has no upper bound at all"; }
    else if (typeof b === "number" && b < 0) { sev = "medium"; why = "is bounded only by another owner-settable variable"; }
    else if (typeof b === "number" && b >= d * 0.5) { sev = "medium"; why = `may be set as high as ${b}/${d} (${Math.round((b / d) * 100)}%)`; }
    else if (typeof b === "number" && b >= d * 0.25) { sev = "low"; why = `may be set as high as ${b}/${d} (${Math.round((b / d) * 100)}%)`; }
    if (!sev) continue;
    if (sellCtx && sev === "high") sev = "critical";
    else if (sellCtx && sev === "medium") sev = "high";
    out.push(mk(ctx, "UNCAPPED_FEE", `${sellCtx ? "Sell" : "Transfer"} fee ${v} is owner-settable and ${b === "unbounded" ? "uncapped" : "weakly capped"}`, sev, FEE_NAME.test(v) ? 0.85 : 0.55, s.w.node, s.fn,
      `${snippet(ctx.source, s.w.node)} in ${s.fn.name}() [${s.fn.privilegeReason}]; ${v} is used in the transfer arithmetic`,
      `${v} feeds the amount deducted on ${sellCtx ? "sells" : "transfers"}. Its setter ${why}, so the owner can raise the fee post-launch to confiscate most or all of every ${sellCtx ? "sell" : "transfer"}. A fee that can reach ~100% is a delayed honeypot.`));
  }
  return out;
}

function isMintLike(c: Contract, f: Func): { kind: "call" | "balance"; node: Node } | null {
  let hit: { kind: "call" | "balance"; node: Node } | null = null;
  walk(f.node.body, (n) => {
    if (hit) return false;
    if (isCallTo(n, ["_mint", "mint", "_mintTokens", "_issue", "issue"])) hit = { kind: "call", node: n };
  });
  if (hit) return hit;
  const balInc = f.writes.find((w) => c.balanceVars.has(w.base) && (w.operator === "+=" || (w.operator === "=" && w.value?.type === "BinaryOperation" && w.value.operator === "+") || (w.operator === "=" && isCallTo(w.value, ["add"]))));
  const supInc = f.writes.find((w) => c.supplyVars.has(w.base) && (w.operator === "+=" || (w.operator === "=" && (w.value?.type === "BinaryOperation" && w.value.operator === "+" || isCallTo(w.value, ["add"])))));
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
    const capped = named && upperBound(c, f, [...f.params, ...c.supplyVars]) !== "unbounded";
    if (f.privileged && capped) {
      out.push(mk(ctx, "OWNER_MINT", "Owner can mint within a hard cap", "low", 0.8, m.node, f, `${snippet(ctx.source, m.node)} in ${f.name}() [${f.privilegeReason}]`, `Minting is privileged but bounded by a supply cap check in the same function.`));
      continue;
    }
    if (f.privileged) {
      out.push(mk(ctx, "HIDDEN_MINT", named ? "Owner can mint unlimited supply" : `Supply inflation hidden in '${f.name}()'`, named ? "medium" : "critical", named ? 0.8 : 0.8, m.node, f,
        `${snippet(ctx.source, m.node)} in ${f.name}() [${f.privilegeReason}]`,
        named ? `A privileged function mints new tokens with no cap. The owner can dilute holders or dump freshly minted supply into the pool.` : `A function whose name does not suggest minting (${f.name}) increases balances and total supply under owner control. This is a disguised inflation backdoor - the owner can print tokens and dump them.`));
    } else if (f.mutability !== "payable") {
      out.push(mk(ctx, "OPEN_MINT", `Anyone can mint via '${f.name}()'`, "critical", 0.75, m.node, f,
        snippet(ctx.source, m.node), `A public, non-payable, unguarded function creates new tokens. Either a critical bug or an intentional backdoor for a co-conspirator address.`));
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
      const arbitrary = idx && identifiers(idx).some((i) => f.params.includes(i));
      if (w.operator === "=" || w.operator === "delete") {
        out.push(mk(ctx, "BALANCE_MANIPULATION", `Owner can overwrite ${arbitrary ? "any holder's" : "a"} balance`, "critical", 0.9, w.node, f,
          `${snippet(ctx.source, w.node)} in ${f.name}() [${f.privilegeReason}]`,
          `A privileged function assigns the balance mapping directly${arbitrary ? " for an address supplied as a parameter" : ""}, bypassing transfer/allowance logic. Holdings can be zeroed or reassigned at will.`));
      } else if (w.operator === "-=" || (w.operator === "=" && w.value?.type === "BinaryOperation" && w.value.operator === "-") || isCallTo(w.value, ["sub"])) {
        out.push(mk(ctx, "BALANCE_MANIPULATION", `Owner can burn tokens from ${arbitrary ? "any address" : "holders"} without consent`, "high", 0.85, w.node, f,
          `${snippet(ctx.source, w.node)} in ${f.name}()`,
          `A privileged function reduces another address's balance without an allowance or signature. Combined with a mint this becomes arbitrary confiscation.`));
      } else if (w.operator === "+=" || (w.operator === "=" && w.value?.type === "BinaryOperation" && w.value.operator === "+")) {
        out.push(mk(ctx, "BALANCE_MANIPULATION", "Balance increased under owner control without supply accounting", "high", 0.7, w.node, f,
          `${snippet(ctx.source, w.node)} in ${f.name}()`,
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
      if (c.transferPath.has(f.name) && (w.operator === "-=" || (w.operator === "=" && (w.value?.type === "BinaryOperation" && w.value.operator === "-" || isCallTo(w.value, ["sub"]))))) continue; // normal allowance spend
      if (f.privileged || /^(public|external|default)$/.test(f.visibility)) {
        out.push(mk(ctx, "APPROVAL_BYPASS", "Allowance mapping written on behalf of other holders", "critical", 0.85, w.node, f,
          `${snippet(ctx.source, w.node)} in ${f.name}()${f.privileged ? ` [${f.privilegeReason}]` : " (unprivileged)"}`,
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
            snippet(ctx.source, n.condition), `When the caller is the owner, the allowance branch is bypassed - the deployer can pull tokens from any holder.`));
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
        snippet(ctx.source, backup.node),
        `The previous owner address is stashed before ownership is set to zero. A companion function (typically lock()/unlock()/getUnlockTime) can restore it, so 'renounced' is cosmetic.`));
    }
  }
  for (const f of c.functions.values()) {
    if (f.isConstructor || OWNERSHIP_FN.test(f.name)) continue;
    for (const w of ownerWritten(f)) {
      const fromBackup = w.value && identifiers(w.value).some((i) => /previous|_prev|backup|old/i.test(i));
      const open = !f.privileged && /^(public|external|default)$/.test(f.visibility);
      out.push(mk(ctx, open ? "OPEN_OWNER_TAKEOVER" : "HIDDEN_OWNER_TRANSFER", open ? `Anyone can become owner via '${f.name}()'` : fromBackup ? `Ownership restored from backup in '${f.name}()'` : `Owner reassigned in unexpected function '${f.name}()'`, open ? "critical" : "high", 0.8, w.node, f,
        `${snippet(ctx.source, w.node)} in ${f.name}()${f.privileged ? ` [${f.privilegeReason}]` : ""}`,
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
      if (isCallTo(n, ["selfdestruct", "suicide"])) {
        const open = !f.privileged && /^(public|external|default)$/.test(f.visibility);
        out.push(mk(ctx, "SELFDESTRUCT", open ? "Unguarded selfdestruct" : "Owner can selfdestruct the contract", open ? "critical" : "high", 0.9, n, f,
          `${snippet(ctx.source, n)} in ${f.name}()`, `selfdestruct removes the contract and sends its ETH to the target address; every holder's balance becomes unreachable.`));
      }
      if (n.type === "FunctionCall" && n.expression?.type === "MemberAccess" && n.expression.memberName === "delegatecall") {
        const target = n.expression.expression;
        const tid = baseName(target);
        const settable = tid && (privilegedSetters(c, tid).length > 0 || f.params.includes(tid));
        const isThis = target?.type === "FunctionCall" && target.arguments?.[0]?.type === "Identifier" && target.arguments[0].name === "this";
        if (!isThis) {
          out.push(mk(ctx, "DELEGATECALL", settable ? "delegatecall to an owner-controlled address" : "delegatecall to external code", settable ? "critical" : "high", settable ? 0.85 : 0.6, n, f,
            `${snippet(ctx.source, n)} in ${f.name}()`, `delegatecall executes foreign code in this contract's storage context. ${settable ? "Because the target is settable, the owner can swap in arbitrary logic (including balance rewrites) after launch." : "Any logic in the target can rewrite balances and ownership."}`));
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
  for (const fname of c.transferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body) continue;
    walk(f.node.body, (n) => {
      if (n.type !== "FunctionCall" || n.expression?.type !== "MemberAccess") return;
      const member = n.expression.memberName;
      if (ROUTER_FN.test(member)) return;
      const recv = n.expression.expression;
      // I(addr).fn(...) or addr.fn(...)
      let addrId: string | null = null;
      if (recv?.type === "FunctionCall" && recv.arguments?.length === 1) addrId = baseName(recv.arguments[0]);
      else addrId = baseName(recv);
      if (!addrId || addrId === "this" || addrId === "super" || addrId === "msg" || addrId === "address") return;
      const sv = c.stateVars.get(addrId);
      if (!sv || sv.isConstant) return;
      if (c.pairVars.has(addrId) || /router|factory|weth/i.test(addrId)) return;
      const setters = privilegedSetters(c, addrId);
      const argsRefFromTo = n.arguments?.some((a: Node) => identifiers(a).some((i) => f.params.includes(i)));
      const sev: Severity = setters.length ? "critical" : "high";
      out.push(mk(ctx, "EXTERNAL_TRANSFER_HOOK", setters.length ? "Transfer logic delegated to an owner-replaceable external contract" : "Transfer logic depends on an external contract", sev, argsRefFromTo ? 0.8 : 0.6, n, f,
        `${snippet(ctx.source, n)} in ${f.name}()${setters.length ? `; ${addrId} set in ${setters[0].fn.name}()` : ""}`,
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
      `${what}: ${snippet(ctx.source, node)} [${f.privilegeReason}]`,
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
        out.push(mk(ctx, "TX_ORIGIN_AUTH", "tx.origin used for authorization", "low", 0.7, n, f, snippet(ctx.source, n), `tx.origin checks are phishable and often used to whitelist the deployer's EOA in a way that is hard to spot.`));
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
      const lim = identifiers(other).find((i) => c.stateVars.has(i) && !c.stateVars.get(i)!.isConstant);
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
      out.push(mk(ctx, "OWNER_LIMIT_TO_ZERO", `${sell ? "Sell" : "Transfer"} amount limit ${lim} can be set to zero by the owner`, sell ? "critical" : "medium", sell ? 0.8 : 0.7, g.node, f,
        `${snippet(ctx.source, g.cond)}  |  ${lim} set in ${s.fn.name}() without a lower bound`,
        `Transfers are rejected when amount exceeds ${lim}. The setter has no minimum, so the owner can set it to 0 (or 1 wei) and effectively stop ${sell ? "sells" : "all transfers"} while the code still looks like a harmless anti-whale limit.`,
        [loc(ctx, s.w.node, s.fn)]));
    });
  }
  // anyone can drain: unprivileged function sending the whole contract balance (or ERC20 holdings) to the caller
  for (const f of c.functions.values()) {
    if (f.isConstructor || f.privileged || !/^(public|external|default)$/.test(f.visibility) || !f.node.body) continue;
    walk(f.node.body, (n) => {
      let hit: string | null = null;
      const isThisBal = (x: Node) => x?.type === "MemberAccess" && x.memberName === "balance" && x.expression?.type === "FunctionCall" && x.expression.arguments?.[0]?.name === "this";
      if (n.type === "FunctionCall" && n.expression?.type === "MemberAccess" && (n.expression.memberName === "transfer" || n.expression.memberName === "send") && isMsgSender(n.expression.expression) && n.arguments?.some(isThisBal)) hit = "ETH";
      if (n.type === "FunctionCall" && n.expression?.type === "FunctionCallOptions" && n.expression.expression?.memberName === "call" && isMsgSender(n.expression.expression.expression) && n.expression.arguments?.some?.(isThisBal)) hit = "ETH";
      if (n.type === "FunctionCall" && n.expression?.type === "MemberAccess" && n.expression.memberName === "transfer" && n.arguments?.length === 2 && isMsgSender(n.arguments[0]) && collect(n.arguments[1], (x) => x.type === "MemberAccess" && x.memberName === "balanceOf").length) hit = "ERC20";
      if (hit) out.push(mk(ctx, "OPEN_DRAIN", `Anyone can drain the contract's ${hit} via '${f.name}()'`, "critical", 0.8, n, f, snippet(ctx.source, n), `An unguarded function transfers the contract's entire ${hit} balance to whoever calls it. Either a fatal bug or a backdoor for a pre-arranged address.`));
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

export const RULES: ((ctx: Ctx) => Finding[])[] = [
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
