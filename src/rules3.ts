// Industry-scanner families (GoPlus / Token Sniffer / Slitherin / SoK): cannot-sell-all, per-holder cooldown, buy block,
// EOA-only gate on the transfer path, per-address fee, phantom Transfer events, gas abuse in the transfer path.
import { Node, walk, collect, identifiers, isCallTo, calleeName, baseName, indexChain, isMsgSender, isTxOrigin, numberValue, snippet, line, endLine } from "./ast";
import { Contract, Func } from "./model";
import { Finding, Severity, Location } from "./types";
import { Ctx, transferGates, refsPair, paramNamed, refsExemption, privilegedSetters, feeStateVars, sellCond, refsIdent, valueFromParam, upperBound, TO_NAMES, FROM_NAMES, AMOUNT_NAMES } from "./rules";

function sn(ctx: Ctx, node: Node): string { return snippet(ctx.sources.get(node?.__file) ?? ctx.source, node); }
function loc(ctx: Ctx, node: Node, fn?: Func): Location {
  return { file: node?.__file ?? fn?.file ?? ctx.c.file, line: line(node), column: node?.loc?.start?.column ?? 0, endLine: endLine(node), contract: fn?.contract ?? ctx.c.name, function: fn?.name, snippet: sn(ctx, node) };
}
function mk(ctx: Ctx, id: string, title: string, severity: Severity, confidence: number, node: Node, fn: Func | undefined, evidence: string, reasoning: string, related?: Location[]): Finding {
  return { id, title, severity, confidence, location: loc(ctx, node, fn), evidence, reasoning, related };
}
const isBlockTime = (n: Node) => n?.type === "MemberAccess" && /^(timestamp|number)$/.test(n.memberName) && n.expression?.type === "Identifier" && n.expression.name === "block" || (n?.type === "Identifier" && n.name === "now");
const isBalanceRead = (c: Contract, n: Node) => (n?.type === "IndexAccess" && c.balanceVars.has(baseName(n) ?? "")) || (n?.type === "FunctionCall" && calleeName(n) === "balanceOf");
function exemptContext(c: Contract, g: { cond: Node; enclosing: Node[] }): boolean { return refsExemption(c, g.cond) || g.enclosing.some((e) => refsExemption(c, e)); }

// ---------------------------------------------------------------- 1. cannot sell all
export function ruleCannotSellAll(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const g of transferGates(c)) {
    if (g.kind === "if") continue;
    const amt = paramNamed(g.fn, AMOUNT_NAMES, 2);
    let hit: Node | null = null;
    walk(g.cond, (n) => {
      if (n.type !== "BinaryOperation") return;
      // amount < balance  (strict)  |  balance - amount >= K  |  balance - amount > 0
      if (n.operator === "<" && refsIdent(n.left, amt) && isBalanceRead(c, n.right)) hit = n;
      if (n.operator === ">" && refsIdent(n.right, amt) && isBalanceRead(c, n.left)) hit = n;
      if ((n.operator === ">=" || n.operator === ">") && n.left?.type === "BinaryOperation" && n.left.operator === "-" && isBalanceRead(c, n.left.left) && refsIdent(n.left.right, amt) && !(n.right?.type === "NumberLiteral" && Number(n.right.number) === 0 && n.operator === ">=")) hit = n;
    });
    if (!hit) continue;
    const sell = sellCond(c, g.fn, g.cond) || g.enclosing.some((e) => sellCond(c, g.fn, e));
    const asym = exemptContext(c, g);
    out.push(mk(ctx, "CANNOT_SELL_ALL", `A holder can never ${sell ? "sell" : "move"} their whole balance`, sell || asym ? "high" : "medium", 0.8, hit, g.fn, sn(ctx, hit),
      `The transfer path rejects any amount equal to the sender's full balance${sell ? " when the recipient is the pair" : ""}. Wallets and routers that 'sell max' revert, the last unit is trapped forever, and scanners that simulate 'sell all' flag the token - which is exactly why the deployer adds this line.${asym ? " The owner / exempt addresses are not subject to it." : ""}`));
  }
  return out;
}

// ---------------------------------------------------------------- 2. per-holder cooldown on the transfer path
export function ruleCooldownGate(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  // mapping(address => uint) written with block.timestamp / block.number on the transfer path
  const stamps = new Set<string>();
  for (const fname of c.transferPath) {
    const f = c.functions.get(fname); if (!f) continue;
    for (const w of f.writes) { const sv = c.stateVars.get(w.base); if (sv?.isMapping && w.value && collect(w.value, isBlockTime).length) stamps.add(w.base); }
  }
  if (!stamps.size) return out;
  for (const g of transferGates(c)) {
    if (g.kind === "if") continue;
    const ids = identifiers(g.cond);
    const st = [...stamps].find((s) => ids.includes(s));
    if (!st || !collect(g.cond, isBlockTime).length) continue;
    // the cooldown length: a state var compared/added in the condition
    const lens = ids.filter((i) => i !== st && c.stateVars.has(i) && !c.stateVars.get(i)!.isMapping && !c.stateVars.get(i)!.isConstant);
    const settable = lens.map((l) => ({ l, s: privilegedSetters(c, l).filter(({ fn, w }) => valueFromParam(fn, w)) })).find((x) => x.s.length);
    const bounded = settable ? upperBound(c, settable.s[0].fn, [settable.l, ...settable.s[0].fn.params]) !== "unbounded" : true;
    const sell = sellCond(c, g.fn, g.cond) || g.enclosing.some((e) => sellCond(c, g.fn, e));
    const asym = exemptContext(c, g);
    if (settable && !bounded) {
      out.push(mk(ctx, "COOLDOWN_GATE", `Per-holder ${sell ? "sell " : ""}cooldown '${settable.l}' that the owner can set to any length`, "critical", 0.8, g.node, g.fn, `${sn(ctx, g.cond)}  |  ${settable.l} set in ${settable.s[0].fn.name}() without a cap`,
        `Each address must wait ${settable.l} after its last transfer. The setter has no upper bound, so the owner can make the wait effectively infinite after launch - a sell block that reads like anti-bot protection.${asym ? " The owner / exempt addresses are not subject to it." : ""}`, [loc(ctx, settable.s[0].w.node, settable.s[0].fn)]));
    } else if (asym || sell) {
      out.push(mk(ctx, "COOLDOWN_GATE", `Per-holder ${sell ? "sell " : ""}cooldown${asym ? " that exempts the owner" : ""}`, asym ? "high" : "medium", 0.7, g.node, g.fn, sn(ctx, g.cond),
        `Holders are rate-limited on ${sell ? "sells" : "transfers"} by a per-address timestamp; ${asym ? "the owner / exempt addresses are not, which makes the limit asymmetric." : "the window is fixed, so this is throttling rather than a lock."}`));
    } else {
      out.push(mk(ctx, "COOLDOWN_GATE", "Fixed per-holder transfer cooldown (applies to everyone)", "low", 0.7, g.node, g.fn, sn(ctx, g.cond), `A constant cooldown between transfers per address. Symmetric availability constraint; noted for completeness.`));
    }
  }
  return out;
}

// ---------------------------------------------------------------- 3. buy block (from == pair) under a privileged switch
export function ruleBuyBlock(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const g of transferGates(c)) {
    if (g.kind === "if") continue;
    const from = paramNamed(g.fn, FROM_NAMES, 0);
    let buy = false;
    const scan = (e: Node) => walk(e, (n) => {
      if (n.type === "BinaryOperation" && n.operator === "==") { const other = refsPair(c, n.left) ? n.right : refsPair(c, n.right) ? n.left : null; if (other && refsIdent(other, from)) buy = true; }
      if (n.type === "IndexAccess" && refsPair(c, n.base) && refsIdent(n.index, from)) buy = true;
    });
    scan(g.cond); for (const e of g.enclosing) scan(e);
    if (!buy || sellCond(c, g.fn, g.cond) || g.enclosing.some((e) => sellCond(c, g.fn, e))) continue;
    const ids = identifiers(g.cond).filter((i) => c.stateVars.has(i) && !c.stateVars.get(i)!.isConstant && !c.pairVars.has(i) && !c.pairMaps.has(i));
    const sw = ids.map((i) => ({ i, s: privilegedSetters(c, i) })).find((x) => x.s.length);
    if (!sw) continue;
    out.push(mk(ctx, "BUY_BLOCK", `Buys from the pair can be switched off via '${sw.i}'`, "medium", 0.7, g.node, g.fn, `${sn(ctx, g.cond)}  |  ${sw.i} written in ${sw.s[0].fn.name}()`,
      `A privileged flag gates transfers whose sender is the liquidity pair (buys). Combined with a working sell path this is a 'liquidity pool block': the owner decides when the market is open. On its own it locks nobody's funds, hence medium.`, [loc(ctx, sw.s[0].w.node, sw.s[0].fn)]));
  }
  return out;
}

// ---------------------------------------------------------------- 4. EOA-only gate on the transfer path (blocks router / pair calls)
export function ruleEoaOnlyGate(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const isEoaCheck = (n: Node) => (n.type === "BinaryOperation" && (n.operator === "==" || n.operator === "!=") && ((isMsgSender(n.left) && isTxOrigin(n.right)) || (isMsgSender(n.right) && isTxOrigin(n.left))))
    || (n.type === "FunctionCall" && /^(isContract|_isContract|isEOA|hasCode|_hasCode)$/i.test(calleeName(n) ?? ""))
    || (n.type === "MemberAccess" && n.memberName === "length" && n.expression?.type === "MemberAccess" && n.expression.memberName === "code")
    || (n.type === "AssemblyCall" && n.functionName === "extcodesize");
  for (const g of transferGates(c)) {
    if (g.kind === "if") continue;
    if (!collect(g.cond, isEoaCheck).length) continue;
    const sell = sellCond(c, g.fn, g.cond) || g.enclosing.some((e) => sellCond(c, g.fn, e));
    const asym = exemptContext(c, g) || g.enclosing.some((e) => identifiers(e).some((i) => c.ownerVars.has(i)));
    out.push(mk(ctx, "EOA_ONLY_GATE", sell ? "Sells are rejected unless the caller is an externally-owned account" : "Transfers are rejected when the caller is a contract", asym ? "critical" : sell ? "high" : "medium", asym ? 0.85 : 0.7, g.node, g.fn, sn(ctx, g.cond),
      `On a DEX every trade is executed by the router or the pair - both contracts - so an 'EOA only' check on the transfer path ${sell ? "makes selling through the pool impossible" : "makes pool trades revert"} while wallet-to-wallet transfers still work and the code reads like anti-bot protection.${asym ? " Owner / exempt addresses bypass it, so the deployer still trades." : ""}`));
  }
  return out;
}

// ---------------------------------------------------------------- 5. per-address fee map fed by a privileged setter
export function rulePersonalFee(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  // uint mappings read on the transfer path whose value reaches * or / arithmetic (directly or through a local)
  const feeMaps = new Set<string>();
  for (const fname of c.transferPath) {
    const f = c.functions.get(fname); if (!f?.node.body) continue;
    const localFrom = new Map<string, Set<string>>();
    const mapsIn = (e: Node) => new Set(collect(e, (x) => x.type === "IndexAccess").map((x) => baseName(x)!).filter((b) => c.stateVars.get(b)?.isMapping && /^u?int/.test(c.stateVars.get(b)!.valueType ?? "")));
    walk(f.node.body, (n) => {
      if (n.type === "VariableDeclarationStatement" && n.variables?.[0]?.name && n.initialValue) localFrom.set(n.variables[0].name, mapsIn(n.initialValue));
      if (n.type === "BinaryOperation" && n.operator === "=" && n.left?.type === "Identifier" && !c.stateVars.has(n.left.name)) localFrom.set(n.left.name, mapsIn(n.right));
    });
    walk(f.node.body, (n) => {
      const arith = (n.type === "BinaryOperation" && (n.operator === "*" || n.operator === "/")) || isCallTo(n, ["mul", "div"]);
      if (!arith) return;
      for (const m of mapsIn(n)) feeMaps.add(m);
      for (const i of identifiers(n)) for (const m of localFrom.get(i) ?? []) feeMaps.add(m);
    });
  }
  for (const v of c.stateVars.values()) {
    if (!v.isMapping || !/^u?int/.test(v.valueType ?? "") || !feeMaps.has(v.name) || c.balanceVars.has(v.name) || c.allowanceVars.has(v.name)) continue;
    const setters = privilegedSetters(c, v.name).filter(({ fn, w }) => indexChain(w.target).some((ix) => identifiers(ix).some((p) => fn.params.includes(p))));
    if (!setters.length) continue;
    const s = setters[0];
    const bound = upperBound(c, s.fn, [v.name, ...s.fn.params]);
    out.push(mk(ctx, "PERSONAL_FEE", `Owner can set a fee for a specific address via '${s.fn.name}()'${bound === "unbounded" ? " with no cap" : ""}`, bound === "unbounded" ? "critical" : "high", 0.8, s.w.node, s.fn, `${sn(ctx, s.w.node)} [${s.fn.privilegeReason}]; ${v.name} feeds the transfer arithmetic`,
      `The fee applied on the transfer path is looked up per address, and a privileged function writes that mapping for any address. The owner can tax one holder at 100 % while everybody else sees the advertised rate - a targeted honeypot that global-fee scanners never see.`));
  }
  return out;
}

// ---------------------------------------------------------------- 6. phantom Transfer: event without any balance movement
export function rulePhantomTransfer(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  if (!c.balanceVars.size) return out;
  const movesBalance = (f: Func, seen = new Set<string>()): boolean => {
    if (seen.has(f.name)) return false; seen.add(f.name);
    if (f.writes.some((w) => c.balanceVars.has(w.base))) return true;
    if ([...f.calls].some((x) => /^_?(mint|burn)$/i.test(x))) return true;
    if (f.callsSuper) return true;
    return [...f.calls].some((x) => { const g = c.functions.get(x); return !!g && movesBalance(g, seen); });
  };
  for (const fname of ["transfer", "transferFrom"]) {
    const f = c.functions.get(fname);
    if (!f?.node.body || f.visibility === "internal" || f.visibility === "private") continue;
    const emits = collect(f.node.body, (n) => n.type === "EmitStatement" && /Transfer$/.test(calleeName(n.eventCall) ?? ""));
    if (!emits.length || movesBalance(f)) continue;
    out.push(mk(ctx, "PHANTOM_TRANSFER", `'${f.name}()' emits Transfer but moves no balance`, "critical", 0.85, emits[0], f, sn(ctx, emits[0]),
      `The function logs a Transfer event so explorers and wallets show a successful transfer, but neither it nor anything it calls writes the balance mapping. Tokens never move; the log is the product.`));
  }
  return out;
}

// ---------------------------------------------------------------- 7. gas abuse on the transfer path
export function ruleGasAbuse(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const fname of c.coreTransferPath) {
    const f = c.functions.get(fname); if (!f?.node.body) continue;
    walk(f.node.body, (n) => {
      if (n.type === "NewExpression" && n.typeName?.type === "UserDefinedTypeName") out.push(mk(ctx, "GAS_ABUSE", `Transfer path deploys a contract on every call ('new' in ${f.name}())`, "high", 0.75, n, f, sn(ctx, n), `Creating a contract inside the transfer path burns the caller's gas for the deployer's benefit (gas-token minting, CREATE2 tricks). No token needs to deploy code to move a balance.`));
      if (n.type === "AssemblyCall" && /^create2?$/.test(n.functionName)) out.push(mk(ctx, "GAS_ABUSE", `Transfer path runs CREATE in assembly (${f.name}())`, "high", 0.75, n, f, sn(ctx, n), `Contract creation inside the transfer path spends the caller's gas on something unrelated to the transfer - the classic gas-token / gas-griefing abuse.`));
      if (n.type === "FunctionCall" && n.expression?.type === "MemberAccess" && /^(mint|free|freeUpTo|freeFrom|freeFromUpTo)$/.test(n.expression.memberName) && n.expression.expression?.type !== "Identifier" || (n.type === "FunctionCall" && n.expression?.type === "MemberAccess" && /^(mint|free|freeUpTo)$/.test(n.expression.memberName) && n.expression.expression?.type === "Identifier" && c.stateVars.has(n.expression.expression.name) && /^(address|I|CHI|GST)/.test(c.stateVars.get(n.expression.expression.name)!.typeStr)))
        out.push(mk(ctx, "GAS_ABUSE", `Transfer path calls an external mint/free (gas token) in ${f.name}()`, "high", 0.7, n, f, sn(ctx, n), `A gas-token style call (CHI / GST2 mint or free) inside the transfer path makes every holder pay extra gas that accrues to the deployer.`));
    });
  }
  return out;
}

export const RULES3 = [ruleCannotSellAll, ruleCooldownGate, ruleBuyBlock, ruleEoaOnlyGate, rulePersonalFee, rulePhantomTransfer, ruleGasAbuse];
