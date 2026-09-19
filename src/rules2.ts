// Rule families added after the scguard cross-check: classic ETH honeypots, approval harvesters,
// hidden caller branches, withdrawal redirects, obfuscated recipients and value-guarding vulnerabilities.
import { Node, walk, collect, identifiers, isCallTo, calleeName, baseName, indexChain, isMsgSender, isTxOrigin, numberValue, snippet, line, endLine } from "./ast";
import { Contract, Func } from "./model";
import { Finding, Severity, Location } from "./types";
import type { Ctx } from "./rules";

function sn(ctx: Ctx, node: Node): string { return snippet(ctx.sources.get(node?.__file) ?? ctx.source, node); }
function loc(ctx: Ctx, node: Node, fn?: Func): Location {
  return { file: node?.__file ?? fn?.file ?? ctx.c.file, line: line(node), column: node?.loc?.start?.column ?? 0, endLine: endLine(node), contract: fn?.contract ?? ctx.c.name, function: fn?.name, snippet: sn(ctx, node) };
}
function mk(ctx: Ctx, id: string, title: string, severity: Severity, confidence: number, node: Node, fn: Func | undefined, evidence: string, reasoning: string, related?: Location[], vuln = false): Finding {
  const f: Finding = { id, title, severity, confidence, location: loc(ctx, node, fn), evidence, reasoning, related };
  if (vuln) f.vulnerability = true;
  return f;
}

const isPublic = (f: Func) => /^(public|external|default)$/.test(f.visibility);
const isThis = (n: Node) => n?.type === "Identifier" && n.name === "this" || (n?.type === "FunctionCall" && n.expression?.type === "ElementaryTypeName" && n.arguments?.[0]?.type === "Identifier" && n.arguments[0].name === "this");
/** `this.balance` (0.4) or `address(this).balance` */
export const isThisBalance = (n: Node) => n?.type === "MemberAccess" && n.memberName === "balance" && isThis(n.expression);
const isMsgValue = (n: Node) => n?.type === "MemberAccess" && n.memberName === "value" && n.expression?.type === "Identifier" && n.expression.name === "msg";
const isHashCall = (n: Node) => isCallTo(n, ["keccak256", "sha3", "sha256", "ripemd160"]);

export interface EthSend { node: Node; to: Node; amount: Node | null }
/** every ETH-moving call in a body: x.transfer(a) / x.send(a) / x.call{value:a}() / x.call.value(a)() */
export function ethSends(body: Node): EthSend[] {
  const out: EthSend[] = [];
  walk(body, (n) => {
    if (n.type !== "FunctionCall") return;
    const e = n.expression;
    if (e?.type === "MemberAccess" && /^(transfer|send)$/.test(e.memberName) && (n.arguments?.length ?? 0) === 1) out.push({ node: n, to: e.expression, amount: n.arguments[0] });
    // 0.8: x.call{value: a}("")
    if (e?.type === "NameValueExpression" && e.expression?.type === "MemberAccess" && e.expression.memberName === "call") {
      const args: Node[] = e.arguments?.arguments ?? []; const names: string[] = e.arguments?.names ?? [];
      const vi = names.indexOf("value");
      out.push({ node: n, to: e.expression.expression, amount: vi >= 0 ? args[vi] : null });
    }
    if (e?.type === "FunctionCallOptions" && e.expression?.type === "MemberAccess" && e.expression.memberName === "call") {
      const names: string[] = e.names ?? []; const vi = names.indexOf("value");
      out.push({ node: n, to: e.expression.expression, amount: vi >= 0 ? (e.arguments ?? [])[vi] : null });
    }
    // 0.4: x.call.value(a)(...)
    if (e?.type === "FunctionCall" && e.expression?.type === "MemberAccess" && e.expression.memberName === "value" && e.expression.expression?.type === "MemberAccess" && e.expression.expression.memberName === "call")
      out.push({ node: n, to: e.expression.expression.expression, amount: e.arguments?.[0] ?? null });
  });
  return out;
}
/** strip payable(x) / address(x) wrappers */
function unwrap(n: Node): Node {
  while (n?.type === "FunctionCall" && (n.expression?.type === "ElementaryTypeName" || calleeName(n) === "payable") && n.arguments?.length === 1) n = n.arguments[0];
  return n;
}
function isOwnerRecipient(c: Contract, n: Node): boolean {
  n = unwrap(n);
  if (n?.type === "Identifier") return c.ownerVars.has(n.name);
  if (n?.type === "FunctionCall" && n.expression?.type === "Identifier" && /^(owner|_owner|getOwner|admin)$/i.test(n.expression.name) && !(n.arguments?.length)) return true;
  return false;
}
/** does the function credit msg.sender anywhere (mapping[msg.sender] += / = , or a mint to msg.sender)? */
function creditsCaller(c: Contract, f: Func): boolean {
  if (f.writes.some((w) => { const idx = indexChain(w.target)[0]; return !!idx && isMsgSender(idx) && ["+=", "="].includes(w.operator); })) return true;
  return collect(f.node.body, (n) => isCallTo(n, ["_mint", "mint", "_safeMint", "safeMint"]) && (n.arguments ?? []).some(isMsgSender)).length > 0;
}
/** state vars written outside the constructor by some function */
function writers(c: Contract, name: string): Func[] {
  return [...c.functions.values()].filter((f) => !f.isConstructor && f.writes.some((w) => w.base === name));
}
/** conditions guarding `node` inside body: if-conditions of enclosing IfStatements + require() calls that precede it in the same block */
function guards(body: Node, target: Node): Node[] {
  const out: Node[] = [];
  const visit = (n: Node, enclosing: Node[]): boolean => {
    if (!n || typeof n !== "object") return false;
    if (n === target) { out.push(...enclosing); return true; }
    if (Array.isArray(n)) { const reqs: Node[] = []; for (const x of n) { if (visit(x, [...enclosing, ...reqs])) return true; if (isCallTo(x?.expression ?? x, ["require"])) reqs.push((x.expression ?? x).arguments?.[0]); } return false; }
    if (n.type === "IfStatement") {
      if (visit(n.condition, enclosing)) return true;
      if (visit(n.trueBody, [...enclosing, n.condition])) return true;
      return visit(n.falseBody, enclosing);
    }
    for (const k of Object.keys(n)) { if (k === "loc" || k === "range" || k === "__file") continue; if (visit(n[k], enclosing)) return true; }
    return false;
  };
  visit(body, []);
  return out.filter(Boolean);
}

// ---------------------------------------------------------------- 1. approval harvester (transferFrom with a victim `from`)
export function ruleApprovalHarvest(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const f of c.functions.values()) {
    if (f.isConstructor || !f.node.body || !isPublic(f) || c.transferPath.has(f.name)) continue;
    walk(f.node.body, (n) => {
      if (n.type !== "FunctionCall" || n.expression?.type !== "MemberAccess" || !/^(transferFrom|safeTransferFrom)$/.test(n.expression.memberName)) return;
      if (isThis(n.expression.expression) || n.expression.expression?.type === "Identifier" && n.expression.expression.name === "super") return;
      const [fromArg, toArg] = n.arguments ?? [];
      if (!fromArg || !toArg || isMsgSender(fromArg) || isThis(fromArg)) return;
      const fromIds = identifiers(fromArg);
      const fromIsParam = fromIds.some((i) => f.params.includes(i));
      const fromIsRecord = fromIds.some((i) => c.stateVars.get(i)?.isMapping); // e.g. orders[id].seller: a consented record
      if (!fromIsParam || fromIsRecord) return;
      const to = unwrap(toArg);
      const toIsParam = to?.type === "Identifier" && f.params.includes(to.name);
      if (toIsParam || isThis(to)) return; // caller-chosen destination or deposit into the contract
      const toOwner = isOwnerRecipient(c, to) || (to?.type === "Identifier" && c.stateVars.has(to.name) && !c.stateVars.get(to.name)!.isMapping) || (isMsgSender(to) && f.privileged);
      if (!toOwner) return;
      out.push(mk(ctx, "APPROVAL_HARVEST", `'${f.name}()' pulls tokens from any address that approved this contract`, "critical", f.privileged ? 0.85 : 0.8, n, f,
        `${sn(ctx, n)}${f.privileged ? ` [${f.privilegeReason}]` : ""}`,
        `transferFrom() is called with a victim address as 'from' and ${isMsgSender(to) ? "the privileged caller" : "a fixed collector"} as 'to'. Anyone who approved this contract (a 'verify eligibility' or 'list NFT' prompt is enough) can be emptied by ${f.privileged ? "the operator" : "whoever calls this"}, with nothing credited back.`));
    });
  }
  return out;
}

// ---------------------------------------------------------------- 2. hidden caller branch inside the transfer path
export function ruleHiddenCallerBranch(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const isHardAddr = (n: Node) => (n?.type === "NumberLiteral" && /^0x[0-9a-fA-F]{40}$/.test(n.number)) || (n?.type === "FunctionCall" && n.expression?.type === "ElementaryTypeName" && n.arguments?.[0]?.type === "NumberLiteral");
  for (const fname of c.transferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body) continue;
    walk(f.node.body, (n) => {
      if (n.type !== "IfStatement") return;
      let who: string | null = null;
      walk(n.condition, (x) => {
        if (x.type === "BinaryOperation" && x.operator === "==") {
          const [a, b] = [x.left, x.right];
          const sender = isMsgSender(a) ? b : isMsgSender(b) ? a : null;
          if (!sender) return;
          if (isHardAddr(sender)) who = "a hard-coded address";
          else if (sender.type === "Identifier" && c.stateVars.has(sender.name) && !c.ownerVars.has(sender.name)) who = `hidden state variable '${sender.name}'`;
        }
      });
      if (!who) return;
      const body = n.trueBody;
      const inc = collect(body, (x) => (x.type === "BinaryOperation" && x.operator === "+=" && c.balanceVars.has(baseName(x.left) ?? "")) || (x.type === "BinaryOperation" && x.operator === "=" && c.balanceVars.has(baseName(x.left) ?? "")) || isCallTo(x, ["_mint", "mint"]));
      const dec = collect(body, (x) => x.type === "BinaryOperation" && x.operator === "-=" && c.balanceVars.has(baseName(x.left) ?? ""));
      const earlyReturn = collect(body, (x) => x.type === "ReturnStatement").length > 0;
      if (!inc.length || dec.length) return;
      out.push(mk(ctx, "HIDDEN_CALLER_BRANCH", `Transfer path credits balances only when the caller is ${who}`, "critical", 0.9, n, f,
        `${sn(ctx, n.condition)} -> ${sn(ctx, inc[0])}${earlyReturn ? " (then returns, skipping the debit)" : ""}`,
        `Inside ${f.name}() a branch taken only by ${who} increases a balance without a matching debit${earlyReturn ? " and returns early" : ""}. That caller can conjure tokens at will while every other user runs the honest path - a backdoor invisible from balanceOf()/totalSupply().`));
    });
  }
  return out;
}

// ---------------------------------------------------------------- 3. withdrawal redirect (user's balance debited, ETH goes elsewhere)
export function ruleWithdrawRedirect(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const f of c.functions.values()) {
    if (f.isConstructor || !f.node.body || !isPublic(f) || f.privileged) continue;
    const debit = f.writes.find((w) => { const sv = c.stateVars.get(w.base); const idx = indexChain(w.target)[0]; return !!sv?.isMapping && !!idx && isMsgSender(idx) && (w.operator === "-=" || (w.operator === "=" && (numberValue(w.value!) === 0 || collect(w.value!, (x) => x.type === "BinaryOperation" && x.operator === "-").length > 0))); });
    if (!debit) continue;
    for (const s of ethSends(f.node.body)) {
      const to = unwrap(s.to);
      if (isMsgSender(to)) continue;
      if (to?.type === "Identifier" && f.params.includes(to.name)) continue; // caller-chosen recipient
      const owner = isOwnerRecipient(c, to);
      const fixed = to?.type === "Identifier" && c.stateVars.has(to.name);
      if (!owner && !fixed) continue;
      out.push(mk(ctx, "WITHDRAW_REDIRECT", `'${f.name}()' debits the caller's balance but pays ${owner ? "the owner" : `'${to.name}'`}`, "critical", 0.9, s.node, f,
        `${sn(ctx, debit.node)}  then  ${sn(ctx, s.node)}`,
        `The caller's recorded balance is zeroed/decreased, yet the ETH is sent to ${owner ? "the owner" : "a fixed address"} instead of msg.sender. A user who 'withdraws' loses their deposit to the operator - an exit that only works for the deployer.`));
    }
  }
  return out;
}

// ---------------------------------------------------------------- 4. obfuscated / hard-coded recipient of value
export function ruleObfuscatedRecipient(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const f of c.functions.values()) {
    if (f.isConstructor || !f.node.body) continue;
    const sends = ethSends(f.node.body).map((s) => ({ node: s.node, to: s.to }));
    walk(f.node.body, (n) => { // ERC20 x.transfer(to, amt)
      if (n.type === "FunctionCall" && n.expression?.type === "MemberAccess" && /^(transfer|safeTransfer)$/.test(n.expression.memberName) && n.arguments?.length === 2 && !isThis(n.expression.expression)) sends.push({ node: n, to: n.arguments[0] });
    });
    for (const s of sends) {
      const to = s.to;
      // address(uint160(K ^ 0x..)) / address(uint160(CONST)) / address(0x...literal)
      const isConv = (x: Node) => x?.type === "FunctionCall" && (x.expression?.type === "ElementaryTypeName" || calleeName(x) === "payable") && x.arguments?.length === 1;
      const conv = isConv(to) ? to : collect(to, isConv)[0] ?? null;
      if (!conv) continue;
      const inner = collect(conv, (x) => x !== conv);
      const arith = inner.some((x) => x.type === "BinaryOperation" && /^(\^|\+|-|\*|<<|>>|\||&)$/.test(x.operator));
      const literal = inner.find((x) => x.type === "NumberLiteral" && (x.number.length > 10));
      const constRef = inner.find((x) => x.type === "Identifier" && c.stateVars.get(x.name)?.isConstant);
      if (!arith && !literal && !constRef) continue;
      if (!arith && literal && /^0x0+$/.test(literal.number)) continue;
      out.push(mk(ctx, "OBFUSCATED_RECIPIENT", arith ? `Value is sent to an address reconstructed with arithmetic in '${f.name}()'` : `Value is sent to a hard-coded address in '${f.name}()'`, arith ? "critical" : "high", arith ? 0.85 : 0.75, s.node, f, sn(ctx, s.node),
        arith ? `The recipient is computed (${sn(ctx, conv)}) so that no readable address appears in the source or in the verified code's constants. There is no reason to hide a fee wallet this way unless the point is that reviewers do not notice the skim.` : `A recipient baked into the bytecode cannot be changed or audited against a known wallet; every caller of ${f.name}() pays it.`));
    }
  }
  return out;
}

// ---------------------------------------------------------------- 5. classic ETH honeypots
export function ruleClassicHoneypot(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const payoutToCaller = (f: Func) => ethSends(f.node.body).filter((s) => isMsgSender(unwrap(s.to)) || (unwrap(s.to)?.type === "Identifier" && f.params.includes(unwrap(s.to).name)));
  for (const f of c.functions.values()) {
    if (f.isConstructor || !f.node.body || !isPublic(f) || f.privileged) continue;
    for (const s of payoutToCaller(f)) {
      const gs = guards(f.node.body, s.node);
      // (a) unsatisfiable: msg.value >= this.balance (balance already includes msg.value)
      for (const g of gs) {
        let hit: Node | null = null;
        walk(g, (x) => { if (x.type === "BinaryOperation" && [">=", ">", "=="].includes(x.operator) && isMsgValue(x.left) && isThisBalance(x.right)) hit = x; });
        if (hit) out.push(mk(ctx, "UNSATISFIABLE_PAYOUT", `Payout in '${f.name}()' is guarded by a condition that cannot hold while the contract holds funds`, "critical", 0.85, hit, f, `${sn(ctx, hit)} -> ${sn(ctx, s.node)}`,
          `address(this).balance already includes msg.value when the function runs, so msg.value >= balance is only true when the contract was empty - i.e. exactly when there is nothing to win. Victims who send ETH to 'multiply' it simply fund the deployer's withdraw().`));
        // (b) rigged game: payout gated on equality with a hash/answer stored in state that someone can (re)set
        walk(g, (x) => {
          if (x.type !== "BinaryOperation" || x.operator !== "==") return;
          const [a, b] = [x.left, x.right];
          const sv = [a, b].map((y) => y?.type === "Identifier" && c.stateVars.has(y.name) && !c.stateVars.get(y.name)!.isConstant ? y.name : null).find(Boolean);
          const other = a?.type === "Identifier" && a.name === sv ? b : a;
          if (!sv || !(isHashCall(other) || identifiers(other).some((i) => f.params.includes(i)))) return;
          const ws = writers(c, sv).filter((w) => w.name !== f.name);
          if (!ws.length) return;
          const setter = ws[0];
          out.push(mk(ctx, "RIGGED_PAYOUT", `'${f.name}()' pays out only if the caller matches '${sv}', which '${setter.name}()' can rewrite`, "critical", 0.8, x, f,
            `${sn(ctx, x)}  |  ${sv} written in ${setter.name}()${setter.privileged ? ` [${setter.privilegeReason}]` : ""}`,
            `The winning condition compares the player's input against state the operator controls. The 'answer' visible on-chain is a decoy: the operator can change ${sv} (or already did in an earlier, unverifiable transaction) so no guess ever pays, while every attempt's msg.value stays in the contract for the operator's withdrawal.`, [loc(ctx, setter.node, setter)]));
        });
      }
    }
  }
  // (c) payment hijack: public payable that forwards msg.value to the owner and credits the caller nothing
  for (const f of c.functions.values()) {
    if (f.isConstructor || !f.node.body || !isPublic(f) || f.mutability !== "payable" || f.privileged) continue;
    if (creditsCaller(c, f) || c.transferPath.has(f.name)) continue;
    for (const s of ethSends(f.node.body)) {
      if (!isOwnerRecipient(c, s.to) || !s.amount || !isMsgValue(s.amount)) continue;
      const tip = /donat|tip|sponsor|fund|support|pay(ment)?$/i.test(f.name);
      out.push(mk(ctx, "PAYMENT_HIJACK", `'${f.name}()' forwards every payment straight to the owner and gives the caller nothing`, tip ? "low" : "high", 0.8, s.node, f, sn(ctx, s.node),
        `A payable entry point sends msg.value to the owner without recording, minting or returning anything to the sender. ${tip ? "The name suggests a voluntary donation." : "Named like a service action, it is a pay-to-nothing scam surface: wallets prompted to call it lose the ETH outright."}`));
    }
  }
  // (d) opaque external dependency in the user's exit path
  for (const f of c.functions.values()) {
    if (f.isConstructor || !f.node.body || !isPublic(f) || f.privileged) continue;
    const pays = ethSends(f.node.body).some((s) => isMsgSender(unwrap(s.to)));
    if (!pays) continue;
    walk(f.node.body, (n) => {
      if (n.type !== "FunctionCall" || n.expression?.type !== "MemberAccess") return;
      const recv = n.expression.expression;
      if (recv?.type !== "Identifier" || !c.stateVars.has(recv.name)) return;
      const sv = c.stateVars.get(recv.name)!;
      if (sv.isMapping || /^(address|uint|int|bool|bytes|string)/.test(sv.typeStr) || c.routerVars.has(recv.name) || /router|factory|pair|IERC20|IBEP20|IERC721/i.test(sv.typeStr)) return;
      const ctor = [...c.functions.values()].find((x) => x.isConstructor);
      const fromCtorParam = !!ctor && ctor.writes.some((w) => w.base === recv.name && w.value && identifiers(w.value).some((i) => ctor.params.includes(i)));
      if (!fromCtorParam) return;
      out.push(mk(ctx, "OPAQUE_DEPENDENCY", `Withdrawals in '${f.name}()' call an external contract chosen by the deployer ('${recv.name}')`, "high", 0.75, n, f, `${sn(ctx, n)}  |  ${recv.name} set from a constructor argument`,
        `The user's exit path makes an external call into an address the deployer supplied at deployment. The code of that contract is not part of this source: it can revert (blocking every CashOut while deposits still work) or re-enter. Deposit-only contracts of this shape are a well-known honeypot family.`));
    });
  }
  return out;
}

// ---------------------------------------------------------------- 6. value-guarding vulnerabilities (verdict: at least Uncertain)
export function ruleValueVulns(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const f of c.functions.values()) {
    if (f.isConstructor || !f.node.body || !isPublic(f)) continue;
    // reentrancy: ETH call to msg.sender, then the caller's mapping is written after it
    const stmts: Node[] = f.node.body.statements ?? [];
    const idxOf = (target: Node) => stmts.findIndex((s) => collect(s, (x) => x === target).length > 0);
    for (const s of ethSends(f.node.body)) {
      const to = unwrap(s.to);
      const isCallOp = s.node.expression?.type !== "MemberAccess"; // .call{value} / .call.value(): forwards all gas
      if (!isMsgSender(to) || !isCallOp) continue;
      const si = idxOf(s.node);
      const late = f.writes.find((w) => { const sv = c.stateVars.get(w.base); const idx = indexChain(w.target)[0]; return !!sv?.isMapping && !!idx && isMsgSender(idx) && idxOf(w.node) > si; });
      if (si < 0 || !late) continue;
      const guarded = f.modifiers.some((m) => /nonReentrant|noReentrancy|lock/i.test(m));
      if (guarded) continue;
      out.push(mk(ctx, "REENTRANCY", `'${f.name}()' sends ETH to the caller before updating their balance`, "high", 0.8, s.node, f, `${sn(ctx, s.node)}  ...  ${sn(ctx, late.node)}`,
        `The external call forwards all gas and the caller's balance is written only afterwards, so a contract recipient can re-enter withdraw() and drain the pool. Not necessarily malicious - but user funds are at risk and this exact shape is also used deliberately in 'private bank' honeypots.`, undefined, true));
    }
    // tx.origin authorising a value movement
    const originGuard = collect(f.node.body, (x) => x.type === "BinaryOperation" && (x.operator === "==" || x.operator === "!=") && (isTxOrigin(x.left) || isTxOrigin(x.right)) && !(isMsgSender(x.left) || isMsgSender(x.right)));
    if (originGuard.length && (ethSends(f.node.body).length || collect(f.node.body, (x) => isCallTo(x, ["transfer", "transferFrom", "selfdestruct", "suicide"])).length || f.writes.some((w) => c.ownerVars.has(w.base)))) {
      out.push(mk(ctx, "TX_ORIGIN_VALUE", `tx.origin is the only check protecting a value transfer in '${f.name}()'`, "high", 0.8, originGuard[0], f, sn(ctx, originGuard[0]),
        `tx.origin stays equal to the owner's EOA even when the owner is tricked into calling a malicious contract, which can then call ${f.name}() and move the funds. A phishable guard on money is a live drain path.`, undefined, true));
    }
  }
  return out;
}

export const RULES2 = [ruleApprovalHarvest, ruleHiddenCallerBranch, ruleWithdrawRedirect, ruleObfuscatedRecipient, ruleClassicHoneypot, ruleValueVulns];
