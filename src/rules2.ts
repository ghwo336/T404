// Rule families added after the scguard cross-check: classic ETH honeypots, approval harvesters,
// hidden caller branches, withdrawal redirects, obfuscated recipients and value-guarding vulnerabilities.
import { Node, walk, collect, identifiers, isCallTo, calleeName, baseName, indexChain, isMsgSender, isTxOrigin, numberValue, snippet, line, endLine } from "./ast";
import { Contract, Func } from "./model";
import { Finding, Severity, Location } from "./types";
import type { Ctx } from "./rules";
import { ruleTransferConservation } from "./conserve";

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

/** is the write to `v` inside f only reachable by an insider (privileged fn, or nested in `if (msg.sender == <state address>)`)? */
function insiderGate(c: Contract, f: Func, v: string): string | null {
  if (f.privileged) return f.privilegeReason;
  let reason: string | null = null;
  walk(f.node.body, (n) => {
    if (reason || n.type !== "IfStatement") return;
    let who: string | null = null;
    walk(n.condition, (x) => {
      if (x.type === "BinaryOperation" && x.operator === "==") {
        const other = isMsgSender(x.left) ? x.right : isMsgSender(x.right) ? x.left : null;
        if (other?.type === "Identifier" && c.stateVars.has(other.name) && !f.params.includes(other.name)) who = other.name;
      }
    });
    if (!who) return;
    const writesV = collect(n.trueBody, (x) => x.type === "BinaryOperation" && /=/.test(x.operator) && baseName(x.left) === v).length > 0;
    if (writesV) reason = `if(msg.sender == ${who})`;
  });
  return reason;
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
      // (b0) whole-balance payout to the caller gated on state that an insider-gated function can rewrite (gift/lottery traps)
      if (s.amount && isThisBalance(s.amount)) {
        const seen = new Set<string>();
        for (const g of gs) for (const v of identifiers(g)) {
          const sv = c.stateVars.get(v);
          if (!sv || sv.isConstant || seen.has(v)) continue;
          const ws = writers(c, v).filter((w) => w.name !== f.name && isPublic(w)).map((w) => ({ w, why: insiderGate(c, w, v) })).filter((x) => x.why);
          if (!ws.length) continue;
          seen.add(v);
          out.push(mk(ctx, "RIGGED_PAYOUT", `'${f.name}()' pays the whole balance only while '${v}' allows it - and '${ws[0].w.name}()' can change that at any time`, "high", 0.8, g, f,
            `${sn(ctx, g)}  |  ${v} written in ${ws[0].w.name}() [${ws[0].why}]`,
            `The exit condition depends on ${v}, which an insider-only function rewrites (a hidden state update the victim cannot see coming). The deposit side stays open, the payout side is under the insider's thumb - the classic 'gift'/'lottery' trap.`, [loc(ctx, ws[0].w.node, ws[0].w)]));
        }
      }
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
          const userSlot = other?.type === "IndexAccess" && isMsgSender(other.index) && c.stateVars.get(baseName(other) ?? "")?.isMapping && writers(c, baseName(other)!).some((w) => !w.privileged && isPublic(w));
          if (!sv || !(isHashCall(other) || identifiers(other).some((i) => f.params.includes(i)) || userSlot)) return;
          const ws = writers(c, sv).filter((w) => w.name !== f.name);
          const svNode = c.stateVars.get(sv)!.node;
          const secret = !ws.length && /^(private|internal)$/.test(svNode?.visibility ?? "") && [...c.functions.values()].some((g) => g.isConstructor && g.writes.some((w) => w.base === sv));
          if (!ws.length && !secret) return;
          if (ws.length) {
            const setter = ws[0];
            out.push(mk(ctx, "RIGGED_PAYOUT", `'${f.name}()' pays out only if the caller matches '${sv}', which '${setter.name}()' can rewrite`, "critical", 0.8, x, f,
              `${sn(ctx, x)}  |  ${sv} written in ${setter.name}()${setter.privileged ? ` [${setter.privilegeReason}]` : ""}`,
              `The winning condition compares the player's input against state the operator controls. The 'answer' visible on-chain is a decoy: the operator can change ${sv} (or already did in an earlier, unverifiable transaction) so no guess ever pays, while every attempt's msg.value stays in the contract for the operator's withdrawal.`, [loc(ctx, setter.node, setter)]));
          } else {
            out.push(mk(ctx, "RIGGED_PAYOUT", `'${f.name}()' pays the whole balance to whoever matches the deployer's private secret '${sv}'`, "critical", 0.8, x, f,
              `${sn(ctx, x)}  |  ${sv} is ${svNode.visibility}, set only in the constructor`,
              `Deposits are open to everyone, but the only way out compares against a value the deployer chose at deployment and nobody else can read. Whatever it is, only the deployer knows it: the pool of deposits is theirs to sweep.`));
          }
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
      const decl = sv.node;
      const hardCoded = !!decl?.expression && collect(decl.expression, (x) => x.type === "NumberLiteral" && /^0x[0-9a-fA-F]{40}$/.test(x.number)).length > 0;
      const setters = writers(c, recv.name).filter((w) => !w.isConstructor);
      const how = fromCtorParam ? "set from a constructor argument" : hardCoded ? "hard-coded to a deployer-chosen address" : setters.length ? `replaceable via ${setters[0].name}()` : "";
      if (!how) return;
      out.push(mk(ctx, "OPAQUE_DEPENDENCY", `Withdrawals in '${f.name}()' call an external contract chosen by the deployer ('${recv.name}')`, "high", 0.75, n, f, `${sn(ctx, n)}  |  ${recv.name} ${how}`,
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
    const idxOf = (target: Node) => target?.range?.[0] ?? (line(target) * 1000 + (target?.loc?.start?.column ?? 0));
    for (const s of ethSends(f.node.body)) {
      const to = unwrap(s.to);
      const isCallOp = s.node.expression?.type !== "MemberAccess"; // .call{value} / .call.value(): forwards all gas
      if (!isMsgSender(to) || !isCallOp) continue;
      const si = idxOf(s.node);
      const late = f.writes.find((w) => { const sv = c.stateVars.get(w.base); const idx = indexChain(w.target)[0]; return !!sv?.isMapping && !!idx && isMsgSender(idx) && idxOf(w.node) > si; });
      if (!late) continue;
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

// ---------------------------------------------------------------- 7. transfer path that credits more than it debits
export function ruleTransferInflation(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const key = (n: Node) => sn(ctx, n).replace(/\s+/g, "");
  for (const fname of c.coreTransferPath) {
    const f = c.functions.get(fname);
    if (!f?.node.body) continue;
    const bal = f.writes.filter((w) => c.balanceVars.has(w.base));
    const debits = bal.filter((w) => w.operator === "-=" || (w.operator === "=" && w.value?.type === "BinaryOperation" && w.value.operator === "-") || (w.operator === "=" && w.value?.type === "FunctionCall" && /^(sub|safeSub)$/i.test(calleeName(w.value) ?? "")));
    const credits = bal.filter((w) => w.operator === "+=" || (w.operator === "=" && w.value?.type === "BinaryOperation" && w.value.operator === "+") || (w.operator === "=" && w.value?.type === "FunctionCall" && /^(add|safeAdd)$/i.test(calleeName(w.value) ?? "")));
    if (debits.length !== 1 || credits.length < 2) continue;
    const amountOf = (w: { operator: string; value?: Node }): Node | null => {
      if (w.operator === "+=" || w.operator === "-=") return w.value ?? null;
      const v = w.value!;
      if (v.type === "BinaryOperation") return v.right;
      return v.arguments?.[1] ?? null;
    };
    const dAmt = amountOf(debits[0]);
    if (!dAmt) continue;
    const D = key(dAmt);
    // the debited amount must be a plain identifier that is never reassigned in this function (so textual equality is semantic equality)
    if (dAmt.type !== "Identifier" || collect(f.node.body, (x) => x.type === "BinaryOperation" && x.operator === "=" && x.left?.type === "Identifier" && x.left.name === dAmt.name).length) continue;
    const full = credits.filter((w) => { const a = amountOf(w); return a && key(a) === D; });
    if (!full.length) continue;
    // any other non-zero credit into a different slot than the full credit's recipient is created from nothing
    const slot = (w: { target: Node }) => indexChain(w.target).map(key).join("|");
    const ex = credits.find((w) => { const a = amountOf(w); return w !== full[0] && a && !(a.type === "NumberLiteral" && Number(a.number) === 0) && slot(w) !== slot(full[0]); });
    if (!ex) continue;
    out.push(mk(ctx, "TRANSFER_INFLATION", `Transfer path credits more than it debits: '${sn(ctx, ex.node)}' on top of the full amount`, "critical", 0.85, ex.node, f,
      `${sn(ctx, debits[0].node)}  |  ${sn(ctx, full[0].node)}  |  ${sn(ctx, ex.node)}`,
      `The sender loses ${D}, the recipient receives the full ${D}, and a third slot is credited as well. Every transfer mints tokens into that slot while totalSupply() stays frozen - a hidden inflation that no minting function reveals.`));
  }
  return out;
}

// ---------------------------------------------------------------- 8. ponzi shape: payouts to stored earlier depositors funded only by later msg.value
export function rulePonziShape(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  const arrays = [...c.stateVars.values()].filter((v) => /\[\]$/.test(v.typeStr) && /address/.test(v.typeStr)).map((v) => v.name);
  if (!arrays.length) return out;
  const pushes = [...c.functions.values()].some((f) => f.mutability === "payable" && collect(f.node.body, (n) => n.type === "FunctionCall" && n.expression?.type === "MemberAccess" && n.expression.memberName === "push" && arrays.includes(baseName(n.expression.expression) ?? "") && (n.arguments ?? []).some(isMsgSender)).length > 0);
  if (!pushes) return out;
  for (const f of c.functions.values()) {
    if (f.isConstructor || !f.node.body || !isPublic(f)) continue;
    for (const s of ethSends(f.node.body)) {
      const to = unwrap(s.to);
      const viaArray = arrays.some((a) => identifiers(to).includes(a)) || (to?.type === "Identifier" && collect(f.node.body, (n) => n.type === "VariableDeclarationStatement" && n.variables?.some((v: Node) => v?.name === to.name) && n.initialValue && arrays.some((a) => identifiers(n.initialValue).includes(a))).length > 0);
      if (!viaArray) continue;
      out.push(mk(ctx, "PONZI_SHAPE", `'${f.name}()' pays stored earlier depositors out of the contract balance`, "high", 0.75, s.node, f, sn(ctx, s.node),
        `Addresses are queued when they pay in, and later paid from whatever ETH is in the contract - there is no yield source, so payouts are funded solely by newer deposits. The shape of a Ponzi: it works until deposits stop, and the last entrants lose everything.`, undefined, true));
    }
  }
  return out;
}

// ---------------------------------------------------------------- 9. layout tricks + pre-emptive drain (HoneyBadger "hidden transfer")
export function ruleHiddenLayout(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  // (a) a statement pushed off-screen by a wall of whitespace on the same line
  const lines = ctx.source.split(/\r?\n/);
  const start = line(c.node), end = endLine(c.node);
  for (let i = start - 1; i < Math.min(end, lines.length); i++) {
    const l = lines[i];
    const m = /^(\s*)(\S.*?)(\s{120,})(\S.+)$/.exec(l) ?? /^(\s{150,})(\S.+)$/.exec(l);
    if (!m) continue;
    const code = m[4] ?? m[2];
    if (/^\/\//.test(code) || !/[;{}]/.test(code)) continue;
    out.push({ id: "HIDDEN_CODE_LAYOUT", title: `Code hidden off-screen by ${(m[3] ?? m[1]).length} spaces of padding`, severity: "high", confidence: 0.85, location: { file: ctx.file, line: i + 1, column: 0, contract: c.name, snippet: code.slice(0, 120) }, evidence: `line ${i + 1}: \`${code.slice(0, 80)}\``,
      reasoning: `A statement is placed after hundreds of spaces so that it scrolls out of view in any editor or explorer. There is no engineering reason to lay code out this way; it exists to keep a reviewer from seeing '${code.slice(0, 60)}'.` });
    if (out.length >= 3) break;
  }
  // (b) pre-emptive drain: the owner is paid the whole balance right before the caller's "payout" in the same unprivileged function
  for (const f of c.functions.values()) {
    if (f.isConstructor || !f.node.body || !isPublic(f) || f.privileged) continue;
    const sends = ethSends(f.node.body);
    for (let i = 0; i < sends.length; i++) {
      const a = sends[i];
      if (!isOwnerRecipient(c, a.to) || !a.amount || !isThisBalance(a.amount)) continue;
      const later = sends.slice(i + 1).find((b) => isMsgSender(unwrap(b.to)));
      if (!later) continue;
      out.push(mk(ctx, "PREEMPTIVE_DRAIN", `'${f.name}()' sends the whole balance to the owner one statement before paying the caller`, "critical", 0.9, a.node, f, `${sn(ctx, a.node)}  then  ${sn(ctx, later.node)}`,
        `By the time the caller's transfer runs, address(this).balance is already zero - the visible 'reward' line pays nothing. The victim's own msg.value is part of what the owner just took.`));
    }
  }
  return out;
}

// ---------------------------------------------------------------- 10. inheritance disorder: a base's auth variable is shadowed by a derived redeclaration
export function ruleShadowedAuth(ctx: Ctx): Finding[] {
  const { c } = ctx;
  const out: Finding[] = [];
  for (const sh of c.shadowedVars) {
    // is the base's copy what a modifier / privilege check reads?  (the modifier is defined in the base, so it binds to the base slot)
    const baseMods = [...c.modifiers.values()].filter((m) => m.contract === sh.base && identifiers(m.node.body ?? m.node).includes(sh.name));
    const derivedWriters = [...c.functions.values()].filter((f) => f.contract === sh.derived && !f.isConstructor && f.writes.some((w) => w.base === sh.name));
    if (!baseMods.length || !derivedWriters.length) continue;
    const gated = [...c.functions.values()].filter((f) => f.modifiers.some((m) => baseMods.some((b) => b.name === m)));
    out.push(mk(ctx, "SHADOWED_AUTH", `'${sh.name}' is redeclared in ${sh.derived}: '${derivedWriters[0].name}()' writes the shadow, but '${baseMods[0].name}' still checks ${sh.base}'s copy`, "critical", 0.85, sh.node, derivedWriters[0],
      `${sh.base}.${sh.name} vs ${sh.derived}.${sh.name}; modifier ${baseMods[0].name} gates ${gated.map((f) => f.name + "()").join(", ") || "-"}`,
      `Two storage slots share one name. Functions in the derived contract (and readers of the public getter) see the shadow; the base modifier that guards ${gated.map((f) => f.name + "()").join(", ") || "the privileged functions"} reads the original, which never changes. Anyone who 'takes ownership' through ${derivedWriters[0].name}() gains nothing - the deployer keeps the real key. This is the HoneyBadger 'inheritance disorder' trap.`, gated.map((f) => loc(ctx, f.node, f))));
  }
  return out;
}

export const RULES2 = [ruleTransferConservation, ruleShadowedAuth, ruleHiddenLayout, rulePonziShape, ruleTransferInflation, ruleApprovalHarvest, ruleHiddenCallerBranch, ruleWithdrawRedirect, ruleObfuscatedRecipient, ruleClassicHoneypot, ruleValueVulns];
