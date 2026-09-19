// Turns findings into (1) a step-by-step attack path a human can replay and
// (2) a checklist of what was verified, so a Benign verdict is also justified.
import { Contract } from "./model";
import { Finding, Check, Location } from "./types";

const L = (l?: Location) => (l ? `${l.function ? l.function + "()" : l.contract ?? ""} L${l.line}` : "?");
const fnOf = (l?: Location) => (l?.function ? `${l.function}()` : "a privileged function");

export function attackPath(f: Finding): string[] | undefined {
  const at = f.location, rel = f.related?.[0];
  const setter = rel ? `${fnOf(rel)} [${L(rel)}]` : null;
  switch (f.id) {
    case "SELL_RESTRICTION":
      return [
        ...(setter ? [`Owner deploys and, if needed, arms the trap via ${setter}.`] : ["Owner deploys the token and adds liquidity."]),
        "Victim buys on the DEX: pair -> victim. The transfer path has no pair-conditioned block for buys, so it succeeds.",
        `Victim tries to sell: victim -> pair. Execution reaches ${L(at)} where the sell branch ${/revert/i.test(f.title) ? "reverts" : /divert/i.test(f.title) ? "credits the tokens elsewhere and returns" : "cannot be satisfied"}: \`${at.snippet}\`.`,
        "Result: the victim can never exit. The owner (exempt) sells into the liquidity the victims provided.",
      ];
    case "SELL_FEE_UNCAPPED":
    case "UNCAPPED_FEE":
      return [
        "Token launches with a small, reasonable-looking fee.",
        `After buyers are in, owner calls ${setter ?? "the fee setter"} with a value near 100% - nothing in the setter rejects it.`,
        `Every ${/sell/i.test(f.title) ? "sell" : "transfer"} now runs through ${L(at)} and the fee arithmetic in the transfer path takes (almost) the whole amount.`,
        "Result: sells succeed on paper but the seller receives ~0. The collected 'fee' goes to the owner's wallet.",
      ];
    case "BLACKLIST_GATE":
      return [
        "Victim buys normally; the blacklist mapping is empty for them.",
        `Owner calls ${setter ?? "the blacklist setter"} with the victim's address.`,
        `Victim's next transfer hits ${L(at)}: \`${at.snippet}\` -> revert.`,
        "Result: targeted freeze. Owner can do this to every holder, or only to large ones, and it is invisible on-chain until the victim tries.",
      ];
    case "TRADING_GATE":
      if (f.severity === "low") return undefined;
      return [
        `Owner enables trading; buys and sells work.`,
        `Owner calls ${setter ?? "the toggle"} and sets the flag back to false.`,
        `Transfers now fail at ${L(at)}: \`${at.snippet}\`${/sell/i.test(f.title) ? " - but only for transfers into the pair, so buying still works and price keeps rising" : ""}.`,
        "Result: holders are locked; owner (exempt) is the only one who can exit.",
      ];
    case "OWNER_LIMIT_TO_ZERO":
      return [
        "Limit is set to a sane value at launch (looks like anti-whale protection).",
        `Owner calls ${setter ?? "the limit setter"} with 0 (or 1 wei) - the setter has no lower bound.`,
        `Every ${/sell/i.test(f.title) ? "sell" : "transfer"} now fails at ${L(at)}: \`${at.snippet}\`.`,
        "Result: functional sell block hidden behind a harmless-looking limit.",
      ];
    case "HIDDEN_MINT":
    case "OPEN_MINT":
      return [
        `${f.id === "OPEN_MINT" ? "Anyone" : "Owner"} calls ${fnOf(at)} [${L(at)}]; balances and supply increase: \`${at.snippet}\`.`,
        "Freshly created tokens are sold into the pool, draining the ETH/USDC side of the liquidity.",
        "Result: every holder is diluted to zero without any transfer being blocked.",
      ];
    case "BALANCE_MANIPULATION":
      return [
        `Owner calls ${fnOf(at)} [${L(at)}] with a victim address: \`${at.snippet}\`.`,
        "The victim's balance is rewritten (zeroed / moved) with no Transfer of their own and no allowance.",
        "Result: direct confiscation; standard ERC20 tooling shows nothing until balanceOf is re-read.",
      ];
    case "APPROVAL_BYPASS":
      return [
        f.title.includes("transferFrom") ? `The privileged caller invokes transferFrom(victim, attacker, amount); the allowance branch at ${L(at)} is skipped for them.` : `Owner calls ${fnOf(at)} [${L(at)}]: \`${at.snippet}\` - grants themselves allowance over the victim.`,
        "Tokens leave the victim's wallet without any approve() from the victim.",
        "Result: every holder can be drained at any time.",
      ];
    case "FAKE_RENOUNCE":
    case "HIDDEN_OWNER_TRANSFER":
      return [
        "Owner calls renounceOwnership(); explorers and holders see owner = 0x0 and treat the token as safe.",
        `${f.id === "HIDDEN_OWNER_TRANSFER" ? `Later, ${fnOf(at)} [${L(at)}] writes the stashed address back: \`${at.snippet}\`.` : `But ${L(at)}: \`${at.snippet}\` - the owner is kept (or stashed) instead of cleared.`}`,
        "Result: every onlyOwner backdoor is still live while the token looks renounced.",
      ];
    case "EXTERNAL_TRANSFER_HOOK":
      return [
        "The visible token contract looks clean; the transfer path defers to an external contract.",
        ...(setter ? [`Owner points that address at new code via ${setter}.`] : []),
        `Every transfer now runs ${L(at)}: \`${at.snippet}\` - the external code decides who may sell.`,
        "Result: the honeypot logic never appears in the audited/verified source.",
      ];
    case "OPEN_DRAIN":
      return [`Anyone calls ${fnOf(at)} [${L(at)}]: \`${at.snippet}\`.`, "The contract's entire balance is sent to the caller.", "Result: total loss of pooled funds; usually the deployer's accomplice is the first caller."];
    case "SELFDESTRUCT":
      return [`${f.severity === "critical" ? "Anyone" : "Owner"} calls ${fnOf(at)} [${L(at)}].`, "The contract code is removed; every balance becomes unreachable and ETH goes to the chosen address."];
    case "DELEGATECALL":
      return [`${fnOf(at)} [${L(at)}] executes foreign code in this contract's storage.`, "That code can rewrite balances, allowances and the owner slot."];
    default:
      return undefined;
  }
}

export function checklist(c: Contract, findings: Finding[]): Check[] {
  const has = (...ids: string[]) => findings.filter((f) => ids.includes(f.id) && f.severity !== "info" && f.severity !== "low");
  const hasSell = (ids: string[]) => findings.filter((f) => ids.includes(f.id) && /sell/i.test(f.title) && f.severity !== "low");
  const out: Check[] = [];
  const tp = c.transferPath.size > 0;
  const pair = [...c.pairVars].join(", ");
  const push = (id: string, status: Check["status"], note: string) => out.push({ id, status, note });

  if (tp) {
    const sell = [...has("SELL_RESTRICTION", "SELL_FEE_UNCAPPED"), ...hasSell(["TRADING_GATE", "OWNER_LIMIT_TO_ZERO"])];
    push("sell_path_symmetric", sell.length ? "fail" : "pass", sell.length ? sell[0].title : pair ? `transfer path treats to==${pair} (sell) and from==${pair} (buy) the same; no revert, diversion or owner-only fee on the sell side` : "no DEX pair role detected in the transfer path; no pair-conditioned branch exists");
    const bl = has("BLACKLIST_GATE");
    push("no_owner_blacklist", bl.length ? "fail" : "pass", bl.length ? bl[0].title : "no owner-writable address mapping is used as a block condition in the transfer path");
    const tg = findings.filter((f) => f.id === "TRADING_GATE");
    push("no_owner_pause", tg.some((f) => f.severity !== "low") ? "fail" : "pass", tg.some((f) => f.severity !== "low") ? tg[0].title : tg.length ? "one-way launch gate only (flag can only be set to true)" : "no owner-controlled flag gates transfers");
    const fee = has("UNCAPPED_FEE", "SELL_FEE_UNCAPPED");
    push("fees_capped", fee.length ? "fail" : "pass", fee.length ? fee[0].title : "every owner-settable variable feeding the transfer arithmetic is bounded by a require() in its setter (or none exists)");
    const lim = has("OWNER_LIMIT_TO_ZERO");
    push("limits_have_floor", lim.length ? "fail" : "pass", lim.length ? lim[0].title : "amount limits in the transfer path either are constant or have a lower bound in their setter");
    const hook = has("EXTERNAL_TRANSFER_HOOK");
    push("transfer_logic_self_contained", hook.length ? "fail" : "pass", hook.length ? hook[0].title : "transfer path calls no owner-replaceable external contract");
  }
  const mint = has("HIDDEN_MINT", "OPEN_MINT");
  push("supply_not_inflatable", mint.length ? "fail" : "pass", mint.length ? mint[0].title : findings.some((f) => f.id === "OWNER_MINT") ? "owner mint exists but is bounded by a hard cap" : "no function outside the constructor increases balances + supply");
  const bal = has("BALANCE_MANIPULATION");
  push("balances_untouchable", bal.length ? "fail" : "pass", bal.length ? bal[0].title : "no privileged function writes the balance mapping outside the transfer path");
  const appr = has("APPROVAL_BYPASS");
  push("allowances_honored", appr.length ? "fail" : "pass", appr.length ? appr[0].title : "transferFrom consults the allowance mapping; no function writes allowances on behalf of other holders");
  const own = has("FAKE_RENOUNCE", "HIDDEN_OWNER_TRANSFER", "OPEN_OWNER_TAKEOVER");
  push("ownership_honest", own.length ? "fail" : "pass", own.length ? own[0].title : c.ownerVars.size ? `owner variable (${[...c.ownerVars].join(", ")}) is written only by constructor / transferOwnership / renounceOwnership-shaped functions` : "no owner variable");
  const ops = has("SELFDESTRUCT", "DELEGATECALL");
  push("no_selfdestruct_delegatecall", ops.length ? "fail" : "pass", ops.length ? ops[0].title : "no selfdestruct; no delegatecall to external code");
  const drain = has("OPEN_DRAIN", "PRIVILEGED_WITHDRAW");
  push("no_hidden_fund_exit", drain.length ? "fail" : "pass", drain.length ? drain[0].title : findings.some((f) => f.id === "PRIVILEGED_WITHDRAW") ? "owner can withdraw contract-held funds via an honestly named function (centralisation, not a trap)" : "no function moves contract funds to the owner or an arbitrary caller");
  return out;
}
