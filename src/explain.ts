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
    case "ALLOWLIST_GATE":
      return [
        "Owner deploys; the constructor puts the owner (and nobody else) on the allow-list.",
        "Victim receives tokens (buys, or is sent them) - receiving is not gated.",
        `Victim tries to transfer or sell: ${L(at)}: \`${at.snippet}\` -> revert, because the victim is not on the list.`,
        `Only ${setter ?? "the privileged setter"} can add addresses. Result: holders exit only if and when the owner lets them.`,
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
    case "APPROVAL_HARVEST":
      return [
        "Victim is lured into approving this contract (an 'eligibility check', a marketplace listing, a fake airdrop claim). The approval itself looks harmless.",
        `${/privileged|\[/.test(f.evidence) ? "The operator" : "Anyone"} calls ${fnOf(at)} with the victim's address as 'from': ${L(at)}: \`${at.snippet}\`.`,
        "transferFrom() succeeds because the allowance exists; the tokens land with the collector, and nothing is credited back.",
        "Result: every wallet that ever approved this contract can be emptied, in batches, at any later time.",
      ];
    case "HIDDEN_CALLER_BRANCH":
      return [
        "Every ordinary transfer runs the honest branch: debit sender, credit recipient.",
        `When the caller is the hidden address, ${L(at)} takes the other branch: \`${at.snippet}\`.`,
        "That branch credits a balance with no matching debit (and returns before the normal accounting), so tokens appear from nowhere.",
        "Result: the hidden address mints at will and dumps into the pool; totalSupply() and the verified source both look normal to a casual reader.",
      ];
    case "WITHDRAW_REDIRECT":
      return [
        "Users deposit ETH; their balance mapping grows and the contract looks like a normal bank.",
        `A user calls ${fnOf(at)}: their recorded balance is zeroed, then ${L(at)}: \`${at.snippet}\` sends the ETH to the owner instead.`,
        "The user's transaction succeeds, so wallets and explorers show a normal 'withdraw' - only the recipient is wrong.",
        "Result: deposits can only ever leave towards the operator; 'withdraw' is the rug.",
      ];
    case "OBFUSCATED_RECIPIENT":
      return [
        "The recipient is not written as an address literal but reconstructed at runtime (constant XOR/arith, uint160 cast).",
        `Every call that reaches ${L(at)} pays that computed address: \`${at.snippet}\`.`,
        "A reviewer scanning for wallet addresses in the verified source finds none; explorers do not link the constant to a known wallet.",
        "Result: a silent skim on every transaction, deliberately hidden from source review.",
      ];
    case "UNSATISFIABLE_PAYOUT":
      return [
        "Contract is seeded with a visible ETH balance as bait ('send X, receive 2X').",
        `Victim sends ETH. At ${L(at)} the check \`${at.snippet}\` compares msg.value against a balance that already includes msg.value.`,
        "The comparison can only hold when the contract held nothing before - so the payout never fires while there is bait.",
        "Result: the victim's ETH stays in the contract; the owner withdraws everything through the privileged withdraw().",
      ];
    case "RIGGED_PAYOUT":
      return [
        "A 'guess the answer / crack the password' game is deployed with an ETH prize and an apparently readable answer hash.",
        `The operator (re)sets the stored answer via ${setter ?? "a setter that runs outside the constructor"} - possibly in a transaction that is not visible with the deployment.`,
        `Victim pays to guess; ${L(at)}: \`${at.snippet}\` compares against the value the operator chose, so no guess ever matches.`,
        "Result: every attempt's msg.value accumulates; the operator drains it with the privileged stop/withdraw function.",
      ];
    case "PAYMENT_HIJACK":
      return [
        "A wallet, dApp prompt or phishing page asks the victim to call a function with a reassuring name (SecurityUpdate, Claim, Verify).",
        `The function is payable; ${L(at)}: \`${at.snippet}\` forwards msg.value to the owner.`,
        "Nothing is minted, recorded or returned to the caller - the contract state does not even remember the payment.",
        "Result: the ETH is gone the moment the transaction confirms.",
      ];
    case "OPAQUE_DEPENDENCY":
      return [
        "Deposits work and are recorded, building trust and a visible balance.",
        `Withdrawals call an external contract that the deployer supplied at deployment: ${L(at)}: \`${at.snippet}\`.`,
        "That contract's code is not in this source and can revert on the withdrawal path (or only for non-owner callers), blocking every exit while deposits keep succeeding.",
        "Result: a bank that only accepts. This is the well-known 'private bank + logger' honeypot shape.",
      ];
    case "REENTRANCY":
      return [
        `${fnOf(at)} sends ETH with a gas-forwarding call before it updates the caller's balance: ${L(at)}: \`${at.snippet}\`.`,
        "A contract recipient re-enters the same function from its receive()/fallback while the balance is still unchanged.",
        "Each re-entry passes the balance check again and sends again, until the pool is empty.",
        "Result: anyone can drain all user deposits. Not proof of malicious intent - but the funds are exposed, and honeypots use this exact shape deliberately.",
      ];
    case "TX_ORIGIN_VALUE":
      return [
        "The owner is lured into calling any function on an attacker contract (a fake airdrop, a 'verify wallet' button).",
        `The attacker contract calls ${fnOf(at)} in the same transaction; tx.origin is still the owner, so ${L(at)}: \`${at.snippet}\` passes.`,
        "The value transfer that the check protects executes with the attacker-chosen parameters.",
        "Result: a phishable guard on money - the funds can be moved by anyone who can get the owner to click.",
      ];
    case "TRANSFER_INFLATION":
      return [
        "Every transfer debits the sender once and credits the recipient the full amount - so far conserving.",
        `Then ${L(at)}: \`${at.snippet}\` credits a third slot as well, out of nothing.`,
        "totalSupply() never moves, so the inflation is invisible to explorers and to anyone checking supply against holdings.",
        "Result: a slot that grows with every trade, ready to be dumped into the pool at the operator's convenience.",
      ];
    case "HIDDEN_ROLE":
      return [
        "Holders check owner() on the explorer and see a normal-looking (perhaps renounced) owner.",
        `The privileged functions never consult that variable; they check ${at.snippet ? "`" + at.snippet + "`" : "a private address"} instead (${L(at)}).`,
        "transferOwnership()/renounceOwnership() only touch the decorative owner, so the hidden key survives them.",
        "Result: whoever holds the hidden key retains every backdoor while the visible ownership story says otherwise.",
      ];
    case "PONZI_SHAPE":
      return [
        "Participants pay in; their address is queued. No external yield source exists.",
        `${fnOf(at)} pays a queued address from the contract balance: ${L(at)}: \`${at.snippet}\`.`,
        "Each payout is funded only by later deposits, so the queue only clears while new money keeps arriving.",
        "Result: early entrants are paid with later entrants' money; when inflow stops, everyone still queued loses their deposit.",
      ];
    case "HIDDEN_CODE_LAYOUT":
      return [
        "The source looks ordinary in the explorer's verified-code view.",
        `Line ${at.line} continues far to the right, past the visible width, where \`${at.snippet}\` sits.`,
        "A reviewer reading the visible column concludes the function is harmless.",
        "Result: the hidden statement (typically a transfer to the deployer or an owner reassignment) runs on every call.",
      ];
    case "PREEMPTIVE_DRAIN":
      return [
        "The victim sees a 'redeem'/'giveaway' function that transfers the contract balance to msg.sender once a deposit threshold is met.",
        `They send ETH. One statement earlier - ${L(at)}: \`${at.snippet}\` - the whole balance (including their deposit) already went to the owner.`,
        "The visible payout line then transfers a balance of zero; the transaction still succeeds, so nothing looks wrong on-chain.",
        "Result: every 'redeem' is a donation to the deployer.",
      ];
    case "SHADOWED_AUTH":
      return [
        "The derived contract re-declares a state variable with the same name as the base's authority variable, creating a second storage slot.",
        `A function in the derived contract (${L(at)}) lets callers write the shadow copy - it looks like 'become the owner'.`,
        "The base modifier that guards withdrawals binds to the original slot, which the new 'owner' never touched.",
        "Result: victims who pay to take control gain a variable that nothing reads; the deployer still passes every onlyOwner check and sweeps the pool.",
      ];
    case "CANNOT_SELL_ALL":
      return [
        "Victim buys; partial sells work, so simulators and 'sell test' bots report the token as sellable.",
        `Victim tries to sell everything: ${L(at)}: \`${at.snippet}\` rejects any amount equal to the full balance.`,
        "Wallets that 'sell max' revert; the holder must leave dust behind every time, and the last unit can never leave.",
        "Result: a permanent floor of trapped tokens per wallet - small per victim, large across thousands.",
      ];
    case "COOLDOWN_GATE":
      return [
        "Launch with a short per-address cooldown that looks like sniper protection.",
        `${setter ? `Owner calls ${setter} with a huge value - the setter has no cap.` : "The cooldown applies to holders but not to the owner / exempt addresses."}`,
        `Every ${/sell/i.test(f.title) ? "sell" : "transfer"} now fails at ${L(at)}: \`${at.snippet}\` until the timestamp passes.`,
        "Result: holders are throttled or frozen while the deployer trades freely.",
      ];
    case "BUY_BLOCK":
      return [`${setter ? `Owner flips the switch via ${setter}.` : "A privileged switch controls buys."}`, `Transfers whose sender is the pair now revert at ${L(at)}: \`${at.snippet}\`.`, "Result: the owner decides when the market is open; combined with other gates this becomes a one-way market."];
    case "EOA_ONLY_GATE":
      return [
        "Victim buys on the DEX (the pair is the msg.sender of that transfer; buys may be exempted so they succeed).",
        `Victim sells through the router: the router is a contract, so ${L(at)}: \`${at.snippet}\` reverts.`,
        "The check reads like anti-bot protection; wallet-to-wallet transfers still work, so the token 'transfers fine'.",
        "Result: nobody can exit through the pool except exempt addresses.",
      ];
    case "PERSONAL_FEE":
      return [
        "Token launches with an advertised global fee; scanners read it and pass.",
        `Owner calls ${fnOf(at)} [${L(at)}] with a victim's address and a fee near 100 %.`,
        "Only that address is taxed on the transfer path; everyone else - and every scanner - sees the normal rate.",
        "Result: targeted confiscation on exit, invisible until the victim sells.",
      ];
    case "PHANTOM_TRANSFER":
      return [
        `Caller invokes ${fnOf(at)}; ${L(at)}: \`${at.snippet}\` fires and the call returns true.`,
        "No balance mapping is written by the function or anything it calls.",
        "Explorers, wallets and indexers show a completed transfer; balanceOf() never changes.",
        "Result: tokens cannot actually move - every 'trade' on record is fiction.",
      ];
    case "GAS_ABUSE":
      return [`Every transfer runs ${L(at)}: \`${at.snippet}\`.`, "The holder pays gas for contract creation / gas-token calls that have nothing to do with moving a balance.", "Result: value extracted from users as gas on every interaction, accruing to the deployer."];
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
    const bl = has("BLACKLIST_GATE", "ALLOWLIST_GATE");
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
