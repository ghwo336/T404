# noexit

**Offline static analysis that finds honeypot, rug-pull and hidden-privilege logic in Solidity source — before anyone signs.**

> Blockchains only record what succeeded. A token that lets you buy but never sell leaves no trace on-chain until the victim tries to exit.
> `noexit` reads the contract's *logic flow and permission structure* and tells you whether there is an exit.

Built for **TRUST404 — Track 1: Smart Contract Threat Detection**.

- Input: one or more `.sol` files or directories (recursive batch mode)
- Output: `Benign` / `Malicious` / `Uncertain` per file, with every finding pinned to a code location, evidence and reasoning
- 100% offline: no compiler, no RPC, no LLM, no network. Pure AST analysis (`@solidity-parser/parser`), works for any `pragma` from 0.4 to 0.8
- Machine-readable JSON (and SARIF) for automated grading, colored CLI for humans

---

## Quick start

```bash
git clone <this repo> && cd noexit
npm install          # only dependency that matters: @solidity-parser/parser (pure JS, bundled offline)
npm run build

# scan a directory (recursive) and write the JSON report
node dist/cli.js scan ./samples --out report.json

# or without building
npx tsx src/cli.ts scan ./samples
```

Verify the network is not needed:

```bash
unshare -n node dist/cli.js scan ./samples   # Linux; or just pull the cable
```

Run the regression suite (every file under `samples/<verdict>/` must be classified as that verdict):

```bash
npm test
```

## CLI

```
noexit scan <paths...> [options]

  -o, --out <file>        write the full JSON report to this file
  -f, --format <fmt>      stdout format: pretty (default) | json | sarif | summary
  -v, --verbose           print evidence + reasoning for every finding (incl. info)
      --no-color          plain output
      --fail-on <verdict> exit 1 if any file is `malicious` (or `uncertain`)
```

`summary` prints one tab-separated line per file (`verdict  score  file  summary`) — convenient for grading scripts.

## Output schema (`--out report.json`)

```jsonc
{
  "tool": "noexit", "version": "0.1.0", "generatedAt": "...", "inputs": ["./samples"],
  "totals": { "files": 19, "malicious": 12, "uncertain": 1, "benign": 6, "errors": 0 },
  "files": [
    {
      "file": "samples/malicious/01_SellBlock.sol",
      "verdict": "Malicious",            // Benign | Malicious | Uncertain
      "score": 44,                       // 0..100 risk score
      "summary": "Malicious: Sell path reverts (buy allowed, sell blocked)",
      "parseErrors": [],
      "contracts": [{
        "name": "MoonRocket", "kind": "contract", "bases": ["ERC20", "Ownable"],
        "privilegedFunctions": ["renounceOwnership [modifier onlyOwner: require(msg.sender vs _owner)]", "..."],
        "transferPath": ["transfer", "transferFrom", "_transfer", "_mint", "burn"],
        "findings": [ /* same objects as below */ ]
      }],
      "findings": [{
        "id": "SELL_RESTRICTION",
        "title": "Sell path reverts (buy allowed, sell blocked)",
        "severity": "critical",          // critical | high | medium | low | info
        "confidence": 0.95,
        "location": { "file": "...", "line": 57, "column": 8, "endLine": 59, "contract": "MoonRocket", "function": "_transfer",
                      "snippet": "if (to == uniswapV2Pair && from != owner()) { revert(...); }" },
        "evidence": "Transfer to the liquidity pair is rejected: to == uniswapV2Pair && from != owner()",
        "reasoning": "Inside the token transfer logic, a transfer whose destination is the DEX pair (i.e. a sell) hits a revert unless the sender is owner/exempt. ...",
        "related": [ { "file": "...", "line": 58, "function": "setPair" } ]   // e.g. the privileged setter that arms the trap
      }]
    }
  ]
}
```

## How it works

`noexit` does **not** grep for keywords. Each file goes through three stages:

### 1. Contract model
The AST is turned into a per-contract model, with inheritance flattened across the analyzed files:

- **state variables** classified by *type + usage*: balance mappings, allowance mappings, supply counters, owner-like addresses, DEX pair addresses / AMM-pair maps
- **modifiers**, analyzed by body: a modifier is *privileged* if it compares `msg.sender` (or `_msgSender()`) against an owner-like address, a hard-coded address, a role mapping, or calls `_checkOwner()` etc. (name is only a fallback for bases outside the file set)
- **functions**: visibility, modifiers, inline privilege checks, every state write (`=`, `+=`, `-=`, `delete`, `++`…), reads and internal calls
- **transfer path**: `transfer/_transfer/_update/_tokenTransfer/…` seeds ∪ every function that writes a balance mapping, closed over the internal call graph. This is where a honeypot has to live.

### 2. Rules — logic and permission flow, not keywords
Every rule reasons about *who can write what* and *what the transfer path does with it*:

| id | what it proves | severity |
|---|---|---|
| `SELL_RESTRICTION` | Inside the transfer path, a branch that is only taken when `to == pair` (a sell) reverts, or credits tokens to someone other than the recipient and returns. Exemptions for owner/excluded addresses raise confidence. | critical |
| `SELL_FEE_UNCAPPED` | The fee variable assigned in the sell branch has a privileged setter with no (or ≥50%) upper bound. | critical |
| `BLACKLIST_GATE` | A `mapping(address=>bool)` is *both* written by a privileged function (for arbitrary addresses) *and* used as a block condition in the transfer path. | critical / high |
| `TRADING_GATE` | A bool read as a transfer requirement that a privileged function can flip back to `false`. Sell-only gate → critical; one-way "enable trading once" → low. | critical / high / low |
| `UNCAPPED_FEE` | A uint that feeds the transfer arithmetic with a privileged setter lacking an effective cap (constants are resolved, denominator inferred from `/100`, `/10000`…). Sell-named fees escalate. | critical … low |
| `OWNER_LIMIT_TO_ZERO` | `require(amount <= limit)` in the (sell) path where the privileged setter of `limit` has no lower bound — anti-whale limit that becomes a sell block. | critical / medium |
| `HIDDEN_MINT` / `OPEN_MINT` / `OWNER_MINT` | Balance + supply increase (or `_mint`) in a function whose name hides it (critical), an unguarded public function (critical), an owner `mint` without cap (medium) or with a cap (low). | critical … low |
| `BALANCE_MANIPULATION` | Privileged direct writes to the balance mapping outside the transfer path (overwrite / burn-from / silent credit). | critical / high |
| `APPROVAL_BYPASS` | Allowance mapping written on behalf of other holders; `transferFrom` that never consults allowances; allowance skipped for the owner. | critical |
| `FAKE_RENOUNCE` / `HIDDEN_OWNER_TRANSFER` / `OPEN_OWNER_TAKEOVER` | `renounceOwnership` that does not zero the owner or stashes it first; owner restored from a backup in `unlock()`; owner written by an unguarded function. | critical / high |
| `EXTERNAL_TRANSFER_HOOK` | The transfer path calls an external contract stored in a state variable — critical if a privileged function can replace that address (logic swap after launch). | critical / high |
| `SELFDESTRUCT`, `DELEGATECALL` | With escalation if unguarded or if the delegatecall target is owner-settable. | critical / high |
| `OPEN_DRAIN` | Unguarded function sending `address(this).balance` (or the contract's whole token balance) to the caller. | critical |
| `PRIVILEGED_WITHDRAW` | Funds moved to the owner; low if the function is named honestly (`withdraw…`), medium if the name hides it. | medium / low |
| `AUTO_BLACKLIST`, `TX_ORIGIN_AUTH`, `UNRESOLVED_BASE` | Informational context that lowers verdict confidence. | medium / low / info |

### 3. Verdict
Findings are weighted by severity × confidence (a low-confidence finding is downgraded one level).
`Malicious` = at least one critical, or two highs. `Uncertain` = one high, or two mediums, or a medium plus unresolved base contracts. Otherwise `Benign`.

## Sample set

`samples/` contains 19 self-contained contracts (12 malicious, 6 benign, 1 uncertain) covering the honeypot families seen in the wild — sell revert, owner blacklist, switchable selling, uncapped sell tax, hidden mint, fake renounce + `unlock()`, approval backdoor, external "guard" contract, balance rewrite, max-sell-to-zero, a full reflection-token clone with `bots[]` + `setSellTax`, an open-drain wallet — and benign controls that *look* similar (fair tax token with capped fees and a one-way launch gate, capped owner mint, OpenZeppelin-style token with unresolved imports, vesting, staking).

```
$ npm test
19 passed, 0 failed
```

## Limitations (honest ones)

- Analysis is per-file; contracts inherited from files outside the input set (`@openzeppelin/...`) are modeled by their well-known names (`_balances`, `onlyOwner`, …) but not analyzed. `UNRESOLVED_BASE` is emitted so the grader can see it.
- No data-flow across storage slots or assembly. Inline `assembly { sstore(...) }` tricks are out of scope for v0.1.
- Heuristics for parameter roles (`from`/`to`/`amount`) use names first, positions second.

## Beyond the CLI

The same engine is exported as a library (`import { scanFile } from "noexit"`), so a dApp or wallet can fetch verified source for the `to` address of a pending transaction and run exactly this analysis before showing the signature prompt — the "pre-flight check" this project started from.

## License

MIT
