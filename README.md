# noexit

**Offline static analysis that finds honeypot, rug-pull and hidden-privilege logic in Solidity source — before anyone signs.**

> Blockchains only record what succeeded. A token that lets you buy but never sell leaves no trace on-chain until the victim tries to exit.
> `noexit` reads the contract's *logic flow and permission structure* and tells you whether there is an exit.

Built for **TRUST404 — Track 1: Smart Contract Threat Detection**.

- Input: one or more `.sol` files or directories (recursive batch mode); `import` statements are resolved offline inside the tree (relative paths, `node_modules`, `lib/`, `remappings.txt`)
- Output: `Benign` / `Malicious` / `Uncertain` per file, with every finding pinned to a code location, evidence, reasoning and a step-by-step **attack path**; Benign verdicts come with the **checklist of what was verified**
- 100% offline: no compiler, no RPC, no LLM, no network. Pure AST analysis (`@solidity-parser/parser`), works for any `pragma` from 0.4 to 0.8
- Machine-readable JSON (and SARIF) for automated grading, colored CLI for humans

---

## Quick start

```bash
git clone https://github.com/ghwo336/T404.git && cd T404
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

## Reading a result

```
MALICIOUS  44/100  samples/malicious/02_OwnerBlacklist.sol
  CRITICAL BLACKLIST_GATE  Owner-controlled address blacklist blocks transfers  @ SafeInu._transfer() L57
           require(!_isBot[from] && !_isBot[to], "SINU: bot detected")
           1. Victim buys normally; the blacklist mapping is empty for them.
           2. Owner calls manageBots() [manageBots() L54] with the victim's address.
           3. Victim's next transfer hits _transfer() L57: `require(!_isBot[from] && !_isBot[to])` -> revert.
           4. Result: targeted freeze. Owner can do this to every holder ... invisible on-chain until the victim tries.

BENIGN      2/100  samples/benign/03_FairTaxToken.sol
  LOW      TRADING_GATE  One-way launch gate (owner enables trading once)  @ FairTaxToken._transfer() L76
           checks for FairTaxToken:
           ✓ sell_path_symmetric      transfer path treats to==uniswapV2Pair (sell) and from==uniswapV2Pair (buy) the same ...
           ✓ fees_capped              every owner-settable variable feeding the transfer arithmetic is bounded by a require() ...
           ✓ ownership_honest         owner variable is written only by constructor / transferOwnership / renounceOwnership-shaped functions
           ...
```

Every finding in the JSON carries `attackPath` (the numbered steps) and every contract carries `checks[]` (pass/fail + note), so a grader can see *why* a file is Benign, not just that nothing fired.

## How it works

`noexit` does **not** grep for keywords. Each file goes through three stages:

### 1. Contract model
The AST is turned into a per-contract model, with inheritance flattened across the analyzed files:

- **state variables** classified by *type + usage*, not by name: the mapping returned by `balanceOf()` is the balance map; the address assigned from `createPair()` or compared against `to`/`from` in the transfer path is the pair; the address assigned `msg.sender` in the constructor or compared against `msg.sender` in a modifier is the owner; a `mapping(address=>bool)` seeded with owner/`address(this)` in the constructor is an exemption map. Names (`_isBot`, `sellFee`) only raise confidence. Functions that just `return msg.sender` or return the owner slot are recognised as `_msgSender()` / `owner()` aliases whatever they are called - see the `*_Obf_*` samples, which are real honeypots with every identifier renamed to `_q1`, `_q2`, …
- **fee data-flow**: a state variable is a "fee" if it reaches a `*`/`/` (or SafeMath `mul`/`div`) in the transfer path directly, through a local, through a state-to-state assignment, or as an argument to an internal function whose parameter is used in arithmetic (2 rounds, interprocedural)
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

`samples/` contains 25 judged contracts (17 malicious, 7 benign, 1 uncertain) plus helper files for the multi-file cases covering the honeypot families seen in the wild — sell revert, owner blacklist, switchable selling, uncapped sell tax, hidden mint, fake renounce + `unlock()`, approval backdoor, external "guard" contract, balance rewrite, max-sell-to-zero, a full reflection-token clone with `bots[]` + `setSellTax`, an open-drain wallet, a multi-file project whose token file is spotless but whose imported `lib/ERC20.sol` skips allowances for the deployer, and four fully identifier-obfuscated variants — and benign controls that *look* similar (fair tax token with capped fees and a one-way launch gate, capped owner mint, OpenZeppelin-style token with unresolved imports, vesting, staking).

```
$ npm test
25 passed, 0 failed
```

## Limitations (honest ones)

- Imports that cannot be resolved inside the input tree (e.g. `@openzeppelin/...` with no `node_modules`) are modeled by their well-known names (`_balances`, `onlyOwner`, …) but not analyzed. `UNRESOLVED_BASE` is emitted and `imports.unresolved` lists them so the grader can see it.
- No data-flow across storage slots or assembly. Inline `assembly { sstore(...) }` tricks are out of scope for v0.1.
- Heuristics for parameter roles (`from`/`to`/`amount`) use names first, positions second.

## Beyond the CLI

The same engine is exported as a library (`import { scanFile } from "noexit"`), so a dApp or wallet can fetch verified source for the `to` address of a pending transaction and run exactly this analysis before showing the signature prompt — the "pre-flight check" this project started from.

## License

MIT
