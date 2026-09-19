import { Node, walk, collect, baseName, identifiers, isMsgSender, isCallTo, calleeName, typeString, isSuperCall } from "./ast";

export interface StateVar {
  name: string;
  contract: string;
  node: Node;
  typeStr: string;
  isMapping: boolean;
  isConstant: boolean;
  keyType?: string;
  valueType?: string; // for mapping: innermost value type
  depth?: number; // mapping nesting depth
}

export interface Modifier {
  name: string;
  contract: string;
  node: Node;
  privileged: boolean;
  reason: string;
}

export interface Assign {
  node: Node; // assignment / unary node
  target: Node; // lvalue
  base: string;
  operator: string;
  value?: Node;
}

export interface Func {
  name: string;
  contract: string; // defining contract
  node: Node;
  visibility: string;
  mutability: string | null;
  modifiers: string[];
  isConstructor: boolean;
  params: string[];
  privileged: boolean;
  privilegeReason: string;
  writes: Assign[];
  reads: Set<string>;
  calls: Set<string>;
  callsSuper: boolean;
}

export interface Contract {
  name: string;
  kind: string;
  node: Node;
  bases: string[];
  unknownBases: string[];
  stateVars: Map<string, StateVar>;
  modifiers: Map<string, Modifier>;
  functions: Map<string, Func>; // resolved (derived overrides base)
  allFunctions: Func[]; // every definition incl. overridden
  ownerVars: Set<string>;
  balanceVars: Set<string>;
  allowanceVars: Set<string>;
  supplyVars: Set<string>;
  pairVars: Set<string>;
  pairMaps: Set<string>;
  transferPath: Set<string>;
  privilegedFunctions: Func[];
}

export const TRANSFER_FN = /^_?(transfer|transferFrom|_?update|_?beforeTokenTransfer|_?afterTokenTransfer|_?transferStandard|_?tokenTransfer|_?transferTokens|_?basicTransfer|_?transferFrom|_?standardTransfer|_?transferToExcluded|_?transferFromExcluded|_?transferBothExcluded|_?takeFee|_?takeTax|_?swapAndLiquify|_?move|_?send)$/i;
export const PRIV_MODIFIER_NAME = /^(only|auth|admin|restricted|governance|operator|isAuthorized|whenOwner|ownerOnly|byOwner)/i;
export const OWNERISH_NAME = /(owner|admin|deployer|governance|operator|authority|dev|team|creator|marketingwallet|taxwallet|feewallet|treasury|controller|manager|master|root|god)/i;
export const PAIR_NAME = /(pair|pool|lp$|amm|liquidity|dex|router)/i;
export const BALANCE_NAME = /(balance|owned|_r|_t|holding)/i;

function stateVarFromNode(n: Node, contract: string): StateVar {
  const t = n.typeName;
  let depth = 0, keyType: string | undefined, valueType: string | undefined;
  let cur = t;
  while (cur?.type === "Mapping") {
    depth++;
    if (!keyType) keyType = typeString(cur.keyType);
    cur = cur.valueType;
  }
  if (depth) valueType = typeString(cur);
  return {
    name: n.name,
    contract,
    node: n,
    typeStr: typeString(t),
    isMapping: depth > 0,
    isConstant: !!(n.isDeclaredConst || n.isImmutable),
    keyType,
    valueType,
    depth,
  };
}

const ASSIGN_OPS = new Set(["=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>="]);

export function collectWrites(body: Node): Assign[] {
  const out: Assign[] = [];
  walk(body, (n) => {
    if (n.type === "BinaryOperation" && ASSIGN_OPS.has(n.operator)) {
      const targets = n.left?.type === "TupleExpression" ? n.left.components : [n.left];
      for (const t of targets) {
        if (!t) continue;
        const b = baseName(t);
        if (b) out.push({ node: n, target: t, base: b, operator: n.operator, value: n.right });
      }
    } else if (n.type === "UnaryOperation" && (n.operator === "++" || n.operator === "--" || n.operator === "delete")) {
      const b = baseName(n.subExpression);
      if (b) out.push({ node: n, target: n.subExpression, base: b, operator: n.operator });
    }
  });
  return out;
}

/** Does this condition compare msg.sender against something "owner-like" (not a function param)? */
export function isPrivilegeCheck(cond: Node, params: Set<string>, ownerVars: Set<string>): string | null {
  let found: string | null = null;
  walk(cond, (n, parent) => {
    if (found) return false;
    if (n.type === "BinaryOperation" && (n.operator === "==" || n.operator === "!=")) {
      const sides = [n.left, n.right];
      for (let i = 0; i < 2; i++) {
        if (isMsgSender(sides[i])) {
          const other = sides[1 - i];
          const ids = identifiers(other);
          if (other.type === "Identifier" && params.has(other.name)) continue; // msg.sender == from  -> not privilege
          if (other.type === "FunctionCall" && /^(owner|getOwner|_owner|admin|getAdmin)$/i.test(calleeName(other) ?? "")) { found = `msg.sender vs ${calleeName(other)}()`; return false; }
          if (other.type === "Identifier" && (ownerVars.has(other.name) || OWNERISH_NAME.test(other.name))) { found = `msg.sender vs ${other.name}`; return false; }
          if (other.type === "NumberLiteral" || (other.type === "FunctionCall" && (other.expression?.type === "ElementaryTypeName" || other.expression?.type === "Identifier") && other.expression.name === "address" && (other.arguments?.[0]?.type === "NumberLiteral" || other.arguments?.[0]?.type === "HexLiteral"))) { found = "msg.sender vs hard-coded address"; return false; }
          if (other.type === "MemberAccess" && other.memberName === "origin") continue; // msg.sender == tx.origin: anti-contract, not privilege
          if (ids.length && !ids.some((id) => params.has(id))) { found = `msg.sender vs ${ids.join(".")}`; return false; }
        }
      }
    }
    // mapping check: require(isAdmin[msg.sender]) / authorized[msg.sender]
    const boolContext = !parent || parent.type === "UnaryOperation" || (parent.type === "BinaryOperation" && (parent.operator === "&&" || parent.operator === "||")) || parent.type === "FunctionCall" || parent.type === "IfStatement";
    if (n.type === "IndexAccess" && isMsgSender(n.index) && boolContext) {
      const b = baseName(n.base);
      if (b && !/(excluded|exempt|whitelist|blacklist|isBot|bots|blocked|frozen|balance|owned|allow|nonces|cooldown|lastBuy|lastTx|holder|deposit|stake|share|debt|reward|claimed|minted|locked|vest|purchas|contribut|entered|voted|registered|used)/i.test(b)) {
        found = `${b}[msg.sender]`;
        return false;
      }
    }
  });
  return found;
}

function modifierPrivileged(m: Node, ownerVars: Set<string>): string | null {
  const params = new Set<string>((m.parameters ?? []).map((p: Node) => p.name));
  let reason: string | null = null;
  walk(m.body, (n) => {
    if (reason) return false;
    if (isCallTo(n, ["require"]) && n.arguments?.[0]) {
      const r = isPrivilegeCheck(n.arguments[0], params, ownerVars);
      if (r) reason = `require(${r})`;
    } else if (n.type === "IfStatement") {
      const r = isPrivilegeCheck(n.condition, params, ownerVars);
      const hasRevert = collect(n.trueBody, (x) => x.type === "RevertStatement" || isCallTo(x, ["revert"])).length > 0 || collect(n.falseBody, (x) => x.type === "RevertStatement" || isCallTo(x, ["revert"])).length > 0;
      if (r && hasRevert) reason = `if(${r}) revert`;
    } else if (isCallTo(n, ["_checkOwner", "_onlyOwner", "_checkRole", "checkRole", "_checkAdmin", "onlyOwner", "_authorizeUpgrade", "_requireOwner", "requireOwner"])) {
      reason = `${calleeName(n)}()`;
    }
  });
  if (!reason && PRIV_MODIFIER_NAME.test(m.name)) reason = `modifier name '${m.name}' (body not conclusive)`;
  return reason;
}

function funcPrivilege(f: Node, mods: Map<string, Modifier>, ownerVars: Set<string>, unknownMods: Set<string>): string {
  for (const m of f.modifiers ?? []) {
    const md = mods.get(m.name);
    if (md?.privileged) return `modifier ${m.name}: ${md.reason}`;
    if (!md && PRIV_MODIFIER_NAME.test(m.name)) { unknownMods.add(m.name); return `modifier ${m.name} (defined outside analyzed files, name implies access control)`; }
    if (!md && /^onlyRole$/i.test(m.name)) return `modifier onlyRole`;
  }
  const params = new Set<string>((f.parameters ?? []).map((p: Node) => p.name));
  let reason = "";
  walk(f.body, (n) => {
    if (reason) return false;
    if (isCallTo(n, ["require"]) && n.arguments?.[0]) {
      const r = isPrivilegeCheck(n.arguments[0], params, ownerVars);
      if (r) reason = `inline require(${r})`;
    } else if (n.type === "IfStatement") {
      const r = isPrivilegeCheck(n.condition, params, ownerVars);
      if (r) {
        const hasRevert = collect(n.trueBody, (x) => x.type === "RevertStatement" || isCallTo(x, ["revert"])).length > 0;
        if (hasRevert) reason = `inline if(${r}) revert`;
      }
    } else if (isCallTo(n, ["_checkOwner", "_onlyOwner", "_checkRole", "_requireOwner", "requireOwner", "_checkAdmin"])) {
      reason = `${calleeName(n)}()`;
    }
  });
  return reason;
}

export function buildModels(sourceUnits: { file: string; ast: Node }[]): Contract[] {
  // 1. index raw contract definitions across all files
  const raw = new Map<string, { node: Node; file: string }>();
  for (const su of sourceUnits) {
    for (const c of su.ast.children ?? []) {
      if (c.type === "ContractDefinition") raw.set(c.name, { node: c, file: su.file });
    }
  }

  const built = new Map<string, Contract>();

  function linearize(name: string, seen = new Set<string>()): string[] {
    // returns [base..., name]  (depth-first, bases first, left to right, deduped)
    if (seen.has(name)) return [];
    seen.add(name);
    const r = raw.get(name);
    if (!r) return [];
    const out: string[] = [];
    for (const b of r.node.baseContracts ?? []) {
      for (const x of linearize(b.baseName.namePath, seen)) if (!out.includes(x)) out.push(x);
    }
    out.push(name);
    return out;
  }

  for (const [name, { node }] of raw) {
    const chain = linearize(name);
    const c: Contract = {
      name,
      kind: node.kind,
      node,
      bases: (node.baseContracts ?? []).map((b: Node) => b.baseName.namePath),
      unknownBases: [],
      stateVars: new Map(),
      modifiers: new Map(),
      functions: new Map(),
      allFunctions: [],
      ownerVars: new Set(),
      balanceVars: new Set(),
      allowanceVars: new Set(),
      supplyVars: new Set(),
      pairVars: new Set(),
      pairMaps: new Set(),
      transferPath: new Set(),
      privilegedFunctions: [],
    };
    c.unknownBases = c.bases.filter((b) => !raw.has(b));

    // state vars + modifiers across chain (base first, derived overrides)
    for (const cn of chain) {
      const cnode = raw.get(cn)!.node;
      for (const sn of cnode.subNodes ?? []) {
        if (sn.type === "StateVariableDeclaration") {
          for (const v of sn.variables ?? []) c.stateVars.set(v.name, stateVarFromNode(v, cn));
        }
      }
    }
    // classify state vars
    for (const v of c.stateVars.values()) {
      if (v.isMapping && v.depth === 1 && v.keyType === "address" && /^uint/.test(v.valueType ?? "") && BALANCE_NAME.test(v.name) && !/(fee|tax|time|block|last|cooldown|nonce|limit|max|min|amount|count|lock|stake|reward|debt|price)/i.test(v.name)) c.balanceVars.add(v.name);
      if (v.isMapping && v.depth === 2 && v.keyType === "address" && /^uint/.test(v.valueType ?? "")) c.allowanceVars.add(v.name);
      if (!v.isMapping && /^uint/.test(v.typeStr) && /supply/i.test(v.name) && !/max|cap|initial|limit/i.test(v.name)) c.supplyVars.add(v.name);
      if (!v.isMapping && v.typeStr === "address" && OWNERISH_NAME.test(v.name) && !/(pair|pool|router|factory|token|weth)/i.test(v.name)) c.ownerVars.add(v.name);
      if (v.typeStr === "address" && PAIR_NAME.test(v.name) && !/router|factory/i.test(v.name)) c.pairVars.add(v.name);
      if (v.isMapping && v.depth === 1 && v.valueType === "bool" && /(pair|amm|marketmaker|pool)/i.test(v.name)) c.pairMaps.add(v.name);
    }
    if (c.unknownBases.some((b) => /^(ERC20|ERC20Upgradeable|BEP20|ERC20Burnable)$/i.test(b))) {
      if (!c.balanceVars.size) c.balanceVars.add("_balances");
      if (!c.allowanceVars.size) c.allowanceVars.add("_allowances");
      if (!c.supplyVars.size) c.supplyVars.add("_totalSupply");
    }
    if (c.unknownBases.some((b) => /^(Ownable|Ownable2Step|OwnableUpgradeable|Owned|Auth)$/i.test(b))) {
      if (!c.ownerVars.size) c.ownerVars.add("_owner");
    }

    // modifiers
    for (const cn of chain) {
      const cnode = raw.get(cn)!.node;
      for (const sn of cnode.subNodes ?? []) {
        if (sn.type === "ModifierDefinition") {
          const reason = modifierPrivileged(sn, c.ownerVars);
          c.modifiers.set(sn.name, { name: sn.name, contract: cn, node: sn, privileged: !!reason, reason: reason ?? "" });
          if (reason) {
            // any identifier compared with msg.sender inside is owner-like
            for (const id of identifiers(sn.body)) if (c.stateVars.get(id)?.typeStr === "address") c.ownerVars.add(id);
          }
        }
      }
    }

    // functions
    const unknownMods = new Set<string>();
    for (const cn of chain) {
      const cnode = raw.get(cn)!.node;
      for (const sn of cnode.subNodes ?? []) {
        if (sn.type !== "FunctionDefinition") continue;
        const isCtor = !!sn.isConstructor || sn.name === null && !sn.isFallback && !sn.isReceiveEther && sn.kind === "constructor";
        const name = sn.name ?? (sn.isFallback ? "fallback" : sn.isReceiveEther ? "receive" : "constructor");
        const params = (sn.parameters ?? []).map((p: Node) => p.name).filter(Boolean);
        const f: Func = {
          name,
          contract: cn,
          node: sn,
          visibility: sn.visibility ?? "default",
          mutability: sn.stateMutability ?? null,
          modifiers: (sn.modifiers ?? []).map((m: Node) => m.name),
          isConstructor: isCtor || name === "constructor",
          params,
          privileged: false,
          privilegeReason: "",
          writes: sn.body ? collectWrites(sn.body) : [],
          reads: new Set(sn.body ? identifiers(sn.body) : []),
          calls: new Set(),
          callsSuper: false,
        };
        if (sn.body) {
          walk(sn.body, (n) => {
            if (n.type === "FunctionCall") {
              const cn2 = calleeName(n);
              if (cn2) f.calls.add(cn2);
              if (isSuperCall(n)) f.callsSuper = true;
            }
          });
        }
        if (!f.isConstructor) {
          f.privilegeReason = funcPrivilege(sn, c.modifiers, c.ownerVars, unknownMods);
          f.privileged = !!f.privilegeReason;
        }
        c.allFunctions.push(f);
        c.functions.set(name, f); // derived overrides base (chain is base-first)
      }
    }
    c.privilegedFunctions = [...c.functions.values()].filter((f) => f.privileged);

    // transfer path: name-based seeds + writers of balance vars, then internal callee closure
    const seeds = new Set<string>();
    for (const f of c.functions.values()) {
      if (TRANSFER_FN.test(f.name)) seeds.add(f.name);
      if (f.writes.some((w) => c.balanceVars.has(w.base)) && !f.isConstructor && !f.privileged) seeds.add(f.name);
    }
    const q = [...seeds];
    while (q.length) {
      const n = q.shift()!;
      if (c.transferPath.has(n)) continue;
      c.transferPath.add(n);
      const f = c.functions.get(n);
      if (!f) continue;
      for (const callee of f.calls) if (c.functions.has(callee) && !c.transferPath.has(callee)) q.push(callee);
    }
    // late discovery of balance vars: mappings written inside the transfer path
    for (const fn of c.transferPath) {
      const f = c.functions.get(fn);
      if (!f) continue;
      for (const w of f.writes) {
        const v = c.stateVars.get(w.base);
        if (v?.isMapping && v.depth === 1 && v.keyType === "address" && /^uint/.test(v.valueType ?? "") && !/(fee|tax|time|block|last|cooldown|nonce|limit|max|min|count|lock)/i.test(v.name)) c.balanceVars.add(v.name);
      }
    }
    built.set(name, c);
  }
  return [...built.values()];
}

/** Which contract in the set is the "main" one: most derived, non-interface, non-library */
export function mainContracts(cs: Contract[]): Contract[] {
  const baseNames = new Set<string>();
  for (const c of cs) for (const b of c.bases) baseNames.add(b);
  const leaves = cs.filter((c) => c.kind === "contract" && !baseNames.has(c.name));
  return leaves.length ? leaves : cs.filter((c) => c.kind === "contract");
}
