// Cheap "would this even compile?" checks. noexit never needs solc, but a file that cannot compile cannot be
// deployed, so its verdict is Uncertain (with the reason) rather than a confident Malicious/Benign.
// Only errors we can prove from the AST alone: identifiers that are declared nowhere, and duplicate declarations.
import { Node, walk } from "./ast";

const BUILTINS = new Set([
  "msg", "tx", "block", "this", "super", "now", "abi", "type", "require", "assert", "revert", "keccak256", "sha3", "sha256", "ripemd160", "ecrecover",
  "addmod", "mulmod", "selfdestruct", "suicide", "blockhash", "gasleft", "payable", "address", "bool", "string", "bytes", "byte", "int", "uint", "fixed", "ufixed",
  "true", "false", "wei", "gwei", "szabo", "finney", "ether", "seconds", "minutes", "hours", "days", "weeks", "years", "_", "unicode", "hex",
  "gas", "value", "length", "push", "pop", "balance", "transfer", "send", "call", "delegatecall", "staticcall", "callcode", "code", "codehash",
  "error", "assembly", "log0", "log1", "log2", "log3", "log4", "sender", "origin", "data", "sig", "timestamp", "number", "coinbase", "difficulty", "gaslimit", "chainid", "basefee", "prevrandao", "blobbasefee", "gasprice",
]);
const TYPE_RE = /^(u?int(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?|bytes([1-9]|[12][0-9]|3[0-2])?|u?fixed[0-9x]*)$/;

export interface DeployCheck { ok: boolean; reasons: string[] }

/** Walks every contract in a source unit (with its known bases available through `allContracts`) and reports undeclared / duplicate names. */
export function deployable(ast: Node, allContracts: Map<string, Node>, hasUnresolvedImports: boolean): DeployCheck {
  const reasons: string[] = [];
  if (!ast) return { ok: true, reasons };
  // file-level names: contracts, libraries, interfaces, free functions, top-level constants/structs/enums/errors/user types, import aliases
  const fileNames = new Set<string>([...allContracts.keys()]);
  for (const c of ast.children ?? []) {
    if (!c) continue;
    if (c.type === "ContractDefinition") fileNames.add(c.name);
    if (c.type === "ImportDirective") { if (c.unitAlias) fileNames.add(c.unitAlias); for (const s of c.symbolAliases ?? []) { const [orig, alias] = s; fileNames.add(alias ?? orig); } }
    for (const k of ["FunctionDefinition", "StructDefinition", "EnumDefinition", "CustomErrorDefinition", "TypeDefinition", "StateVariableDeclaration", "FileLevelConstant"]) if (c.type === k) { if (c.name) fileNames.add(c.name); for (const v of c.variables ?? []) if (v?.name) fileNames.add(v.name); }
  }
  const contracts = (ast.children ?? []).filter((c: Node) => c?.type === "ContractDefinition");
  for (const c of contracts) {
    // linearize bases we know about; if any base is unknown, this contract's names are unknowable -> skip
    const chain: Node[] = []; const seen = new Set<string>(); let unknownBase = false;
    const visit = (n: Node) => {
      if (!n || seen.has(n.name)) return; seen.add(n.name); chain.push(n);
      for (const b of n.baseContracts ?? []) { const bn = allContracts.get(b.baseName?.namePath); if (bn) visit(bn); else unknownBase = true; }
    };
    visit(c);
    if (unknownBase || hasUnresolvedImports) continue;
    const declared = new Set<string>(fileNames);
    const dupState = new Map<string, number>();
    for (const cn of chain) for (const sn of cn.subNodes ?? []) {
      if (!sn) continue;
      if (sn.type === "StateVariableDeclaration") for (const v of sn.variables ?? []) if (v?.name) { declared.add(v.name); if (cn === c) dupState.set(v.name, (dupState.get(v.name) ?? 0) + 1); }
      if (sn.type === "FunctionDefinition" && sn.name) declared.add(sn.name);
      if (sn.type === "ModifierDefinition" && sn.name) declared.add(sn.name);
      if (sn.type === "EventDefinition" && sn.name) declared.add(sn.name);
      if (sn.type === "StructDefinition" && sn.name) declared.add(sn.name);
      if (sn.type === "EnumDefinition" && sn.name) declared.add(sn.name);
      if (sn.type === "CustomErrorDefinition" && sn.name) declared.add(sn.name);
      if (sn.type === "TypeDefinition" && sn.name) declared.add(sn.name);
      if (sn.type === "UsingForDeclaration" && sn.libraryName) declared.add(sn.libraryName);
    }
    for (const [name, n] of dupState) if (n > 1) reasons.push(`${c.name}: state variable '${name}' declared ${n} times`);
    // per function: params, returns, locals (anywhere in the body - Solidity <0.5 hoists, and we do not want scope false positives)
    for (const sn of c.subNodes ?? []) {
      if (!sn || (sn.type !== "FunctionDefinition" && sn.type !== "ModifierDefinition") || !sn.body) continue;
      const local = new Set<string>(declared);
      for (const p of [...(sn.parameters ?? []), ...(sn.returnParameters ?? [])]) if (p?.name) local.add(p.name);
      walk(sn.body, (n) => {
        if (n.type === "VariableDeclaration" && n.name) local.add(n.name);
        if (n.type === "VariableDeclarationStatement") for (const v of n.variables ?? []) if (v?.name) local.add(v.name);
        if (n.type === "InlineAssemblyStatement") { walk(n.body, (a) => { if (a.type === "AssemblyLocalDefinition") for (const nm of a.names ?? []) if (nm?.name) local.add(nm.name); }); }
        if (n.type === "CatchClause") for (const p of n.parameters ?? []) if (p?.name) local.add(p.name);
      });
      const missing = new Set<string>();
      walk(sn.body, (n, parent) => {
        if (n.type === "InlineAssemblyStatement") return false; // yul has its own scoping and builtins
        if (n.type !== "Identifier") return;
        if (parent?.type === "MemberAccess" && parent.expression !== n) return; // member names
        if (parent?.type === "NameValueList" || parent?.type === "NameValueExpression") return;
        if (parent?.type === "FunctionCall" && (parent.identifiers ?? []).includes(n)) return; // struct literal / named-arg keys: Pool({lpToken: x})
        const nm = n.name;
        if (local.has(nm) || BUILTINS.has(nm) || TYPE_RE.test(nm)) return;
        missing.add(nm);
      });
      for (const m of missing) { reasons.push(`${c.name}.${sn.name || "fallback"}: undeclared identifier '${m}'`); if (reasons.length > 5) break; }
    }
  }
  return { ok: reasons.length === 0, reasons };
}
