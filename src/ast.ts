// Generic AST helpers over @solidity-parser/parser output.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type Node = any;

export function walk(node: Node, cb: (n: Node, parent: Node | null) => void | false, parent: Node | null = null): void {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const c of node) walk(c, cb, parent);
    return;
  }
  if (typeof node.type === "string") {
    if (cb(node, parent) === false) return;
    parent = node;
  }
  for (const key of Object.keys(node)) {
    if (key === "loc" || key === "range" || key === "parent") continue;
    const v = node[key];
    if (v && typeof v === "object") walk(v, cb, parent);
  }
}

export function collect(node: Node, pred: (n: Node) => boolean): Node[] {
  const out: Node[] = [];
  walk(node, (n) => {
    if (pred(n)) out.push(n);
  });
  return out;
}

export function identifiers(node: Node): string[] {
  const out: string[] = [];
  walk(node, (n) => {
    if (n.type === "Identifier") out.push(n.name);
  });
  return out;
}

/** Root identifier of an lvalue: `_balances[a][b]` -> _balances, `a.b` -> a */
export function baseName(node: Node): string | null {
  let n = node;
  while (n) {
    if (n.type === "Identifier") return n.name;
    if (n.type === "IndexAccess") n = n.base;
    else if (n.type === "MemberAccess") n = n.expression;
    else if (n.type === "TupleExpression" && n.components?.length === 1) n = n.components[0];
    else return null;
  }
  return null;
}

/** Index expressions of a mapping access: `m[a][b]` -> [a, b] */
export function indexChain(node: Node): Node[] {
  const idx: Node[] = [];
  let n = node;
  while (n && n.type === "IndexAccess") {
    idx.unshift(n.index);
    n = n.base;
  }
  return idx;
}

export function line(node: Node): number {
  return node?.loc?.start?.line ?? 0;
}
export function endLine(node: Node): number {
  return node?.loc?.end?.line ?? line(node);
}

export function isMsgSender(n: Node): boolean {
  return (
    n?.type === "MemberAccess" && n.memberName === "sender" && n.expression?.type === "Identifier" && n.expression.name === "msg"
  ) || (n?.type === "FunctionCall" && n.expression?.type === "Identifier" && n.expression.name === "_msgSender");
}

export function isTxOrigin(n: Node): boolean {
  return n?.type === "MemberAccess" && n.memberName === "origin" && n.expression?.name === "tx";
}

export function isCallTo(n: Node, names: string[]): boolean {
  if (n?.type !== "FunctionCall") return false;
  const e = n.expression;
  if (e?.type === "Identifier") return names.includes(e.name);
  if (e?.type === "MemberAccess") return names.includes(e.memberName);
  return false;
}

export function calleeName(n: Node): string | null {
  if (n?.type !== "FunctionCall") return null;
  const e = n.expression;
  if (e?.type === "Identifier") return e.name;
  if (e?.type === "MemberAccess") return e.memberName;
  return null;
}

export function isSuperCall(n: Node): boolean {
  return n?.type === "FunctionCall" && n.expression?.type === "MemberAccess" && n.expression.expression?.type === "Identifier" && n.expression.expression.name === "super";
}

export function numberValue(n: Node): number | null {
  if (n?.type === "NumberLiteral") {
    const v = Number(String(n.number).replace(/_/g, ""));
    if (Number.isNaN(v)) return null;
    const sub = n.subdenomination;
    const mult: Record<string, number> = { wei: 1, gwei: 1e9, ether: 1e18, seconds: 1, minutes: 60, hours: 3600, days: 86400, weeks: 604800 };
    return sub ? v * (mult[sub] ?? 1) : v;
  }
  if (n?.type === "BinaryOperation") {
    const l = numberValue(n.left), r = numberValue(n.right);
    if (l === null || r === null) return null;
    switch (n.operator) {
      case "+": return l + r;
      case "-": return l - r;
      case "*": return l * r;
      case "/": return r === 0 ? null : l / r;
      case "**": return l ** r;
    }
  }
  return null;
}

export function isZeroAddress(n: Node): boolean {
  if (n?.type === "FunctionCall" && ((n.expression?.type === "ElementaryTypeName" && n.expression.name === "address") || (n.expression?.type === "Identifier" && n.expression.name === "address"))) {
    const a = n.arguments?.[0];
    return (a?.type === "NumberLiteral" && Number(a.number) === 0) || (a?.type === "HexLiteral" && /^0x0*$/.test(a.value ?? ""));
  }
  if (n?.type === "NumberLiteral" && n.number === "0") return true;
  if (n?.type === "Identifier" && /^(ZERO|DEAD|BURN)/i.test(n.name)) return true;
  if (n?.type === "Identifier" && /(zero|dead|burn)address/i.test(n.name)) return true;
  return false;
}

export function typeString(t: Node): string {
  if (!t) return "?";
  switch (t.type) {
    case "ElementaryTypeName": return t.name;
    case "UserDefinedTypeName": return t.namePath;
    case "Mapping": return `mapping(${typeString(t.keyType)}=>${typeString(t.valueType)})`;
    case "ArrayTypeName": return `${typeString(t.baseTypeName)}[]`;
    default: return t.type;
  }
}

export function snippet(source: string, node: Node, maxLen = 160): string {
  if (!node?.range) return "";
  const s = source.slice(node.range[0], node.range[1] + 1).replace(/\s+/g, " ").trim();
  return s.length > maxLen ? s.slice(0, maxLen - 1) + "…" : s;
}
