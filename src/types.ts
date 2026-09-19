export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Verdict = "Malicious" | "Uncertain" | "Benign";

export interface Location {
  file: string;
  line: number;
  column: number;
  endLine?: number;
  contract?: string;
  function?: string;
  snippet?: string;
}

export interface Finding {
  id: string; // rule id, e.g. SELL_RESTRICTION
  title: string;
  severity: Severity;
  confidence: number; // 0..1
  location: Location;
  evidence: string; // what in the code triggered it
  reasoning: string; // why this is dangerous (logic / privilege explanation)
  related?: Location[];
}

export interface ContractReport {
  name: string;
  kind: string;
  bases: string[];
  privilegedFunctions: string[];
  transferPath: string[];
  findings: Finding[];
}

export interface FileReport {
  file: string;
  verdict: Verdict;
  score: number;
  parseErrors: string[];
  contracts: ContractReport[];
  findings: Finding[]; // flattened, sorted by severity
  summary: string;
}

export interface ScanReport {
  tool: string;
  version: string;
  generatedAt: string;
  inputs: string[];
  totals: { files: number; malicious: number; uncertain: number; benign: number; errors: number };
  files: FileReport[];
}
