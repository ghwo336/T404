// Regression test: every sample under samples/<verdict>/ must be classified as that verdict.
import * as path from "node:path";
import { scan } from "../src/scan";

const root = path.join(__dirname, "..", "samples");
const expected: Record<string, string> = { malicious: "Malicious", benign: "Benign", uncertain: "Uncertain" };
const report = scan([root]);
let pass = 0, fail = 0;
for (const f of report.files) {
  const folder = path.relative(root, f.file).split(path.sep)[0];
  const want = expected[folder];
  if (f.role === "library") continue; // imported helper files are not judged on their own
  const ok = f.verdict === want;
  if (ok) pass++; else fail++;
  console.log(`${ok ? "PASS" : "FAIL"}  want=${want.padEnd(9)} got=${f.verdict.padEnd(9)} ${path.relative(root, f.file)}  ${ok ? "" : "-> " + f.summary}`);
}
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
