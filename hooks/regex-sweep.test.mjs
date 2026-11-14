import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { extractRegexLiterals, nestedQuantifierGroups, sweepRegex } from "../server/test/helpers/regex-scan.mjs";
import { REVIEWED_NESTED } from "../server/test/helpers/reviewed-nested.mjs";

// The hooks ship their own copies of the server's rules and run on every Stop and PreToolUse, under a hard timeout that fails
// open. This is the same adversarial sweep server/test/regex-sweep.test.mjs runs over the kit, over every regex literal in the
// hook sources (it found `(?:NAME=\S*\s*)+$`, exponential on `a=` x28 + ` b`, in the hook's copy of the verify rules).
// Data only: every string is handed to a regex; nothing is executed.
const here = dirname(fileURLToPath(import.meta.url));
const FILES = ["jev-stop-verify.js", "jev-redact.js", "honest/jev-honest-runtime.js", "honest/jev-honest-activate.js", "honest/jev-honest-mode-tracker.js", "honest/jev-honest-subagent.js"].map((f) => join(here, f));
const EXP_BOUND_MS = 150;
const POLY_BOUND_MS = 1000;
const literals = FILES.flatMap((file) => extractRegexLiterals(readFileSync(file, "utf8")).map((l) => ({ ...l, file: file.slice(here.length + 1) })));
const unique = [...new Map(literals.map((l) => [`${l.source}/${l.flags}`, l])).values()];

test("the hook regex extractor finds the hooks' literals", () => {
  assert.ok(literals.length >= 120, `only ${literals.length} regex literals found`);
  for (const f of ["jev-stop-verify.js", "jev-redact.js", "honest/jev-honest-runtime.js"]) assert.ok(literals.some((l) => l.file === f), `${f}: none found`);
});

test("every regex literal in the hooks survives adversarial pumps built from its own characters", () => {
  const failures = [];
  for (const re of unique) {
    try { new RegExp(re.source, re.flags); } catch { continue; }
    const r = sweepRegex(re);
    if (r.error) failures.push(`${re.file}:${re.line} threw ${r.error}`);
    if (r.exp.ms > EXP_BOUND_MS) failures.push(`${re.file}:${re.line} ${re.source.slice(0, 90)}  EXPONENTIAL-STYLE ${r.exp.timedOut ? "(interrupted)" : r.exp.ms.toFixed(0) + " ms"} on ${r.exp.label}`);
    if (r.poly.ms > POLY_BOUND_MS) failures.push(`${re.file}:${re.line} ${re.source.slice(0, 90)}  SUPER-LINEAR ${r.poly.timedOut ? "(interrupted)" : r.poly.ms.toFixed(0) + " ms"} on ${r.poly.label}`);
  }
  assert.deepEqual(failures, [], `\n${failures.join("\n")}`);
});

test("every hook regex that repeats a group containing another quantifier or an alternation is on the reviewed list", () => {
  const unreviewed = unique.filter((l) => nestedQuantifierGroups(l.source).length > 0 && !REVIEWED_NESTED.has(l.source)).map((l) => `${l.file}:${l.line} ${l.source}`);
  assert.deepEqual(unreviewed, [], `read each for ambiguity, time it, then add it to server/test/helpers/reviewed-nested.mjs with the reason:\n${unreviewed.join("\n")}`);
});

test("the old assignment-run regex is exponential and the shipped one is not (both copies)", async () => {
  const old = { source: "^(?:[A-Za-z_]\\w*\\+?=\\S*\\s*)+$", flags: "" };
  const bad = sweepRegex(old, { timeoutMs: 1000 });
  assert.ok(bad.exp.timedOut || bad.exp.ms > EXP_BOUND_MS, `the old regex was not flagged: ${JSON.stringify(bad.exp)}`);
  const server = await import("../server/src/kit/verify.mjs");
  const hook = (await import("node:module")).createRequire(import.meta.url)("./jev-stop-verify.js");
  const cpu = () => { const u = process.cpuUsage(); return (u.user + u.system) / 1000; };
  for (const n of [28, 60, 300]) {
    const cmd = `${"a=".repeat(n)} b`;
    for (const [name, fn] of [["server exitIsMasked", () => server.exitIsMasked(cmd)], ["hook exitIsMasked", () => hook.exitIsMasked(cmd)], ["server runOutcome", () => server.runOutcome(cmd, "", 0)], ["hook runOutcome", () => hook.runOutcome(cmd, "", 0)],
      ["server env prefix", () => server.exitIsMasked(`${"a=1 ".repeat(n)}npm test`)], ["hook env prefix", () => hook.exitIsMasked(`${"a=1 ".repeat(n)}npm test`)]]) {
      const t0 = cpu();
      fn();
      const ms = cpu() - t0;
      assert.ok(ms < 300, `${name} on ${n} assignments used ${ms.toFixed(0)} ms CPU`);
    }
  }
});
