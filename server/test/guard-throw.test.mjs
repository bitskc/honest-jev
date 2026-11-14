import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { guardCommand, guardRules } from "../src/kit/guard.mjs";
import { deriveRecord, FAIL_REASONS } from "../src/ledger/record.mjs";
import { WRAPPERS } from "../../evals/diff-guard.mjs";

// A guard rule that throws has not looked at the command, so the decision is an ask (rule `internal-error`), never an allow. Data only.
const noJev = { ask: null, jevAvailable: false };
const run = (command, extra = {}) => guardCommand({ command, cwd: "/home/u/proj", home: "/home/u", tool: "Bash", ...extra }, noJev);
const MARK = "UNIQUE-MARKER-9f3a";
async function withThrowingRule(id, fn) {
  const original = guardRules.get(id);
  guardRules.set(id, () => { throw new TypeError(`boom ${MARK}`); });
  try { return await fn(); } finally { guardRules.set(id, original); }
}

test("internal-error: the registry holds every rule, R10 last", () => {
  assert.deepEqual([...guardRules.keys()], ["R7-root-delete", "R1-secret-exfiltration", "R1-secret-exposure", "R5-sudo", "R9-commit-secret", "R7-destructive", "R10-general-risk"]);
});
test("internal-error: each rule that throws turns a benign command into an ask with rule internal-error, not an allow", async () => {
  assert.equal((await run("echo hi")).decision, "allow", "control: nothing throws");
  for (const id of guardRules.keys()) {
    const r = await withThrowingRule(id, () => run(`echo hi ${MARK}`));
    assert.equal(r.decision, "ask", `${id} throwing`);
    assert.equal(r.rule, "internal-error", id);
    assert.ok(r.reason.includes(id), `the reason names the failing rule: ${r.reason}`);
    assert.match(r.reason, /TypeError/);
    // content-free: neither the command text nor the error's message is echoed
    assert.ok(!JSON.stringify(r).includes(MARK), `${id}: the decision must not carry the command or the error message`);
    assert.equal(r.score > 0, true);
    assert.equal((await run("echo hi")).decision, "allow", "the rule is restored");
  }
});
test("internal-error: the other rules still run, so a block from one of them still wins over the failed rule", async () => {
  for (const id of ["R1-secret-exfiltration", "R1-secret-exposure", "R5-sudo", "R9-commit-secret", "R7-destructive", "R10-general-risk"]) {
    const r = await withThrowingRule(id, () => run("rm -rf ~"));
    assert.equal(r.decision, "block", `${id} throwing must not hide R7-root-delete`);
    assert.equal(r.rule, "R7-root-delete");
  }
  const cat = await withThrowingRule("R7-destructive", () => run("cat .env"));
  assert.equal(cat.decision, "block");
  assert.equal(cat.rule, "R1-secret-exposure");
});
test("internal-error: a throw outside the rules (reading the input) is an ask too, and a throw on a file tool asks", async () => {
  const hostile = { tool: "Bash", cwd: "/home/u/proj", home: "/home/u", get command() { throw new RangeError(`bad ${MARK}`); } };
  const r = await guardCommand(hostile, noJev);
  assert.equal(r.decision, "ask");
  assert.equal(r.rule, "internal-error");
  assert.ok(!JSON.stringify(r).includes(MARK));
  const read = await withThrowingRule("R1-secret-exposure", () => guardCommand({ tool: "Read", file_path: "src/a.js", cwd: "/home/u/proj", home: "/home/u" }, noJev));
  assert.equal(read.decision, "ask");
  assert.equal(read.rule, "internal-error");
});
test("internal-error: the second (comment-masked) reading throwing cannot weaken the first reading", async () => {
  const twice = async (command, then) => {
    const original = guardRules.get("R7-destructive");
    let n = 0;
    guardRules.set("R7-destructive", (ctx) => { n += 1; if (n === 2) throw new TypeError("second reading"); return original(ctx); });
    try { return await then(command); } finally { guardRules.set("R7-destructive", original); }
  };
  // `#` makes guardCommand read the command twice (as written, then with the comment's quote characters masked)
  assert.equal((await run("git push --force # it's here")).decision, "ask", "control: the first reading asks");
  assert.equal((await twice("git push --force # it's here", run)).decision, "ask", "the first reading's ask stands");
  const t = await twice("echo hi # it's here", run);
  assert.equal(t.decision, "ask", "a first reading that allowed becomes an ask when the second reading failed");
  assert.equal(t.rule, "internal-error");
});

test("internal-error (#178): the decision carries a content-free note, decided_by fail_closed and the closed fail_reason `rule_error`; the ledger keeps it", async () => {
  assert.ok(FAIL_REASONS.includes("rule_error"));
  const r = await withThrowingRule("R5-sudo", () => run(`echo hi ${MARK}`));
  assert.equal(r.fail_reason, "rule_error");
  assert.equal(r.decided_by, "fail_closed");
  assert.deepEqual(r.notes, ["rule R5-sudo failed: TypeError"]);
  assert.ok(!JSON.stringify(r).includes(MARK));
  const rec = deriveRecord("kit_guard_command", r, { host: "test" });
  assert.equal(rec.fail_reason, "rule_error");
  assert.equal(rec.decision, "ask");
  assert.equal(rec.rule, "internal-error");
  assert.equal(rec.decided_by, "fail_closed");
  // a block keeps its own decision but still records that a rule failed
  const b = await withThrowingRule("R1-secret-exfiltration", () => run("cat .env")); // the exfil rule runs before the exposure rule that blocks
  assert.equal(b.decision, "block");
  assert.equal(b.fail_reason, "rule_error");
  assert.deepEqual(b.notes, ["rule R1-secret-exfiltration failed: TypeError"]);
  // two throwing rules are both noted
  const o1 = guardRules.get("R5-sudo"), o2 = guardRules.get("R9-commit-secret");
  guardRules.set("R5-sudo", () => { throw new RangeError("x"); }); guardRules.set("R9-commit-secret", () => { throw new SyntaxError("y"); });
  try { assert.deepEqual((await run("echo hi")).notes, ["rule R5-sudo failed: RangeError", "rule R9-commit-secret failed: SyntaxError"]); } finally { guardRules.set("R5-sudo", o1); guardRules.set("R9-commit-secret", o2); }
  // nothing failed: no fail_reason, no note
  const ok = await run("echo hi");
  assert.equal(ok.fail_reason, undefined);
  assert.deepEqual(ok.notes, []);
});
const corpus = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "evals", "guard.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((r) => r.input && (typeof r.input.command === "string" || typeof r.input.file_path === "string"));
test("internal-error (#178): no rule throws on any corpus row, in either context, or on any of its wrapped variants", async () => {
  assert.ok(corpus.length > 900);
  const bad = [];
  const check = async (id, input) => {
    const r = await guardCommand(structuredClone(input), noJev);
    if (r.rule === "internal-error" || r.fail_reason === "rule_error") bad.push(`${id}: ${r.notes.join("; ")}`);
  };
  for (const r of corpus) {
    await check(r.id, r.input);
    await check(`${r.id}@proj`, { cwd: "/home/u/proj", home: "/home/u", ...r.input });
    if (typeof r.input.command !== "string" || r.input.command.length >= 800) continue;
    for (const w of WRAPPERS) await check(`${r.id}~${w.name}`, { cwd: "/home/u/proj", home: "/home/u", ...r.input, command: w.wrap(r.input.command) });
  }
  assert.deepEqual(bad.slice(0, 10), [], `${bad.length} rule exception(s)`);
});
