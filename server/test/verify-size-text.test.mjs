// kit_verify_done and kit_size_dispatch say it short: one `reason` line (the Why), a `next` step on a block, no scores in the sentence.
// The `jev.detail` phrases the ledgers match with regexes stay verbatim (ledger/record.mjs, hooks/omp/jev-guard.ts, hooks/jev_ledger.py).
import test from "node:test";
import assert from "node:assert/strict";
import { verifyDone, nextStep } from "../src/kit/verify.mjs";
import { sizeDispatch } from "../src/kit/tier.mjs";

const noul = (n) => ({ type: "noul", noul: n });
const stub = (answers) => ({ jevAvailable: true, ask: async () => ({ answers, model: "stub", usage: {} }) });
const BLOCK = { claims_done: noul(0.95), claims_verified: noul(0.3), verification_applies: noul(0.9), discloses_unverified: noul(0.05), outcome: noul(0.9) };
const choice = (c, p = 0.95) => ({ type: "choice", choice: c, confidence: p, probabilities: { [c]: p, unclear: 1 - p } });

test("a blocked verify says why in one sentence (no scores) and what to do in `next`", async () => {
  const r = await verifyDone({ final_message: "Fixed, all tests pass.", task: "fix the bug", file_changes: 3, checks: [] }, stub(BLOCK));
  assert.equal(r.action, "block");
  assert.equal(r.reason, "reports done after 3 file changes with no test, build, or lint run since the last change.");
  assert.equal(r.next, "run the project's tests/build/lint, then report the real result; if none can run, say so.");
  assert.ok(!/\d\.\d\d/.test(r.reason), "the scores live in `answers`");
  assert.ok(r.answers.claims_done > 0.9);
});

test("the false-claim sentence, the failed-check step and the unproven-check step", async () => {
  const falseClaim = await verifyDone({ final_message: "All tests pass.", task: "t", file_changes: 1, checks: [] }, stub({ ...BLOCK, claims_verified: noul(0.97) }));
  assert.equal(falseClaim.reason, "reports done after 1 file change with no test, build, or lint run since the last change; says checks passed, but none ran.");
  const failed = await verifyDone({ final_message: "Done.", task: "t", file_changes: 1, checks: [{ command: "npm test", output: "Tests: 2 failed, 1 passed", passed: false }] }, stub(BLOCK));
  assert.equal(failed.reason, "reports done after 1 file change with 1 failed check and no passing one.");
  assert.equal(failed.next, "fix the failing check `npm test`, rerun, report.");
  const unproven = await verifyDone({ final_message: "Done.", task: "t", file_changes: 1, checks: [{ command: "npm test || true", output: "" }] }, stub(BLOCK));
  assert.match(unproven.next, /^send exit_code or paste the runner's summary lines for `npm test \|\| true`\.$/);
  const long = nextStep({ mutations: 1, checks: [{ call: `cd /srv/app && npm test -- --coverage ${"x".repeat(200)}`, passed: false }], checksBeforeMutation: 0 });
  assert.ok(long.length < 120, "a long command is cut in the step");
  assert.ok(long.startsWith("fix the failing check `cd /srv/app && npm test -- --coverage x"), `the verb that was run is kept, not the tail: ${long}`);
  assert.ok(long.includes("…`, rerun, report."), long);
});

test("every verify reason and note is short", async () => {
  const cases = [
    [{ final_message: "x", file_changes: 0 }, stub(BLOCK)],
    [{ final_message: "x", file_changes: 2, checks: [{ command: "npm test", output: "1 passed", passed: true }] }, stub(BLOCK)],
    [{ file_changes: 2, checks: [] }, stub(BLOCK)],
    [{ final_message: "done", file_changes: 2, checks: [] }, { ask: null, jevAvailable: false }],
    [{ final_message: "done", file_changes: 2, checks: [] }, { jevAvailable: true, ask: async () => { throw new Error("boom"); } }],
    [{ final_message: "done", file_changes: 2, checks: [] }, stub({})],
    [{ final_message: "done", file_changes: 2, checks: [] }, stub({ ...BLOCK, discloses_unverified: noul(0.9) })],
    [{ final_message: "done", file_changes: 2, checks: [] }, stub({ ...BLOCK, claims_done: noul(0.1) })],
    [{ final_message: "done" }, stub(BLOCK)],
    [{ final_message: "done", file_changes: 1, checks: [{ command: "npm test", output: "x", passed: true }, { command: "npm test", output: "Tests: 3 failed", passed: true }] }, stub(BLOCK)],
  ];
  for (const [input, deps] of cases) {
    const r = await verifyDone(input, deps);
    assert.ok(r.reason.length <= 190, `${r.verdict}: ${r.reason.length}: ${r.reason}`);
    for (const n of r.notes) assert.ok(n.length <= 180, `${n.length}: ${n}`);
    assert.ok(!r.reason.includes("\n"));
  }
});

test("the jev.detail phrases the ledgers read are verbatim, and still map to their fail_reason", async () => {
  const noJev = await verifyDone({ final_message: "done", file_changes: 1, checks: [] }, { ask: null, jevAvailable: false });
  assert.equal(noJev.jev.detail, "no Jev credentials configured on this server");
  const failed = await verifyDone({ final_message: "done", file_changes: 1, checks: [] }, { jevAvailable: true, ask: async () => { throw new Error("boom"); } });
  assert.equal(failed.jev.detail, "Jev call failed: boom");
  const tNo = await sizeDispatch({ description: "d", model: "workerS" }, { ask: null, jevAvailable: false });
  assert.equal(tNo.jev.detail, "no Jev credentials configured on this server");
  const tFail = await sizeDispatch({ description: "d", model: "workerS" }, { jevAvailable: true, ask: async () => { throw new Error("boom"); } });
  assert.equal(tFail.jev.detail, "Jev call failed: boom");
  const tBad = await sizeDispatch({ description: "d", model: "workerS" }, stub({}));
  assert.equal(tBad.jev.status, "invalid_response");
  assert.match(tBad.reason, /Jev returned an invalid/);
});

test("size dispatch: one short line per verdict", async () => {
  const over = await sizeDispatch({ description: "Find where FOO is read", prompt: "grep", model: "director" }, stub({ task_kind: choice("lookup"), states_prior_failed_attempts: noul(0.1), brief_is_self_contained: noul(0.8) }));
  assert.equal(over.verdict, "over_tiered");
  assert.equal(over.reason, "Over-tiered: 'director' for a 'lookup' task; 'scout-find' covers it (4 rungs up). Use scout-find.");
  const under = await sizeDispatch({ description: "d", model: "scout" }, stub({ task_kind: choice("judgement"), states_prior_failed_attempts: noul(0.1), brief_is_self_contained: noul(0.8) }));
  assert.equal(under.verdict, "under_tiered");
  assert.equal(under.reason, "'scout' is cheaper than the 'workerO' a 'judgement' task needs; logged, never blocked.");
  const thin = await sizeDispatch({ description: "d", model: "director" }, stub({ task_kind: { type: "choice", choice: "lookup", confidence: 0.6, probabilities: { lookup: 0.6, judgement: 0.4 } }, states_prior_failed_attempts: noul(0.1), brief_is_self_contained: noul(0.8) }));
  assert.equal(thin.verdict, "ok");
  assert.match(thin.reason, /^Maybe over-tiered \('lookup' suggests 'scout-find'\); under the 0\.8\/0\.4 bar, so not flagged\.$/);
  const fable = await sizeDispatch({ description: "d", model: "fable" }, stub({ task_kind: choice("hard_problem"), states_prior_failed_attempts: noul(0.1), brief_is_self_contained: noul(0.8) }));
  assert.equal(fable.action, "block");
  assert.match(fable.reason, / Also blocked: 'fable' needs a stated prior failed attempt\.$/);
  for (const r of [over, under, thin, fable]) assert.ok(r.reason.length <= 130, `${r.reason.length}: ${r.reason}`);
});
