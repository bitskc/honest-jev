import test from "node:test";
import assert from "node:assert/strict";
import { verifyDone } from "../src/kit/verify.mjs";

// `passed: true` is documented as a fallback for unrecognised runs only. It must never outrank failure text or a nonzero
// exit code ("Failure text ... beats every pass signal", README). Data only: nothing is executed.
const noJev = { ask: null, jevAvailable: false };
const v = (checks) => verifyDone({ final_message: "Done, all tests pass", file_changes: 2, checks }, noJev);

test("passed:true beside a recognised failing summary or a nonzero exit_code is not a verified run", async () => {
  for (const check of [
    { command: "npm test", output: "Tests:  3 failed, 10 passed, 13 total", passed: true },
    { command: "pytest", output: "==== 2 failed, 8 passed in 1.20s ====", passed: true },
    { command: "cargo test", output: "test result: FAILED. 4 passed; 1 failed; 0 ignored", passed: true },
    { command: "npx tsc --noEmit", output: "", exit_code: 2, passed: true },
  ]) {
    const r = await v([check]);
    assert.notEqual(r.verified, true, JSON.stringify(check));
    assert.notEqual(r.verdict, "verified", JSON.stringify(check));
    assert.equal(r.evidence.fresh_checks[0].passed, false, JSON.stringify(check));
    assert.ok(r.notes.some((n) => /failure wins/.test(n)), JSON.stringify(r.notes));
  }
});
test("passed:true still verifies an unrecognised run, and passed:false still fails a green one", async () => {
  assert.equal((await v([{ command: "npm test", output: "custom reporter: all good", passed: true }])).verified, true);
  assert.equal((await v([{ command: "npm test", passed: true }])).verified, true);
  assert.equal((await v([{ command: "npm test", output: "Tests:  10 passed, 10 total", passed: false }])).evidence.fresh_checks[0].passed, false);
});
