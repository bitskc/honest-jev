import test from "node:test";
import assert from "node:assert/strict";
import { runOutcome, verifyDone } from "../src/kit/verify.mjs";
import { cpuNow } from "./helpers/cpu.mjs";

// #28: a green `12 passing` beside a connection error, with no exit_code, is not a verified run. Data only.
const E2E = "  12 passing (1s)\nscripts/e2e.js: connection refused";
test("#28: a connection error beside a pass summary withholds a summary-only pass (unknown), never claims a failure", () => {
  for (const noise of ["scripts/e2e.js: connection refused", "Error: connect ECONNREFUSED 127.0.0.1:5432", "ECONNRESET", "getaddrinfo ENOTFOUND api.test", "socket hang up", "Unable to connect to the server", "ETIMEDOUT", "Connection timed out"]) {
    for (const summary of ["  12 passing (3s)", "ℹ pass 12\nℹ fail 0", "=== 3 passed in 0.2s ==="]) {
      assert.equal(runOutcome("npm test", `${summary}\n${noise}`, undefined), "unknown", `${summary.slice(0, 10)} + ${noise}`);
      assert.equal(runOutcome("npm test", `${noise}\n${summary}`, undefined), "unknown");
      assert.equal(runOutcome("npm test | tail -5", `${summary}\n${noise}`, 0), "unknown", "an exit status a pipe masked is not the runner's");
    }
  }
  assert.equal(runOutcome("npm test", E2E, 0), "pass", "a real unmasked exit 0 is the runner's own verdict");
  assert.equal(runOutcome("npm test", E2E, 1), "fail");
  assert.equal(runOutcome("npm test", `${E2E}\n  1 failing`, undefined), "fail", "a failure summary still wins");
});
test("#28: a passing test's title that mentions the error, and plain output, stay a pass", () => {
  for (const out of ["  ✓ retries on ECONNREFUSED\n  12 passing", "  ✔ handles a connection refused error\n  12 passing (3ms)", "PASS src/net.test.js\nTests: 5 passed, 5 total", "  12 passing (1s)"]) {
    assert.equal(runOutcome("npm test", out, undefined), "pass", out);
  }
});
test("#28 through kit_verify_done: the e2e-refused run is not verified when the agent sends no exit_code", async () => {
  const ask = async () => ({ model: "stub", answers: { claims_done: { noul: 0.95 }, claims_verified: { noul: 0.9 }, verification_applies: { noul: 0.9 }, discloses_unverified: { noul: 0.05 }, outcome: { choice: { passed: 0.9, failed: 0.05, none: 0.05 } } } });
  const run = (check) => verifyDone({ final_message: "All tests pass.", file_changes: 2, checks: [check] }, { ask, jevAvailable: false });
  const bad = await run({ command: "npm test", output: E2E });
  assert.notEqual(bad.verified, true, JSON.stringify(bad));
  const good = await run({ command: "npm test", output: E2E, exit_code: 0 });
  assert.equal(good.verified, true);
});
test("#28: the network scan is linear (CPU time)", () => {
  const ms = (fn) => { const t = cpuNow(); fn(); return cpuNow() - t; };
  assert.ok(ms(() => runOutcome("npm test", "  12 passing\nconnection ".repeat(100000), undefined)) < 500, "2 MB of near-misses");
  assert.ok(ms(() => runOutcome("npm test", "a".repeat(2_000_000) + "\n  12 passing", undefined)) < 500, "2 MB on one line");
});
