import test from "node:test";
import assert from "node:assert/strict";
import { exitIsMasked, runOutcome } from "../src/kit/verify.mjs";
import { cpuNow } from "./helpers/cpu.mjs";
import { PIPEFAIL96, CRASH96 } from "./helpers/verify96-cases.mjs";

// Issue #96 (round 27): pipefail lifts the pipe mask only as an executable `set` before the pipe in the same shell, and a
// crash beside a pass summary is no pass. Data only: nothing here is executed.
test("#96: pipefail lifts the pipe mask only as an executable `set` before the pipe, in the same shell; `set +o pipefail` re-masks", () => {
  for (const [command, masked] of PIPEFAIL96) assert.equal(exitIsMasked(command), masked, command);
  // outcome: no runner summary, exit 0 from the pipeline. Unmasked it is the runner's status (pass); masked it is tail's (unknown).
  for (const [command, masked] of PIPEFAIL96) assert.equal(runOutcome(command, "", 0), masked ? "unknown" : "pass", command);
});
test("#96: a crash marker beside a pass summary is never a pass (unknown), masked or not; failure text still wins", () => {
  for (const crash of CRASH96) {
    for (const command of ["npm test", "npm test | tail -5", "node --test", "set +o pipefail; npm test | tail -5", "set -o pipefail; npm test | tail -5", "npm test -- -t pipefail | tail -5"]) {
      for (const summary of ["  12 passing (3s)", "ℹ pass 12\nℹ fail 0", "=== 3 passed in 0.2s ==="]) {
        assert.equal(runOutcome(command, `${crash}\n${summary}`, 0), "unknown", `${command} | ${crash.slice(0, 24)} + ${summary.slice(0, 12)}`);
        assert.equal(runOutcome(command, `${summary}\n${crash}`, 0), "unknown", `${command} | ${summary.slice(0, 12)} + ${crash.slice(0, 24)}`);
      }
      assert.equal(runOutcome(command, crash, 0), "unknown", `${command} | ${crash.slice(0, 24)}`); // and with no summary at all
    }
    assert.equal(runOutcome("npm test", `${crash}\n  12 passing`, 1), "fail"); // a nonzero exit is still a fail
    assert.equal(runOutcome("npm test", `${crash}\n  1 failing`, 0), "fail"); // a failure summary is still a fail
  }
  assert.equal(runOutcome("npm test", "npm ERR! code ELIFECYCLE\n  12 passing", 0), "fail");
  assert.equal(runOutcome("npm test", "npm error code 1\n  12 passing", 0), "fail");
});
test("#96: crash markers are anchored: a passing test's title, an indented stack line or other text stays a pass", () => {
  for (const out of ["  ✓ handles TypeError: bad input\n  12 passing", "  ✔ throws SyntaxError on bad json\n  12 passing (3ms)", "  ✓ ReferenceError: is thrown\nTests: 5 passed, 5 total",
    "test_x.py::test_syntax_error PASSED\n=== 3 passed in 0.2s ===", "  12 passing\n  the word typeerror in lowercase", "  12 passing\n  Expected a TypeError: x", "  12 passing\n  a segmentation fault was fixed in 1.2"]) {
    assert.equal(runOutcome("npm test", out, 0), "pass", out);
    assert.equal(runOutcome("npm test | tail -5", out, 0), "pass", `${out} (masked by tail only: the runner's own summary)`);
  }
});
test("#96: both checks stay linear on hostile input (CPU time)", () => {
  const ms = (fn) => { const t = cpuNow(); fn(); return cpuNow() - t; };
  const big = "TypeError: x\n  12 passing\n".repeat(100000); // 2.3 MB of output
  assert.ok(ms(() => runOutcome("npm test", big, 0)) < 500, "crash scan of a 2 MB output");
  assert.ok(ms(() => runOutcome("npm test", "a".repeat(2_000_000), 0)) < 500, "2 MB without a newline");
  assert.ok(ms(() => runOutcome("npm test", "\n".repeat(2_000_000) + "  12 passing", 0)) < 500, "2 million newlines");
  const cmd = `set -o pipefail; ${"set +o pipefail; set -o pipefail; ".repeat(50)}npm test | tail`; // under the 2000-char analysis cap
  assert.ok(ms(() => { for (let i = 0; i < 20; i++) exitIsMasked(cmd); }) < 500, "set chain");
  assert.ok(ms(() => exitIsMasked(`set ${"-o pipefail ".repeat(160)}; npm test | tail`)) < 500, "long set option list");
  assert.ok(ms(() => exitIsMasked(`set ${"-e ".repeat(600)}; npm test | tail`)) < 500, "long set option cluster list");
});
