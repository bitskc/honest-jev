import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { exitIsMasked as serverMasked, runOutcome as serverOutcome } from "../server/src/kit/verify.mjs";
import { PIPEFAIL96, CRASH96 } from "../server/test/helpers/verify96-cases.mjs";

// Issue #96 parity: the hook ships its own copy of the outcome rules; these pin it to the server on every #96 case, with the
// expected verdict stated too (so a change to both copies cannot drift together). Data only: nothing here is executed.
const hook = createRequire(import.meta.url)("./jev-stop-verify.js");
const cpu = () => { const u = process.cpuUsage(); return (u.user + u.system) / 1000; };

test("#96 parity: the hook and the server agree on every pipefail case, and on the verdict", () => {
  for (const [command, masked] of PIPEFAIL96) {
    assert.equal(hook.exitIsMasked(command), masked, `hook: ${command}`);
    assert.equal(hook.exitIsMasked(command), serverMasked(command), `parity: ${command}`);
    assert.equal(hook.runOutcome(command, "", 0), masked ? "unknown" : "pass", `hook outcome: ${command}`);
  }
});
test("#96 parity: the hook and the server agree that a crash beside a pass summary is unknown", () => {
  const commands = ["npm test", "npm test | tail -5", "set +o pipefail; npm test | tail -5", "set -o pipefail; npm test | tail -5", "npm test -- -t pipefail | tail -5"];
  const summaries = ["  12 passing (3s)", "ℹ pass 12\nℹ fail 0", "=== 3 passed in 0.2s ===", ""];
  for (const crash of CRASH96) for (const command of commands) for (const summary of summaries) for (const out of [`${crash}\n${summary}`, `${summary}\n${crash}`]) {
    assert.equal(hook.runOutcome(command, out, 0), "unknown", `hook: ${command} | ${JSON.stringify(out.slice(0, 40))}`);
    assert.equal(hook.runOutcome(command, out, 0), serverOutcome(command, out, 0), `parity: ${command}`);
  }
  for (const crash of CRASH96) {
    assert.equal(hook.runOutcome("npm test", `${crash}\n  12 passing`, 1), "fail");
    assert.equal(hook.runOutcome("npm test", `${crash}\n  1 failing`, 0), "fail");
  }
  for (const out of ["  ✓ handles TypeError: bad input\n  12 passing", "  12 passing\n  Expected a TypeError: x", "  12 passing\n  a segmentation fault was fixed in 1.2", "npm ERR! code X\n  12 passing"]) {
    assert.equal(hook.runOutcome("npm test", out, 0), serverOutcome("npm test", out, 0), `parity: ${out}`);
  }
  assert.equal(hook.runOutcome("npm test", "npm ERR! code ELIFECYCLE\n  12 passing", 0), "fail");
});
test("#96 parity: the hook's copy stays linear on hostile input (CPU time)", () => {
  const ms = (fn) => { const t = cpu(); fn(); return cpu() - t; };
  assert.ok(ms(() => hook.runOutcome("npm test", "TypeError: x\n  12 passing\n".repeat(100000), 0)) < 500);
  assert.ok(ms(() => hook.runOutcome("npm test", "a".repeat(2000000), 0)) < 500);
  assert.ok(ms(() => hook.exitIsMasked(`set ${"-o pipefail ".repeat(160)}; npm test | tail`)) < 500);
});
