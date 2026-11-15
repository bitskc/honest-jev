import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const hook = join(here, "jev-classify-redact.js");

function run(input) {
  const r = spawnSync(process.execPath, [hook], { input: JSON.stringify(input), encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout || "{}");
}

test("redacts secret-shaped classify evidence", () => {
  const out = run({
    tool_name: "mcp__jev__jev_classify",
    tool_input: {
      items: [
        { id: "c1", text: "CLAIM: ok. EVIDENCE: token ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      ],
    },
  });
  assert.equal(out.decision, "allow");
  assert.match(out.updatedInput.items[0].text, /CLAIM: ok/);
  assert.doesNotMatch(out.updatedInput.items[0].text, /ghp_aaaaaaaa/);
});

test("non-classify tools pass through", () => {
  const out = run({ tool_name: "Bash", tool_input: { command: "ls" } });
  assert.equal(out.decision, "allow");
  assert.equal(out.updatedInput, undefined);
});
