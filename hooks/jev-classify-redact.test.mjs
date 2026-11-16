import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const hook = join(here, "jev-classify-redact.js");
const SECRET = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// Returns the hook's raw stdout: Claude Code reads nothing from it when the hook prints nothing.
function run(input) {
  const r = spawnSync(process.execPath, [hook], { input: JSON.stringify(input), encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout;
}

test("redacted classify evidence goes back as hookSpecificOutput.updatedInput", () => {
  const out = JSON.parse(run({
    tool_name: "mcp__jev__jev_classify",
    tool_input: { items: [{ id: "c1", text: `CLAIM: ok. EVIDENCE: token ${SECRET}` }] },
  }));
  assert.equal(out.hookSpecificOutput.hookEventName, "PreToolUse");
  assert.equal(out.decision, undefined, "deprecated top-level decision must not be emitted");
  assert.equal(out.hookSpecificOutput.permissionDecision, undefined, "permission flow must stay unchanged");
  const text = out.hookSpecificOutput.updatedInput.items[0].text;
  assert.match(text, /CLAIM: ok/);
  assert.doesNotMatch(text, /ghp_aaaaaaaa/);
});

test("updatedInput keeps the rest of tool_input and each item's other fields", () => {
  const out = JSON.parse(run({
    tool_name: "jev_classify",
    tool_input: { purpose: "check", items: [{ id: "c1", text: `EVIDENCE: ${SECRET}` }, { id: "c2", text: "CLAIM: plain" }] },
  }));
  const ui = out.hookSpecificOutput.updatedInput;
  assert.equal(ui.purpose, "check");
  assert.equal(ui.items[0].id, "c1");
  assert.equal(ui.items[1].id, "c2");
  assert.equal(ui.items[1].text, "CLAIM: plain");
});

test("nothing to redact: prints nothing", () => {
  assert.equal(run({
    tool_name: "mcp__jev__jev_classify",
    tool_input: { items: [{ id: "c1", text: "CLAIM: ok. EVIDENCE: 12 passed" }] },
  }), "");
});

test("non-classify tools print nothing", () => {
  assert.equal(run({ tool_name: "Bash", tool_input: { command: "ls" } }), "");
});

test("an item whose text is empty or whitespace only is removed; the other item is unchanged and systemMessage reports 1 dropped", () => {
  const out = JSON.parse(run({
    tool_name: "jev_classify",
    tool_input: { items: [{ id: "c1", text: "   " }, { id: "c2", text: "CLAIM: plain" }] },
  }));
  const items = out.hookSpecificOutput.updatedInput.items;
  assert.equal(items.length, 1);
  assert.equal(items[0].id, "c2");
  assert.equal(items[0].text, "CLAIM: plain");
  assert.equal(out.systemMessage, "honest-jev: dropped 1 jev_classify item(s) after redact-or-refuse");
});

test("a secret-only item is kept with its text replaced by the redaction marker and produces no systemMessage", () => {
  const out = JSON.parse(run({
    tool_name: "jev_classify",
    tool_input: { items: [{ id: "c1", text: SECRET }, { id: "c2", text: "CLAIM: plain" }] },
  }));
  const items = out.hookSpecificOutput.updatedInput.items;
  assert.equal(items.length, 2);
  assert.equal(items[0].id, "c1");
  assert.equal(items[0].text, "<redacted>");
  assert.equal(items[1].text, "CLAIM: plain");
  assert.equal(out.systemMessage, undefined);
});
