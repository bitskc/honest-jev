// The tool-surface drift test: what tools/list serves must be what the repo claims it serves.
// Live names against the pinned upstream + kit names, docs/TOOLS.md against the generator's own output,
// README names against live, install.sh's doctor count against live. Needs `npm run vendor` (CI runs it
// before npm test); gen-tools-doc.mjs says so if vendor/ is missing.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { listTools, renderToolsDoc, TOOLS_MD_URL } from "../scripts/gen-tools-doc.mjs";
import { UPSTREAM_TOOL_NAMES } from "./helpers/upstream-tools.mjs";
import { KIT_TOOL_NAMES } from "../src/kit/tools.mjs";

const README_URL = new URL("../../README.md", import.meta.url);
const INSTALL_URL = new URL("../../install.sh", import.meta.url);

const tools = await listTools();
const names = tools.map((tool) => tool.name);

test("tools/list is the pinned upstream names plus the kit tools", () => {
  assert.deepEqual(names, [...UPSTREAM_TOOL_NAMES, ...KIT_TOOL_NAMES, "kit_decide"],
    "vendor pin bump or kit tool change: update UPSTREAM_TOOL_NAMES / KIT_TOOL_NAMES, then `npm run gen:tools`");
});

test("docs/TOOLS.md is exactly the regenerated output", async () => {
  assert.equal(readFileSync(TOOLS_MD_URL, "utf8"), await renderToolsDoc(),
    "docs/TOOLS.md drifted from tools/list - run `cd server && npm run gen:tools`");
});

test("every backticked tool name in README.md is a live tool", () => {
  const live = new Set(names);
  const readme = readFileSync(README_URL, "utf8");
  const mentioned = [...readme.matchAll(/`((?:jev|kit)_[a-z0-9_]+)`/g)].map((m) => m[1]);
  assert.ok(mentioned.length > 0, "README should name at least one tool");
  for (const name of new Set(mentioned)) assert.ok(live.has(name), `README mentions \`${name}\`, which tools/list does not serve`);
});

test("install.sh's --doctor expects the live tool count", () => {
  const install = readFileSync(INSTALL_URL, "utf8");
  const expected = Number(/^EXPECTED_TOOLS=(\d+)$/m.exec(install)[1]);
  assert.equal(expected, names.length, "install.sh EXPECTED_TOOLS");
});
