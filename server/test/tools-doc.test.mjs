// The tool-surface drift test: what tools/list serves must be what the repo claims it serves.
// Live names against the pinned upstream + kit names, docs/TOOLS.md against the generator's own output,
// README names and its "+ N more" count against live, install.sh's doctor count against live.
// Without server/vendor there is no live list: locally that is a skipped suite with the remedy
// printed; in CI the vendor step runs first, so an absent bundle must fail, never skip.
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { listTools, renderToolsDoc, TOOLS_MD_URL } from "../scripts/gen-tools-doc.mjs";
import { UPSTREAM_TOOL_NAMES } from "./helpers/upstream-tools.mjs";
import { KIT_TOOL_NAMES } from "../src/kit/tools.mjs";

const README_URL = new URL("../../README.md", import.meta.url);
const INSTALL_URL = new URL("../../install.sh", import.meta.url);

const skip = existsSync(new URL("../vendor/server.js", import.meta.url)) || process.env.GITHUB_ACTIONS
  ? false
  : "server/vendor is missing - run `npm run vendor` (CI builds it before npm test)";

test("tools/list is the pinned upstream names plus the kit tools", { skip }, async () => {
  const names = (await listTools()).map((tool) => tool.name);
  assert.deepEqual(names, [...UPSTREAM_TOOL_NAMES, ...KIT_TOOL_NAMES, "kit_decide"],
    "vendor pin bump or kit tool change: update UPSTREAM_TOOL_NAMES / KIT_TOOL_NAMES, then `npm run gen:tools`");
});

test("docs/TOOLS.md is exactly the regenerated output", { skip }, async () => {
  assert.equal(readFileSync(TOOLS_MD_URL, "utf8"), await renderToolsDoc(),
    "docs/TOOLS.md drifted from tools/list - run `cd server && npm run gen:tools`");
});

test("every backticked tool name in README.md is a live tool", { skip }, async () => {
  const live = new Set((await listTools()).map((tool) => tool.name));
  const readme = readFileSync(README_URL, "utf8");
  const mentioned = [...readme.matchAll(/`((?:jev|kit)_[a-z0-9_]+)`/g)].map((m) => m[1]);
  assert.ok(mentioned.length > 0, "README should name at least one tool");
  for (const name of new Set(mentioned)) assert.ok(live.has(name), `README mentions \`${name}\`, which tools/list does not serve`);
});

test("README's '+ N more upstream' count matches the live upstream tools", { skip }, async () => {
  const readme = readFileSync(README_URL, "utf8");
  const section = /^## Tools\n([\s\S]*?)(?=\n## )/m.exec(readme)?.[1] ?? "";
  const claimed = Number(/\+ (\d+) more upstream `jev_\*` tools/.exec(section)?.[1]);
  const named = new Set([...section.matchAll(/`(jev_[a-z0-9_]+)`/g)].map((m) => m[1]));
  const expected = UPSTREAM_TOOL_NAMES.length - [...named].filter((name) => UPSTREAM_TOOL_NAMES.includes(name)).length;
  assert.ok(Number.isFinite(claimed), "README Tools table has a '+ N more upstream `jev_*` tools' row");
  assert.equal(claimed, expected, "README's remaining-tool count vs the pinned upstream names");
});

test("install.sh's --doctor expects the live tool count", { skip }, async () => {
  const install = readFileSync(INSTALL_URL, "utf8");
  const expected = Number(/^EXPECTED_TOOLS=(\d+)$/m.exec(install)[1]);
  assert.equal(expected, (await listTools()).length, "install.sh EXPECTED_TOOLS");
});
