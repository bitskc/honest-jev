// The local rules path must stay dependency-free: every module it loads imports only node: builtins or sibling files in its own directory.
// Static text check, not a timing assertion, so it is safe in CI. Covers the rule files the fingerprint hashes (RULE_FILES) and the two
// hook-side loader files that import them. If this fails, a rule file grew a dependency, and the local decision would depend on
// node_modules being present on the machine that runs the hook.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve, relative, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import { RULE_FILES } from "./jev-rules-fingerprint.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const KIT = resolve(HERE, "..", "server", "src", "kit");

const TARGETS = [
  ...RULE_FILES.map((f) => join(KIT, f)),
  join(HERE, "jev-guard-local.mjs"),
  join(HERE, "jev-rules-fingerprint.mjs"),
];

// Specifiers from import/export-from statements and string-literal dynamic import(). Comments are stripped first so prose can't match.
function specifiers(src) {
  const code = src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:"'`\\])\/\/[^\n]*/g, "$1");
  const out = [];
  const re = /\b(?:import|export)\s+(?:[^'"`;]*?\s+from\s+)?['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)/g;
  for (const m of code.matchAll(re)) out.push(m[1] ?? m[2]);
  return out;
}

test("the scan covers every rule file the fingerprint hashes", () => {
  assert.deepEqual([...RULE_FILES].sort(), ["guard.mjs", "safere.mjs", "shell.mjs"]);
});

for (const file of TARGETS) {
  test(`${relative(resolve(HERE, ".."), file)}: imports are node: builtins or same-directory siblings`, () => {
    const dir = dirname(file);
    const src = readFileSync(file, "utf8");
    for (const spec of specifiers(src)) {
      assert.ok(!spec.includes("node_modules"), `${file} imports from node_modules: ${spec}`);
      if (spec.startsWith("node:")) continue;
      assert.ok(
        spec.startsWith("./") || spec.startsWith("../"),
        `${file} imports a bare specifier (a package, which the local path must not load): ${spec}`,
      );
      const target = resolve(dir, spec);
      const rel = relative(dir, target);
      assert.ok(
        !isAbsolute(rel) && !rel.startsWith(".."),
        `${file} imports outside its directory: ${spec}`,
      );
    }
  });
}
