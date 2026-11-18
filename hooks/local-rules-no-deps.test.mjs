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

// Comments are stripped first so prose can't match. A // counts as a comment only at line start or after whitespace, so "https://..." and "a//b" inside a string are kept.
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|\s)\/\/[^\n]*/g, "$1");
}

// Specifiers from import/export-from statements and string-literal dynamic import(). A scan of literal text, not a parser.
function specifiers(code) {
  const out = [];
  const re = /\b(?:import|export)\s+(?:[^'"`;]*?\s+from\s+)?['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)/g;
  for (const m of code.matchAll(re)) out.push(m[1] ?? m[2]);
  return out;
}

// Forms the literal scan cannot resolve: a non-literal or template import(), require(), or createRequire().
function unresolvedForms(code) {
  const re = /\bimport\(\s*(?!['"][^'"]+['"]\s*\))[^)]*\)|\brequire\s*\(|\bcreateRequire\s*\(/g;
  return [...code.matchAll(re)].map((m) => m[0]);
}

test("the scan covers every rule file the fingerprint hashes", () => {
  assert.deepEqual([...RULE_FILES].sort(), ["guard.mjs", "safere.mjs", "shell.mjs"]);
});

const LOADER = join(HERE, "jev-guard-local.mjs");
// The one intended dynamic import: the hook loads the rules file it resolved (guard.mjs) by path. Any other unresolved form fails the test.
const ALLOWED_UNRESOLVED = new Map([[LOADER, ["import(pathToFileURL(loadFrom)"]]]);

test("the scan sees the sibling imports it must check", () => {
  const guard = specifiers(stripComments(readFileSync(join(KIT, "guard.mjs"), "utf8")));
  assert.ok(guard.includes("./shell.mjs") && guard.includes("./safere.mjs"), `guard.mjs specifiers: ${guard}`);
  const loader = specifiers(stripComments(readFileSync(LOADER, "utf8")));
  assert.ok(loader.includes("./jev-rules-fingerprint.mjs"), `jev-guard-local.mjs specifiers: ${loader}`);
});

for (const file of TARGETS) {
  test(`${relative(resolve(HERE, ".."), file)}: imports are node: builtins or same-directory siblings`, () => {
    const dir = dirname(file);
    const code = stripComments(readFileSync(file, "utf8"));
    for (const spec of specifiers(code)) {
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
  test(`${relative(resolve(HERE, ".."), file)}: no unresolved import, require, or createRequire`, () => {
    const found = unresolvedForms(stripComments(readFileSync(file, "utf8")));
    assert.deepEqual(found, ALLOWED_UNRESOLVED.get(file) ?? [], `${file} has forms the literal scan cannot resolve: ${found}`);
  });
}
