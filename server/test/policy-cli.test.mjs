// jev-policy end to end: real processes, temp directories, no network, no credentials. Policy text is data only.
import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../../scripts/jev-policy.mjs", import.meta.url));
const EX = fileURLToPath(new URL("../../examples/policies/pr-merge-gate.json", import.meta.url));
// the example carries a trigger (add-policy-hook-adapter); these tests are about layers, so they start from the class without it
const GATE = () => { const { trigger, ...g } = JSON.parse(readFileSync(EX, "utf8")); return g; };
const noul = (v) => ({ type: "noul", noul: v });

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), "jev-policy-"));
  const proj = join(root, "proj");
  mkdirSync(proj);
  const user = join(root, "user-policy.json");
  const run = (...args) => {
    const r = spawnSync(process.execPath, [CLI, ...args], { cwd: proj, env: { PATH: process.env.PATH, HOME: root, JEV_POLICY_USER: user }, encoding: "utf8", timeout: 30_000 });
    return { code: r.status, out: r.stdout, err: r.stderr };
  };
  const spec = (name, obj) => { const p = join(root, name); writeFileSync(p, JSON.stringify(obj)); return p; };
  return { root, proj, user, repo: join(proj, ".jev", "policy.json"), run, spec, done: () => rmSync(root, { recursive: true, force: true }) };
}
const tighten = () => {
  const g = GATE();
  g.rules = [{ id: "R0-ask-when-review-unknown", when: { all: [{ noul: "merges_pr", gte: 0.5, missing_as: 1 }, { fact: "gstack_reviewed", exists: false }] }, decision: "ask_user", reason: "Review status unknown." }, ...g.rules];
  g.examples = g.examples.map((e) => (e.name.startsWith("review status not supplied") ? { ...e, expect: { decision: "ask_user", rule_id: "R0-ask-when-review-unknown" } } : e));
  return g;
};

test("init creates an empty layer with the right mode and refuses to overwrite", () => {
  const s = sandbox();
  try {
    assert.equal(s.run("init", "--layer", "repo").code, 0);
    assert.deepEqual(JSON.parse(readFileSync(s.repo, "utf8")), { v: 1, decisions: [] });
    assert.equal(statSync(s.repo).mode & 0o777, 0o644);
    assert.equal(s.run("init", "--layer", "user").code, 0);
    assert.equal(statSync(s.user).mode & 0o777, 0o600);
    const again = s.run("init", "--layer", "repo");
    assert.equal(again.code, 1);
    assert.match(again.err, /already exists/);
    assert.equal(s.run("init").code, 2);
    assert.equal(s.run("init", "--layer", "root").code, 2);
  } finally { s.done(); }
});

test("add: the user layer needs --yes, and without it nothing is written", () => {
  const s = sandbox();
  try {
    const r = s.run("add", EX, "--layer", "user");
    assert.equal(r.code, 3);
    assert.match(r.err, /NOT WRITTEN: the user layer can loosen gates everywhere/);
    assert.match(r.out, /7\/7 pass offline/);
    assert.equal(existsSync(s.user), false);
    const ok = s.run("add", EX, "--layer", "user", "--yes");
    assert.equal(ok.code, 0, ok.err);
    assert.equal(statSync(s.user).mode & 0o777, 0o600);
    assert.equal(JSON.parse(readFileSync(s.user, "utf8")).decisions[0].id, "pr-merge-gate");
    assert.deepEqual(readdirSync(s.root).filter((f) => f.includes(".tmp")), [], "no temp file left behind");
  } finally { s.done(); }
});

test("add: a repo layer is written without --yes and tells the author to commit it", () => {
  const s = sandbox();
  try {
    const r = s.run("add", EX, "--layer", "repo");
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /commit it like any other reviewed change/);
    assert.equal(statSync(join(s.proj, ".jev")).mode & 0o777, 0o755);
  } finally { s.done(); }
});

test("add refuses, and writes nothing, for: a rule with no example, a shadowed rule, a failing example, an unknown key", () => {
  const s = sandbox();
  try {
    const noExample = GATE(); noExample.examples = noExample.examples.filter((e) => e.expect.rule_id !== "R3-reviewed-merge");
    let r = s.run("add", s.spec("a.json", noExample), "--layer", "user", "--yes");
    assert.equal(r.code, 1);
    assert.match(r.err, /rule "R3-reviewed-merge" has no passing example/);

    const shadow = GATE();
    shadow.rules.unshift({ id: "R0-always", when: { noul: "merges_pr", gte: 0, missing_as: 1 }, decision: "ask_user", reason: "x" });
    shadow.examples.push({ facts: {}, answers: { merges_pr: noul(0.5) }, expect: { decision: "ask_user", rule_id: "R0-always" } });
    r = s.run("add", s.spec("b.json", shadow), "--layer", "user", "--yes");
    assert.equal(r.code, 1);
    assert.match(r.err, /expected .* but the evaluator returned/);

    const wrong = GATE(); wrong.examples[0].expect.decision = "proceed";
    assert.equal(s.run("add", s.spec("c.json", wrong), "--layer", "user", "--yes").code, 1);

    const extra = GATE(); extra.regex = "merge.*";
    r = s.run("add", s.spec("d.json", extra), "--layer", "user", "--yes");
    assert.equal(r.code, 1);
    assert.match(r.err, /unknown key "regex"/);

    assert.equal(existsSync(s.user), false, "nothing was written by any refused add");
    assert.equal(s.run("add", join(s.root, "missing.json"), "--layer", "user", "--yes").code, 2);
    writeFileSync(join(s.root, "bad.json"), "{");
    assert.equal(s.run("add", join(s.root, "bad.json"), "--layer", "user", "--yes").code, 1);
  } finally { s.done(); }
});

test("add: an existing class needs --replace and a higher version; the old file survives a refusal", () => {
  const s = sandbox();
  try {
    assert.equal(s.run("add", EX, "--layer", "user", "--yes").code, 0);
    const before = readFileSync(s.user, "utf8");
    let r = s.run("add", EX, "--layer", "user", "--yes");
    assert.equal(r.code, 1);
    assert.match(r.err, /already exists.*--replace/);
    r = s.run("add", EX, "--layer", "user", "--yes", "--replace");
    assert.equal(r.code, 1);
    assert.match(r.err, /needs version > 1/);
    assert.equal(readFileSync(s.user, "utf8"), before);
    const v2 = GATE(); v2.version = 2; v2.rules[1].reason = "Not a pull request merge (v2).";
    r = s.run("add", s.spec("v2.json", v2), "--layer", "user", "--yes", "--replace");
    assert.equal(r.code, 0, r.err);
    assert.equal(JSON.parse(readFileSync(s.user, "utf8")).decisions[0].version, 2);
    assert.equal(JSON.parse(readFileSync(s.user, "utf8")).decisions.length, 1);
  } finally { s.done(); }
});

test("add is atomic: when the write cannot complete the previous file is unchanged", { skip: process.getuid && process.getuid() === 0 }, () => {
  const s = sandbox();
  try {
    assert.equal(s.run("add", EX, "--layer", "repo").code, 0);
    const before = readFileSync(s.repo, "utf8");
    chmodSync(join(s.proj, ".jev"), 0o555); // the temp file cannot be created
    const other = GATE(); other.id = "second-gate";
    const r = s.run("add", s.spec("o.json", other), "--layer", "repo");
    chmodSync(join(s.proj, ".jev"), 0o755);
    assert.equal(r.code, 1);
    assert.equal(readFileSync(s.repo, "utf8"), before);
    assert.deepEqual(readdirSync(join(s.proj, ".jev")), ["policy.json"]);
  } finally { chmodSync(join(s.proj, ".jev"), 0o755); s.done(); }
});

test("add refuses an existing layer that is invalid instead of overwriting it", () => {
  const s = sandbox();
  try {
    mkdirSync(join(s.proj, ".jev"));
    writeFileSync(s.repo, "{ hand edited, broken");
    const r = s.run("add", EX, "--layer", "repo");
    assert.equal(r.code, 1);
    assert.match(r.err, /existing repo layer is invalid/);
    assert.equal(readFileSync(s.repo, "utf8"), "{ hand edited, broken");
  } finally { s.done(); }
});

test("check: valid layers pass; an invalid layer fails with its errors; --spec checks a draft without writing", () => {
  const s = sandbox();
  try {
    assert.equal(s.run("check").code, 0, "no files is not a failure");
    assert.equal(s.run("add", EX, "--layer", "user", "--yes").code, 0);
    let r = s.run("check");
    assert.equal(r.code, 0);
    assert.match(r.out, /user: .* ok, 1 class\(es\)/);
    r = s.run("check", "--spec", EX);
    assert.equal(r.code, 0);
    assert.match(r.out, /pass {2}unreviewed merge asks/);
    writeFileSync(s.user, JSON.stringify({ v: 1, decisions: [], tools: {} }));
    r = s.run("check");
    assert.equal(r.code, 1);
    assert.match(r.err, /unknown key "tools"/);
    const bad = GATE(); bad.examples = [];
    assert.equal(s.run("check", "--spec", s.spec("bad.json", bad)).code, 1);
    assert.equal(s.run("check", "--layer", "nope").code, 2);
  } finally { s.done(); }
});

test("test: examples pass offline; ad hoc facts and answers work; unknown class fails; a lower layer's tightening is visible", () => {
  const s = sandbox();
  try {
    assert.equal(s.run("add", EX, "--layer", "user", "--yes").code, 0);
    let r = s.run("test", "pr-merge-gate");
    assert.equal(r.code, 0);
    assert.match(r.out, /7\/7 examples pass \(offline, no model call\)/);
    r = s.run("test", "pr-merge-gate", "--facts", '{"gstack_reviewed":true}', "--answers", JSON.stringify({ merges_pr: noul(0.95) }));
    assert.equal(r.code, 0);
    assert.match(r.out, /decision proceed {2}rule R3-reviewed-merge {2}decided_by jev/);
    r = s.run("test", "pr-merge-gate", "--facts", "{");
    assert.equal(r.code, 2);
    assert.equal(s.run("test", "nope").code, 1);
    assert.equal(s.run("test", "Bad Id").code, 2);

    // a repo layer that tightens: the user's own "review status not supplied" example now reaches R0, so the effective class FAILS it
    assert.equal(s.run("add", s.spec("t.json", tighten()), "--layer", "repo").code, 0);
    r = s.run("test", "pr-merge-gate");
    assert.equal(r.code, 1);
    assert.match(r.out, /FAIL {2}review status not supplied: a merge asks/);
    assert.match(r.out, /origins user\+repo/);
  } finally { s.done(); }
});

test("list: effective classes, origins, tightened_by and versions; --json is parseable", () => {
  const s = sandbox();
  try {
    assert.match(s.run("list").out, /no policy classes/);
    assert.equal(s.run("add", EX, "--layer", "user", "--yes").code, 0);
    assert.equal(s.run("add", s.spec("t.json", tighten()), "--layer", "repo").code, 0);
    const j = JSON.parse(s.run("list", "--json").out);
    assert.equal(j.classes.length, 1);
    assert.deepEqual([j.classes[0].class, j.classes[0].origins, j.classes[0].tightened_by, j.classes[0].rules, j.classes[0].fail_mode], ["pr-merge-gate", ["user", "repo"], ["R0-ask-when-review-unknown"], 4, "closed"]);
    assert.match(j.classes[0].policy_version, /^[0-9a-f]{12}$/);
    assert.match(s.run("list").out, /pr-merge-gate {2}v1 {2}user\+repo {2}4 rule\(s\) \(1 added by lower layers\)/);
  } finally { s.done(); }
});

test("args: prints kit_decide arguments with only locally valid layers", () => {
  const s = sandbox();
  try {
    assert.equal(s.run("add", EX, "--layer", "user", "--yes").code, 0);
    const r = s.run("args", "pr-merge-gate", "--facts", '{"gstack_reviewed":false}', "--state", '{"action":{"text":"gh pr merge 3"}}', "--budget-ms", "3000", "--host", "claude-code", "--correlation-id", "t-1");
    assert.equal(r.code, 0);
    const a = JSON.parse(r.out);
    assert.deepEqual(Object.keys(a), ["class", "policy_layers", "facts", "state", "budget_ms", "host", "correlation_id"]);
    assert.deepEqual(a.policy_layers.map((l) => l.origin), ["user"]);
    assert.equal(a.policy_layers[0].text, readFileSync(s.user, "utf8"), "the file text is forwarded unparsed");
    assert.equal(s.run("args", "nope").code, 1);
    assert.equal(s.run("args", "pr-merge-gate", "--budget-ms", "x").code, 2);
  } finally { s.done(); }
});

test("args never forwards a file that is a symlink, not valid policy, or oversized; it names why", () => {
  const s = sandbox();
  try {
    assert.equal(s.run("add", EX, "--layer", "user", "--yes").code, 0);
    mkdirSync(join(s.proj, ".jev"));
    const secret = join(s.root, "not-policy.txt");
    writeFileSync(secret, "TOP-SECRET-TOKEN-VALUE");
    symlinkSync(secret, s.repo);
    let r = s.run("args", "pr-merge-gate");
    assert.equal(r.code, 0);
    assert.ok(!r.out.includes("TOP-SECRET") && !r.err.includes("TOP-SECRET"));
    assert.deepEqual(JSON.parse(r.out).policy_layers.map((l) => l.origin), ["user"]);
    assert.match(r.err, /repo layer .* is a symlink: refusing to read it/);
    rmSync(s.repo);
    writeFileSync(s.repo, "TOP-SECRET-TOKEN-VALUE is not json");
    r = s.run("args", "pr-merge-gate");
    assert.ok(!r.out.includes("TOP-SECRET"), "an invalid layer is not forwarded");
    assert.ok(!r.err.includes("TOP-SECRET"), "and its content is not echoed");
    assert.match(r.err, /repo layer .* is invalid: layer is not valid JSON/);
    writeFileSync(s.repo, "x".repeat(20_000));
    r = s.run("args", "pr-merge-gate");
    assert.match(r.err, /repo layer \S+ is over 16384 bytes/);
    assert.deepEqual(JSON.parse(r.out).policy_layers.map((l) => l.origin), ["user"]);
    // check and list report the symlink too, and read nothing through it
    rmSync(s.repo);
    symlinkSync(secret, s.repo);
    r = s.run("check", "--layer", "repo");
    assert.equal(r.code, 1);
    assert.ok(!r.out.includes("TOP-SECRET") && !r.err.includes("TOP-SECRET"));
  } finally { s.done(); }
});

test("usage errors exit 2 and unknown options are rejected", () => {
  const s = sandbox();
  try {
    assert.equal(s.run().code, 2);
    assert.equal(s.run("frobnicate").code, 2);
    assert.equal(s.run("list", "--nope").code, 2);
    assert.equal(s.run("add").code, 2);
    assert.equal(s.run("add", "a", "b", "--layer", "user").code, 2);
    assert.equal(s.run("test").code, 2);
    assert.equal(s.run("list", "--layer").code, 2);
  } finally { s.done(); }
});

test("static: the CLI and the policy modules make no network call, spawn nothing and use no dynamic code", () => {
  const files = ["../../scripts/jev-policy.mjs", "../src/policy/schema.mjs", "../src/policy/merge.mjs", "../src/policy/examples.mjs"];
  for (const f of files) {
    const src = readFileSync(new URL(f, import.meta.url), "utf8");
    assert.doesNotMatch(src, /\bfetch\s*\(|node:(http|https|net|dgram|tls|child_process|vm)|\beval\s*\(|new Function\s*\(|\bimport\s*\(/, f);
  }
});

test("args refuses when valid layers together exceed the call cap, rather than sending them to a Worker that would reject them", () => {
  const s = sandbox();
  try {
    const big = (id) => {
      const questions = {}, conds = [];
      for (let i = 1; i <= 6; i++) { questions[`q${i}`] = { type: "noul", instructions: "Is it so? ".repeat(140), criteria: { true: "yes", false: "no" } }; conds.push({ noul: `q${i}`, gte: 0.5, missing_as: 1 }); }
      const zero = Object.fromEntries(Object.keys(questions).map((q) => [q, noul(0)]));
      return { id, version: 1, questions, vocabulary: ["proceed", "ask_user"], baseline: "proceed", rules: [{ id: "R1", when: { any: conds }, decision: "ask_user", reason: "any is risky" }],
        default: { decision: "proceed", reason: "none is" }, on_unavailable: { decision: "ask_user" },
        examples: [{ name: "one risky", facts: {}, answers: { ...zero, q1: noul(0.9) }, expect: { decision: "ask_user", rule_id: "R1" } }, { name: "none risky", facts: {}, answers: zero, expect: { decision: "proceed", rule_id: null } }] };
    };
    assert.equal(s.run("add", s.spec("big.json", big("big")), "--layer", "user", "--yes").code, 0);
    // add itself refuses to create the oversized pair; a hand-copied file can still make one, and args must refuse it
    const refused = s.run("add", s.spec("big2.json", big("big-too")), "--layer", "repo");
    assert.equal(refused.code, 1);
    assert.match(refused.err, /NOT WRITTEN: with the user layer as it is now, policy_layers total \d+ bytes, over the 16384 byte cap/);
    assert.equal(existsSync(s.repo), false);
    mkdirSync(join(s.proj, ".jev"));
    writeFileSync(s.repo, readFileSync(s.user, "utf8"));
    const a = s.run("args", "big");
    assert.equal(statSync(s.user).size < 16_384 && statSync(s.repo).size < 16_384, true, "each layer alone is under the cap");
    assert.equal(statSync(s.user).size + statSync(s.repo).size > 16_384, true, "together they are over it");
    assert.equal(a.code, 1);
    assert.match(a.err, /over the 16384 byte cap/);
    assert.equal(a.out, "");
  } finally { s.done(); }
});

test("a repo layer cannot write the user layer through a symlinked parent directory: no --yes bypass, no mode change", () => {
  const s = sandbox();
  try {
    assert.equal(s.run("add", EX, "--layer", "user", "--yes").code, 0);
    const before = readFileSync(s.user, "utf8");
    assert.equal(statSync(s.user).mode & 0o777, 0o600);
    // the hostile checkout ships .jev -> the user's config directory, and the user file is named policy.json there
    const cfg = join(s.root, "cfg"); mkdirSync(cfg);
    const userAtCfg = join(cfg, "policy.json");
    writeFileSync(userAtCfg, before, { mode: 0o600 });
    symlinkSync(cfg, join(s.proj, ".jev"));
    const run = (...a) => {
      const r = spawnSync(process.execPath, [CLI, ...a], { cwd: s.proj, env: { PATH: process.env.PATH, HOME: s.root, JEV_POLICY_USER: userAtCfg }, encoding: "utf8" });
      return { code: r.status, out: r.stdout, err: r.stderr };
    };
    const other = GATE(); other.id = "squatter";
    const r = run("add", s.spec("squat.json", other), "--layer", "repo");
    assert.equal(r.code, 1);
    assert.match(r.err, /NOT WRITTEN: the repo layer path resolves to the user layer file/);
    assert.equal(readFileSync(userAtCfg, "utf8"), before, "the user layer is untouched");
    assert.equal(statSync(userAtCfg).mode & 0o777, 0o600, "and keeps its mode");
    const i = run("init", "--layer", "repo");
    assert.equal(i.code, 1);
    assert.match(i.err, /resolves to the user layer file/);
    // reading: the symlinked repo path is not read as a repo layer, by check, list or args
    const c = run("check", "--layer", "repo");
    assert.equal(c.code, 1);
    assert.match(c.err, /repo: .* the repo layer path resolves to the user layer file; not read/);
    const l = run("list");
    assert.match(l.err, /repo layer .*resolves to the user layer file; not read/);
    const a = run("args", "pr-merge-gate");
    assert.equal(a.code, 0);
    assert.deepEqual(JSON.parse(a.out).policy_layers.map((x) => x.origin), ["user"], "the user's file is not forwarded a second time as a repo layer");
  } finally { s.done(); }
});

test("a symlinked directory under the repo root is refused even when it points somewhere harmless", () => {
  const s = sandbox();
  try {
    const elsewhere = join(s.root, "elsewhere"); mkdirSync(elsewhere);
    symlinkSync(elsewhere, join(s.proj, ".jev"));
    const r = s.run("add", EX, "--layer", "repo");
    assert.equal(r.code, 1);
    assert.match(r.err, /NOT WRITTEN: a directory in the repo layer path \(\.jev\) is a symlink/);
    assert.deepEqual(readdirSync(elsewhere), []);
    assert.equal(s.run("init", "--layer", "repo").code, 1);
    // an explicit --repo FILE skips the directory walk but never the same-file check
    const explicit = join(s.root, "explicit-policy.json");
    assert.equal(s.run("add", EX, "--layer", "repo", "--repo", explicit).code, 0);
    const same = s.run("add", EX, "--layer", "repo", "--repo", s.user);
    assert.equal(same.code, 1);
    assert.match(same.err, /resolves to the user layer file/);
  } finally { s.done(); }
});

test("replacing an existing layer file keeps its mode", () => {
  const s = sandbox();
  try {
    assert.equal(s.run("add", EX, "--layer", "user", "--yes").code, 0);
    chmodSync(s.user, 0o640);
    const v2 = GATE(); v2.version = 2;
    assert.equal(s.run("add", s.spec("v2.json", v2), "--layer", "user", "--yes", "--replace").code, 0);
    assert.equal(statSync(s.user).mode & 0o777, 0o640, "an existing mode is preserved, not reset");
    assert.equal(s.run("add", EX, "--layer", "repo").code, 0);
    chmodSync(s.repo, 0o664);
    const t = GATE(); t.version = 2;
    assert.equal(s.run("add", s.spec("t2.json", t), "--layer", "repo", "--replace").code, 0);
    assert.equal(statSync(s.repo).mode & 0o777, 0o664);
  } finally { s.done(); }
});

test("an invalid or unreadable user file stops list, test and args (exit 1), and check; the repo layer never stands in for it", () => {
  const s = sandbox();
  try {
    assert.equal(s.run("add", EX, "--layer", "user", "--yes").code, 0);
    assert.equal(s.run("add", s.spec("t.json", tighten()), "--layer", "repo").code, 0);
    writeFileSync(s.user, "{ hand edited, broken");
    for (const cmd of [["list"], ["test", "pr-merge-gate"], ["args", "pr-merge-gate"], ["check"]]) {
      const r = s.run(...cmd);
      assert.equal(r.code, 1, cmd.join(" "));
      assert.equal(r.out.includes("policy_layers"), false, "no call is built");
    }
    assert.match(s.run("args", "pr-merge-gate").err, /the user layer is invalid or unreadable: refusing to build a call/);
    assert.match(s.run("test", "pr-merge-gate").err, /the user layer is invalid or unreadable: not testing against the remaining layers/);
    const jl = s.run("list", "--json");
    assert.equal(jl.code, 1, "list --json also exits 1");
    const j = JSON.parse(s.run("list", "--json").out);
    assert.deepEqual([j.user_layer_broken, j.classes], [true, []], "the repo copy is not listed as the class");
    // a user file that is a symlink is also 'broken'
    rmSync(s.user);
    const real = join(s.root, "real-user.json");
    writeFileSync(real, "{}");
    symlinkSync(real, s.user);
    const symlinked = s.run("args", "pr-merge-gate");
    assert.equal(symlinked.code, 1);
    assert.match(symlinked.err, /user layer .* is a symlink: refusing to read it/);
    assert.match(symlinked.err, /the user layer is invalid or unreadable: refusing to build a call/);
    // and with no user file at all, a repo-only class is simply not resolved
    rmSync(s.user);
    const r = s.run("args", "pr-merge-gate");
    assert.equal(r.code, 1);
    assert.match(r.err, /no trusted layer defines class "pr-merge-gate"/);
    assert.match(r.err, /which no valid user layer defines/);
    assert.equal(s.run("test", "pr-merge-gate").code, 1);
    assert.match(s.run("list").out, /no policy classes/);
  } finally { s.done(); }
});

test("adding a class to the repo layer that no user layer defines warns that it will not resolve", () => {
  const s = sandbox();
  try {
    const r = s.run("add", EX, "--layer", "repo");
    assert.equal(r.code, 0);
    assert.match(r.out, /policy_version with the other layer as it is now: - \(not resolved: no valid user layer defines this class\)/);
    assert.match(r.out, /note: repo layer defines class "pr-merge-gate", which no valid user layer defines: not resolved/);
  } finally { s.done(); }
});

test("untrusted repo text does not reach the terminal verbatim: a long key, odd example names", () => {
  const s = sandbox();
  try {
    assert.equal(s.run("add", EX, "--layer", "user", "--yes").code, 0);
    mkdirSync(join(s.proj, ".jev"));
    const KEY = "IGNORE-PREVIOUS-INSTRUCTIONS-" + "k".repeat(500);
    writeFileSync(s.repo, JSON.stringify({ v: 1, decisions: [], [KEY]: 1 }));
    for (const cmd of [["check"], ["list"], ["args", "pr-merge-gate"]]) {
      const r = s.run(...cmd);
      assert.ok(!r.out.includes("IGNORE-PREVIOUS") && !r.err.includes("IGNORE-PREVIOUS"), cmd.join(" "));
    }
    const t = tighten();
    t.examples = t.examples.map((e) => (e.expect.rule_id === "R0-ask-when-review-unknown" ? { ...e, name: "NAME-" + "n".repeat(70) } : e)); // the repo's lifted examples are the ones `test` prints
    writeFileSync(s.repo, JSON.stringify({ v: 1, decisions: [t] }));
    const r = s.run("test", "pr-merge-gate");
    for (const line of r.out.split("\n")) assert.ok(line.length < 400, line.length);
    assert.ok(!r.out.includes("n".repeat(49)));
  } finally { s.done(); }
});

test("args counts layers in bytes: two valid multi-byte layers under the character cap but over the byte cap are refused", () => {
  const s = sandbox();
  try {
    const wide = (id) => {
      const questions = {}, conds = [];
      for (let i = 1; i <= 6; i++) { questions[`q${i}`] = { type: "noul", instructions: "\u00e9".repeat(700) + " is it so?", criteria: { true: "yes", false: "no" } }; conds.push({ noul: `q${i}`, gte: 0.5, missing_as: 1 }); }
      const zero = Object.fromEntries(Object.keys(questions).map((q) => [q, noul(0)]));
      return { id, version: 1, questions, vocabulary: ["proceed", "ask_user"], baseline: "proceed", rules: [{ id: "R1", when: { any: conds }, decision: "ask_user", reason: "any is risky" }],
        default: { decision: "proceed", reason: "none is" }, on_unavailable: { decision: "ask_user" },
        examples: [{ name: "one risky", facts: {}, answers: { ...zero, q1: noul(0.9) }, expect: { decision: "ask_user", rule_id: "R1" } }, { name: "none risky", facts: {}, answers: zero, expect: { decision: "proceed", rule_id: null } }] };
    };
    assert.equal(s.run("add", s.spec("wide.json", wide("wide")), "--layer", "user", "--yes").code, 0);
    mkdirSync(join(s.proj, ".jev"));
    writeFileSync(s.repo, readFileSync(s.user, "utf8"));
    const bytes = statSync(s.user).size + statSync(s.repo).size;
    const chars = readFileSync(s.user, "utf8").length + readFileSync(s.repo, "utf8").length;
    assert.ok(bytes > 16_384 && chars < 16_384, `bytes ${bytes} over the cap, characters ${chars} under it`);
    const a = s.run("args", "wide");
    assert.equal(a.code, 1);
    assert.match(a.err, /over the 16384 byte cap/);
  } finally { s.done(); }
});
