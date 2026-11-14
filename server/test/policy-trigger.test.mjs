// Policy triggers (openspec add-policy-hook-adapter): grammar, command-word matching, merge handling. Data only: command
// strings are text handed to a parser, never executed.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { EFFECTS, FACT_SOURCES, TRIGGER_LIMITS, TRIGGER_TOOLS, commandSegments, effectMap, MAX_MERGE_TARGETS, ghPrMergeTarget, ghPrMergeTargets, matchCommand, stricter, targetHazard, validateTrigger } from "../src/policy/trigger.mjs";
import { parseLayer, validateDocument } from "../src/policy/schema.mjs";
import { mergeLayers, policyVersion } from "../src/policy/merge.mjs";
import { validateSpec } from "../src/decide/validate.mjs";

const EX = fileURLToPath(new URL("../../examples/policies/pr-merge-gate.json", import.meta.url));
const gate = () => JSON.parse(readFileSync(EX, "utf8"));
const spec = () => { const { examples, trigger, ...raw } = gate(); return validateSpec(raw).spec; };
const good = () => ({ tool: "Bash", command: ["gh", "pr", "merge"], facts: { pr: { source: "gh_pr_target" }, gstack_reviewed: { source: "gh_pr_review_marker", marker: "gstack-review: pass", target_from: "pr" } }, effect: { ask_user: "ask" } });
const errs = (t) => { const r = validateTrigger(t, spec()); assert.equal(r.ok, false, JSON.stringify(t).slice(0, 80)); return r.errors.join(" | "); };

test("the shipped example class carries a valid trigger and the document validates", () => {
  const r = validateDocument({ v: 1, decisions: [gate()] });
  assert.ok(r.ok, r.errors?.[0]);
  assert.deepEqual(r.decisions[0].trigger.command, ["gh", "pr", "merge"]);
  assert.equal(r.decisions[0].trigger.facts.gstack_reviewed.timeout_ms, 1000, "the default timeout is filled in");
  assert.deepEqual([...TRIGGER_TOOLS], ["Bash"]);
  assert.deepEqual([...FACT_SOURCES], ["repo_root", "branch", "gh_pr_target", "gh_pr_review_marker"]);
  assert.deepEqual([...EFFECTS], ["ask", "deny"]);
});

test("grammar: unknown keys, tools and shapes are errors that name the place", () => {
  assert.match(errs({ ...good(), regex: ".*" }), /unknown key "regex"/);
  assert.match(errs({ ...good(), tool: "Read" }), /trigger\.tool: must be one of Bash/);
  assert.match(errs({ ...good(), tool: undefined }), /trigger\.tool/);
  assert.match(errs(null), /must be an object/);
  assert.match(errs([]), /must be an object/);
  assert.match(errs({ ...good(), command: [] }), /1 to 4 words/);
  assert.match(errs({ ...good(), command: ["a", "b", "c", "d", "e"] }), /1 to 4 words/);
  assert.match(errs({ ...good(), command: "gh pr merge" }), /1 to 4 words/);
  assert.equal(TRIGGER_LIMITS.command_words, 4);
});

test("command words are plain words: no spaces, no pattern syntax, no leading dash", () => {
  for (const w of ["gh.*", "g h", "gh|git", "^gh", "gh$", "(gh)", "[gh]", "gh*", "-x", "", "a".repeat(41), "gh;ls", "$(x)", "gh\n", 7, null, ["gh"]]) {
    assert.match(errs({ ...good(), command: ["gh", w] }), /command\[1\]/, JSON.stringify(w));
  }
  for (const w of ["gh", "pr", "merge", "git-lfs", "python3.11", "a_b", "0x", "a".repeat(40)]) assert.ok(validateTrigger({ ...good(), command: [w], facts: undefined }, spec()).ok, w);
});

test("facts: sources are a closed list, parameters are checked, a fact the class never reads is an error", () => {
  const t = good();
  t.facts.nope = { source: "branch" };
  assert.match(errs(t), /no rule of the class reads fact "nope"/);
  const u = good(); u.facts.gstack_reviewed = { source: "shell", cmd: "ls" };
  assert.match(errs(u), /source: must be one of repo_root, branch, gh_pr_target, gh_pr_review_marker/);
  const k = good(); k.facts.gstack_reviewed.extra = 1;
  assert.match(errs(k), /unknown key "extra" for source gh_pr_review_marker/);
  const r = good(); r.facts.pr.marker = "x";
  assert.match(errs(r), /unknown key "marker" for source gh_pr_target/);
  for (const m of ["a;b", "a$b", "a`b`", "a\nb", "a|b", "(x)", "a".repeat(81), "", 5, null]) {
    const x = good(); x.facts.gstack_reviewed.marker = m;
    assert.match(errs(x), /marker: a string of 1 to 80/, JSON.stringify(m));
  }
  for (const ms of [99, 1501, 1.5, "100", -1]) { const x = good(); x.facts.gstack_reviewed.timeout_ms = ms; assert.match(errs(x), /timeout_ms: an integer from 100 to 1500/, String(ms)); }
  const nf = good(); nf.facts.gstack_reviewed.target_from = "gstack_reviewed";
  assert.match(errs(nf), /target_from: required, and must name a gh_pr_target fact/);
  const nm = good(); nm.facts.gstack_reviewed.target_from = "missing";
  assert.match(errs(nm), /target_from: required, and must name a gh_pr_target fact/);
  const none = good(); delete none.facts.gstack_reviewed.target_from;
  assert.match(errs(none), /target_from: required/, "a review provider without a target would read the current branch's PR, whatever the command names");
  const old = good(); old.facts.gstack_reviewed.number_from = "pr";
  assert.match(errs(old), /unknown key "number_from"/);
  const bad = good(); bad.facts = { "Bad-Name": { source: "branch" } };
  assert.match(errs(bad), /key "Bad-Name" must match/);
  const many = good(); many.facts = Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`f${i}`, { source: "branch" }]));
  assert.match(errs(many), /at most 8 entries/);
  assert.ok(validateTrigger({ ...good(), facts: undefined }, spec()).ok, "facts are optional");
});

test("gh_pr_target understands the flags of gh pr merge only: another command is refused", () => {
  const other = good(); other.command = ["gh", "pr", "close"];
  assert.match(errs(other), /gh_pr_target reads the argument list of `gh pr merge`/);
  const prefix = good(); prefix.command = ["gh", "pr", "merge", "extra"];
  assert.ok(validateTrigger(prefix, spec()).ok, "a longer command that starts with gh pr merge is fine");
  const bare = good(); bare.command = ["gh"];
  assert.match(errs(bare), /gh_pr_target/);
});

test("a fact that only feeds a provider need not be read by a rule", () => {
  const r = validateTrigger(good(), spec());
  assert.ok(r.ok);
  assert.ok(!spec().rules.some((x) => JSON.stringify(x).includes('"pr"')), "no rule reads the pr fact");
});

test("effect: words must be in the vocabulary and map to ask or deny", () => {
  assert.match(errs({ ...good(), effect: { merge_now: "ask" } }), /"merge_now" is not a decision word/);
  assert.match(errs({ ...good(), effect: { ask_user: "allow" } }), /must be one of ask, deny/);
  assert.match(errs({ ...good(), effect: [] }), /effect: must be an object/);
  const s = spec();
  const t = validateTrigger(good(), s).trigger;
  assert.deepEqual(effectMap(s, t), { proceed: "allow", ask_user: "ask" });
  assert.deepEqual(effectMap(s, { ...t, effect: { ask_user: "deny" } }), { proceed: "allow", ask_user: "deny" });
  assert.deepEqual(effectMap(s, { ...t, effect: {} }), { proceed: "allow", ask_user: "ask" }, "an unmapped restrictive word still asks");
  assert.deepEqual(effectMap({ ...s, grants: [] }, { ...t, effect: {} }), { proceed: "ask", ask_user: "ask" }, "a word nobody grants asks");
  assert.equal(stricter("allow", "ask"), "ask");
  assert.equal(stricter("deny", "ask"), "deny");
  assert.equal(stricter("allow", "allow"), "allow");
});

const T = { command: ["gh", "pr", "merge"] };
test("matching: plain, wrapped, optioned and chained commands fire", () => {
  for (const c of ["gh pr merge 12 --squash", "gh pr merge", "gh -R owner/repo pr merge 12", "gh --repo o/r pr merge --auto 3", "env X=1 gh pr merge 12", "GH_TOKEN=x gh pr merge 7",
    "time gh pr merge 3", "cd /tmp && gh pr merge 12", "echo hi; gh pr merge 12", "gh pr merge 12 | cat", 'bash -c "gh pr merge 12"', "sh -c 'cd x && gh pr merge 5'",
    "x=gh; $x pr merge 3", "$(echo gh) pr merge 3", "xargs -I{} gh pr merge {} <<< 5", "/usr/bin/gh pr merge 12", "nohup gh pr merge 12", "echo $(gh pr merge 12)", "echo `gh pr merge 12`", "x=$(gh pr merge 12)", "y=`gh pr merge 12`", "export A=$(gh pr merge 5 && ls)", "a=$(b=$(gh pr merge 5))", "a=$(b=$(c=$(d=$(gh pr merge 5))))", "cat <(gh pr merge 12)", "echo \"$(gh pr merge 3)\"", "gh\tpr  merge   99", "(gh pr merge 12)", "{ gh pr merge 12; }"]) {
    assert.equal(matchCommand(T, c).matched, true, c);
  }
});

test("matching: other commands, quoted words and echoes do not fire", () => {
  for (const c of ["gh pr view 12", "gh pr create --fill", "gh pr list", "gh issue merge", "git merge main", "echo gh pr merge", 'git commit -m "gh pr merge"', "ls", "gh", "pr merge",
    "gh pr", "grep 'gh pr merge' file", "printf '%s' gh pr merge", "ghx pr merge 1", "gh-pr merge", "merge pr gh", "gh merge pr 12", "gh merge 12 pr"]) {
    assert.equal(matchCommand(T, c).matched, false, c);
  }
  assert.equal(matchCommand(T, "").matched, false);
  assert.equal(matchCommand(T, undefined).matched, false);
  assert.equal(matchCommand({ command: ["gh"] }, "gh pr view 3").matched, true, "a one-word trigger fires on any use of the program");
});

const target = (c) => { const m = matchCommand(T, c); return m.matched ? (m.fallback ? { kind: "ambiguous" } : ghPrMergeTarget(m.hits[0])) : "no match"; };
const num = (n, repo = null) => ({ kind: "number", n, repo });
test("gh pr merge target: the first positional, with gh's flag arity, so a flag's value never becomes the PR", () => {
  // the shapes that selected the wrong PR in review: a valued flag whose value looks like a number
  assert.deepEqual(target("gh pr merge --subject 12 99"), num(99));
  assert.deepEqual(target("gh pr merge -t 12 99"), num(99));
  assert.deepEqual(target("gh pr merge -b 12 99"), num(99));
  assert.deepEqual(target("gh pr merge --body 12 99"), num(99));
  assert.deepEqual(target("gh pr merge --body=12 99"), num(99));
  assert.deepEqual(target("gh pr merge --body-file 12 99"), num(99));
  assert.deepEqual(target("gh pr merge -F 12 99"), num(99));
  assert.deepEqual(target("gh pr merge --match-head-commit 123 99"), num(99));
  assert.deepEqual(target("gh pr merge --author-email 12 99"), num(99));
  assert.deepEqual(target("gh pr merge -A 12 99"), num(99));
  assert.deepEqual(target("gh pr merge 99 --subject 12"), num(99));
  assert.deepEqual(target("gh pr merge --squash --subject 'a b' --body \"c d\" 99"), num(99));
  // short-flag clusters: booleans, then a value-taking flag that takes its value from the cluster tail or the next word
  assert.deepEqual(target("gh pr merge -sd 5"), num(5));
  assert.deepEqual(target("gh pr merge -sb text 5"), num(5));
  assert.deepEqual(target("gh pr merge -sbtext 5"), num(5));
  assert.deepEqual(target("gh pr merge -b=12 99"), num(99));
  // plain forms
  assert.deepEqual(target("gh pr merge 12 --squash"), num(12));
  assert.deepEqual(target("gh pr merge --auto 40"), num(40));
  assert.deepEqual(target("gh pr merge --squash=true 5"), num(5));
  assert.deepEqual(target("gh pr merge -- 7"), num(7));
  assert.deepEqual(target("gh pr merge 007"), num(7));
  assert.deepEqual(target("gh pr merge"), { kind: "none" }, "no positional: gh uses the current branch's PR");
  assert.deepEqual(target("gh pr merge --auto --squash"), { kind: "none" });
});

test("gh pr merge target: --repo and a PR URL pass through only in exactly validated shapes", () => {
  assert.deepEqual(target("gh pr merge 99 --repo other/repo"), num(99, "other/repo"));
  assert.deepEqual(target("gh pr merge 99 --repo=other/repo"), num(99, "other/repo"));
  assert.deepEqual(target("gh pr merge 99 -R other/repo"), num(99, "other/repo"));
  assert.deepEqual(target("gh pr merge -R other/repo 99"), num(99, "other/repo"));
  assert.deepEqual(target("gh pr merge -Rother/repo 99"), num(99, "other/repo"));
  assert.deepEqual(target("gh pr merge -sR other/repo 99"), num(99, "other/repo"));
  assert.deepEqual(target("gh -R other/repo pr merge 99"), num(99, "other/repo"), "the repo flag is read wherever it sits among the arguments");
  assert.deepEqual(target("gh pr merge 99 --repo github.example.com/o/r"), num(99, "github.example.com/o/r"));
  assert.deepEqual(target("gh pr merge https://github.com/o/r/pull/99"), { kind: "url", url: "https://github.com/o/r/pull/99" });
  assert.deepEqual(target("gh pr merge https://ghe.example.com/my-org/my.repo/pull/7 --squash"), { kind: "url", url: "https://ghe.example.com/my-org/my.repo/pull/7" });
  // not exactly shaped: ambiguous, never passed through
  for (const c of ["gh pr merge https://github.com/o/r/pull/99/files", "gh pr merge http://github.com/o/r/pull/99", "gh pr merge https://github.com/o/r/issues/99", "gh pr merge https://github.com/o/r/pull/99#discussion", "gh pr merge https://github.com/o/r/pull/99?x=1",
    "gh pr merge https://user@github.com/o/r/pull/99", "gh pr merge https://-evil.com/o/r/pull/99", "gh pr merge 99 --repo -x/y", "gh pr merge 99 --repo o", "gh pr merge 99 --repo o/r/s/t", "gh pr merge 99 --repo 'o r/x'", "gh pr merge 99 --repo $(id)/x",
    "gh pr merge 99 --repo o/r --repo p/q", "gh pr merge 99 -R o/r -R p/q", "gh pr merge https://github.com/o/r/pull/99 --repo o/r", "gh pr merge 99 --repo", "gh pr merge -R o/r", "gh pr merge --repo=o/r"]) {
    assert.deepEqual(target(c), { kind: "ambiguous" }, c);
  }
});

test("gh pr merge target: a branch, #N, two positionals, an unknown flag or a 10-digit number are ambiguous", () => {
  for (const c of ["gh pr merge feature-x", "gh pr merge #99", "gh pr merge 99abc", "gh pr merge 1234567890", "gh pr merge -5", "gh pr merge 12 99", "gh pr merge 12 feature", "gh pr merge --nope 5", "gh pr merge --squash=maybe 5", "gh pr merge -x 5", "gh pr merge -sx 5",
    "gh pr merge --subject", "gh pr merge -b", "gh pr merge 99 --body", "gh pr merge -", "gh pr merge '' 5", "gh pr merge ../../etc", "gh pr merge -- -rf"]) {
    assert.deepEqual(target(c), { kind: "ambiguous" }, c);
  }
  assert.deepEqual(ghPrMergeTarget(null), { kind: "ambiguous" });
  assert.deepEqual(ghPrMergeTarget([5]), { kind: "ambiguous" });
});

test("a match found by the whitespace scan, or anything that can move gh to another repository, makes the target unknowable", () => {
  assert.equal(matchCommand(T, "gh pr merge 12", { segments: () => { throw new Error("x"); } }).fallback, true);
  assert.equal(matchCommand(T, "gh pr merge 12").fallback, false);
  for (const c of ["cd ../other && gh pr merge 12", "pushd /x; gh pr merge 3", "popd; gh pr merge 3", "GH_REPO=o/r gh pr merge 99", "env GH_REPO=o/r gh pr merge 99", "GH_HOST=x gh pr merge 1", "(cd /tmp; gh pr merge 5)", "env -C /x gh pr merge 5",
    "git --git-dir=/x gh pr merge 1", "GIT_DIR=/x gh pr merge 1", "GH_CONFIG_DIR=/x gh pr merge 1", "echo ok\ncd x\ngh pr merge 5"]) assert.equal(targetHazard(c), true, c);
  for (const c of ["gh pr merge 12", "gh pr merge 12 --squash --delete-branch", "gh pr merge --subject abc 99", "echo hello && gh pr merge 5", "gh pr merge 5 | cat", "x=1 gh pr merge 5"]) assert.equal(targetHazard(c), false, c);
});

test("an over-long or hostile command never throws and always answers (property test, seeded)", () => {
  let a = 20261113;
  const rnd = () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  const parts = ["gh", "pr", "merge", "12", "'", '"', "`", "$(", ")", "(", "{", "}", "&&", ";", "|", "<<", "<<<", "EOF", "\n", "\\", "bash -c", "sudo", "env", "x=", "$x", "${", "\t", " ", "é", "\u0000", "*", "[", "]"];
  for (let i = 0; i < 400; i++) {
    const len = 1 + Math.floor(rnd() * 30);
    const cmd = Array.from({ length: len }, () => parts[Math.floor(rnd() * parts.length)]).join(rnd() < 0.5 ? " " : "");
    const r = matchCommand(T, cmd);
    assert.equal(typeof r.matched, "boolean");
    assert.ok(Array.isArray(r.hits) && r.hits.every(Array.isArray));
    assert.ok(Array.isArray(commandSegments(cmd)));
  }
  const long = `${"a ".repeat(15_000)}gh pr merge 3`;
  assert.equal(matchCommand(T, long).matched, true, "over the parser cap the whitespace fallback still finds it");
  assert.equal(matchCommand(T, "x".repeat(30_000)).matched, false);
});

test("merge: only the user layer's trigger is kept; a repo layer's is ignored with a note and the layer still loads", () => {
  const withTrigger = { v: 1, decisions: [gate()] };
  const userNoTrigger = (() => { const g = gate(); delete g.trigger; return { v: 1, decisions: [g] }; })();
  const user = JSON.stringify(withTrigger);
  const m = mergeLayers([{ origin: "user", text: user }]);
  assert.deepEqual(m.classes.get("pr-merge-gate").trigger.command, ["gh", "pr", "merge"]);
  const m2 = mergeLayers([{ origin: "user", text: JSON.stringify(userNoTrigger) }, { origin: "repo", text: user }]);
  assert.equal(m2.classes.get("pr-merge-gate").trigger, null, "a repo layer cannot switch a gate on");
  assert.ok(m2.notes.some((n) => /repo layer, class "pr-merge-gate": trigger ignored: triggers are read from the user layer only/.test(n)), m2.notes.join("|"));
  assert.ok(m2.used.includes("repo"), "the repo layer was not skipped");
  const m3 = mergeLayers([{ origin: "repo", text: user }]);
  assert.equal(m3.classes.size, 0);
  assert.ok(m3.notes.some((n) => /trigger ignored/.test(n)));
});

test("the trigger is not behaviour: it does not change policy_version, and a document with a bad trigger is refused whole", async () => {
  const a = gate(); const b = gate(); delete b.trigger;
  const va = await policyVersion(mergeLayers([{ origin: "user", text: JSON.stringify({ v: 1, decisions: [a] }) }]).classes.get("pr-merge-gate"));
  const vb = await policyVersion(mergeLayers([{ origin: "user", text: JSON.stringify({ v: 1, decisions: [b] }) }]).classes.get("pr-merge-gate"));
  assert.equal(va, vb);
  const bad = gate(); bad.trigger.command = ["gh.*"];
  const r = parseLayer(JSON.stringify({ v: 1, decisions: [bad] }));
  assert.equal(r.ok, false);
  assert.match(r.errors.join(" "), /command\[0\]/);
  assert.equal(mergeLayers([{ origin: "user", text: JSON.stringify({ v: 1, decisions: [bad] }) }]).classes.size, 0);
});

test("a trigger error never echoes a long hostile value", () => {
  const bad = gate(); bad.trigger.facts.gstack_reviewed.marker = `${"A".repeat(500)}${";"}`;
  bad.trigger.effect = { ["w".repeat(300)]: "ask" };
  const r = validateDocument({ v: 1, decisions: [bad] });
  assert.equal(r.ok, false);
  assert.ok(r.errors.every((e) => e.length <= 260));
  assert.ok(!r.errors.join("").includes("A".repeat(60)));
});

test("a parser that throws falls back to the whitespace scan, which only widens the match", () => {
  const boom = () => { throw new Error("parser exploded"); };
  assert.equal(matchCommand(T, "gh pr merge 12", { segments: boom }).matched, true);
  assert.deepEqual(matchCommand(T, "gh pr merge 12", { segments: boom }).hits, [["12"]]);
  assert.equal(matchCommand(T, "gh pr view 12", { segments: boom }).matched, false);
  assert.equal(matchCommand(T, "gh merge pr 12", { segments: boom }).matched, false);
});

test("a depth limit falls back to the whitespace scan, so the trigger errs toward firing", () => {
  const deepSubst = (n) => `${"echo $(".repeat(n)}gh pr merge 5${")".repeat(n)}`;
  assert.equal(matchCommand(T, deepSubst(3)).matched, true);
  assert.equal(matchCommand(T, deepSubst(3)).fallback, false, "within the limit the parser answers");
  for (const n of [7, 8, 12]) { const r = matchCommand(T, deepSubst(n)); assert.equal(r.matched, true, `${n} levels of substitution`); assert.equal(r.fallback, true); }
  assert.equal(matchCommand(T, deepSubst(9).replace("gh pr merge", "gh pr view")).matched, false, "deep but not a merge: no match");
  // bash -c nested past the unwrap limit
  let inner = "gh pr merge 5";
  for (let i = 0; i < 12; i++) inner = `bash -c ${JSON.stringify(inner)}`;
  const r = matchCommand(T, inner);
  assert.equal(r.matched, true, "12 nested bash -c");
  assert.equal(r.fallback, true);
  let shallow = "gh pr merge 5";
  for (let i = 0; i < 3; i++) shallow = `bash -c ${JSON.stringify(shallow)}`;
  assert.equal(matchCommand(T, shallow).fallback, false);
  assert.equal(target(deepSubst(8)).kind, "ambiguous", "a fallback match never names a PR");
});

test("the whitespace scan sees a program glued to substitution punctuation", () => {
  const boom = { segments: () => { throw new Error("x"); } };
  for (const c of ["echo $(gh pr merge 5)", "echo `gh pr merge 5`", "(gh pr merge 5)", '"gh" pr merge 5'.replace('"gh"', "gh"), "x;gh pr merge 5", "a&&gh pr merge 5", "{gh pr merge 5;}"]) assert.equal(matchCommand(T, c, boom).matched, true, c);
  assert.equal(matchCommand(T, "ghx pr merge 5", boom).matched, false);
});

// ---- every merge in the command counts; a bare target is trusted only for a lone merge ----------------------------------
const targets = (c) => { const m = matchCommand(T, c); return m.matched ? ghPrMergeTargets(m, c) : "no match"; };
const amb = { kind: "ambiguous" }, bare = { kind: "none" };

test("matchCommand reports EVERY matching segment, not the first", () => {
  assert.deepEqual(matchCommand(T, "gh pr merge 1 && gh pr merge 2").hits, [["1"], ["2"]]);
  assert.deepEqual(matchCommand(T, "gh pr merge 1; gh pr merge 2 --squash").hits, [["1"], ["2", "--squash"]]);
  assert.deepEqual(matchCommand(T, "gh pr merge 1\ngh pr merge 2").hits, [["1"], ["2"]]);
  assert.deepEqual(matchCommand(T, "gh pr merge 1 || gh pr merge 2 | cat").hits, [["1"], ["2"]]);
  assert.deepEqual(matchCommand(T, 'bash -c "gh pr merge 1; gh pr merge 2"').hits, [["1"], ["2"]]);
  assert.deepEqual(matchCommand(T, "echo $(gh pr merge 1) && gh pr merge 2").hits.map(String).sort(), ["1", "2"], "a substitution body counts too");
  const lone = matchCommand(T, "gh pr merge 7");
  assert.deepEqual([lone.hits, lone.segment_count, lone.fallback], [[["7"]], 1, false]);
  assert.equal(matchCommand(T, "gh pr merge 1 && echo done").segment_count, 2);
  assert.equal(matchCommand(T, "gh pr view 1 && gh pr view 2").matched, false);
  // the whitespace scan reports every occurrence too, and always as a fallback
  const f = matchCommand(T, "gh pr merge 1 && gh pr merge 2", { segments: () => { throw new Error("x"); } });
  assert.deepEqual([f.hits, f.fallback], [[["1"], ["2"]], true]);
});

test("several merges: one target each; a bare merge among them, or too many, is ambiguous", () => {
  assert.deepEqual(targets("gh pr merge 1 && gh pr merge 2"), [num(1), num(2)]);
  assert.deepEqual(targets("gh pr merge 1; gh pr merge 2 --squash"), [num(1), num(2)]);
  assert.deepEqual(targets("gh pr merge 1 && gh pr merge 2 -R o/r"), [num(1), num(2, "o/r")]);
  assert.deepEqual(targets("gh pr merge 1 && gh pr merge"), [num(1), amb], "the bare one is not the sole segment");
  assert.deepEqual(targets("gh pr merge && gh pr merge 1"), [amb, num(1)]);
  assert.deepEqual(targets("gh pr merge 1 && gh pr merge feature-x"), [num(1), amb]);
  const many = Array.from({ length: MAX_MERGE_TARGETS }, (_, i) => `gh pr merge ${i + 1}`);
  assert.equal(targets(many.join(" && ")).length, MAX_MERGE_TARGETS);
  assert.deepEqual(targets([...many, "gh pr merge 99"].join(" && ")), [amb]);
});

test("a merge that names no PR is trusted (gh uses the current branch's) only when it is the whole command", () => {
  assert.deepEqual(targets("gh pr merge"), [bare]);
  assert.deepEqual(targets("gh pr merge --squash --delete-branch"), [bare]);
  assert.deepEqual(targets("env X=1 gh pr merge"), [bare]);
  assert.deepEqual(targets("sudo gh pr merge --auto"), [bare]);
  assert.deepEqual(targets("(gh pr merge)"), [bare], "a subshell around the lone merge changes nothing");
  for (const c of [
    "gh pr checkout 2 && gh pr merge --squash", "git checkout other && gh pr merge", "git switch other; gh pr merge", "gh pr merge; gh pr checkout 2",
    "echo 2 | xargs gh pr merge", "echo 2 | gh pr merge", "xargs -a prs.txt gh pr merge", "xargs gh pr merge", "cat prs | parallel gh pr merge {}",
    "find . -name pr -exec gh pr merge {} \\;", 'bash -c "gh pr merge"', "echo $(gh pr merge)", "gh pr merge && echo done",
  ]) assert.deepEqual(targets(c), [amb], c);
});

test("an explicit number survives a branch switch, a push or a checkout before it (the repository is unchanged)", () => {
  assert.deepEqual(targets("gh pr checkout 2 && gh pr merge 99"), [num(99)]);
  assert.deepEqual(targets("git checkout other && gh pr merge 99 --squash"), [num(99)]);
  assert.deepEqual(targets("git push && gh pr merge 99"), [num(99)]);
  assert.deepEqual(targets("git fetch origin; git log -1 | cat; gh pr merge 99"), [num(99)]);
});

test("rewriting a remote or the default repository, supplying operands from outside, or splitting a name is a hazard", () => {
  for (const c of [
    "git remote set-url origin https://example.com/o/other.git && gh pr merge 99", "git remote add up x && gh pr merge 99", "git remote rename origin old; gh pr merge 99",
    "git -C /x remote set-url origin y; gh pr merge 99", "gh repo set-default o/other && gh pr merge 99",
    "git config remote.origin.url https://example.com/o/other.git && gh pr merge 99", "git config --local remote.origin.gh-resolved base && gh pr merge 99",
    "git -c remote.origin.url=x push && gh pr merge 99", "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.url gh pr merge 99",
    "env GH_RE''PO=o/r gh pr merge 99", 'env "GH_"REPO=o/r gh pr merge 99', 'env G""H_REPO=o/r gh pr merge 99', "env GH_RE\\PO=o/r gh pr merge 99",
    "X=GH_; export ${X}REPO=o/r; gh pr merge 99", "a=G; b=H_REPO; env $a$b=x gh pr merge 99", "$a=x gh pr merge 99", "env $(printf x) gh pr merge 99",
    "declare -x R=o/r; gh pr merge 99", "typeset -x R=o/r; gh pr merge 99", "readonly R=1; gh pr merge 99", "eval \"$E\"; gh pr merge 99", "source env.sh; gh pr merge 99", ". ./env.sh && gh pr merge 99",
    "GH_TOKEN=x gh pr merge 99", "$'GH\\x5fREPO'=o/r gh pr merge 99",
    "echo 2 | xargs gh pr merge 99", "printf '1\\n' | parallel gh pr merge", "find . -execdir gh pr merge 99 \\;",
  ]) {
    assert.equal(targetHazard(c), true, c);
    const m = matchCommand(T, c); // some spellings are not a gh pr merge the parser can see at all (documented limit); the rest must be ambiguous
    if (m.matched) assert.deepEqual(ghPrMergeTargets(m, c), [amb], c);
  }
  for (const c of ["git push origin main && gh pr merge 99", "git commit -m wip && gh pr merge 99", "gh pr merge 99 --squash", "git log --oneline | head -3; gh pr merge 99", "env X=1 gh pr merge 99"]) assert.equal(targetHazard(c), false, c);
});

test("a depth-limited or whitespace-scan match is ambiguous for every target", () => {
  const boom = { segments: () => { throw new Error("x"); } };
  const m = matchCommand(T, "gh pr merge 1 && gh pr merge 2", boom);
  assert.deepEqual(ghPrMergeTargets(m, "gh pr merge 1 && gh pr merge 2"), [amb]);
  const deep = "echo " + "$(".repeat(9) + "gh pr merge 3" + ")".repeat(9) + " && gh pr merge 4";
  const d = matchCommand(T, deep);
  assert.equal(d.fallback, true, "hits were found, but a nested body past the limit was not walked");
  assert.deepEqual(ghPrMergeTargets(d, deep), [amb]);
  assert.deepEqual(ghPrMergeTargets({ matched: false, hits: [], segment_count: 0, fallback: false }, "x"), [amb]);
  assert.deepEqual(ghPrMergeTargets(undefined, "x"), [amb]);
});
