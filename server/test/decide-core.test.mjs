// Evaluator, validator and worked examples for kit_decide. Data only: nothing here executes a string from a spec.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { countNodes, evaluate, normalizeAnswer } from "../src/decide/evaluate.mjs";
import { decideOffline, failMode, failureFor } from "../src/decide/core.mjs";
import { LIMITS, canonicalJson, specHash, validateFacts, validateSpec } from "../src/decide/validate.mjs";
import { decide } from "../src/decide/eval-target.mjs";
import { FAIL_REASONS } from "../src/ledger/record.mjs";

const EX = new URL("../../examples/decisions/", import.meta.url);
const example = (n) => JSON.parse(readFileSync(new URL(`${n}.json`, EX), "utf8"));

const QS = {
  a: { type: "noul", instructions: "Is it a?", criteria: { true: "yes", false: "no" } },
  b: { type: "noul", instructions: "Is it b?", criteria: { true: "yes", false: "no" } },
  k: { type: "choice", instructions: "Which?", criteria: { X: "x", Y: "y", Z: "z" } },
};
/** A valid spec whose rules are supplied by the test. */
const mk = (rules, over = {}) => ({
  id: "t", version: 1, questions: QS, vocabulary: ["go", "ask", "stop"], baseline: "ask",
  rules, default: { decision: "ask", reason: "default" }, on_unavailable: { decision: "ask" }, ...over,
});
const R = (id, when, decision = "go") => ({ id, when, decision, reason: `r ${id}` });
const noul = (v) => ({ type: "noul", value: v });
const choice = (c, probs, conf) => ({ type: "choice", choice: c, confidence: conf ?? probs[c], probabilities: { X: 0, Y: 0, Z: 0, ...probs } });
// every question used so mk() specs validate
const USE_ALL = [{ noul: "a", gte: 0.5 }, { noul: "b", gte: 0.5 }, { choice: "k", is: "X" }];

test("noul comparisons honour gte/gt/lte/lt at the boundary", () => {
  for (const [op, at, below, above] of [["gte", true, false, true], ["gt", false, false, true], ["lte", true, true, false], ["lt", false, true, false]]) {
    const spec = mk([R("r", { all: [{ noul: "a", [op]: 0.5 }, { noul: "b", gte: 0 }, { choice: "k", is: "X", missing_as: false }] })]);
    const run = (a) => evaluate(spec, { answers: { a: noul(a), b: noul(0), k: choice("X", { X: 1 }) } });
    assert.equal(run(0.5).rule_id === "r", at, `${op} at`);
    assert.equal(run(0.4).rule_id === "r", below, `${op} below`);
    assert.equal(run(0.6).rule_id === "r", above, `${op} above`);
  }
});

test("first match wins, and a fact-only rule decides with no answers", () => {
  const spec = mk([
    R("model-first", { all: [{ fact: "x", eq: 1 }, { noul: "a", gte: 0.5 }, { noul: "b", gte: 0 }, { choice: "k", is: "X" }] }, "stop"),
    R("fact", { fact: "x", eq: 1 }, "go"),
  ]);
  // rule 1 needs answers: the walk must stop there rather than skip ahead to the fact rule
  const stopped = evaluate(spec, { facts: { x: 1 } });
  assert.equal(stopped.resolved, false);
  assert.deepEqual(stopped.needs.sort(), ["a", "b", "k"]);
  // with answers that make rule 1 false, rule 2 decides
  const r = evaluate(spec, { facts: { x: 1 }, answers: { a: noul(0), b: noul(0), k: choice("Y", { Y: 1 }) } });
  assert.deepEqual([r.resolved, r.rule_id, r.decision], [true, "fact", "go"]);
  // a fact-only rule placed first decides with no answers at all
  const first = mk([R("f", { fact: "x", eq: 1 }, "stop"), R("m", { all: USE_ALL })]);
  assert.deepEqual(evaluate(first, { facts: { x: 1 } }), { resolved: true, decision: "stop", rule_id: "f", reason: "r f", steps: 1 });
});

test("needs lists exactly the missing question ids of the stopping rule", () => {
  const spec = mk([R("m", { any: [{ noul: "a", gte: 0.5 }, { all: [{ noul: "b", gte: 0.5 }, { choice: "k", is: "X" }] }] })]);
  assert.deepEqual(evaluate(spec, {}).needs.sort(), ["a", "b", "k"]);
  assert.deepEqual(evaluate(spec, { answers: { a: noul(0), k: choice("Y", { Y: 1 }) } }), { resolved: true, decision: "ask", rule_id: null, reason: "default", steps: 5 });
  assert.deepEqual(evaluate(spec, { answers: { a: noul(0) } }).needs.sort(), ["b", "k"]);
});

test("default decides when every rule is false, with no answers when the rules are fact-only", () => {
  const spec = mk([R("f", { fact: "x", eq: 1 }), R("g", { fact: "y", in: ["p", "q"] })]);
  // questions unused: validateSpec would reject it, evaluate itself only needs the table
  const r = evaluate(spec, { facts: { x: 2, y: "z" } });
  assert.deepEqual([r.resolved, r.decision, r.rule_id], [true, "ask", null]);
});

test("three-valued logic: decisive child wins over unknown and invalid; not passes them through", () => {
  const inv = { invalid: true };
  const only = (when, answers) => evaluate(mk([R("r", when)]), { answers });
  // all with a false child is false even beside an invalid one
  assert.equal(only({ all: [{ noul: "a", gte: 0.5 }, { noul: "b", gte: 0.5 }] }, { a: noul(0), b: inv }).resolved, true);
  assert.equal(only({ all: [{ noul: "a", gte: 0.5 }, { noul: "b", gte: 0.5 }] }, { a: noul(0), b: inv }).rule_id, null);
  // any with a true child is true beside an invalid one
  assert.equal(only({ any: [{ noul: "a", gte: 0.5 }, { noul: "b", gte: 0.5 }] }, { a: noul(1), b: inv }).rule_id, "r");
  // invalid dominates unknown
  assert.deepEqual(only({ all: [{ noul: "a", gte: 0.5 }, { noul: "b", gte: 0.5 }] }, { a: inv }), { resolved: false, invalid: ["a"], steps: 3 });
  // not of unknown stays unknown; not of invalid stays invalid
  assert.deepEqual(only({ not: { noul: "a", gte: 0.5 } }, {}).needs, ["a"]);
  assert.deepEqual(only({ not: { noul: "a", gte: 0.5 } }, { a: inv }).invalid, ["a"]);
  assert.equal(only({ not: { noul: "a", gte: 0.5 } }, { a: noul(0.1) }).rule_id, "r");
});

test("missing_as stands in for an invalid answer, per condition kind", () => {
  const inv = { invalid: true };
  const run = (when) => evaluate(mk([R("r", when)]), { answers: { a: inv, k: inv } });
  assert.equal(run({ noul: "a", gte: 0.5, missing_as: 1 }).rule_id, "r");
  assert.equal(run({ noul: "a", gte: 0.5, missing_as: 0 }).rule_id, null);
  assert.equal(run({ choice: "k", is: "X", missing_as: true }).rule_id, "r");
  assert.equal(run({ choice: "k", is: "X", missing_as: false }).rule_id, null);
  assert.equal(run({ choice: "k", prob_of: ["X", "Y"], gte: 0.5, missing_as: 1 }).rule_id, "r");
  assert.deepEqual(run({ noul: "a", gte: 0.5 }).invalid, ["a"]);
});

test("choice tests: label sets, min_confidence, prob_of sums, absent probability counts as 0", () => {
  const run = (when, ans) => evaluate(mk([R("r", when)]), { answers: { k: ans } }).rule_id;
  assert.equal(run({ choice: "k", is: "X", min_confidence: 0.9 }, choice("X", { X: 0.9, Y: 0.1 })), "r");
  assert.equal(run({ choice: "k", is: "X", min_confidence: 0.9 }, choice("X", { X: 0.89, Y: 0.11 })), null);
  assert.equal(run({ choice: "k", is: "X", min_confidence: 0.9 }, choice("X", { X: 0.6 }, 0.95)), "r", "explicit confidence wins");
  assert.equal(run({ choice: "k", in: ["Y", "Z"] }, choice("Z", { Z: 0.5, X: 0.5 })), "r");
  assert.equal(run({ choice: "k", in: ["Y", "Z"] }, choice("X", { X: 1 })), null);
  assert.equal(run({ choice: "k", prob_of: ["Y", "Z"], gte: 0.5 }, choice("X", { X: 0.5, Y: 0.25, Z: 0.25 })), "r");
  assert.equal(run({ choice: "k", prob_of: ["Y", "Z"], gt: 0.5 }, choice("X", { X: 0.5, Y: 0.25, Z: 0.25 })), null);
});

test("fact conditions: absent is false (not unknown), exists, in, numeric ops need numbers", () => {
  const run = (when, facts) => evaluate(mk([R("r", when)], {}), { facts }).rule_id;
  assert.equal(run({ fact: "x", eq: "a" }, {}), null);
  assert.equal(run({ not: { fact: "x", eq: "a" } }, {}), "r", "not flips an absent-fact false");
  assert.equal(run({ fact: "x", exists: false }, {}), "r");
  assert.equal(run({ fact: "x", exists: true }, { x: null }), "r", "null is present");
  assert.equal(run({ fact: "x", exists: true }, {}), null, "exists:true needs the key");
  assert.equal(run({ fact: "x", exists: false }, { x: 1 }), null, "exists:false needs the key absent");
  assert.equal(run({ fact: "x", in: [1, 2] }, { x: 2 }), "r");
  assert.equal(run({ fact: "x", gt: 5 }, { x: "9" }), null, "a string is not a number");
  assert.equal(run({ fact: "x", lte: 5 }, { x: 5 }), "r");
  assert.equal(run({ fact: "x", eq: 1 }, { x: "1" }), null, "strict equality");
});

test("steps are bounded by rules x nodes-per-rule whatever the answers", () => {
  const spec = mk([
    R("r1", { all: [{ noul: "a", gte: 0.5 }, { any: [{ noul: "b", gte: 0.5 }, { not: { choice: "k", is: "X" } }] }] }),
    R("r2", { fact: "x", eq: 1 }),
    R("r3", { any: [{ noul: "a", lt: 0.1 }, { noul: "b", lt: 0.1 }, { choice: "k", in: ["Y", "Z"] }] }),
  ]);
  const bound = spec.rules.reduce((n, r) => n + countNodes(r.when), 0);
  assert.equal(bound, 6 + 1 + 4);
  const grid = [0, 0.05, 0.5, 1];
  for (const a of grid) for (const b of grid) for (const lbl of ["X", "Y", "Z"]) {
    for (const x of [1, 2, undefined]) {
      const r = evaluate(spec, { facts: x === undefined ? {} : { x }, answers: { a: noul(a), b: noul(b), k: choice(lbl, { [lbl]: 1 }) } });
      assert.ok(r.steps >= 1 && r.steps <= bound, `steps ${r.steps} within ${bound}`);
    }
  }
  // no rule matches: every node of every rule is visited exactly once
  const none = evaluate(spec, { facts: { x: 2 }, answers: { a: noul(0.3), b: noul(0.3), k: choice("X", { X: 1 }) } });
  assert.equal(none.steps, bound);
});

test("knobs replace a named threshold; non-finite knobs are ignored", () => {
  const spec = example("route-read-or-full");
  const v = validateSpec(spec).spec;
  const ans = { route_choice: choice("READ", { READ: 0.85, WRITE: 0.1, BOTH: 0.05 }) };
  assert.equal(evaluate(v, { facts: { open_ask: false }, answers: ans }).decision, "full_agent");
  assert.equal(evaluate(v, { facts: { open_ask: false }, answers: ans, knobs: { read_min: 0.8 } }).decision, "read_only");
  assert.equal(evaluate(v, { facts: { open_ask: false }, answers: ans, knobs: { read_min: Number.NaN } }).decision, "full_agent");
  assert.equal(evaluate(v, { facts: { open_ask: false }, answers: ans, knobs: { other: 0 } }).decision, "full_agent");
});

test("normalizeAnswer: strict about ranges, labels and shapes", () => {
  const n = QS.a, c = QS.k;
  assert.deepEqual(normalizeAnswer(n, { type: "noul", noul: 0 }), { type: "noul", value: 0 });
  for (const bad of [{ noul: 1.01 }, { noul: -0.01 }, { noul: "0.5" }, { noul: NaN }, { noul: null }, {}, null, 7, "x", [], undefined]) assert.deepEqual(normalizeAnswer(n, bad), { invalid: true }, JSON.stringify(bad));
  assert.equal(normalizeAnswer(c, { choice: "X", probabilities: { X: 0.7, Y: 0.3 } }).confidence, 0.7);
  assert.deepEqual(normalizeAnswer(c, { choice: "X", probabilities: { X: 0.7, Y: 0.3 } }).probabilities, { X: 0.7, Y: 0.3, Z: 0 });
  for (const bad of [{ choice: "W", probabilities: { X: 1 } }, { choice: "X" }, { choice: "X", probabilities: [] }, { choice: "X", probabilities: { X: 2 } }, { choice: "X", probabilities: { X: "1" } }, { probabilities: { X: 1 } }]) assert.deepEqual(normalizeAnswer(c, bad), { invalid: true }, JSON.stringify(bad));
  // prototype keys are not labels
  assert.deepEqual(normalizeAnswer(c, { choice: "__proto__", probabilities: {} }), { invalid: true });
  // confidence outside [0,1] or non-numeric is invalid, never silently replaced by the choice's probability
  for (const badc of [1.5, -0.2, "0.9", true, NaN]) assert.deepEqual(normalizeAnswer(c, { choice: "X", confidence: badc, probabilities: { X: 0.7, Y: 0.3 } }), { invalid: true }, String(badc));
  assert.equal(normalizeAnswer(c, { choice: "X", confidence: 0.2, probabilities: { X: 0.7, Y: 0.3 } }).confidence, 0.2);
  assert.equal(normalizeAnswer(c, { choice: "X", confidence: null, probabilities: { X: 0.7, Y: 0.3 } }).confidence, 0.7);
});

test("validateSpec accepts every shipped example and reports the derived fail mode", async () => {
  const names = readdirSync(EX).filter((f) => f.endsWith(".json") && !f.endsWith(".cases.json") && !f.endsWith(".suite.json")).map((f) => f.slice(0, -5));
  assert.deepEqual(names.sort(), ["ask-before-migration", "route-read-or-full", "support-reply-auto-send"]);
  for (const n of names) {
    const r = validateSpec(example(n));
    assert.equal(r.ok, true, `${n}: ${r.errors}`);
    assert.equal(r.fail_mode, "open");
    assert.match(await specHash(r.spec), /^[0-9a-f]{12}$/);
  }
});

test("validateSpec is closed: unknown keys fail at every level", () => {
  const base = () => structuredClone(example("ask-before-migration"));
  const cases = {
    spec: (s) => { s.script = "x"; },
    rule: (s) => { s.rules[0].run = "x"; },
    cond: (s) => { s.rules[1].when.regex = "x"; },
    question: (s) => { s.questions.destructive.tool = "x"; },
    criteria: (s) => { s.questions.destructive.criteria.maybe = "x"; },
    default: (s) => { s.default.template = "{{x}}"; },
    on_unavailable: (s) => { s.on_unavailable.retry = 3; },
    criterion: (s) => { s.questions.destructive.criteria.true.regex = "x"; },
  };
  for (const [name, mut] of Object.entries(cases)) { const s = base(); mut(s); const r = validateSpec(s); assert.equal(r.ok, false, name); assert.match(r.errors.join("|"), /unknown key/, name); }
  // exactly one condition kind per node
  const s = base(); s.rules[1].when = { noul: "destructive", gte: 0.5, fact: "x", eq: 1 };
  assert.equal(validateSpec(s).ok, false);
});

test("validateSpec requires baseline and on_unavailable.decision, both from the vocabulary", () => {
  const without = (k) => { const s = structuredClone(example("ask-before-migration")); delete s[k]; return validateSpec(s); };
  assert.match(without("baseline").errors.join("|"), /baseline/);
  assert.match(without("on_unavailable").errors.join("|"), /on_unavailable/);
  const s = structuredClone(example("ask-before-migration"));
  s.on_unavailable = { decision: "retry" };
  assert.match(validateSpec(s).errors.join("|"), /on_unavailable\.decision/);
  s.on_unavailable = {}; assert.equal(validateSpec(s).ok, false);
});

test("lint: failing may not grant; restrictive must be disjoint from grants and exclude the baseline", () => {
  const base = () => structuredClone(example("ask-before-migration"));
  let s = base(); s.on_unavailable = { decision: "proceed" };
  assert.match(validateSpec(s).errors.join("|"), /failing may not grant/);
  // allowed only when the granting decision is also the baseline: then it is not a grant relative to the no-decider case
  s = base(); s.baseline = "proceed"; s.on_unavailable = { decision: "proceed" }; s.default = { decision: "proceed", reason: "d" };
  assert.equal(validateSpec(s).ok, true);
  assert.equal(validateSpec(s).fail_mode, "open");
  s = base(); s.restrictive = ["proceed"]; assert.match(validateSpec(s).errors.join("|"), /must not overlap grants/);
  s = base(); s.restrictive = ["ask_user"]; assert.match(validateSpec(s).errors.join("|"), /must not contain the baseline/);
  s = base(); s.grants = ["fly"]; assert.match(validateSpec(s).errors.join("|"), /grants/);
  // closed: failing decision differs from the baseline
  s = base(); s.on_unavailable = { decision: "block" };
  assert.equal(validateSpec(s).ok, true); assert.equal(validateSpec(s).fail_mode, "closed");
});

test("failMode/failureFor follow the spec text and name the closed fail reason", () => {
  const open = validateSpec(example("ask-before-migration")).spec;
  assert.equal(failMode(open), "open");
  assert.deepEqual(failureFor(open, "timeout"), { decision: "ask_user", rule_id: null, reason: "The model could not be consulted; ask the user.", decided_by: "fail_open", fail_mode_applied: "open", fail_reason: "timeout" });
  const closed = { ...open, on_unavailable: { decision: "block" } };
  const f = failureFor(closed, "upstream_error");
  assert.deepEqual([f.decision, f.decided_by, f.fail_mode_applied], ["block", "fail_closed", "closed"]);
});

test("validateSpec enforces every cap and rejects rather than truncates", () => {
  const rules = (n) => Array.from({ length: n }, (_, i) => R(`r${i}`, { noul: "a", gte: 0.5 }));
  const qs = { a: QS.a };
  const ok = (s) => validateSpec(s).ok;
  assert.equal(ok(mk(rules(LIMITS.rules), { questions: qs })), true);
  assert.equal(ok(mk(rules(LIMITS.rules + 1), { questions: qs })), false);
  assert.equal(ok(mk([], { questions: qs })), false);
  const perQ = (n) => mk(Array.from({ length: n }, (_, i) => R(`r${i}`, { noul: `q${i}`, gte: 0.5 })), { questions: Object.fromEntries(Array.from({ length: n }, (_, i) => [`q${i}`, QS.a])) });
  assert.equal(ok(perQ(LIMITS.questions)), true, "16 questions");
  assert.equal(ok(perQ(LIMITS.questions + 1)), false, "17 questions");
  // depth: root all(1) > any(2) > all(3) > any(4) > leaf(5) is too deep
  const deep = (d) => (d === 0 ? { noul: "a", gte: 0.5 } : { [d % 2 ? "all" : "any"]: [deep(d - 1)] });
  assert.equal(ok(mk([R("r", deep(3))], { questions: qs })), true, "4 levels");
  assert.equal(ok(mk([R("r", deep(4))], { questions: qs })), false, "5 levels");
  // nodes per rule
  const wide = { any: Array.from({ length: 16 }, () => ({ all: Array.from({ length: 5 }, () => ({ noul: "a", gte: 0.5 })) })) };
  assert.equal(countNodes(wide), 1 + 16 * 6);
  assert.equal(ok(mk([R("r", wide)], { questions: qs })), false, "over 64 nodes");
  // facts
  assert.equal(validateFacts(Object.fromEntries(Array.from({ length: LIMITS.facts }, (_, i) => [`f${i}`, i]))).ok, true);
  assert.equal(validateFacts(Object.fromEntries(Array.from({ length: LIMITS.facts + 1 }, (_, i) => [`f${i}`, i]))).ok, false);
});

test("validateSpec lints references and shapes", () => {
  const base = () => structuredClone(example("support-reply-auto-send"));
  const err = (mut) => { const s = base(); mut(s); const r = validateSpec(s); assert.equal(r.ok, false); return r.errors.join("|"); };
  assert.match(err((s) => { s.rules[1].when = { noul: "nope", gte: 0.5 }; }), /not a question/);
  assert.match(err((s) => { s.rules[1].when = { noul: "reply_kind", gte: 0.5 }; }), /choice question/);
  assert.match(err((s) => { s.rules[2].when = { any: [{ choice: "tone_risk", is: "X" }] }; }), /noul question/);
  assert.match(err((s) => { s.rules[3].when.all[0].is = "NOPE"; }), /not a label/);
  assert.match(err((s) => { s.rules[1].when.gte = 1.5; }), /0 to 1/);
  assert.match(err((s) => { s.rules[1].when.missing_as = 2; }), /0 to 1/);
  assert.match(err((s) => { s.rules[0].id = "bad id"; }), /rules\[0\]\.id/);
  assert.match(err((s) => { s.rules[1].id = "R1-enterprise"; }), /duplicate/);
  assert.match(err((s) => { s.vocabulary.push("Bad Word"); }), /vocabulary/);
  assert.match(err((s) => { s.rules[0].decision = "other"; }), /decision/);
  assert.match(err((s) => { s.questions.tone_risk.criteria = { true: "y" }; }), /both/);
  assert.match(err((s) => { s.questions.zzz = s.questions.tone_risk; }), /never used/);
  assert.match(err((s) => { s.rules[1].when.knob = "answer_min"; s.rules[3].when.all[0].knob = "answer_min"; }), /used twice/);
  assert.match(err((s) => { s.rules[0].when.knob = "x"; }), /exactly one of all|knob|unknown key/);
  assert.match(err((s) => { s.rules[2].reason = "x".repeat(LIMITS.reason + 1); }), /reason/);
});

test("validateSpec never throws on garbage, cycles or hostile keys", () => {
  const cyc = { id: "x" }; cyc.self = cyc;
  for (const bad of [null, undefined, 1, "s", [], {}, cyc, { rules: "x" }, { rules: [null], questions: [], vocabulary: {} }, JSON.parse('{"__proto__":{"x":1},"id":"t"}')]) {
    const r = validateSpec(bad);
    assert.equal(r.ok, false);
    assert.ok(Array.isArray(r.errors) && r.errors.length > 0);
  }
  assert.equal(validateSpec(JSON.parse(`{"id":"t","pad":"${"x".repeat(LIMITS.spec_bytes)}"}`)).ok, false);
});

test("canonicalJson and specHash ignore key order and change with content", async () => {
  const a = example("ask-before-migration");
  const rev = (v) => (Array.isArray(v) ? v.map(rev) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).reverse().map((k) => [k, rev(v[k])])) : v);
  const b = rev(a);
  assert.notEqual(JSON.stringify(a), JSON.stringify(b));
  assert.equal(await specHash(a), await specHash(b));
  const c = structuredClone(a); c.version = 2;
  assert.notEqual(await specHash(a), await specHash(c));
  assert.equal(canonicalJson({ b: 1, a: [2, { d: 1, c: 2 }] }), '{"a":[2,{"c":2,"d":1}],"b":1}');
});

test("FAIL_REASONS is pinned (a shared closed list with the ledger)", () => {
  assert.deepEqual([...FAIL_REASONS], ["no_upstream", "upstream_error", "timeout", "invalid_response", "oversize", "client_config", "client_input", "client_timeout", "client_network", "client_http_5xx", "client_parse", "client_rejected", "rule_error", "local_rules_unavailable"]);
});

// ── worked examples behave as documented ────────────────────────────────────
for (const name of ["route-read-or-full", "ask-before-migration", "support-reply-auto-send"]) {
  const cases = JSON.parse(readFileSync(new URL(`${name}.cases.json`, EX), "utf8"));
  test(`example ${name}: ${cases.length} documented cases (decideOffline and the jev-eval module target agree)`, () => {
    const spec = validateSpec(example(name)).spec;
    assert.ok(cases.length >= 6);
    for (const c of cases) {
      const r = decideOffline(spec, { facts: c.facts, rawAnswers: c.answers });
      assert.equal(r.decision, c.expect.decision, c.name);
      assert.equal(r.rule_id, c.expect.rule_id, c.name);
      assert.equal(r.decided_by, c.expect.decided_by, c.name);
      if (c.expect.fail_reason) assert.equal(r.fail_reason, c.expect.fail_reason, c.name);
      if (c.expect.decided_by === "prefilter") assert.deepEqual(r.answers, {}, `${c.name}: fact-only decisions use no answers`);
      assert.deepEqual(decide({ example: name, facts: c.facts, answers: c.answers }), { decision: r.decision, rule_id: r.rule_id, decided_by: r.decided_by, fail_reason: r.fail_reason }, c.name);
    }
  });
}

test("eval target: knob params change a threshold; bad input throws instead of guessing", () => {
  const row = { example: "route-read-or-full", facts: { open_ask: false }, answers: { route_choice: { type: "choice", choice: "READ", probabilities: { READ: 0.85, WRITE: 0.1, BOTH: 0.05 } } } };
  assert.equal(decide(row, {}).decision, "full_agent");
  assert.equal(decide(row, { read_min: 0.8 }).decision, "read_only");
  assert.throws(() => decide({ example: "../../etc/passwd", answers: {} }), /example/);
  assert.throws(() => decide({ spec: { id: "x" }, answers: {} }), /invalid spec/);
});

test("the shipped jev-eval suite points at a real module export and a corpus the spec can decide", async () => {
  const suite = JSON.parse(readFileSync(new URL("route-read-or-full.suite.json", EX), "utf8"));
  assert.deepEqual(suite.target, { kind: "module", path: "../../server/src/decide/eval-target.mjs", export: "decide" });
  const mod = await import(new URL(suite.target.path, EX));
  assert.equal(typeof mod[suite.target.export], "function");
  const spec = validateSpec(example("route-read-or-full")).spec;
  const rows = readFileSync(new URL(suite.corpus, EX), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.ok(rows.length >= 50);
  assert.deepEqual([...new Set(rows.map((r) => r.label_source))], ["derived"], "synthetic labels are declared derived, never human");
  assert.ok(new Set(rows.map((r) => r.id)).size === rows.length);
  for (const r of rows) {
    assert.ok(spec.vocabulary.includes(r.expected), r.id);
    assert.ok(spec.vocabulary.includes(mod.decide(r.input, { read_min: 0.85 }).decision), r.id);
  }
  assert.deepEqual(suite.sweep.map((s) => s.name), ["read_min"]);
});

test("wiring: the Worker registers kit_decide and the installer's doctor expects the resulting tool count", async () => {
  const index = readFileSync(new URL("../src/index.mjs", import.meta.url), "utf8");
  assert.match(index, /registerKitTools\(server, \(\) => currentEnv\);\n\s*registerDecideTool\(server, \(\) => currentEnv\);/);
  const { KIT_TOOL_NAMES } = await import("../src/kit/tools.mjs");
  const upstream = 12; // jkudish/jev-mcp jev_* tools, pinned in server/build-vendor.sh
  const install = readFileSync(new URL("../../install.sh", import.meta.url), "utf8");
  assert.equal(Number(/^EXPECTED_TOOLS=(\d+)$/m.exec(install)[1]), upstream + KIT_TOOL_NAMES.length + 1);
});

test("knobs on a noul threshold: a finite override replaces it, a non-finite one is ignored", () => {
  const spec = validateSpec(example("ask-before-migration")).spec;
  const facts = { environment: "staging", has_backup: true };
  const answers = { destructive: { type: "noul", value: 0.4 }, additive_only: { type: "noul", value: 0.4 } };
  assert.equal(evaluate(spec, { facts, answers }).decision, "ask_user");
  assert.equal(evaluate(spec, { facts, answers }).rule_id, null, "0.4 is under the literal 0.5");
  assert.equal(evaluate(spec, { facts, answers, knobs: { destructive_min: 0.3 } }).rule_id, "R2-destructive");
  assert.equal(evaluate(spec, { facts, answers, knobs: { destructive_min: Number.NaN } }).rule_id, null);
  assert.equal(evaluate(spec, { facts, answers, knobs: { destructive_min: "0.3" } }).rule_id, null);
  const high = { destructive: { type: "noul", value: 0.8 }, additive_only: { type: "noul", value: 0.4 } };
  assert.equal(evaluate(spec, { facts, answers: high, knobs: { destructive_min: Number.NaN } }).rule_id, "R2-destructive", "NaN falls back to the literal 0.5, which 0.8 meets");
  assert.equal(evaluate(spec, { facts, answers: high, knobs: { destructive_min: Infinity } }).rule_id, "R2-destructive", "Infinity falls back to the literal");
});

test("static: the Worker-side decide modules hold no module-level mutable state", () => {
  for (const f of ["evaluate", "validate", "core", "tool"]) {
    const src = readFileSync(new URL(`../src/decide/${f}.mjs`, import.meta.url), "utf8");
    assert.doesNotMatch(src, /^(let|var)\s/m, `${f}.mjs has a top-level let/var`);
    assert.doesNotMatch(src, /^(export )?const\s+\w+\s*=\s*new\s+(Map|Set|WeakMap)\b/m, `${f}.mjs has a module-level Map/Set`);
  }
  // the pure evaluator imports nothing at all
  assert.doesNotMatch(readFileSync(new URL("../src/decide/evaluate.mjs", import.meta.url), "utf8"), /^\s*import\s/m);
});
