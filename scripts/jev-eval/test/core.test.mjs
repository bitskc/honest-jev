// jev-eval core: intervals, pointers, suite validation, stable split, harm scoring. Synthetic data only.
//   node --test scripts/jev-eval/test/
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { wilson, zeroUpper95, proportion } from "../lib/stats.mjs";
import { pointerGet } from "../lib/pointer.mjs";
import { SuiteError, validateSuite, loadSuite, loadCorpus } from "../lib/suite.mjs";
import { bucket, splitOf } from "../lib/split.mjs";
import { costOf, isHardZero, readDecision, summarize, runRows } from "../lib/score.mjs";
import { gateRows, gateSuite, tmp, writeGate, writeJsonl, writeJson, FIXTURES } from "./helpers.mjs";

const near = (a, b, eps = 5e-4) => assert.ok(Math.abs(a - b) < eps, `${a} vs ${b}`);
const suiteOf = (over = {}) => validateSuite({ ...gateSuite(), ...over });

// ── intervals ────────────────────────────────────────────────────────────────
test("wilson: 39/40 is about 0.871 to 0.996 (two-sided), and the edges are clipped", () => {
  const w = wilson(39, 40);
  near(w.low, 0.8712); near(w.high, 0.9956);
  assert.equal(wilson(40, 40).high, 1); assert.equal(wilson(0, 40).low, 0);
  assert.equal(wilson(0, 0), null);
  const p = proportion(39, 40);
  assert.deepEqual([p.k, p.n, p.method], [39, 40, "wilson-95-two-sided"]);
});

test("zeroUpper95: one-sided exact bound 1 - 0.05^(1/n): 7.2% at n=40, 0.46% at n=656; n=0 is vacuous", () => {
  near(zeroUpper95(40), 0.0722); near(zeroUpper95(656), 0.004556, 5e-6); assert.equal(zeroUpper95(0), 1);
  assert.ok(zeroUpper95(100) < zeroUpper95(50));
});

// ── pointers ─────────────────────────────────────────────────────────────────
test("pointerGet: RFC 6901 paths, escapes, missing keys, whole document", () => {
  const d = { a: { "b/c": [1, { "~x": 7 }] }, n: null };
  assert.equal(pointerGet(d, "/a/b~1c/1/~0x"), 7); assert.equal(pointerGet(d, ""), d);
  assert.equal(pointerGet(d, "/a/missing"), undefined); assert.equal(pointerGet(d, "/n/x"), undefined);
  assert.throws(() => pointerGet(d, "a/b"), /not a JSON pointer/);
});

// ── suite validation ─────────────────────────────────────────────────────────
test("suite: unknown keys anywhere are errors, so a typo cannot fall back to a default", () => {
  for (const bad of [{ typo: 1 }, { harm: { cost: {}, hard_zeros: [] } }, { split: { holdout: 20 } }, { target: { kind: "module", path: "x", export: "y", extra: 1 } }, { min_evidence: { train: 1 } }, { sweep: [{ name: "a", values: [1], strict: "low" }] }]) {
    assert.throws(() => validateSuite({ ...gateSuite(), ...bad }), SuiteError, JSON.stringify(bad).slice(0, 60));
  }
});

test("suite: field-level validation", () => {
  const bad = (over, re) => assert.throws(() => validateSuite({ ...gateSuite(), ...over }), re);
  bad({ version: 2 }, /version/); bad({ id: "Bad Id" }, /id/); bad({ corpus: "" }, /corpus/);
  bad({ target: { kind: "nope" } }, /target.kind/); bad({ target: { kind: "builtin", tool: "rm" } }, /target.tool/);
  bad({ decision: undefined }, /decision/);
  bad({ harm: { cost: { A: { b: -1 } } } }, /finite number >= 0/); bad({ harm: { hard_zero: [["A"]] } }, /pairs/);
  bad({ split: { holdout_pct: 0 } }, /holdout_pct/); bad({ split: { holdout_pct: 100 } }, /holdout_pct/);
  bad({ sweep: [{ name: "x", values: [] }] }, /values/); bad({ sweep: [{ name: "x", values: [1] }, { name: "x", values: [2] }] }, /distinct/);
  bad({ sweep: [{ name: "x", values: [{}] }] }, /scalars/); bad({ sweep: [{ name: "x", values: [1], stricter: "mid" }] }, /stricter/);
  bad({ label_source_default: "guess" }, /label_source_default/); bad({ label_overrides: { a: "guess" } }, /label_overrides/);
  bad({ not_evaluated: [{ pointer: "/a" }] }, /exactly one/); bad({ min_evidence: { train_per_class: -1 } }, /min_evidence/);
  bad({ concurrency: 99 }, /concurrency/);
});

test("suite: builtin targets get their decision pointer and the jev_unavailable rule by default; label default is derived", () => {
  const s = validateSuite({ version: 1, id: "g", target: { kind: "builtin", tool: "kit_verify_done" }, corpus: "c.jsonl" });
  assert.equal(s.decision, "/action"); assert.equal(s.label_source_default, "derived");
  assert.deepEqual(s.notEvaluated.map((r) => [r.pointer, r.reason]), [["/jev/status", "jev_unavailable"]]);
  assert.equal(s.min_evidence.train_per_class, 30); assert.equal(s.min_evidence.holdout_per_class, 20);
  assert.equal(s.sweep.length, 0);
});

test("suite: sweep.apply defaults to params for modules and input for tools", () => {
  assert.equal(suiteOf().sweep[0].apply, "params");
  assert.equal(validateSuite({ version: 1, id: "g", target: { kind: "builtin", tool: "kit_guard_command" }, corpus: "c", sweep: [{ name: "ask_at", values: [0.5] }] }).sweep[0].apply, "input");
});

test("corpus: ids, pointers, label provenance resolution and tags", () => {
  const dir = tmp();
  writeJsonl(join(dir, "c.jsonl"), [
    { id: "a", expected: "x", input: { v: 1 }, label_source: "human", tags: ["t1", "bad tag!"] },
    { id: "b", expected: "y", input: { v: 2 } },
    { id: "c", expected: "y", input: { v: 3 }, label_source: "outcome" },
  ]);
  writeJson(join(dir, "s.json"), { version: 1, id: "s", target: { kind: "module", path: "m.mjs", export: "f" }, decision: "/d", corpus: "c.jsonl", label_overrides: { c: "derived" } });
  const { suite } = loadSuite(join(dir, "s.json"));
  const { rows } = loadCorpus(join(dir, "c.jsonl"), suite);
  assert.deepEqual(rows.map((r) => r.label_source), ["human", "derived", "derived"]); // missing = derived; override beats the row's own label
  assert.deepEqual(rows[0].tags, ["t1"]);
});

test("corpus: bad rows are rejected with the line number", () => {
  const dir = tmp();
  const s = suiteOf({ row_id: "/id", expected: "/expected" });
  for (const [rows, re] of [
    [[{ id: "a", expected: "x", input: 1 }, { id: "a", expected: "x", input: 1 }], /duplicate id a/],
    [[{ id: "a", input: 1 }], /expected/], [[{ id: "a", expected: "x" }], /input/], [[{ expected: "x", input: 1 }], /row id/],
    [[{ id: "a b", expected: "x", input: 1 }], /row id/], [[{ id: "a", expected: "x", input: 1, label_source: "guess" }], /label_source/],
  ]) { writeJsonl(join(dir, "c.jsonl"), rows); assert.throws(() => loadCorpus(join(dir, "c.jsonl"), s), re); }
  writeJsonl(join(dir, "c.jsonl"), []);
  assert.throws(() => loadCorpus(join(dir, "c.jsonl"), s), /no rows/);
});

// ── split ────────────────────────────────────────────────────────────────────
test("split: a thread-level split (sha256 of the `channel:thread` key, first 4 bytes big-endian, mod 100 < 20)", () => {
  const reference = (ch, threadKey) => (createHash("sha256").update(`${ch}:${threadKey}`).digest().readUInt32BE(0) % 100 < 20 ? "holdout" : "train");
  const s = suiteOf({ split: { holdout_pct: 20, key: "/split_key" } });
  let holdout = 0;
  for (let i = 0; i < 300; i++) {
    const row = { split_key: `chan-a:17000000${i}.0001` };
    const got = splitOf(row, s, String(i));
    assert.equal(got, reference("chan-a", `17000000${i}.0001`));
    if (got === "holdout") holdout++;
  }
  assert.ok(holdout > 30 && holdout < 90, `about 20% holdout, got ${holdout}/300`);
});

test("split: stable when rows are appended; correlated rows share a side; salt re-cuts; a precomputed field wins", () => {
  const s = suiteOf({ split: { holdout_pct: 20, key: "/thread" } });
  const rows = Array.from({ length: 200 }, (_, i) => ({ thread: `T${i % 40}` }));
  const before = rows.map((r, i) => splitOf(r, s, String(i)));
  const after = [...rows, ...Array.from({ length: 50 }, (_, i) => ({ thread: `N${i}` }))].map((r, i) => splitOf(r, s, String(i)));
  assert.deepEqual(after.slice(0, 200), before);
  const bySide = new Map();
  rows.forEach((r, i) => bySide.set(r.thread, new Set([...(bySide.get(r.thread) ?? []), before[i]])));
  assert.ok([...bySide.values()].every((v) => v.size === 1));
  const salted = suiteOf({ split: { holdout_pct: 20, key: "/thread", salt: "cut2" } });
  assert.notDeepEqual(rows.map((r, i) => splitOf(r, salted, String(i))), before);
  assert.equal(bucket("k", ""), createHash("sha256").update("k").digest().readUInt32BE(0) % 100);
  const pre = suiteOf({ split: { holdout_pct: 20, field: "/split" } });
  assert.equal(splitOf({ split: "holdout" }, pre, "x"), "holdout"); assert.equal(splitOf({ split: "train" }, pre, "x"), "train");
});

// ── scoring ──────────────────────────────────────────────────────────────────
test("costOf: listed cell wins, equal pairs are free, other pairs use default_error_cost; zero off-diagonal cells are acceptable", () => {
  const h = suiteOf({ harm: { cost: { READ: { routed: 0, not_read: 1 }, WRITE: { routed: 10 } }, default_error_cost: 3, hard_zero: [["WRITE", "routed"]] } }).harm;
  assert.equal(costOf(h, "READ", "routed"), 0); assert.equal(costOf(h, "READ", "not_read"), 1); assert.equal(costOf(h, "WRITE", "routed"), 10);
  assert.equal(costOf(h, "WRITE", "WRITE"), 0); assert.equal(costOf(h, "WRITE", "vetoed"), 3);
  assert.equal(isHardZero(h, "WRITE", "routed"), true); assert.equal(isHardZero(h, "READ", "routed"), false);
});

test("asymmetric cost: WRITE->routed (10) and READ->not_read (1), once each, is expected harm 11", () => {
  const s = suiteOf({ harm: { cost: { WRITE: { routed: 10 }, READ: { not_read: 1 } } } });
  const m = summarize([
    { id: "1", truth: "WRITE", decision: "routed", evaluated: true, tags: [], usage: null }, { id: "2", truth: "READ", decision: "not_read", evaluated: true, tags: [], usage: null },
  ], s);
  assert.equal(m.expected_harm, 11); assert.equal(m.accuracy.k, 0);
});

test("hard-zero: violations list the row ids; every cell reports exposure; zero observed carries the exact upper bound, not a zero-risk claim", () => {
  const s = suiteOf();
  const rows = [
    ...Array.from({ length: 40 }, (_, i) => ({ id: `r${i}`, truth: "READ", decision: "routed", evaluated: true, tags: [], usage: null })),
    { id: "w1", truth: "WRITE", decision: "routed", evaluated: true, tags: [], usage: null }, { id: "w2", truth: "WRITE", decision: "vetoed", evaluated: true, tags: [], usage: null },
    ...Array.from({ length: 40 }, (_, i) => ({ id: `b${i}`, truth: "BOTH", decision: "vetoed", evaluated: true, tags: [], usage: null })),
  ];
  const m = summarize(rows, s);
  const w = m.hard_zero.find((c) => c.truth === "WRITE");
  assert.deepEqual([w.violations, w.ids, w.exposed, w.upper95_if_zero], [1, ["w1"], 2, null]);
  const b = m.hard_zero.find((c) => c.truth === "BOTH");
  assert.equal(b.violations, 0); assert.equal(b.exposed, 40); near(b.upper95_if_zero.value, 0.0722); assert.equal(b.upper95_if_zero.method, "exact-95-one-sided");
  assert.equal(m.hard_zero_violations, 1);
  assert.deepEqual(m.hard_zero.find((c) => c.truth === "CORRECTION"), { truth: "CORRECTION", decision: "routed", exposed: 0, violations: 0, ids: [], upper95_if_zero: { value: 1, method: "exact-95-one-sided", n: 0 } });
});

test("not_evaluated rules mark rows out of every figure and count them by reason", () => {
  const s = suiteOf({ decision: "/decision", not_evaluated: [{ pointer: "/jev/status", in: ["unavailable"], reason: "jev_unavailable" }, { pointer: "/flag", equals: true, reason: "flagged" }] });
  assert.deepEqual(readDecision({ decision: "x", jev: { status: "unavailable" } }, s), { decision: null, notEvaluated: "jev_unavailable" });
  assert.deepEqual(readDecision({ decision: "x", flag: true }, s), { decision: null, notEvaluated: "flagged" });
  assert.deepEqual(readDecision({ decision: "x" }, s), { decision: "x" });
  assert.deepEqual(readDecision({}, s), { decision: null, notEvaluated: "no_decision_in_output" });
  const m = summarize([
    { id: "1", truth: "READ", decision: "routed", evaluated: true, tags: [], usage: null },
    { id: "2", truth: "READ", decision: null, evaluated: false, reason: "jev_unavailable", tags: [], usage: null },
    { id: "3", truth: "WRITE", decision: null, evaluated: false, reason: "call_error", tags: [], usage: null },
  ], s);
  assert.deepEqual([m.n_rows, m.n_evaluated, m.not_evaluated.n, m.not_evaluated.reasons], [3, 1, 2, { jev_unavailable: 1, call_error: 1 }]);
  assert.equal(m.accuracy.n, 1);
});

test("a throwing target becomes NOT EVALUATED call_error with a truncated message, never a guessed decision", async () => {
  const dir = tmp();
  writeJsonl(join(dir, "c.jsonl"), [{ id: "a", expected: "x", input: { v: 1 }, label_source: "human" }]);
  writeJson(join(dir, "s.json"), { version: 1, id: "s", target: { kind: "module", path: join(FIXTURES, "decide.mjs"), export: "boom" }, decision: "/decision", corpus: "c.jsonl" });
  const { suite } = loadSuite(join(dir, "s.json"));
  const { makeTarget } = await import("../lib/target.mjs");
  const target = await makeTarget(suite, { suiteDir: dir });
  const [r] = await runRows(loadCorpus(join(dir, "c.jsonl"), suite).rows, suite, target, {});
  assert.deepEqual([r.evaluated, r.decision, r.reason], [false, null, "call_error"]);
  assert.ok(r.error.length <= 120);
});

test("routing-gate-shaped suite loads: numeric ids, class labels, precomputed split, grid sweep with stricter directions", () => {
  const { suitePath } = writeGate(gateRows());
  const { suite, dir } = loadSuite(suitePath);
  const { rows } = loadCorpus(join(dir, suite.corpus), suite);
  assert.equal(rows[0].id, "1"); assert.deepEqual([...new Set(rows.map((r) => r.truth))].sort(), ["BOTH", "READ", "WRITE"]);
  assert.deepEqual(suite.sweep.map((e) => [e.name, e.stricter]), [["change_max", "low"], ["answer_min", "high"]]);
  assert.ok(rows.some((r) => r.split === "holdout") && rows.some((r) => r.split === "train"));
});
