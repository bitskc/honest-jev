// jev-eval calibration: sweep on train, one holdout judgement, evidence and provenance refusals, failed-holdout discipline.
import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { calibrate, combos, holdoutId, readHoldoutLog } from "../lib/calibrate.mjs";
import { loadCorpus, loadSuite } from "../lib/suite.mjs";
import { makeTarget } from "../lib/target.mjs";
import { cmdCalibrate } from "../run.mjs";
import { callCount, resetCalls } from "./fixtures/decide.mjs";
import { gateRows, tmp, writeGate, writeJson } from "./helpers.mjs";

const quiet = () => {};
async function run(rows, suiteOver = {}, opts = {}) {
  const { dir, suitePath } = writeGate(rows, suiteOver);
  const { suite } = loadSuite(suitePath);
  const corpus = loadCorpus(join(dir, "corpus.jsonl"), suite);
  const target = await makeTarget(suite, { suiteDir: dir });
  const statePath = join(dir, "state", "holdout.jsonl");
  resetCalls();
  const rec = await calibrate(suite, corpus, target, { statePath, ...opts });
  return { rec, dir, suitePath, suite, corpus, statePath, calls: callCount() };
}
const trainN = (c) => c.rows.filter((r) => r.split === "train").length;
const holdN = (c) => c.rows.filter((r) => r.split === "holdout").length;
const writeInHoldout = { truth: "WRITE", split: "holdout", input: { facts: { open_ask: false }, answers: { wants_answer: 0.96, wants_change: 0.2 }, write_mass: 0.01 } };

test("combos: cross product of every sweep entry", () => {
  assert.equal(combos([{ name: "a", values: [1, 2] }, { name: "b", values: ["x", "y", "z"] }]).length, 6);
  assert.deepEqual(combos([]), [{}]);
});

test("recommended: lowest train harm among values with zero hard-zero violations, ties to the stricter setting, judged once on holdout", async () => {
  const { rec, corpus, calls, statePath } = await run(gateRows());
  assert.equal(rec.status, "recommended");
  // change_max 0.3 admits a WRITE (rc 0.30) on train, so it is infeasible; 0.25 is the largest feasible; answer_min is a plateau and "high" is stricter
  assert.deepEqual(rec.candidate, { change_max: 0.25, answer_min: 0.85 }); assert.deepEqual(rec.recommended, rec.candidate);
  assert.equal(rec.grid.length, 10);
  assert.ok(rec.grid.filter((g) => g.params.change_max >= 0.3).every((g) => g.hard_zero_violations > 0));
  assert.equal(calls, 10 * trainN(corpus) + holdN(corpus), "the grid ran on train only; holdout rows ran exactly once, for the chosen value");
  assert.equal(rec.holdout.hard_zero_violations, 0);
  assert.equal(rec.holdout_evaluations, 1);
  const log = readHoldoutLog(statePath, rec.holdout_id);
  assert.deepEqual([log.length, log[0].evaluated, log[0].evaluation, log[0].status, log[0].forced], [1, true, 1, "recommended", false]);
  assert.deepEqual(rec.methods, { proportions: "wilson-95-two-sided", zero_count_bound: "exact-95-one-sided" });
});

test("tie-break follows the per-entry stricter direction", async () => {
  const low = await run(gateRows(), { sweep: [{ name: "change_max", values: [0.15, 0.2, 0.25, 0.3, 0.35], stricter: "low" }, { name: "answer_min", values: [0.7, 0.85], stricter: "low" }] });
  assert.equal(low.rec.candidate.answer_min, 0.7);
  const high = await run(gateRows(), { sweep: [{ name: "change_max", values: [0.15, 0.2, 0.25, 0.3, 0.35], stricter: "low" }, { name: "answer_min", values: [0.7, 0.85], stricter: "high" }] });
  assert.equal(high.rec.candidate.answer_min, 0.85);
});

test("derived labels are refused: counted and excluded, nothing is run, the holdout is untouched", async () => {
  const { rec, corpus, calls, statePath } = await run(gateRows({ label: "derived" }));
  assert.equal(rec.status, "insufficient_evidence"); assert.match(rec.reason, /every row is derived/);
  assert.equal(rec.excluded_derived, corpus.rows.length); assert.equal(calls, 0); assert.equal(existsSync(statePath), false);
  assert.equal(rec.candidate, null); assert.equal(rec.recommended, null);
});

test("a corpus with no label_source at all is treated as derived", async () => {
  const rows = gateRows().map(({ label_source, ...r }) => r);
  const { rec } = await run(rows);
  assert.equal(rec.status, "insufficient_evidence"); assert.equal(rec.excluded_derived, rows.length);
});

test("mixed provenance: only human and outcome rows are used and the excluded count is exact", async () => {
  const rows = gateRows().map((r, i) => ({ ...r, label_source: i % 4 === 0 ? "derived" : i % 4 === 1 ? "outcome" : "human" }));
  const { rec } = await run(rows);
  assert.equal(rec.excluded_derived, rows.filter((r) => r.label_source === "derived").length);
});

test("insufficient evidence: per-class minimums on train stop the run before any holdout row is touched", async () => {
  const { rec, corpus, calls, statePath } = await run(gateRows(), { min_evidence: { train_per_class: 100, holdout_per_class: 3 } });
  assert.equal(rec.status, "insufficient_evidence"); assert.match(rec.reason, /train classes below the minimum: .*READ n=\d+<100/);
  assert.equal(calls, 10 * trainN(corpus)); assert.equal(rec.holdout, null); assert.equal(existsSync(statePath), false);
  assert.equal(rec.holdout_evaluations, 0);
});

test("insufficient evidence on the holdout label counts is decided before any holdout row runs", async () => {
  const { rec, corpus, calls, statePath } = await run(gateRows(), { min_evidence: { train_per_class: 5, holdout_per_class: 99 } });
  assert.equal(rec.status, "insufficient_evidence"); assert.match(rec.reason, /holdout classes below the minimum/);
  assert.equal(calls, 10 * trainN(corpus)); assert.equal(existsSync(statePath), false);
});

test("no feasible value: every swept value violates a hard-zero cell on train", async () => {
  const { rec, calls, corpus } = await run(gateRows(), { sweep: [{ name: "change_max", values: [0.3, 0.35], stricter: "low" }] });
  assert.equal(rec.status, "no_feasible_value"); assert.equal(rec.candidate, null); assert.equal(calls, 2 * trainN(corpus));
});

test("a suite with no sweep cannot be calibrated", async () => {
  const { dir, suitePath } = writeGate(gateRows(), { sweep: [] });
  const { suite } = loadSuite(suitePath);
  await assert.rejects(calibrate(suite, loadCorpus(join(dir, "corpus.jsonl"), suite), await makeTarget(suite, { suiteDir: dir }), {}), /no sweep/);
});

test("holdout_violation: nothing is recommended, the failure is logged, a re-run is refused without touching holdout rows, force needs a reason and is logged, a new salt is a new holdout", async () => {
  const first = await run(gateRows({ extra: [writeInHoldout] }));
  assert.equal(first.rec.status, "holdout_violation"); assert.equal(first.rec.recommended, null); assert.deepEqual(first.rec.candidate, { change_max: 0.25, answer_min: 0.85 });
  assert.match(first.rec.reason, /WRITE>routed x1/); assert.equal(first.rec.holdout_evaluations, 1);
  const { suite, corpus, statePath, dir } = first;
  const target = await makeTarget(suite, { suiteDir: dir });

  resetCalls();
  const second = await calibrate(suite, corpus, target, { statePath });
  assert.equal(second.status, "refused_failed_holdout"); assert.match(second.reason, /already failed 1 time/);
  assert.equal(callCount(), 10 * trainN(corpus), "the refused run evaluated train only: no holdout row was run");
  assert.equal(second.holdout_evaluations, 1); assert.equal(readHoldoutLog(statePath, first.rec.holdout_id).length, 1);

  const forced = await calibrate(suite, corpus, target, { statePath, force: "owner wants a second look after fixing the corpus" });
  assert.equal(forced.status, "holdout_violation"); assert.equal(forced.forced, true); assert.equal(forced.holdout_evaluations, 2);
  const log = readHoldoutLog(statePath, first.rec.holdout_id);
  assert.deepEqual([log.length, log[1].forced, log[1].evaluation], [2, true, 2]);
  assert.match(log[1].force_reason, /owner wants a second look/);

  const salted = loadSuite((() => { const s = JSON.parse(readFileSync(join(dir, "suite.json"), "utf8")); s.split.salt = "cut2"; writeJson(join(dir, "suite2.json"), s); return join(dir, "suite2.json"); })()).suite;
  assert.notEqual(holdoutId(salted), holdoutId(suite));
  const fresh = await calibrate(salted, corpus, target, { statePath });
  assert.notEqual(fresh.status, "refused_failed_holdout"); assert.equal(fresh.holdout_evaluations, 1);
});

test("the holdout identity does not change when rows are appended, so growing the corpus cannot dodge a failed holdout", async () => {
  const a = await run(gateRows({ extra: [writeInHoldout] }));
  const grown = [...gateRows({ extra: [writeInHoldout] }), ...gateRows({ reads: 5, writes: 0 }).map((r, i) => ({ ...r, i: 1000 + i }))];
  const { suitePath, dir } = writeGate(grown);
  const { suite } = loadSuite(suitePath);
  assert.equal(holdoutId(suite), a.rec.holdout_id);
  const r = await calibrate(suite, loadCorpus(join(dir, "corpus.jsonl"), suite), await makeTarget(suite, { suiteDir: dir }), { statePath: a.statePath });
  assert.equal(r.status, "refused_failed_holdout");
});

test("calibration never edits a config, policy, suite or corpus file: only the recommendation file (and the holdout log) are written", async () => {
  const { dir, suitePath } = writeGate(gateRows());
  const hash = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
  const before = [hash(suitePath), hash(join(dir, "corpus.jsonl"))];
  const out = join(dir, "out"), state = join(dir, "state.jsonl");
  const code = await cmdCalibrate({ _: ["calibrate", suitePath], out, state }, {}, quiet);
  assert.equal(code, 0);
  assert.deepEqual([hash(suitePath), hash(join(dir, "corpus.jsonl"))], before);
  assert.deepEqual(readdirSync(out), ["gate-like.recommendation.json"]);
  assert.deepEqual(readdirSync(dir).sort(), ["corpus.jsonl", "out", "state.jsonl", "suite.json"]);
  const saved = JSON.parse(readFileSync(join(out, "gate-like.recommendation.json"), "utf8"));
  assert.equal(saved.status, "recommended"); assert.equal(saved.kind, "calibrate");
});

test("CLI exit codes: 0 recommended, 4 not recommended, 5 refused after a failed holdout, 2 for a force reason that is too short", async () => {
  const good = writeGate(gateRows());
  assert.equal(await cmdCalibrate({ _: ["calibrate", good.suitePath], out: join(good.dir, "o"), state: join(good.dir, "s.jsonl") }, {}, quiet), 0);
  const derived = writeGate(gateRows({ label: "derived" }));
  assert.equal(await cmdCalibrate({ _: ["calibrate", derived.suitePath], out: join(derived.dir, "o"), state: join(derived.dir, "s.jsonl") }, {}, quiet), 4);
  const bad = writeGate(gateRows({ extra: [writeInHoldout] }));
  const o = { _: ["calibrate", bad.suitePath], out: join(bad.dir, "o"), state: join(bad.dir, "s.jsonl") };
  assert.equal(await cmdCalibrate(o, {}, quiet), 4);
  assert.equal(await cmdCalibrate(o, {}, quiet), 5);
  await assert.rejects(cmdCalibrate({ ...o, "force-holdout": "short" }, {}, quiet), /at least 8 characters/);
  assert.equal(await cmdCalibrate({ ...o, "force-holdout": "re-judging after a corpus fix" }, {}, quiet), 4);
});

test("a routing-gate-style multi-parameter grid with hard-zero cells over three truth classes is expressible end to end", async () => {
  const rows = gateRows({ extra: [{ truth: "CORRECTION", split: "train", input: { facts: { open_ask: false }, answers: { wants_answer: 0.96, wants_change: 0.45 }, write_mass: 0.01 } }] });
  const { rec } = await run(rows, { min_evidence: { train_per_class: 1, holdout_per_class: 3 } });
  assert.equal(rec.status, "recommended");
  assert.ok(Object.keys(rec.n_per_class.train).includes("CORRECTION"));
});

test("calibrate --dry-run counts the target calls and runs nothing: no target call, no holdout row, no log", async () => {
  const { dir, suitePath } = writeGate(gateRows());
  const lines = [];
  resetCalls();
  const code = await cmdCalibrate({ _: ["calibrate", suitePath], "dry-run": true, out: join(dir, "o"), state: join(dir, "s.jsonl") }, {}, (s) => lines.push(s));
  assert.equal(code, 0); assert.equal(callCount(), 0);
  assert.match(lines.join("\n"), /up to \d+ target calls/); assert.match(lines.join("\n"), /No request was sent and no holdout row was run/);
  assert.equal(existsSync(join(dir, "o")), false); assert.equal(existsSync(join(dir, "s.jsonl")), false);
});
