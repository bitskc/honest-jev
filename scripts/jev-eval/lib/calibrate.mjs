// Calibration: sweep on TRAIN, pick the lowest expected harm among values with zero hard-zero violations (ties to the
// stricter setting), then judge that single value on HOLDOUT once. It only ever recommends: nothing here edits a
// config, policy or spec file.
//
// Holdout discipline. A holdout is identified by (suite id, split definition: pct, key pointer, salt). Every holdout
// evaluation is appended to a local log with its count. After a holdout_violation the same holdout is not judged
// again until the split salt changes (a new split key); `force` overrides that and the override is logged with its
// reason. Evaluations that never reach the holdout (insufficient evidence, no feasible value) do not consume it.
//
// Evidence discipline. Only `human` and `outcome` labels are eligible; `derived` rows are counted and excluded (a
// threshold tuned on labels copied from the system's own behaviour tunes the system to itself, issue #125). Rows not
// evaluated (for example Jev unavailable offline) are excluded and counted. Per-class minimums apply to eligible rows.
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { sha256, stableStringify } from "./suite.mjs";
import { runRows, summarize } from "./score.mjs";

const ELIGIBLE = new Set(["human", "outcome"]);

export function holdoutId(suite) {
  return sha256(stableStringify({ suite: suite.id, pct: suite.split.holdout_pct, key: suite.split.key, field: suite.split.field, salt: suite.split.salt })).slice(0, 16);
}

export function readHoldoutLog(path, hid) {
  if (!path || !existsSync(path)) return [];
  return readFileSync(path, "utf8").split("\n").filter(Boolean).flatMap((l) => { try { const r = JSON.parse(l); return r.holdout_id === hid ? [r] : []; } catch { return []; } });
}

function appendHoldoutLog(path, entry) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  appendFileSync(path, `${JSON.stringify(entry)}\n`, { mode: 0o600 });
}

export function combos(sweep) {
  let out = [{}];
  for (const e of sweep) out = out.flatMap((c) => e.values.map((v) => ({ ...c, [e.name]: v })));
  return out;
}

/** Strictness rank tuple: lower is stricter. Per entry, "low" prefers lower values, "high" prefers higher ones. */
function strictness(sweep, combo) {
  return sweep.map((e) => {
    const sorted = [...e.values].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    if (e.stricter === "high") sorted.reverse();
    return sorted.indexOf(combo[e.name]);
  });
}
const cmpTuple = (a, b) => { for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; };

const classCounts = (rows) => rows.reduce((m, r) => { m[r.truth] = (m[r.truth] ?? 0) + 1; return m; }, {});
const belowMin = (counts, min) => Object.entries(counts).filter(([, n]) => n < min).map(([cls, n]) => ({ class: cls, n, min }));

export async function calibrate(suite, corpus, target, { statePath, force = null, now = () => new Date() } = {}) {
  if (suite.sweep.length === 0) throw new Error("suite has no sweep: nothing to calibrate");
  const hid = holdoutId(suite);
  const rec = {
    suite_id: suite.id, holdout_id: hid, status: null, reason: null, candidate: null, recommended: null, sweep: suite.sweep.map((e) => ({ name: e.name, apply: e.apply, values: e.values, stricter: e.stricter })),
    min_evidence: suite.min_evidence, excluded_derived: 0, not_evaluated: null, n_per_class: { train: null, holdout: null }, train: null, holdout: null, grid: [],
    holdout_evaluations: readHoldoutLog(statePath, hid).filter((e) => e.evaluated).length, forced: false,
    methods: { proportions: "wilson-95-two-sided", zero_count_bound: "exact-95-one-sided" },
  };

  const eligible = corpus.rows.filter((r) => ELIGIBLE.has(r.label_source));
  rec.excluded_derived = corpus.rows.length - eligible.length;
  const train = eligible.filter((r) => r.split === "train");
  const holdout = eligible.filter((r) => r.split === "holdout");
  if (eligible.length === 0) { rec.status = "insufficient_evidence"; rec.reason = "no human or outcome labelled rows: every row is derived"; return rec; }

  // Evaluate the default call once per train row to learn which rows can be evaluated at all (offline Jev gaps).
  const grid = combos(suite.sweep);
  const scored = [];
  for (const combo of grid) {
    const results = await runRows(train, suite, target, combo);
    const s = summarize(results, suite);
    scored.push({ combo, summary: s, results });
  }
  const base = scored[0];
  rec.not_evaluated = { train: base.summary.not_evaluated };
  const evalTrain = base.results.filter((r) => r.evaluated);
  rec.n_per_class.train = classCounts(evalTrain);
  const trainShort = belowMin(rec.n_per_class.train, suite.min_evidence.train_per_class);
  if (evalTrain.length === 0 || trainShort.length) {
    rec.status = "insufficient_evidence";
    rec.reason = evalTrain.length === 0 ? "no train row could be evaluated" : `train classes below the minimum: ${trainShort.map((c) => `${c.class} n=${c.n}<${c.min}`).join(", ")}`;
    rec.grid = scored.map(({ combo, summary }) => ({ params: combo, expected_harm: summary.expected_harm, hard_zero_violations: summary.hard_zero_violations, accuracy: summary.accuracy }));
    return rec;
  }
  rec.grid = scored.map(({ combo, summary }) => ({ params: combo, expected_harm: summary.expected_harm, hard_zero_violations: summary.hard_zero_violations, accuracy: summary.accuracy }));
  const feasible = scored.filter((c) => c.summary.hard_zero_violations === 0);
  if (feasible.length === 0) { rec.status = "no_feasible_value"; rec.reason = "every swept value violates a hard-zero cell on train"; return rec; }
  feasible.sort((a, b) => a.summary.expected_harm - b.summary.expected_harm || cmpTuple(strictness(suite.sweep, a.combo), strictness(suite.sweep, b.combo)));
  const best = feasible[0];
  rec.candidate = best.combo;
  rec.train = best.summary;

  // Holdout. Everything that can be decided without running a holdout row happens first: label-count minimums, then the
  // failed-holdout refusal. Only then are holdout rows run, once, for the single judgement.
  rec.n_per_class.holdout = classCounts(holdout);
  const labelShort = belowMin(rec.n_per_class.holdout, suite.min_evidence.holdout_per_class);
  if (holdout.length === 0 || labelShort.length) {
    rec.status = "insufficient_evidence";
    rec.reason = holdout.length === 0 ? "no eligible holdout rows" : `holdout classes below the minimum: ${labelShort.map((c) => `${c.class} n=${c.n}<${c.min}`).join(", ")}`;
    return rec;
  }
  const log = readHoldoutLog(statePath, hid);
  const failedBefore = log.filter((e) => e.evaluated && e.status === "holdout_violation");
  if (failedBefore.length && !force) {
    rec.status = "refused_failed_holdout";
    rec.reason = `this holdout (${hid}) already failed ${failedBefore.length} time(s); change split.salt to cut a new holdout, or re-run with force and a reason`;
    rec.holdout_evaluations = log.filter((e) => e.evaluated).length;
    return rec;
  }
  const holdResults = await runRows(holdout, suite, target, best.combo);
  const hs = summarize(holdResults, suite);
  rec.n_per_class.holdout = classCounts(holdResults.filter((r) => r.evaluated));
  rec.not_evaluated.holdout = hs.not_evaluated;
  const holdShort = belowMin(rec.n_per_class.holdout, suite.min_evidence.holdout_per_class);
  if (hs.n_evaluated === 0 || holdShort.length) {
    rec.status = "insufficient_evidence";
    rec.reason = hs.n_evaluated === 0 ? "no holdout row could be evaluated" : `evaluable holdout classes below the minimum: ${holdShort.map((c) => `${c.class} n=${c.n}<${c.min}`).join(", ")}`;
    if (statePath) appendHoldoutLog(statePath, { ts: now().toISOString(), holdout_id: hid, suite_id: suite.id, evaluated: false, status: rec.status, chosen: best.combo, forced: false, force_reason: null });
    return rec;
  }
  rec.holdout = hs;
  rec.forced = Boolean(failedBefore.length && force);
  rec.status = hs.hard_zero_violations === 0 ? "recommended" : "holdout_violation";
  rec.reason = rec.status === "recommended" ? "zero hard-zero violations on train and on the single holdout evaluation" : `hard-zero violation(s) on holdout: ${hs.hard_zero.filter((c) => c.violations).map((c) => `${c.truth}>${c.decision} x${c.violations}`).join(", ")}; no value is recommended`;
  rec.recommended = rec.status === "recommended" ? best.combo : null;
  rec.holdout_evaluations = log.filter((e) => e.evaluated).length + 1;
  if (statePath) {
    appendHoldoutLog(statePath, { ts: now().toISOString(), holdout_id: hid, suite_id: suite.id, evaluated: true, evaluation: rec.holdout_evaluations, status: rec.status, chosen: best.combo, forced: rec.forced, force_reason: rec.forced ? String(force).slice(0, 200) : null });
  }
  return rec;
}
