// Running rows through a target and scoring them against a harm matrix.
//
// Correctness is the harm matrix, not string equality: cost(truth, decision) is the listed cell if present, else 0 when
// truth === decision, else harm.default_error_cost. A row is "acceptable" when its cost is 0, so a suite can say that
// truth READ with decision "routed" is fine while truth WRITE with decision "routed" is a hard-zero violation.
import { pointerGet } from "./pointer.mjs";
import { proportion, zeroUpper95 } from "./stats.mjs";

export function costOf(harm, truth, decision) {
  const row = harm.cost[truth];
  if (row && Object.hasOwn(row, decision)) return row[decision];
  return truth === decision ? 0 : harm.default_error_cost;
}

export const isHardZero = (harm, truth, decision) => harm.hard_zero.some(([t, d]) => t === truth && d === decision);

/** {decision, notEvaluated?: reason}. A row whose output matches a not_evaluated rule (e.g. Jev unavailable) is not scored. */
export function readDecision(output, suite) {
  for (const r of suite.notEvaluated) {
    const v = pointerGet(output, r.pointer);
    if (r.hasEquals ? v === r.equals : Array.isArray(r.in) && r.in.includes(v)) return { decision: null, notEvaluated: r.reason };
  }
  const d = pointerGet(output, suite.decision);
  return typeof d === "string" ? { decision: d } : { decision: null, notEvaluated: "no_decision_in_output" };
}

async function pMap(items, fn, concurrency) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (next < items.length) { const i = next++; out[i] = await fn(items[i], i); }
  }));
  return out;
}

/** Run each row once under `params`. Returns per-row results; a thrown call becomes NOT EVALUATED (call_error), never a guess. */
export async function runRows(rows, suite, target, params = {}, { concurrency = suite.concurrency } = {}) {
  return pMap(rows, async (row) => {
    const base = { id: row.id, truth: row.truth, split: row.split, label_source: row.label_source, tags: row.tags };
    try {
      const r = await target.run(row.input, params);
      const { decision, notEvaluated } = readDecision(r.output, suite);
      return { ...base, decision, evaluated: !notEvaluated, reason: notEvaluated ?? null, usage: r.usage, model: r.model, cached: r.cached };
    } catch (e) {
      if (e?.name === "BudgetExceeded") throw e;
      return { ...base, decision: null, evaluated: false, reason: "call_error", usage: null, model: null, cached: false, error: String(e?.message ?? e).slice(0, 120) };
    }
  }, concurrency);
}

const inc = (m, k, by = 1) => { m[k] = (m[k] ?? 0) + by; };

/** Metrics over evaluated rows only; not-evaluated rows are counted by reason and otherwise excluded. */
export function summarize(results, suite) {
  const evald = results.filter((r) => r.evaluated);
  const notEval = results.filter((r) => !r.evaluated);
  const reasons = {};
  for (const r of notEval) inc(reasons, r.reason);

  const confusion = {};
  const byTruth = {};
  let harm = 0, acceptable = 0;
  const violations = {};
  for (const r of evald) {
    (confusion[r.truth] ??= {})[r.decision] = (confusion[r.truth][r.decision] ?? 0) + 1;
    const c = costOf(suite.harm, r.truth, r.decision);
    harm += c;
    const t = (byTruth[r.truth] ??= { n: 0, acceptable: 0 });
    t.n++;
    if (c === 0) { acceptable++; t.acceptable++; }
    if (isHardZero(suite.harm, r.truth, r.decision)) (violations[`${r.truth}>${r.decision}`] ??= []).push(r.id);
  }
  const perClass = Object.fromEntries(Object.entries(byTruth).map(([k, v]) => [k, { n: v.n, acceptable: proportion(v.acceptable, v.n) }]));

  // Every hard-zero cell is reported, observed or not. With zero observed events the claim is bounded, never "no risk":
  // one-sided exact 95% upper bound on the true rate among rows of that truth class.
  const hardZero = suite.harm.hard_zero.map(([truth, decision]) => {
    const ids = violations[`${truth}>${decision}`] ?? [];
    const n = byTruth[truth]?.n ?? 0;
    return { truth, decision, exposed: n, violations: ids.length, ids, upper95_if_zero: ids.length === 0 ? { value: zeroUpper95(n), method: "exact-95-one-sided", n } : null };
  });

  const tagStats = {};
  for (const r of evald) for (const t of r.tags) { const s = (tagStats[t] ??= { n: 0, k: 0 }); s.n++; if (costOf(suite.harm, r.truth, r.decision) === 0) s.k++; }

  let inTok = 0, outTok = 0, cost = 0, costRows = 0;
  const models = new Set();
  for (const r of results) {
    if (r.model) models.add(r.model);
    if (r.usage) { inTok += r.usage.input_tokens; outTok += r.usage.output_tokens; if (r.usage.cost !== null) { cost += r.usage.cost; costRows++; } }
  }
  return {
    n_rows: results.length, n_evaluated: evald.length,
    not_evaluated: { n: notEval.length, reasons },
    accuracy: proportion(acceptable, evald.length), expected_harm: harm, mean_harm: evald.length ? harm / evald.length : null,
    confusion, per_class: perClass, hard_zero: hardZero, hard_zero_violations: hardZero.reduce((a, c) => a + c.violations, 0),
    by_tag: Object.fromEntries(Object.entries(tagStats).map(([t, s]) => [t, proportion(s.k, s.n)])),
    usage: { input_tokens: inTok, output_tokens: outTok, cost: costRows ? cost : null, cost_rows: costRows, cached_rows: results.filter((r) => r.cached).length },
    models: [...models].sort(),
  };
}
