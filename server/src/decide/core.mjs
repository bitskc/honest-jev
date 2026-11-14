// Decision core logic that needs no I/O: failure semantics and "decide from a set of raw upstream answers". Shared by
// the kit_decide tool (after the upstream replies) and by the jev-eval module target (over stored answer vectors), so
// calibration measures exactly the function production runs. Pure: no imports beyond the evaluator.
import { evaluate, normalizeAnswer } from "./evaluate.mjs";

export const DEFAULT_FAIL_REASON_TEXT = "The model could not be consulted; the spec's failure decision was applied.";

/** "open" when failing lands on the decision a host takes without any decider (the baseline), otherwise "closed". */
export const failMode = (spec) => (spec.on_unavailable.decision === spec.baseline ? "open" : "closed");

/** The result fields for a failure: the spec's own on_unavailable decision, with the mode derived and recorded. */
export function failureFor(spec, code) {
  const mode = failMode(spec);
  return {
    decision: spec.on_unavailable.decision, rule_id: null, reason: spec.on_unavailable.reason ?? DEFAULT_FAIL_REASON_TEXT,
    decided_by: mode === "open" ? "fail_open" : "fail_closed", fail_mode_applied: mode, fail_reason: code,
  };
}

/** Normalise every question's raw answer; a missing or malformed one becomes {invalid:true}. */
export function normalizeAll(spec, rawAnswers) {
  const raw = rawAnswers && typeof rawAnswers === "object" ? rawAnswers : {};
  const out = {};
  for (const [qid, q] of Object.entries(spec.questions)) out[qid] = normalizeAnswer(q, Object.prototype.hasOwnProperty.call(raw, qid) ? raw[qid] : undefined);
  return out;
}

/** What the caller sees of the answers: numbers and labels only, from spec-defined shapes. */
export function publicAnswers(answers) {
  const out = {};
  for (const [qid, a] of Object.entries(answers)) {
    out[qid] = a.invalid ? { invalid: true } : a.type === "noul" ? { noul: a.value } : { choice: a.choice, confidence: a.confidence, probabilities: a.probabilities };
  }
  return out;
}

/**
 * Decide with no network: fact-only prefix first (decided_by "prefilter"), then the supplied raw answers. A condition on
 * an invalid or missing answer with no `missing_as` follows the failure path with fail_reason "invalid_response".
 */
export function decideOffline(spec, { facts = {}, rawAnswers = {}, knobs = {} } = {}) {
  const pre = evaluate(spec, { facts, knobs });
  if (pre.resolved) return { decision: pre.decision, rule_id: pre.rule_id, reason: pre.reason, decided_by: "prefilter", fail_mode_applied: null, fail_reason: null, answers: {}, steps: pre.steps };
  // askUpstream rejects a reply that omits any asked question; offline vectors follow the same rule.
  const raw = rawAnswers && typeof rawAnswers === "object" ? rawAnswers : {};
  const omitted = Object.keys(spec.questions).filter((q) => !Object.prototype.hasOwnProperty.call(raw, q));
  if (omitted.length) return { ...failureFor(spec, "invalid_response"), answers: {}, steps: pre.steps, invalid: omitted };
  const answers = normalizeAll(spec, rawAnswers);
  const r = evaluate(spec, { facts, answers, knobs });
  if (r.resolved) return { decision: r.decision, rule_id: r.rule_id, reason: r.reason, decided_by: "jev", fail_mode_applied: null, fail_reason: null, answers: publicAnswers(answers), steps: r.steps };
  return { ...failureFor(spec, "invalid_response"), answers: publicAnswers(answers), steps: r.steps, invalid: r.invalid ?? [] };
}
