// Examples as offline tests (openspec change add-policy-layers, D5). An example is
//   {name?, facts?, answers?, expect: {decision, rule_id, decided_by?}}
// Facts and answers are supplied directly and run through the same pure function the tool runs after the upstream
// replies (decideOffline), so a check is free, deterministic and needs no network and no model. `answers` use the
// upstream's raw shape, so an example that needs a model answer must give one for every question, exactly as a real
// reply must.
//
// Every rule and the default must be the target of at least one PASSING example. A rule shadowed by an earlier rule can
// never be the first match, so its own example fails. Examples prove the table's logic, not the model's answers.
import { decideOffline } from "../decide/core.mjs";
import { canonicalJson, validateFacts } from "../decide/validate.mjs";

export const EXAMPLE_LIMITS = Object.freeze({ per_spec: 64, answer_bytes: 1024, name: 80 });
const DECIDED_BY = ["prefilter", "jev", "fail_open", "fail_closed"];
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Structural validation against a validated spec. Returns a list of error strings (empty when fine). */
export function validateExamples(spec, examples) {
  const errs = [];
  if (!Array.isArray(examples) || examples.length === 0) return [`decision "${spec.id}": examples is required, a non-empty array (every rule and the default need one)`];
  if (examples.length > EXAMPLE_LIMITS.per_spec) return [`decision "${spec.id}": at most ${EXAMPLE_LIMITS.per_spec} examples`];
  const ruleIds = spec.rules.map((r) => r.id);
  examples.forEach((ex, i) => {
    const p = `decision "${spec.id}" example[${i}]`;
    if (!isObj(ex)) { errs.push(`${p}: must be an object`); return; }
    for (const k of Object.keys(ex)) if (!["name", "facts", "answers", "expect"].includes(k)) errs.push(`${p}: unknown key "${k}"`);
    if (ex.name !== undefined && (typeof ex.name !== "string" || ex.name.length === 0 || ex.name.length > EXAMPLE_LIMITS.name)) errs.push(`${p}.name: a string of 1 to ${EXAMPLE_LIMITS.name} characters`);
    const f = validateFacts(ex.facts);
    if (!f.ok) errs.push(...f.errors.map((e) => `${p}: ${e}`));
    if (ex.answers !== undefined) {
      if (!isObj(ex.answers)) errs.push(`${p}.answers: must be an object of raw answers`);
      else for (const [q, a] of Object.entries(ex.answers)) {
        if (!Object.hasOwn(spec.questions, q)) errs.push(`${p}.answers: "${q.slice(0, 40)}" is not a question of this decision`);
        else if (!isObj(a) || JSON.stringify(a).length > EXAMPLE_LIMITS.answer_bytes) errs.push(`${p}.answers.${q}: an answer object of at most ${EXAMPLE_LIMITS.answer_bytes} bytes`);
      }
    }
    const e = ex.expect;
    if (!isObj(e)) { errs.push(`${p}.expect: required, {decision, rule_id, decided_by?}`); return; }
    for (const k of Object.keys(e)) if (!["decision", "rule_id", "decided_by"].includes(k)) errs.push(`${p}.expect: unknown key "${k}"`);
    if (!spec.vocabulary.includes(e.decision)) errs.push(`${p}.expect.decision: a word from the vocabulary`);
    if (!(e.rule_id === null || ruleIds.includes(e.rule_id))) errs.push(`${p}.expect.rule_id: a rule id of this decision, or null for the default`);
    if (e.decided_by !== undefined && !DECIDED_BY.includes(e.decided_by)) errs.push(`${p}.expect.decided_by: one of ${DECIDED_BY.join(", ")}`);
  });
  return errs;
}

/** Run every example offline. Returns [{index, name, ok, expected, got}]. Never throws. */
export function runExamples(spec, examples) {
  return examples.map((ex, index) => {
    const name = typeof ex.name === "string" ? ex.name : `example ${index}`;
    let got;
    try {
      const r = decideOffline(spec, { facts: ex.facts ?? {}, rawAnswers: ex.answers ?? {} });
      got = { decision: r.decision, rule_id: r.rule_id, decided_by: r.decided_by };
    } catch {
      got = { decision: null, rule_id: null, decided_by: null };
    }
    const want = ex.expect;
    const ok = got.decision === want.decision && got.rule_id === want.rule_id && (want.decided_by === undefined || got.decided_by === want.decided_by);
    return { index, name, ok, expected: { decision: want.decision, rule_id: want.rule_id, ...(want.decided_by ? { decided_by: want.decided_by } : {}) }, got };
  });
}

/**
 * The full check for one decision: structure, every example passes, every rule and the default is reached by a passing
 * example (the default only by a model or fact decision, not by the failure path), and no rule repeats an earlier
 * rule's condition. Returns {ok, errors, results}.
 */
export function checkDecision(spec, examples) {
  const errors = validateExamples(spec, examples);
  if (errors.length) return { ok: false, errors, results: [] };
  const results = runExamples(spec, examples);
  for (const r of results) {
    if (!r.ok) errors.push(`decision "${spec.id}" ${r.name}: expected ${JSON.stringify(r.expected)} but the evaluator returned ${JSON.stringify(r.got)}`);
  }
  const passing = results.filter((r) => r.ok);
  for (const rule of spec.rules) {
    if (!passing.some((r) => r.got.rule_id === rule.id)) errors.push(`decision "${spec.id}": rule "${rule.id}" has no passing example that reaches it (it has no example, or an earlier rule shadows it)`);
  }
  if (!passing.some((r) => r.got.rule_id === null && (r.got.decided_by === "prefilter" || r.got.decided_by === "jev"))) {
    errors.push(`decision "${spec.id}": the default has no passing example that reaches it (an example whose rule_id is null and that is decided by facts or the model, not the failure path)`);
  }
  const seen = new Map();
  for (const rule of spec.rules) {
    const key = canonicalJson(rule.when);
    if (seen.has(key)) errors.push(`decision "${spec.id}": rule "${rule.id}" has the same condition as earlier rule "${seen.get(key)}" and can never match first`);
    else seen.set(key, rule.id);
  }
  return { ok: errors.length === 0, errors, results };
}
