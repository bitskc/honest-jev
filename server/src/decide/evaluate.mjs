// The decision-spec evaluator (openspec change add-decision-core). PURE: no imports, no I/O, no clock, no randomness,
// no recursion into anything but the spec's own condition tree. Hosts can run the same table locally without the Worker.
//
// A spec is validated by validate.mjs; this file assumes a validated spec and never throws on one.
//
// Rules are first-match. Conditions are evaluated in three-valued logic over a normalised answer set:
//   true | false   decided
//   unknown        references an answer that has not been supplied yet (the model has not been asked)
//   invalid        references an answer the upstream returned malformed, and the condition has no `missing_as`
// With `all`, a false child makes the node false; with `any`, a true child makes it true; otherwise invalid dominates
// unknown, which dominates the neutral value. `not` passes unknown and invalid through. Every node is visited exactly
// once per rule (no short-circuit), so the step count is bounded by rules x nodes-per-rule, independent of input size.
//
// Walking rules with no answers decides whatever fact-only rules decide without a model call: the first rule whose
// condition is true wins; false rules are skipped; the first unknown rule stops the walk (first-match order must hold).

const T = 1, F = 0, U = 2, I = 3;

const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function cmp(op, x, t) {
  switch (op) {
    case "gte": return x >= t;
    case "gt": return x > t;
    case "lte": return x <= t;
    default: return x < t; // lt
  }
}
const OPS = ["gte", "gt", "lte", "lt"];
const opOf = (c) => OPS.find((o) => own(c, o));

/** Threshold actually used: a named knob override (calibration sweeps) wins over the literal in the spec. */
function threshold(c, op, knobs) {
  if (typeof c.knob === "string" && knobs && own(knobs, c.knob) && typeof knobs[c.knob] === "number" && Number.isFinite(knobs[c.knob])) return knobs[c.knob];
  return c[op];
}

/**
 * Normalise one raw upstream answer for its question. Returns {type:"noul", value}, {type:"choice", choice, confidence,
 * probabilities} or {invalid:true}. A noul must be a finite number in [0,1]; a choice must name one of the question's
 * labels and carry a probabilities object (confidence defaults to the chosen label's probability).
 */
export function normalizeAnswer(question, raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return { invalid: true };
  if (question.type === "noul") {
    return typeof raw.noul === "number" && Number.isFinite(raw.noul) && raw.noul >= 0 && raw.noul <= 1 ? { type: "noul", value: raw.noul } : { invalid: true };
  }
  const labels = Object.keys(question.criteria);
  const p = raw.probabilities;
  if (typeof raw.choice !== "string" || !labels.includes(raw.choice) || !p || typeof p !== "object" || Array.isArray(p)) return { invalid: true };
  const probabilities = {};
  for (const l of labels) {
    const v = own(p, l) ? p[l] : 0;
    if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 1) return { invalid: true };
    probabilities[l] = v;
  }
  if (raw.confidence != null && !(typeof raw.confidence === "number" && raw.confidence >= 0 && raw.confidence <= 1)) return { invalid: true };
  const conf = raw.confidence ?? probabilities[raw.choice];
  return { type: "choice", choice: raw.choice, confidence: conf, probabilities };
}

const merge = (a, b) => { for (const x of b) if (!a.includes(x)) a.push(x); return a; };

function evalNode(c, ctx) {
  ctx.steps++;
  if (own(c, "all") || own(c, "any")) {
    const isAll = own(c, "all");
    let seenDecisive = false, inv = false, unk = false;
    const needs = [], bad = [];
    for (const child of isAll ? c.all : c.any) {
      const r = evalNode(child, ctx);
      if (r.v === (isAll ? F : T)) seenDecisive = true;
      else if (r.v === I) { inv = true; merge(bad, r.bad); }
      else if (r.v === U) { unk = true; merge(needs, r.needs); }
    }
    if (seenDecisive) return { v: isAll ? F : T, needs: [], bad: [] };
    if (inv) return { v: I, needs: [], bad };
    if (unk) return { v: U, needs, bad: [] };
    return { v: isAll ? T : F, needs: [], bad: [] };
  }
  if (own(c, "not")) {
    const r = evalNode(c.not, ctx);
    return r.v === T ? { v: F, needs: [], bad: [] } : r.v === F ? { v: T, needs: [], bad: [] } : r;
  }
  if (own(c, "fact")) {
    const has = own(ctx.facts, c.fact) && ctx.facts[c.fact] !== undefined;
    const x = has ? ctx.facts[c.fact] : undefined;
    let ok;
    if (own(c, "exists")) ok = has === c.exists;
    else if (!has) ok = false;
    else if (own(c, "eq")) ok = x === c.eq;
    else if (own(c, "in")) ok = c.in.includes(x);
    else { const op = opOf(c); ok = typeof x === "number" && Number.isFinite(x) && cmp(op, x, c[op]); }
    return { v: ok ? T : F, needs: [], bad: [] };
  }
  // answer-dependent conditions
  const qid = own(c, "noul") ? c.noul : c.choice;
  const a = ctx.answers[qid];
  if (a === undefined) return { v: U, needs: [qid], bad: [] };
  if (a.invalid) {
    if (own(c, "missing_as")) {
      if (own(c, "noul")) { const op = opOf(c); return { v: cmp(op, c.missing_as, threshold(c, op, ctx.knobs)) ? T : F, needs: [], bad: [] }; }
      if (own(c, "prob_of")) { const op = opOf(c); return { v: cmp(op, c.missing_as, threshold(c, op, ctx.knobs)) ? T : F, needs: [], bad: [] }; }
      return { v: c.missing_as ? T : F, needs: [], bad: [] };
    }
    return { v: I, needs: [], bad: [qid] };
  }
  if (own(c, "noul")) { const op = opOf(c); return { v: cmp(op, a.value, threshold(c, op, ctx.knobs)) ? T : F, needs: [], bad: [] }; }
  if (own(c, "prob_of")) {
    let s = 0;
    for (const l of c.prob_of) s += a.probabilities[l] ?? 0;
    const op = opOf(c);
    return { v: cmp(op, s, threshold(c, op, ctx.knobs)) ? T : F, needs: [], bad: [] };
  }
  // choice label test
  const labels = own(c, "is") ? [c.is] : c.in;
  let ok = labels.includes(a.choice);
  if (ok && own(c, "min_confidence")) ok = a.confidence >= (typeof c.knob === "string" && ctx.knobs && own(ctx.knobs, c.knob) && Number.isFinite(ctx.knobs[c.knob]) ? ctx.knobs[c.knob] : c.min_confidence);
  return { v: ok ? T : F, needs: [], bad: [] };
}

/** Number of condition nodes in a tree (the per-rule step bound). */
export function countNodes(c) {
  if (own(c, "all")) return 1 + c.all.reduce((n, x) => n + countNodes(x), 0);
  if (own(c, "any")) return 1 + c.any.reduce((n, x) => n + countNodes(x), 0);
  if (own(c, "not")) return 1 + countNodes(c.not);
  return 1;
}

/** Question ids a condition tree reads. */
export function questionsIn(c, out = new Set()) {
  if (own(c, "all")) c.all.forEach((x) => questionsIn(x, out));
  else if (own(c, "any")) c.any.forEach((x) => questionsIn(x, out));
  else if (own(c, "not")) questionsIn(c.not, out);
  else if (own(c, "noul")) out.add(c.noul);
  else if (own(c, "choice")) out.add(c.choice);
  return out;
}

/**
 * @param spec    a validated decision spec
 * @param input   {facts, answers, knobs}: facts are flat scalars; answers map question id to a normalised answer
 *                (normalizeAnswer); knobs map a condition's `knob` name to a replacement number (calibration only)
 * @returns {resolved:true, decision, rule_id|null, reason, steps}
 *        | {resolved:false, needs:[question ids], steps}   stopped at a rule whose answers are not supplied yet
 *        | {resolved:false, invalid:[question ids], steps} reached a condition on an invalid answer with no missing_as
 */
export function evaluate(spec, { facts = {}, answers = {}, knobs = {} } = {}) {
  const ctx = { facts, answers, knobs, steps: 0 };
  for (const rule of spec.rules) {
    const r = evalNode(rule.when, ctx);
    if (r.v === T) return { resolved: true, decision: rule.decision, rule_id: rule.id, reason: rule.reason, steps: ctx.steps };
    if (r.v === U) return { resolved: false, needs: r.needs, steps: ctx.steps };
    if (r.v === I) return { resolved: false, invalid: r.bad, steps: ctx.steps };
  }
  return { resolved: true, decision: spec.default.decision, rule_id: null, reason: spec.default.reason, steps: ctx.steps };
}
