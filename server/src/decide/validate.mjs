// Decision-spec validation (openspec change add-decision-core). The grammar is CLOSED: noul comparisons, choice label
// tests, choice probability sums, fact comparisons, all / any / not. No regular expressions, no expressions, no code, no
// templating; any other key is an error. Decision words, rule ids and labels are allow-list shapes so a decision record
// built from them is content-free by construction. Evaluation cost is bounded by rules x nodes (caps below).
import { countNodes, questionsIn } from "./evaluate.mjs";
import { RULE, WORD } from "../ledger/record.mjs";

export const LIMITS = Object.freeze({ spec_bytes: 32_768, questions: 16, vocabulary: 16, rules: 32, depth: 4, nodes_per_rule: 64, children: 16, facts: 32, state_chars: 12_000, text: 1_500, reason: 300, labels: 12, examples: 6 });
const ID = /^[a-z0-9][a-z0-9._-]{0,47}$/;
const QID = /^[a-z][a-z0-9_]{0,47}$/;
const LABEL = /^[A-Za-z0-9_-]{1,32}$/;
const KNOB = /^[a-z][a-z0-9_]{0,47}$/;
const FACT = /^[a-z][a-z0-9_]{0,47}$/;
const OPS = ["gte", "gt", "lte", "lt"];
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isScalar = (v) => typeof v === "string" || typeof v === "boolean" || (typeof v === "number" && Number.isFinite(v));
const unit = (v) => typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1;

/** Cap an error list at `max` entries plus a count of the rest, so a hostile input cannot build an unbounded error payload. */
export const capErrors = (errs, max = 20) => (errs.length > max ? [...errs.slice(0, max), `and ${errs.length - max} more`] : errs);

/** Canonical JSON (sorted keys): the same spec hashes the same whatever its key order. */
export function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (isObj(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

/** First 12 hex of SHA-256 over the canonical JSON of any JSON value. */
export async function hash12(value) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalJson(value)));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 12);
}

/** hash12 of a spec: ties a decision to the exact table that made it. */
export const specHash = hash12;

function keysOnly(o, allowed, path, errs) {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) errs.push(`${path}: unknown key "${k}"`);
}

function textField(v, path, errs, max = LIMITS.text) {
  if (typeof v !== "string" || v.length === 0 || v.length > max) { errs.push(`${path}: must be a non-empty string of at most ${max} characters`); return false; }
  return true;
}

function validateCriteriaValue(v, path, errs) {
  if (typeof v === "string") { textField(v, path, errs); return; }
  if (!isObj(v)) { errs.push(`${path}: must be a string or an object {what, not_for?, examples?}`); return; }
  keysOnly(v, ["what", "not_for", "examples"], path, errs);
  textField(v.what, `${path}.what`, errs);
  if (own(v, "not_for")) textField(v.not_for, `${path}.not_for`, errs);
  if (own(v, "examples") && (!Array.isArray(v.examples) || v.examples.length > LIMITS.examples || v.examples.some((e) => typeof e !== "string" || e.length === 0 || e.length > 200))) errs.push(`${path}.examples: at most ${LIMITS.examples} strings of at most 200 characters`);
}

function validateQuestion(q, path, errs) {
  if (!isObj(q)) { errs.push(`${path}: must be an object`); return; }
  keysOnly(q, ["type", "instructions", "criteria"], path, errs);
  if (q.type !== "noul" && q.type !== "choice") { errs.push(`${path}.type: must be "noul" or "choice"`); return; }
  const ins = q.instructions;
  if (typeof ins === "string") textField(ins, `${path}.instructions`, errs);
  else if (isObj(ins)) {
    const ks = Object.keys(ins);
    if (ks.length === 0 || ks.length > 6) errs.push(`${path}.instructions: an object of 1 to 6 text fields`);
    for (const k of ks) { if (!QID.test(k)) errs.push(`${path}.instructions: key "${k}" is not an identifier`); textField(ins[k], `${path}.instructions.${k}`, errs); }
  } else errs.push(`${path}.instructions: must be a string or an object of strings`);
  if (!isObj(q.criteria)) { errs.push(`${path}.criteria: must be an object`); return; }
  if (q.type === "noul") {
    keysOnly(q.criteria, ["true", "false"], `${path}.criteria`, errs);
    for (const k of ["true", "false"]) if (!own(q.criteria, k)) errs.push(`${path}.criteria: a noul needs both "true" and "false"`); else validateCriteriaValue(q.criteria[k], `${path}.criteria.${k}`, errs);
  } else {
    const labels = Object.keys(q.criteria);
    if (labels.length < 2 || labels.length > LIMITS.labels) errs.push(`${path}.criteria: a choice needs 2 to ${LIMITS.labels} labels`);
    for (const l of labels) { if (!LABEL.test(l)) errs.push(`${path}.criteria: label "${l}" must match ${LABEL}`); validateCriteriaValue(q.criteria[l], `${path}.criteria.${l}`, errs); }
  }
}

function validateCond(c, path, depth, ctx, errs, knobs) {
  if (!isObj(c)) { errs.push(`${path}: a condition must be an object`); return; }
  if (depth > LIMITS.depth) { errs.push(`${path}: nested deeper than ${LIMITS.depth}`); return; }
  const kind = ["all", "any", "not", "fact", "noul", "choice"].filter((k) => own(c, k));
  if (kind.length !== 1) { errs.push(`${path}: exactly one of all, any, not, fact, noul, choice (found ${kind.length ? kind.join("+") : "none"})`); return; }
  const k = kind[0];
  if (k === "all" || k === "any") {
    keysOnly(c, [k], path, errs);
    if (!Array.isArray(c[k]) || c[k].length === 0 || c[k].length > LIMITS.children) { errs.push(`${path}.${k}: 1 to ${LIMITS.children} conditions`); return; }
    c[k].forEach((x, i) => validateCond(x, `${path}.${k}[${i}]`, depth + 1, ctx, errs, knobs));
    return;
  }
  if (k === "not") { keysOnly(c, ["not"], path, errs); validateCond(c.not, `${path}.not`, depth + 1, ctx, errs, knobs); return; }
  if (k === "fact") {
    keysOnly(c, ["fact", "eq", "in", "gt", "gte", "lt", "lte", "exists"], path, errs);
    if (typeof c.fact !== "string" || !FACT.test(c.fact)) errs.push(`${path}.fact: must match ${FACT}`);
    const ops = ["eq", "in", "exists", ...OPS].filter((o) => own(c, o));
    if (ops.length !== 1) { errs.push(`${path}: exactly one of eq, in, exists, gt, gte, lt, lte`); return; }
    const op = ops[0];
    if (op === "eq" && !isScalar(c.eq)) errs.push(`${path}.eq: must be a string, number or boolean`);
    if (op === "in" && (!Array.isArray(c.in) || c.in.length === 0 || c.in.length > 16 || !c.in.every(isScalar))) errs.push(`${path}.in: 1 to 16 scalars`);
    if (op === "exists" && typeof c.exists !== "boolean") errs.push(`${path}.exists: must be a boolean`);
    if (OPS.includes(op) && !(typeof c[op] === "number" && Number.isFinite(c[op]))) errs.push(`${path}.${op}: must be a finite number`);
    return;
  }
  const qid = c[k];
  const q = typeof qid === "string" ? ctx.questions[qid] : undefined;
  if (!q) { errs.push(`${path}.${k}: "${String(qid).slice(0, 40)}" is not a question in this spec`); return; }
  const noteKnob = (hasNumber) => {
    if (!own(c, "knob")) return;
    if (typeof c.knob !== "string" || !KNOB.test(c.knob)) errs.push(`${path}.knob: must match ${KNOB}`);
    else if (knobs.has(c.knob)) errs.push(`${path}.knob: "${c.knob}" is used twice`);
    else knobs.add(c.knob);
    if (!hasNumber) errs.push(`${path}.knob: only valid on a numeric threshold`);
  };
  if (k === "noul") {
    keysOnly(c, ["noul", ...OPS, "missing_as", "knob"], path, errs);
    if (q.type !== "noul") errs.push(`${path}.noul: "${qid}" is a choice question`);
    const ops = OPS.filter((o) => own(c, o));
    if (ops.length !== 1) errs.push(`${path}: exactly one of gte, gt, lte, lt`); else if (!unit(c[ops[0]])) errs.push(`${path}.${ops[0]}: must be a number from 0 to 1`);
    if (own(c, "missing_as") && !unit(c.missing_as)) errs.push(`${path}.missing_as: must be a number from 0 to 1`);
    noteKnob(ops.length === 1);
    return;
  }
  // choice
  if (q.type !== "choice") { errs.push(`${path}.choice: "${qid}" is a noul question`); return; }
  const labels = Object.keys(q.criteria);
  if (own(c, "prob_of")) {
    keysOnly(c, ["choice", "prob_of", ...OPS, "missing_as", "knob"], path, errs);
    if (!Array.isArray(c.prob_of) || c.prob_of.length === 0 || c.prob_of.some((l) => !labels.includes(l))) errs.push(`${path}.prob_of: a non-empty list of this question's labels`);
    const ops = OPS.filter((o) => own(c, o));
    if (ops.length !== 1) errs.push(`${path}: exactly one of gte, gt, lte, lt`); else if (!unit(c[ops[0]])) errs.push(`${path}.${ops[0]}: must be a number from 0 to 1`);
    if (own(c, "missing_as") && !unit(c.missing_as)) errs.push(`${path}.missing_as: must be a number from 0 to 1`);
    noteKnob(ops.length === 1);
    return;
  }
  keysOnly(c, ["choice", "is", "in", "min_confidence", "missing_as", "knob"], path, errs);
  if (own(c, "is") === own(c, "in")) errs.push(`${path}: exactly one of is, in (or prob_of)`);
  else if (own(c, "is") && !labels.includes(c.is)) errs.push(`${path}.is: not a label of "${qid}"`);
  else if (own(c, "in") && (!Array.isArray(c.in) || c.in.length === 0 || c.in.some((l) => !labels.includes(l)))) errs.push(`${path}.in: a non-empty list of this question's labels`);
  if (own(c, "min_confidence") && !unit(c.min_confidence)) errs.push(`${path}.min_confidence: must be a number from 0 to 1`);
  if (own(c, "missing_as") && typeof c.missing_as !== "boolean") errs.push(`${path}.missing_as: must be a boolean for a label test`);
  noteKnob(own(c, "min_confidence"));
}

/** @returns {ok:true, spec} | {ok:false, errors:[string]}. Never throws on any input. */
export function validateSpec(raw) {
  const errs = [];
  try {
    if (!isObj(raw)) return { ok: false, errors: ["spec must be an object"] };
    if (canonicalJson(raw).length > LIMITS.spec_bytes) return { ok: false, errors: [`spec is over ${LIMITS.spec_bytes} bytes`] };
    keysOnly(raw, ["id", "version", "description", "questions", "vocabulary", "grants", "restrictive", "baseline", "rules", "default", "on_unavailable"], "spec", errs);
    if (typeof raw.id !== "string" || !ID.test(raw.id)) errs.push(`spec.id: must match ${ID}`);
    if (!Number.isInteger(raw.version) || raw.version < 1) errs.push("spec.version: must be an integer >= 1");
    if (own(raw, "description")) textField(raw.description, "spec.description", errs, 500);

    const questions = isObj(raw.questions) ? raw.questions : {};
    const qids = Object.keys(questions);
    if (!isObj(raw.questions) || qids.length === 0 || qids.length > LIMITS.questions) errs.push(`spec.questions: 1 to ${LIMITS.questions} questions`);
    for (const id of qids) { if (!QID.test(id)) errs.push(`spec.questions: id "${id}" must match ${QID}`); validateQuestion(questions[id], `questions.${id}`, errs); }

    const vocab = Array.isArray(raw.vocabulary) ? raw.vocabulary : [];
    if (!Array.isArray(raw.vocabulary) || vocab.length < 2 || vocab.length > LIMITS.vocabulary || new Set(vocab).size !== vocab.length || vocab.some((w) => typeof w !== "string" || !WORD.test(w))) errs.push(`spec.vocabulary: 2 to ${LIMITS.vocabulary} distinct words matching ${WORD}`);
    const inVocab = (w) => typeof w === "string" && vocab.includes(w);
    const list = (key) => {
      if (!own(raw, key)) return [];
      if (!Array.isArray(raw[key]) || raw[key].some((w) => !inVocab(w))) { errs.push(`spec.${key}: must list words from vocabulary`); return []; }
      return raw[key];
    };
    const grants = list("grants"), restrictive = list("restrictive");
    if (!inVocab(raw.baseline)) errs.push("spec.baseline: required, and a word from vocabulary (the decision a host takes when no decider exists)");
    if (restrictive.some((w) => grants.includes(w))) errs.push("spec.restrictive: must not overlap grants");
    if (restrictive.includes(raw.baseline)) errs.push("spec.restrictive: must not contain the baseline");

    const ou = raw.on_unavailable;
    if (!isObj(ou)) errs.push("spec.on_unavailable: required, an object {decision, reason?}");
    else {
      keysOnly(ou, ["decision", "reason"], "spec.on_unavailable", errs);
      if (!inVocab(ou.decision)) errs.push("spec.on_unavailable.decision: required, a word from vocabulary");
      else if (grants.includes(ou.decision) && ou.decision !== raw.baseline) errs.push("spec.on_unavailable.decision: failing may not grant (a granted decision is allowed here only if it is also the baseline)");
      if (own(ou, "reason")) textField(ou.reason, "spec.on_unavailable.reason", errs, LIMITS.reason);
    }
    if (!isObj(raw.default)) errs.push("spec.default: required, an object {decision, reason}");
    else {
      keysOnly(raw.default, ["decision", "reason"], "spec.default", errs);
      if (!inVocab(raw.default.decision)) errs.push("spec.default.decision: a word from vocabulary");
      textField(raw.default.reason, "spec.default.reason", errs, LIMITS.reason);
    }

    const rules = Array.isArray(raw.rules) ? raw.rules : [];
    if (!Array.isArray(raw.rules) || rules.length === 0 || rules.length > LIMITS.rules) errs.push(`spec.rules: 1 to ${LIMITS.rules} rules`);
    const ruleIds = new Set(), knobs = new Set(), used = new Set();
    rules.forEach((r, i) => {
      const p = `rules[${i}]`;
      if (!isObj(r)) { errs.push(`${p}: must be an object`); return; }
      keysOnly(r, ["id", "when", "decision", "reason"], p, errs);
      if (typeof r.id !== "string" || !RULE.test(r.id)) errs.push(`${p}.id: must match ${RULE}`); else if (ruleIds.has(r.id)) errs.push(`${p}.id: duplicate "${r.id}"`); else ruleIds.add(r.id);
      if (!inVocab(r.decision)) errs.push(`${p}.decision: a word from vocabulary`);
      textField(r.reason, `${p}.reason`, errs, LIMITS.reason);
      validateCond(r.when, `${p}.when`, 1, { questions }, errs, knobs);
      if (isObj(r.when)) {
        try { if (countNodes(r.when) > LIMITS.nodes_per_rule) errs.push(`${p}.when: more than ${LIMITS.nodes_per_rule} condition nodes`); questionsIn(r.when, used); } catch { /* malformed tree already reported */ }
      }
    });
    for (const q of qids) if (!used.has(q)) errs.push(`spec.questions: "${q}" is never used by a rule (an unused question costs tokens for nothing)`);

    if (errs.length) return { ok: false, errors: capErrors(errs) };
    const mode = raw.on_unavailable.decision === raw.baseline ? "open" : "closed";
    return { ok: true, spec: { id: raw.id, version: raw.version, ...(own(raw, "description") ? { description: raw.description } : {}), questions, vocabulary: vocab, grants, restrictive, baseline: raw.baseline, rules, default: raw.default, on_unavailable: raw.on_unavailable }, fail_mode: mode, facts_used: factsIn(rules) };
  } catch (e) {
    return { ok: false, errors: ["spec could not be validated"] };
  }
}

export function factsIn(rules) {
  const out = new Set();
  const walk = (c) => { if (own(c, "all")) c.all.forEach(walk); else if (own(c, "any")) c.any.forEach(walk); else if (own(c, "not")) walk(c.not); else if (own(c, "fact")) out.add(c.fact); };
  rules.forEach((r) => walk(r.when));
  return [...out];
}

/** Validate call facts: flat scalars, at most LIMITS.facts keys, keys of a fixed shape. */
export function validateFacts(facts) {
  if (facts === undefined) return { ok: true, facts: {} };
  if (!isObj(facts)) return { ok: false, errors: ["facts must be an object of scalars"] };
  const keys = Object.keys(facts);
  // Count first: an over-cap object is rejected before any per-key work or per-key error text.
  if (keys.length > LIMITS.facts) return { ok: false, errors: [`facts: at most ${LIMITS.facts} keys`] };
  const errs = [];
  for (const k of keys) {
    if (!FACT.test(k)) errs.push(`facts: key "${k.slice(0, 40)}" must match ${FACT}`);
    else if (!(isScalar(facts[k]) || facts[k] === null) || (typeof facts[k] === "string" && facts[k].length > 200)) errs.push(`facts.${k}: must be a string (200 characters at most), number, boolean or null`);
  }
  return errs.length ? { ok: false, errors: capErrors(errs) } : { ok: true, facts };
}
