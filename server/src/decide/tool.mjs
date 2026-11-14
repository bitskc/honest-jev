// kit_decide (openspec change add-decision-core): evaluate a caller-supplied decision spec over caller-supplied facts and
// state. Fact-only rules decide with no model call; otherwise exactly one upstream call asks the spec's questions, and the
// pure evaluator in evaluate.mjs turns the answers into a decision. Failure follows the spec's own on_unavailable
// decision; the tool never invents a decision and never reports failure as a normal decision.
import { z } from "zod";
import { askUpstream, resolveUpstream } from "../kit/jev.mjs";
import { redact } from "../kit/shell.mjs";
import { assembleRecord, logDecision, MAX_RECORD_BYTES, pricesFrom } from "../ledger/record.mjs";
import { evaluate } from "./evaluate.mjs";
import { failureFor, failMode, normalizeAll, publicAnswers } from "./core.mjs";
import { LIMITS, capErrors, specHash, validateFacts, validateSpec } from "./validate.mjs";
import { ORIGINS, POLICY_LIMITS } from "../policy/schema.mjs";
import { isClassId, mergeLayers, policyVersion as policyVersionOf } from "../policy/merge.mjs";

export const DEFAULT_BUDGET_MS = 5_000;
export const MAX_BUDGET_MS = 20_000;
/** The call's hard deadline: the caller's budget_ms clamped to 100..MAX_BUDGET_MS, DEFAULT_BUDGET_MS when absent or not a number. */
export const clampBudget = (ms) => Math.min(MAX_BUDGET_MS, Math.max(100, Number.isFinite(ms) ? Math.round(ms) : DEFAULT_BUDGET_MS));
const STATE_KEY = /^[A-Za-z0-9_.-]{1,64}$/;
const MAX_STATE_NODES = 600;

/** Map an upstream failure to the closed fail_reason list. Never keeps the message. */
export function failCodeFor(err) {
  const m = String(err && err.message ? err.message : err);
  if (/timed out|timeout|abort/i.test(m)) return "timeout";
  if (/malformed answers envelope|unparseable response|omitted the answer/i.test(m)) return "invalid_response";
  return "upstream_error";
}

const serializedSize = (v) => JSON.stringify(v).length;

/** Redact every string leaf of a JSON value (question text goes upstream, so it gets the same treatment as state). */
export function redactStrings(v) {
  if (typeof v === "string") return redact(v);
  if (Array.isArray(v)) return v.map(redactStrings);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, redactStrings(x)]));
  return v;
}

/**
 * Validate the state tree and redact every string leaf. Keys are a fixed shape so no text rides in a key. The size cap is
 * checked on the input before any walking or redaction, then again on what will be sent (redaction can lengthen a short
 * secret), and an over-cap state is rejected, never truncated.
 */
export function prepareState(state) {
  if (state === undefined) return { ok: true, state: {} };
  if (state === null || typeof state !== "object" || Array.isArray(state)) return { ok: false, errors: ["state must be an object"] };
  const tooBig = { ok: false, errors: [`state is over ${LIMITS.state_chars} characters serialized`] };
  try {
    if (serializedSize(state) > LIMITS.state_chars) return tooBig;
  } catch {
    return { ok: false, errors: ["state is not JSON-serializable"] };
  }
  let nodes = 0;
  const errs = [];
  const walk = (v, depth, path) => {
    if (++nodes > MAX_STATE_NODES) { if (nodes === MAX_STATE_NODES + 1) errs.push(`state: more than ${MAX_STATE_NODES} values`); return null; }
    if (depth > 8) { errs.push(`${path}: nested deeper than 8`); return null; }
    if (typeof v === "string") return redact(v);
    if (typeof v === "boolean" || v === null) return v;
    if (typeof v === "number") { if (!Number.isFinite(v)) errs.push(`${path}: not a finite number`); return v; }
    if (Array.isArray(v)) return v.map((x, i) => walk(x, depth + 1, `${path}[${i}]`));
    if (typeof v === "object") {
      const o = {};
      for (const k of Object.keys(v)) {
        if (!STATE_KEY.test(k)) { errs.push(`${path}: key "${k.slice(0, 20)}" must match ${STATE_KEY}`); continue; }
        o[k] = walk(v[k], depth + 1, `${path}.${k}`);
      }
      return o;
    }
    errs.push(`${path}: unsupported value`);
    return null;
  };
  const out = walk(state, 0, "state");
  if (errs.length) return { ok: false, errors: capErrors(errs) };
  if (serializedSize(out) > LIMITS.state_chars) return tooBig;
  return { ok: true, state: out };
}

/** One upstream call that returns inside budget_ms even if the upstream's own retry backoff would overrun it. */
async function askWithin(upstream, state, questions, budget, fetchImpl) {
  const ac = new AbortController();
  const timedOut = () => new Error("Jev request timed out");
  let timer;
  const deadline = new Promise((_, reject) => { timer = setTimeout(() => { ac.abort(timedOut()); reject(timedOut()); }, budget); });
  try {
    return await Promise.race([askUpstream(upstream, state, questions, { fetchImpl, timeoutMs: budget, signal: ac.signal }), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * @param input {spec | class + policy_layers, state?, facts?, budget_ms?, host?, correlation_id?}
 * @param deps  {env, fetchImpl?, now?, log?}
 * @returns {error:true, payload} for a caller bug (nothing was decided), else {payload} with the decision
 */
export async function runDecide(input, deps = {}) {
  const now = deps.now ?? Date.now;
  const env = deps.env ?? {};
  const t0 = now();
  const bad = (code, errors) => ({ error: true, payload: { tool: "kit_decide", error: code, errors, note: "No decision was made. Apply your own failure policy." } });

  const hasSpec = input.spec !== undefined, hasClass = input.class !== undefined;
  if (hasSpec === hasClass) return bad("invalid_input", ["exactly one of spec or class is required"]);
  if (hasSpec && input.policy_layers !== undefined) return bad("invalid_input", ["policy_layers apply only with class"]);
  let policy = null, policyVersion = null, mergeNotes = [];
  let v;
  if (hasClass) {
    if (!isClassId(input.class)) return bad("invalid_class", ["class must match [a-z0-9][a-z0-9._-]{0,47}"]);
    const merged = mergeLayers(input.policy_layers);
    if (merged.error) return bad("invalid_policy_layers", [merged.error]);
    mergeNotes = merged.notes;
    const entry = merged.classes.get(input.class);
    if (!entry) return { error: true, payload: { tool: "kit_decide", error: "unknown_class", errors: [`no valid policy layer defines class "${input.class}"`], notes: merged.notes, note: "No decision was made. Apply your own failure policy." } };
    policy = entry;
    policyVersion = await policyVersionOf(entry);
    v = { ok: true, spec: entry.spec };
  } else {
    v = validateSpec(input.spec);
    if (!v.ok) return bad("invalid_spec", v.errors);
  }
  const f = validateFacts(input.facts);
  if (!f.ok) return bad("invalid_facts", f.errors);
  const st = prepareState(input.state);
  if (!st.ok) return bad("invalid_state", st.errors);
  const spec = v.spec;
  const hash = await specHash(spec);
  const budget = clampBudget(input.budget_ms);

  let out; // {decision, rule_id, reason, decided_by, fail_mode_applied, fail_reason}
  let answers = {}, steps = 0, used = false, usage = null, model = null, jevStatus = "not_needed";
  const notes = [];

  const pre = evaluate(spec, { facts: f.facts });
  steps = pre.steps;
  if (pre.resolved) {
    out = { decision: pre.decision, rule_id: pre.rule_id, reason: pre.reason, decided_by: "prefilter", fail_mode_applied: null, fail_reason: null };
    notes.push("Decided from facts alone; no model call.");
  } else {
    const upstream = resolveUpstream(env);
    if (!upstream) {
      out = failureFor(spec, "no_upstream"); jevStatus = "unavailable";
    } else {
      used = true;
      let reply = null, code = null;
      try {
        reply = await askWithin(upstream, st.state, redactStrings(spec.questions), budget, deps.fetchImpl);
      } catch (e) {
        code = failCodeFor(e);
      }
      if (code) { out = failureFor(spec, code); jevStatus = "unavailable"; }
      else {
        usage = reply.usage ?? null;
        model = reply.model ?? null;
        answers = normalizeAll(spec, reply.answers);
        const r = evaluate(spec, { facts: f.facts, answers });
        steps = r.steps;
        if (r.resolved) { out = { decision: r.decision, rule_id: r.rule_id, reason: r.reason, decided_by: "jev", fail_mode_applied: null, fail_reason: null }; jevStatus = "ok"; }
        else { out = failureFor(spec, "invalid_response"); jevStatus = "invalid_response"; notes.push("A rule depended on an answer the model returned malformed and the spec gives no missing_as for it."); }
      }
    }
    if (out.decided_by !== "jev") notes.push(`Failure path (${out.fail_reason}): applied the spec's on_unavailable decision (${out.fail_mode_applied}).`);
  }

  const record = assembleRecord({
    tool: "kit_decide", decision: out.decision, verdict: null, decided_by: out.decided_by, rule: out.rule_id, fail_reason: out.fail_reason,
    latency_ms: now() - t0, jev_used: used, jev_status: jevStatus, model, usage, prices: pricesFrom(env),
    host: input.host, correlation_id: input.correlation_id, policy_version: policyVersion,
  });
  const logged = JSON.stringify(record).length <= MAX_RECORD_BYTES;
  if (logged) logDecision(record, env, deps.log);

  return {
    payload: {
      tool: "kit_decide",
      decision: out.decision, rule_id: out.rule_id, reason: out.reason, decided_by: out.decided_by,
      fail_mode_applied: out.fail_mode_applied, fail_reason: out.fail_reason,
      spec: { id: spec.id, version: spec.version, hash, fail_mode: failMode(spec) },
      policy: policy ? { class: spec.id, version: policyVersion, origins: policy.origins, tightened_by: policy.lifted } : null,
      answers: publicAnswers(answers), steps,
      jev: { used, status: jevStatus, model: record.jev.model, usage: used ? { input_tokens: record.jev.input_tokens, output_tokens: record.jev.output_tokens, cost: record.jev.cost } : null },
      notes: [...mergeNotes, ...notes],
      record: logged ? record : null,
    },
  };
}

const asText = (payload, isError = false) => ({ content: [{ type: "text", text: JSON.stringify(payload, null, 2) }], ...(isError ? { isError: true } : {}) });

const DESCRIPTION = "Evaluate a decision spec, given inline or as a class resolved from policy layers: an ordered rule table over facts you supply and yes/no or pick-one questions Jev answers about `state`. "
  + "Fact-only rules decide with no model call; otherwise one Jev call asks the spec's questions and the first matching rule decides. "
  + "Returns the decision, the matching rule id, whether it came from facts, Jev or the spec's failure path, the answers used, and a content-free record. "
  + "The spec fixes what happens when Jev is unavailable (on_unavailable) and the decision a host takes with no decider (baseline). "
  + "An error result means NO decision was made (bad spec, facts or state): apply your own failure policy. state is redacted by a deny-list before it leaves, so do not put secrets in it.";

/**
 * Register kit_decide. Separate from registerKitTools so the three fixed kit tools stay untouched.
 * @param opts {fetchImpl?, now?, log?} test seams
 */
export function registerDecideTool(server, getEnv, opts = {}) {
  server.registerTool(
    "kit_decide",
    {
      title: "Decide from a spec",
      description: DESCRIPTION,
      inputSchema: z.object({
        spec: z.record(z.string(), z.unknown()).optional().describe("Inline decision spec: id, version, questions, vocabulary, baseline, rules, default, on_unavailable (see the jev-decide skill). Exactly one of spec or class."),
        class: z.string().max(64).optional().describe("A decision class id resolved from policy_layers (see the jev-policy-author skill). Exactly one of spec or class."),
        policy_layers: z.array(z.object({
          origin: z.enum(ORIGINS).describe("user for ~/.config/jev/policy.json, repo for .jev/policy.json, session for a layer your host built. Only user may loosen."),
          text: z.string().max(POLICY_LIMITS.total_bytes).describe("The file's raw JSON text, forwarded unparsed."),
        }).strict()).max(POLICY_LIMITS.layers).optional().describe(`Policy files to resolve class against; at most ${POLICY_LIMITS.total_bytes} bytes in total. Only valid with class.`),
        state: z.record(z.string(), z.unknown()).optional().describe("What Jev reads to answer the questions. Strings are redacted; keys must be simple identifiers."),
        facts: z.record(z.string(), z.unknown()).optional().describe("Flat scalars your rules test deterministically (never sent to Jev)."),
        budget_ms: z.number().int().min(100).max(MAX_BUDGET_MS).optional().describe(`Hard deadline for the model call, default ${DEFAULT_BUDGET_MS}.`),
        host: z.string().max(64).optional().describe("Caller label for the record, e.g. claude-code."),
        correlation_id: z.string().max(200).optional().describe("Opaque id to join this record to your own logs."),
      }).strict(),
    },
    async (args) => {
      const r = await runDecide(args, { env: getEnv(), ...opts });
      return asText(r.payload, r.error === true);
    },
  );
}
