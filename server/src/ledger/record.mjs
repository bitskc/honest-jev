// Decision record v1 (openspec add-decision-ledger). Content-free by construction: every field is rebuilt from a
// whitelist of validated scalars, so no command, path, prompt, task, message or evidence text can reach a record,
// whatever the tool payload contains. Derived from the tool's returned payload; the rule modules are not touched.
import { redact } from "../kit/shell.mjs";

export const RECORD_VERSION = 1;
export const DECIDED_BY = Object.freeze(["prefilter", "jev", "fail_open", "fail_closed", "policy"]);
// Closed list. Never exception text, upstream text, hostnames or URLs.
export const FAIL_REASONS = Object.freeze([
  "no_upstream", "upstream_error", "timeout", "invalid_response", "oversize",
  "client_config", "client_input", "client_timeout", "client_network", "client_http_5xx", "client_parse", "client_rejected", "rule_error",
]);
export const MAX_RECORD_BYTES = 2048; // a record over this is dropped, never truncated
export const COST_SOURCES = Object.freeze(["upstream", "configured", "unknown"]);
// The record's keys, in order. The key set is the schema: a test pins it.
export const RECORD_KEYS = Object.freeze(["v", "decision_id", "ts", "tool", "decision", "verdict", "decided_by", "rule", "fail_reason", "latency_ms", "jev", "tiers", "host", "correlation_id", "policy_version", "source", "enforced", "would_have"]);

// Allow-list shapes. A value that does not match is rejected to null, never redacted and kept.
export const WORD = /^[a-z][a-z_]{0,31}$/;                  // decision / verdict / jev status words
export const RULE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$/;    // R1-secret-exposure
const TOOL = /^[a-z][a-z0-9_]{0,31}$/;                      // kit_guard_command
const TIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;           // ladder rung names (caller-chosen identifiers by design)
const HOST = /^[a-z0-9][a-z0-9._-]{0,31}$/;                 // caller label: claude-code, omp
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:\/-]{0,63}$/;       // typesafe-ai/jev
const CORRELATION = /^[A-Za-z0-9_-]{1,64}$/;                // opaque id; no whitespace, punctuation or length for free text
const POLICY_VERSION = /^[0-9a-f]{12}$/;                    // first 12 hex of a SHA-256 (add-policy-layers D7)

export const pick = (re, v) => (typeof v === "string" && re.test(v) ? v : null);
export const nonneg = (v) => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : null);

/** Price per token in USD from the Worker env; null when not configured or not a finite number >= 0. */
export function pricesFrom(env = {}) {
  const read = (k) => { const s = typeof env[k] === "string" ? env[k].trim() : ""; return s === "" ? null : nonneg(Number(s)); };
  return { input: read("JEV_PRICE_PER_INPUT_TOKEN_USD"), output: read("JEV_PRICE_PER_OUTPUT_TOKEN_USD") };
}

/**
 * Caller-supplied opaque id. `redact` runs first because it catches key-shaped tokens that happen to fit the id
 * alphabet, but it is a deny-list: the shape check is the guarantee. Over-long or non-conforming input is rejected.
 */
export function cleanCorrelationId(v) {
  if (typeof v !== "string") return null;
  return pick(CORRELATION, redact(v));
}

/** Map a Jev status block to a closed fail_reason code. Reads `detail` only to choose a code; never copies it. */
export function failReasonFrom(jev) {
  const status = jev && typeof jev.status === "string" ? jev.status : "";
  if (status === "invalid_response") return "invalid_response";
  const detail = jev && typeof jev.detail === "string" ? jev.detail : "";
  if (/no jev credentials/i.test(detail)) return "no_upstream";
  if (/returned an invalid/i.test(detail)) return "invalid_response"; // guard reports an invalid answer as status "unavailable"
  if (/timed out|timeout|abort/i.test(detail)) return "timeout";
  return "upstream_error";
}

function costOf(used, usage, prices) {
  if (!used) return { cost: null, cost_source: null };
  const upstream = nonneg(usage.cost);
  if (upstream !== null) return { cost: upstream, cost_source: "upstream" };
  const i = nonneg(usage.input_tokens), o = nonneg(usage.output_tokens);
  if (i !== null && prices && prices.input !== null && (o === null ? true : prices.output !== null)) {
    return { cost: i * prices.input + (o === null ? 0 : o * prices.output), cost_source: "configured" };
  }
  return { cost: null, cost_source: "unknown" };
}

/**
 * Field-level record builder: every field is re-validated against its allow-list shape, so a tool that already holds
 * explicit fields (kit_decide) and `deriveRecord` (payload to fields) share one place where a record is made.
 * @param f {tool, decision, verdict, decided_by, rule, fail_reason, latency_ms, jev_used, jev_status, model, usage,
 *           prices, tiers: {chosen, recommended}|null, host, correlation_id, id, ts}
 */
export function assembleRecord(f) {
  const usage = f.usage && typeof f.usage === "object" ? f.usage : {};
  const used = f.jev_used === true;
  const status = pick(WORD, f.jev_status);
  const { cost, cost_source } = costOf(used, usage, f.prices);
  const chosen = pick(TIER, f.tiers && f.tiers.chosen);
  const recommended = pick(TIER, f.tiers && f.tiers.recommended);

  return {
    v: RECORD_VERSION,
    decision_id: typeof f.id === "string" ? f.id : crypto.randomUUID(),
    ts: typeof f.ts === "string" ? f.ts : new Date().toISOString(),
    tool: pick(TOOL, f.tool),
    decision: pick(WORD, f.decision),
    verdict: pick(WORD, f.verdict),
    decided_by: DECIDED_BY.includes(f.decided_by) ? f.decided_by : null,
    rule: pick(RULE, f.rule),
    fail_reason: FAIL_REASONS.includes(f.fail_reason) ? f.fail_reason : null,
    latency_ms: nonneg(f.latency_ms) === null ? null : Math.round(f.latency_ms),
    jev: {
      calls: used ? 1 : 0,
      status,
      model: used ? pick(MODEL, f.model) : null,
      input_tokens: used ? nonneg(usage.input_tokens) : null,
      output_tokens: used ? nonneg(usage.output_tokens) : null,
      cost,
      cost_source,
    },
    tiers: chosen || recommended ? { chosen, recommended } : null,
    host: pick(HOST, f.host),
    correlation_id: cleanCorrelationId(f.correlation_id),
    policy_version: pick(POLICY_VERSION, f.policy_version),
    source: "server",
    enforced: true,
    would_have: null,
  };
}

/**
 * @param tool    kit tool name
 * @param payload the tool's returned JSON payload (untrusted shape; only whitelisted scalars are read)
 * @param ctx     {host, correlation_id, latency_ms, prices, id, ts}
 */
export function deriveRecord(tool, payload, ctx = {}) {
  const p = payload && typeof payload === "object" ? payload : {};
  const jev = p.jev && typeof p.jev === "object" ? p.jev : {};
  const used = jev.used === true;
  const status = pick(WORD, jev.status);
  const failed = status === "unavailable" || status === "invalid_response";

  // decision = the tool's own action word (guard and kit_decide: decision; dispatch and verify: action)
  const ownsDecision = tool === "kit_guard_command" || tool === "kit_decide";
  const decision = ownsDecision ? p.decision : p.action;
  const verdict = tool === "kit_guard_command" || tool === "kit_decide" ? null : p.verdict;

  // D2 mapping. Guard (and any tool that reports it, e.g. kit_decide) passes decided_by through, restricted to the
  // closed vocabulary; dispatch and verify derive it from the Jev status block.
  const derived = failed ? "fail_open" : used ? "jev" : "prefilter";
  const passthrough = tool !== "kit_size_dispatch" && tool !== "kit_verify_done" && DECIDED_BY.includes(p.decided_by);
  const decided_by = passthrough ? p.decided_by : derived;
  // A tool that reports an explicit closed-list code keeps it for any decided_by (kit_decide's fail_closed rows);
  // otherwise only fail_open rows get a code, derived from the Jev status block.
  const fail_reason = FAIL_REASONS.includes(p.fail_reason) ? p.fail_reason : decided_by === "fail_open" ? failReasonFrom(jev) : null;

  const dispatch = tool === "kit_size_dispatch";
  return assembleRecord({
    tool, decision, verdict, decided_by, rule: p.rule, fail_reason, latency_ms: ctx.latency_ms,
    jev_used: used, jev_status: jev.status, model: jev.model, usage: jev.usage, prices: ctx.prices,
    tiers: dispatch ? { chosen: p.chosen && p.chosen.tier, recommended: p.recommended_tier } : null,
    host: ctx.host, correlation_id: ctx.correlation_id, id: ctx.id, ts: ctx.ts,
  });
}

/**
 * The one operational log line for a decision record: `{kind:"jev.decision", ...record}`. Shared by withRecord and by
 * kit_decide so the key and the opt-out (`JEV_DECISION_LOG=off`, case- and space-insensitive) cannot drift. Never throws.
 */
export function logDecision(record, env = {}, log = (s) => console.log(s)) {
  if (String(env.JEV_DECISION_LOG ?? "").trim().toLowerCase() === "off") return false;
  log(JSON.stringify({ kind: "jev.decision", ...record }));
  return true;
}

/**
 * Run a tool body, attach `record` as the LAST key of its payload, and emit one operational log line.
 * Never changes the decision: a derive or log failure returns the payload untouched.
 */
export async function withRecord(tool, args, run, { env = {}, now = () => Date.now(), log = (s) => console.log(s) } = {}) {
  const { host, correlation_id, ...rest } = args || {};
  const t0 = now();
  const payload = await run(rest);
  let record;
  try {
    record = deriveRecord(tool, payload, { host, correlation_id, latency_ms: now() - t0, prices: pricesFrom(env) });
    if (JSON.stringify(record).length > MAX_RECORD_BYTES) return payload; // by construction unreachable; never emit a partial or oversize record
    logDecision(record, env, log);
  } catch {
    if (!record) return payload;
  }
  return { ...payload, record };
}
