// Policy documents (openspec change add-policy-layers). Strict, bounded JSON:
//   {"v": 1, "decisions": [ <decision spec from add-decision-core> + "examples": [...] , ... ]}
// A decision spec inside a policy must satisfy the decision-core grammar and caps (no regex, no expressions, no code),
// and carries examples that run offline as tests. Anything else is an error: a layer is all or nothing, so a document
// the CLI refused to write cannot be half-loaded by the Worker.
//
// A decision entry may carry an optional `trigger` (add-policy-hook-adapter): a closed-grammar opt-in for the PreToolUse hooks.
// Every layer validates it (so the Worker accepts a user layer that has one); only the user layer's triggers are ever read.
//
// v1 of the format carries decisions only. The `tools` overlay for the three fixed kit tools described in the design is
// not part of this version: a `tools` key is rejected as unknown, never silently ignored.
import { validateSpec, capErrors } from "../decide/validate.mjs";
import { checkDecision } from "./examples.mjs";
import { validateTrigger } from "./trigger.mjs";

export const ORIGINS = Object.freeze(["user", "repo", "session"]);
export const POLICY_LIMITS = Object.freeze({ total_bytes: 16_384, decisions: 64, layers: ORIGINS.length });
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** Size in UTF-8 bytes: the unit of every cap (the CLI's file sizes are bytes; a string's .length is not). */
export const byteLength = (s) => new TextEncoder().encode(s).length;

/**
 * Bound text that came from a layer before it reaches a tool result or a terminal. A quoted string that is not
 * identifier-shaped becomes "<text>", an unquoted run of 49 or more identifier characters becomes <long>, anything outside
 * printable ASCII becomes `?`, and the whole message is cut at `max` characters. It does not make prose safe to obey (a
 * short sentence still passes); it bounds what an untrusted file can put in front of the agent and keeps long key names,
 * ids and example names out of notes.
 */
export function sanitize(s, max = 240) {
  return String(s)
    .replace(/"([^"]*)"/g, (m, t) => (/^[A-Za-z0-9._:-]{1,48}$/.test(t) ? m : '"<text>"'))
    .replace(/[^\x20-\x7e]/g, "?")
    .replace(/[A-Za-z0-9_.-]{49,}/g, "<long>")
    .slice(0, max);
}

/**
 * Validate a parsed policy document and run its examples. Returns {ok:true, decisions:[{spec, examples, facts_used}]}
 * or {ok:false, errors}. Never throws.
 */
export function validateDocument(doc) {
  try {
    if (!isObj(doc)) return { ok: false, errors: ["policy must be a JSON object"] };
    const errs = [];
    for (const k of Object.keys(doc)) if (!["v", "decisions"].includes(k)) errs.push(`policy: unknown key "${k}"${k === "tools" ? " (the tools overlay is not part of policy v1)" : ""}`);
    if (doc.v !== 1) errs.push("policy.v: must be 1");
    if (!Array.isArray(doc.decisions) || doc.decisions.length > POLICY_LIMITS.decisions) errs.push(`policy.decisions: an array of at most ${POLICY_LIMITS.decisions} decision specs`);
    if (errs.length) return { ok: false, errors: capErrors(errs).map((e) => sanitize(e)) };
    const out = [], ids = new Set();
    doc.decisions.forEach((d, i) => {
      if (!isObj(d)) { errs.push(`decisions[${i}]: must be an object`); return; }
      const { examples, trigger, ...raw } = d;
      const v = validateSpec(raw);
      if (!v.ok) { errs.push(...v.errors.map((e) => `decisions[${i}] ${e}`)); return; }
      if (ids.has(v.spec.id)) { errs.push(`decisions[${i}]: duplicate id "${v.spec.id}"`); return; }
      ids.add(v.spec.id);
      const c = checkDecision(v.spec, examples);
      if (!c.ok) { errs.push(...c.errors); return; }
      let trig;
      if (trigger !== undefined) {
        const t = validateTrigger(trigger, v.spec, `decisions[${i}].trigger`);
        if (!t.ok) { errs.push(...t.errors); return; }
        trig = t.trigger;
      }
      out.push({ spec: v.spec, examples, facts_used: v.facts_used, ...(trig ? { trigger: trig } : {}) });
    });
    return errs.length ? { ok: false, errors: capErrors(errs).map((e) => sanitize(e)) } : { ok: true, decisions: out };
  } catch {
    return { ok: false, errors: ["policy could not be validated"] };
  }
}

/** Parse one layer's raw text (what a host forwards) and validate it. Never throws; never echoes the text. */
export function parseLayer(text) {
  if (typeof text !== "string") return { ok: false, errors: ["layer text must be a string"] };
  if (byteLength(text) > POLICY_LIMITS.total_bytes) return { ok: false, errors: [`layer is over ${POLICY_LIMITS.total_bytes} bytes`] };
  let doc;
  try { doc = JSON.parse(text); } catch { return { ok: false, errors: ["layer is not valid JSON"] }; }
  return validateDocument(doc);
}
