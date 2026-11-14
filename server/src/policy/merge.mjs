// Merge policy layers once, in the Worker (openspec change add-policy-layers, D1 to D3).
//
// Origins, most trusted first: user > repo = session. Only `user` defines or changes a decision class freely.
//   - For a class the user layer defines, a repo or session layer may ONLY prepend rules that tighten:
//       decision in the effective spec's declared `restrictive` set, conditions over questions and facts the effective
//       spec already uses, and a result that still validates (caps, label and type references).
//     Nothing else in that layer's copy of the spec (questions, vocabulary, default, on_unavailable, ...) is read. A spec
//     with no `restrictive` set accepts nothing.
//   - Anything out of direction is dropped and reported in `notes`. It is never an error: policy content must not be able
//     to raise an error that switches a gate off.
// A layer that fails size, JSON, schema or its own examples is skipped whole and reported. A skipped USER layer means no
// class resolves from the layers that remain unless the user layer defined it: see below.
//   - A class that only a repo or session layer defines is NOT resolved (it is reported in `notes`). Those layers are
//     untrusted input; letting one be the sole author of a class would let a skipped or missing user layer hand the whole
//     decision (default, failure decision, grants) to a repository file. To use such a class, put it in the user layer.
//   - Text from a layer that reaches `notes` is sanitised and bounded (see schema.sanitize); a lifted rule's `reason` is
//     replaced by a fixed string, so no layer-authored prose becomes a decision reason.
//
// Pure: no I/O, no clock. The effective class's `policy_version` is the first 12 hex of SHA-256 over its effective spec.
import { canonicalJson, factsIn, hash12, validateSpec } from "../decide/validate.mjs";
import { questionsIn } from "../decide/evaluate.mjs";
import { ORIGINS, POLICY_LIMITS, byteLength, parseLayer, sanitize } from "./schema.mjs";

const ID = /^[a-z0-9][a-z0-9._-]{0,47}$/;

/** True when `id` is a safe class id to echo back in a message. */
export const isClassId = (id) => typeof id === "string" && ID.test(id);

function lift(entry, layerDecision, origin, notes) {
  const { spec: theirs, examples } = layerDecision;
  const eff = entry.spec;
  const label = `${origin} layer, class "${eff.id}"`;
  if (eff.restrictive.length === 0) {
    const novel = theirs.rules.filter((r) => !eff.rules.some((t) => t.id === r.id && canonicalJson(t) === canonicalJson(r)));
    if (novel.length) notes.push(`${label}: dropped ${novel.length} rule(s): the effective spec declares no \`restrictive\` decisions, so it accepts no added rules`);
    return;
  }
  const have = new Set(eff.rules.map((r) => r.id));
  const taken = [];
  for (const rule of theirs.rules) {
    // a lower layer normally carries a full copy of the spec it extends: rules identical to ones already effective are not news
    const twin = eff.rules.find((r) => r.id === rule.id);
    if (twin && canonicalJson(twin) === canonicalJson(rule)) continue;
    const why = (() => {
      if (!eff.restrictive.includes(rule.decision)) return `decision "${rule.decision}" is not in the effective spec's restrictive set`;
      if (have.has(rule.id)) return "its id is already used by a rule of the effective spec";
      const q = [...questionsIn(rule.when)].find((x) => !Object.hasOwn(eff.questions, x));
      if (q) return `it asks question "${q}", which the effective spec does not ask`;
      const f = factsIn([rule]).find((x) => !entry.facts.includes(x));
      if (f) return `it reads fact "${f}", which no rule of the effective spec reads`;
      const trial = validateSpec({ ...eff, rules: [rule, ...eff.rules] });
      return trial.ok ? null : `it does not fit the effective spec (${trial.errors[0]})`;
    })();
    if (why) { notes.push(`${label}: dropped rule "${rule.id}": ${why}`); continue; }
    // the lifted rule keeps its id and decision; its free text is the lower layer's, so the reason is replaced by a fixed string
    taken.push({ ...rule, reason: `Added by a lower layer (rule ${rule.id}).` }); have.add(rule.id);
  }
  const rest = Object.keys(theirs).filter((k) => !["rules", "id", "version"].includes(k) && JSON.stringify(theirs[k]) !== JSON.stringify(eff[k]));
  if (rest.length) notes.push(`${label}: ignored differing field(s) ${rest.join(", ")}: a ${origin} layer may only add restrictive rules to a class defined above it`);
  if (!taken.length) return;
  const merged = validateSpec({ ...eff, rules: [...taken, ...eff.rules] });
  if (!merged.ok) { notes.push(`${label}: dropped ${taken.length} rule(s): the merged class would be invalid (${merged.errors[0]})`); return; }
  const ids = new Set(taken.map((r) => r.id));
  entry.spec = merged.spec;
  entry.facts = merged.facts_used;
  entry.examples = [...entry.examples, ...examples.filter((e) => e.expect && ids.has(e.expect.rule_id))];
  entry.origins.push(origin);
  entry.lifted.push(...taken.map((r) => r.id));
}

/**
 * @param layers [{origin: "user"|"repo"|"session", text: string}] as forwarded by a host
 * @returns {error?, classes: Map<id, {spec, examples, facts, origins, lifted}>, notes: [string], used: [origin]}
 *   `error` is set only when the layers together exceed the call cap (the one call-level rejection).
 */
export function mergeLayers(layers) {
  const notes = [], used = [], classes = new Map();
  if (!Array.isArray(layers)) return { classes, notes, used };
  const total = layers.reduce((n, l) => n + (l && typeof l.text === "string" ? byteLength(l.text) : 0), 0);
  if (total > POLICY_LIMITS.total_bytes) return { error: `policy_layers total ${total} bytes, over the ${POLICY_LIMITS.total_bytes} byte cap`, classes, notes, used };

  const parsed = [];
  const seen = new Set();
  for (const l of layers.slice(0, POLICY_LIMITS.layers + 4)) {
    const origin = l && l.origin;
    if (!ORIGINS.includes(origin)) { notes.push("a layer with an unknown origin was skipped"); continue; }
    if (seen.has(origin)) { notes.push(`a second ${origin} layer was skipped (one layer per origin)`); continue; }
    seen.add(origin);
    const r = parseLayer(l.text);
    if (!r.ok) { notes.push(`${origin} layer skipped: ${r.errors[0]}${r.errors.length > 1 ? ` (and ${r.errors.length - 1} more)` : ""}`); continue; }
    parsed.push({ origin, decisions: r.decisions });
  }
  // user first, then repo, then session: the untrusted layers see what the more trusted ones defined. Each layer's lifted
  // rules are prepended, so the evaluation order is session rules, repo rules, then the user's own rules.
  parsed.sort((a, b) => ORIGINS.indexOf(a.origin) - ORIGINS.indexOf(b.origin));
  const userSkipped = seen.has("user") && !parsed.some((l) => l.origin === "user");
  for (const layer of parsed) {
    used.push(layer.origin);
    for (const d of layer.decisions) {
      const have = classes.get(d.spec.id);
      if (!have) {
        if (layer.origin === "user") {
          classes.set(d.spec.id, { spec: d.spec, examples: d.examples, facts: d.facts_used, origins: ["user"], lifted: [], trigger: d.trigger ?? null });
        } else {
          // A repo or session layer is untrusted input: it may tighten a class the user defined, never be the only author of
          // one. Otherwise a skipped user layer (a hand edit, a grammar mismatch) would hand the class, with its own default,
          // failure decision and grants, to whoever wrote the repository file.
          if (d.trigger) notes.push(`${layer.origin} layer, class "${d.spec.id}": trigger ignored: triggers are read from the user layer only`);
          notes.push(`${layer.origin} layer defines class "${d.spec.id}", which no valid user layer defines${userSkipped ? " (the user layer was skipped)" : ""}: not resolved. A ${layer.origin} layer cannot be the only author of a class; to use it, put it in the user layer after reading it`);
        }
      } else {
        // `have` can only be a user definition here (a document cannot define a class twice, and there is one layer per
        // origin), so this is always a repo or session layer tightening it
        lift(have, d, layer.origin, notes);
        if (d.trigger) notes.push(`${layer.origin} layer, class "${d.spec.id}": trigger ignored: triggers are read from the user layer only`);
      }
    }
  }
  return { classes, notes: notes.map((n) => sanitize(n)), used };
}

/**
 * policy_version of one effective class: the first 12 hex of SHA-256 over the canonical JSON of its effective spec. It is
 * the behaviour of the class and nothing else, so it is the same whichever layer supplied a rule, whatever the order of the
 * examples, and whether or not examples changed (examples are tests, not behaviour). It equals the class's `spec.hash`;
 * the decision record has no field for a spec hash, and this is how the hash reaches the ledger.
 */
export const policyVersion = (entry) => hash12(entry.spec);
