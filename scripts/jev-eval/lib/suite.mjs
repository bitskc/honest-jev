// Suite manifest and corpus loading for jev-eval. Zero dependencies. Strict: unknown keys are errors, so a typo in a
// harm cell or a split key cannot silently fall back to a default.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pointerGet } from "./pointer.mjs";
import { splitOf } from "./split.mjs";

export class SuiteError extends Error {}

export const LABEL_SOURCES = ["human", "outcome", "derived"];
const BUILTIN = {
  kit_guard_command: { decision: "/decision" },
  kit_verify_done: { decision: "/action" },
  kit_size_dispatch: { decision: "/verdict" },
};
const BUILTIN_NOT_EVALUATED = [{ pointer: "/jev/status", in: ["unavailable", "invalid_response"], reason: "jev_unavailable" }];
const TOP_KEYS = new Set(["id", "version", "description", "target", "corpus", "row_id", "input", "expected", "decision", "not_evaluated", "harm", "split", "sweep", "min_evidence", "label_source_default", "label_overrides", "concurrency"]);
const ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const WORD_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

const fail = (m) => { throw new SuiteError(m); };
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
function onlyKeys(o, allowed, where) {
  for (const k of Object.keys(o)) if (!allowed.includes(k)) fail(`${where}: unknown key "${k}"`);
}
const scalar = (v) => ["string", "number", "boolean"].includes(typeof v) || v === null;

export function stableStringify(v) {
  if (Array.isArray(v)) return `[${v.map(stableStringify).join(",")}]`;
  if (isObj(v)) return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(v[k])}`).join(",")}}`;
  return JSON.stringify(v);
}
export const sha256 = (data) => createHash("sha256").update(data).digest("hex");

export function validateSuite(raw) {
  if (!isObj(raw)) fail("suite must be a JSON object");
  for (const k of Object.keys(raw)) if (!TOP_KEYS.has(k)) fail(`suite: unknown key "${k}"`);
  if (raw.version !== 1) fail("suite.version must be 1");
  if (typeof raw.id !== "string" || !ID_RE.test(raw.id)) fail("suite.id must match [a-z0-9][a-z0-9._-]{0,63}");
  if (typeof raw.corpus !== "string" || !raw.corpus) fail("suite.corpus must be a path");

  const t = raw.target;
  if (!isObj(t)) fail("suite.target must be an object");
  if (t.kind === "builtin") {
    onlyKeys(t, ["kind", "tool"], "target");
    if (!BUILTIN[t.tool]) fail(`target.tool must be one of ${Object.keys(BUILTIN).join(", ")}`);
  } else if (t.kind === "module") {
    onlyKeys(t, ["kind", "path", "export"], "target");
    if (typeof t.path !== "string" || typeof t.export !== "string") fail("target.path and target.export are required for kind module");
  } else if (t.kind === "mcp") {
    onlyKeys(t, ["kind", "tool", "url_env", "token_env"], "target");
    if (typeof t.tool !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(t.tool)) fail("target.tool is required for kind mcp");
  } else fail("target.kind must be builtin, module or mcp");

  const decision = raw.decision ?? (t.kind === "builtin" ? BUILTIN[t.tool].decision : undefined);
  if (typeof decision !== "string") fail("suite.decision (a JSON pointer into the target's output) is required for this target");

  const ne = raw.not_evaluated ?? (t.kind === "builtin" ? BUILTIN_NOT_EVALUATED : []);
  if (!Array.isArray(ne)) fail("suite.not_evaluated must be an array");
  const notEvaluated = ne.map((r, i) => {
    if (!isObj(r)) fail(`not_evaluated[${i}] must be an object`);
    onlyKeys(r, ["pointer", "equals", "in", "reason"], `not_evaluated[${i}]`);
    if (typeof r.pointer !== "string") fail(`not_evaluated[${i}].pointer is required`);
    if (!("equals" in r) === !("in" in r)) fail(`not_evaluated[${i}] needs exactly one of equals / in`);
    if ("in" in r && !Array.isArray(r.in)) fail(`not_evaluated[${i}].in must be an array`);
    return { pointer: r.pointer, equals: r.equals, in: r.in, hasEquals: "equals" in r, reason: typeof r.reason === "string" ? r.reason : `${r.pointer} matched` };
  });

  const h = raw.harm ?? {};
  if (!isObj(h)) fail("suite.harm must be an object");
  onlyKeys(h, ["cost", "default_error_cost", "hard_zero"], "harm");
  const cost = h.cost ?? {};
  if (!isObj(cost)) fail("harm.cost must be an object of {truth: {decision: number}}");
  for (const [truth, row] of Object.entries(cost)) {
    if (!isObj(row)) fail(`harm.cost.${truth} must be an object`);
    for (const [d, c] of Object.entries(row)) if (typeof c !== "number" || !Number.isFinite(c) || c < 0) fail(`harm.cost.${truth}.${d} must be a finite number >= 0`);
  }
  const defErr = h.default_error_cost ?? 1;
  if (typeof defErr !== "number" || !Number.isFinite(defErr) || defErr < 0) fail("harm.default_error_cost must be a finite number >= 0");
  const hz = h.hard_zero ?? [];
  if (!Array.isArray(hz) || hz.some((c) => !Array.isArray(c) || c.length !== 2 || c.some((x) => typeof x !== "string"))) fail("harm.hard_zero must be an array of [truth, decision] pairs");

  const s = raw.split ?? {};
  if (!isObj(s)) fail("suite.split must be an object");
  onlyKeys(s, ["holdout_pct", "key", "salt", "field"], "split");
  const pct = s.holdout_pct ?? 20;
  if (!Number.isInteger(pct) || pct < 1 || pct > 99) fail("split.holdout_pct must be an integer 1..99");
  const split = { holdout_pct: pct, key: s.key ?? "/id", salt: s.salt ?? "", field: s.field ?? null };
  if (typeof split.key !== "string" || typeof split.salt !== "string" || (split.field !== null && typeof split.field !== "string")) fail("split.key, split.salt and split.field must be strings");

  const sw = raw.sweep ?? [];
  if (!Array.isArray(sw)) fail("suite.sweep must be an array");
  const sweep = sw.map((e, i) => {
    if (!isObj(e)) fail(`sweep[${i}] must be an object`);
    onlyKeys(e, ["name", "apply", "values", "stricter"], `sweep[${i}]`);
    if (typeof e.name !== "string" || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(e.name)) fail(`sweep[${i}].name must be an identifier`);
    const apply = e.apply ?? (t.kind === "module" ? "params" : "input");
    if (apply !== "input" && apply !== "params") fail(`sweep[${i}].apply must be input or params`);
    if (!Array.isArray(e.values) || e.values.length === 0 || e.values.length > 64 || !e.values.every(scalar)) fail(`sweep[${i}].values must be 1..64 scalars`);
    const stricter = e.stricter ?? "low";
    if (stricter !== "low" && stricter !== "high") fail(`sweep[${i}].stricter must be low or high`);
    return { name: e.name, apply, values: e.values, stricter };
  });
  const names = sweep.map((e) => `${e.apply}:${e.name}`);
  if (new Set(names).size !== names.length) fail("sweep entries must have distinct names");

  const me = raw.min_evidence ?? {};
  if (!isObj(me)) fail("suite.min_evidence must be an object");
  onlyKeys(me, ["train_per_class", "holdout_per_class"], "min_evidence");
  const minEvidence = { train_per_class: me.train_per_class ?? 30, holdout_per_class: me.holdout_per_class ?? 20 };
  for (const [k, v] of Object.entries(minEvidence)) if (!Number.isInteger(v) || v < 0) fail(`min_evidence.${k} must be an integer >= 0`);

  const lsd = raw.label_source_default ?? "derived";
  if (!LABEL_SOURCES.includes(lsd)) fail(`label_source_default must be one of ${LABEL_SOURCES.join(", ")}`);
  const lo = raw.label_overrides ?? {};
  if (!isObj(lo) || Object.values(lo).some((v) => !LABEL_SOURCES.includes(v))) fail("label_overrides must map row ids to human, outcome or derived");

  const conc = raw.concurrency ?? 4;
  if (!Number.isInteger(conc) || conc < 1 || conc > 16) fail("concurrency must be an integer 1..16");

  return {
    id: raw.id, version: 1, description: typeof raw.description === "string" ? raw.description.slice(0, 500) : null, target: t, corpus: raw.corpus,
    row_id: raw.row_id ?? "/id", input: raw.input ?? "/input", expected: raw.expected ?? "/expected", decision, notEvaluated,
    harm: { cost, default_error_cost: defErr, hard_zero: hz }, split, sweep, min_evidence: minEvidence,
    label_source_default: lsd, label_overrides: lo, concurrency: conc,
  };
}

/** Load and validate a suite file. Returns {suite, suiteHash, dir}. */
export function loadSuite(path) {
  let text;
  try { text = readFileSync(path, "utf8"); } catch { fail(`cannot read suite file ${path}`); }
  if (text.length > 1_000_000) fail("suite file is over 1 MB");
  let raw;
  try { raw = JSON.parse(text); } catch { fail("suite file is not valid JSON"); }
  const suite = validateSuite(raw);
  return { suite, suiteHash: sha256(stableStringify(raw)), dir: dirname(resolve(path)) };
}

/** Load the corpus JSONL. Rows are never executed or interpreted; only the manifest's pointers read them. */
export function loadCorpus(path, suite) {
  let buf;
  try { buf = readFileSync(path); } catch { fail(`cannot read corpus ${path}`); }
  const rows = [];
  const seen = new Set();
  const lines = buf.toString("utf8").split("\n");
  lines.forEach((line, i) => {
    if (!line.trim()) return;
    let r;
    try { r = JSON.parse(line); } catch { fail(`corpus line ${i + 1} is not valid JSON`); }
    if (!isObj(r)) fail(`corpus line ${i + 1} is not an object`);
    const rawId = pointerGet(r, suite.row_id);
    const id = Number.isInteger(rawId) ? String(rawId) : rawId;
    if (typeof id !== "string" || !WORD_RE.test(id)) fail(`corpus line ${i + 1}: row id (${suite.row_id}) is required and must match ${WORD_RE}`);
    if (seen.has(id)) fail(`corpus line ${i + 1}: duplicate id ${id}`);
    seen.add(id);
    const truth = pointerGet(r, suite.expected);
    if (typeof truth !== "string") fail(`corpus row ${id}: expected (${suite.expected}) must be a string`);
    const input = pointerGet(r, suite.input);
    if (input === undefined) fail(`corpus row ${id}: input (${suite.input}) is missing`);
    const declared = r.label_source;
    if (declared !== undefined && !LABEL_SOURCES.includes(declared)) fail(`corpus row ${id}: label_source must be one of ${LABEL_SOURCES.join(", ")}`);
    const label_source = suite.label_overrides[id] ?? declared ?? suite.label_source_default;
    const tags = Array.isArray(r.tags) ? r.tags.filter((t) => typeof t === "string" && WORD_RE.test(t)).slice(0, 8) : [];
    rows.push({ id, truth, input, label_source, tags, split: splitOf(r, suite, id) });
  });
  if (rows.length === 0) fail("corpus has no rows");
  return { rows, corpusHash: sha256(buf) };
}
