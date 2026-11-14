#!/usr/bin/env node
// jev-policy: author, check, test and list reusable decision classes (openspec change add-policy-layers).
//
//   jev-policy init  --layer user|repo
//   jev-policy add   <spec.json> --layer user|repo [--replace] [--yes]   a decision spec WITH examples; writes only if clean
//   jev-policy check [--layer user|repo|all] | [--spec <spec.json>]       validate files and run every example offline
//   jev-policy test  <class> [--facts JSON --answers JSON]               run a class's examples (or one ad hoc input) offline
//   jev-policy list  [--json]                                            effective classes after merging, with notes
//   jev-policy args  <class> [--facts JSON] [--state JSON] [--budget-ms N] [--host H] [--correlation-id C]
//                                                                        print the kit_decide arguments for `jev-call kit_decide "$(jev-policy args ...)"`
// Files: user layer ~/.config/jev/policy.json ($XDG_CONFIG_HOME, or $JEV_POLICY_USER), repo layer ./.jev/policy.json
// (`--repo-root DIR` for another project). `--user FILE` / `--repo FILE` name a file explicitly.
//
// No network, no model, no shell: everything runs the pure evaluator over the files. A policy file is data; nothing in
// it is ever executed. Layer files are read only if they are regular files (never through a symlink) under the size cap,
// and `args` forwards a layer only after it validated locally, so a hostile repo cannot make this tool send some other
// file's contents to the Worker. The Worker merges again; this CLI is the authoring and offline-testing side.
// Exit: 0 ok | 1 check or test failed, or nothing to act on | 2 bad usage | 3 confirmation needed (user layer, no --yes).
import { closeSync, constants, fchmodSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, realpathSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { POLICY_LIMITS, byteLength, parseLayer, sanitize, validateDocument } from "../server/src/policy/schema.mjs";
import { mergeLayers, policyVersion } from "../server/src/policy/merge.mjs";
import { runExamples } from "../server/src/policy/examples.mjs";
import { decideOffline, failMode } from "../server/src/decide/core.mjs";
import { effectMap } from "../server/src/policy/trigger.mjs";
import { validateFacts, validateSpec } from "../server/src/decide/validate.mjs";

const FLAGS = new Set(["yes", "replace", "json"]);
const VALUE = new Set(["layer", "spec", "user", "repo", "repo-root", "facts", "answers", "state", "budget-ms", "host", "correlation-id"]);
const CLASS = /^[a-z0-9][a-z0-9._-]{0,47}$/;

class Usage extends Error {}
const usage = (m) => { throw new Usage(m); };

function parseArgs(argv) {
  const pos = [], o = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) { pos.push(a); continue; }
    const k = a.slice(2);
    if (FLAGS.has(k)) o[k] = true;
    else if (VALUE.has(k)) { if (i + 1 >= argv.length) usage(`--${k} needs a value`); o[k] = argv[++i]; }
    else usage(`unknown option --${k}`);
  }
  return { pos, o };
}

export const paths = (o, env, cwd) => ({
  user: resolve(cwd, o.user ?? env.JEV_POLICY_USER ?? join(env.XDG_CONFIG_HOME || join(homedir(), ".config"), "jev", "policy.json")),
  repo: resolve(cwd, o.repo ?? join(o["repo-root"] ?? ".", ".jev", "policy.json")),
  repoRoot: resolve(cwd, o["repo-root"] ?? "."),
  repoExplicit: o.repo !== undefined,
});

/** Read a layer file safely. {exists:false} | {exists:true, text} | {exists:true, error}. Never follows a symlink. */
export function readLayerFile(path) {
  let st;
  try { st = lstatSync(path); } catch { return { exists: false }; }
  if (st.isSymbolicLink()) return { exists: true, error: "is a symlink: refusing to read it" };
  if (!st.isFile()) return { exists: true, error: "is not a regular file" };
  if (st.size > POLICY_LIMITS.total_bytes) return { exists: true, error: `is over ${POLICY_LIMITS.total_bytes} bytes` };
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    if (!fstatSync(fd).isFile()) return { exists: true, error: "is not a regular file" };
    return { exists: true, text: readFileSync(fd, "utf8"), mode: st.mode & 0o777 };
  } catch (e) {
    return { exists: true, error: `could not be read (${e.code || "error"})` };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/** Atomic write: temp file in the same directory, fsync, rename. A failure leaves the previous file untouched. */
function writeAtomic(path, text, mode, dirMode) {
  const dir = dirname(path);
  mkdirSync(dir, { recursive: true, mode: dirMode });
  try {
    if (lstatSync(path).isSymbolicLink()) throw new Error("refusing to write through a symlink");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  const tmp = join(dir, `.policy.${process.pid}.${Date.now()}.tmp`);
  let fd;
  try {
    fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, mode);
    fchmodSync(fd, mode); // openSync's mode is narrowed by the umask; the file keeps exactly the mode it had
    writeSync(fd, text);
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    renameSync(tmp, path);
  } catch (e) {
    if (fd !== undefined) closeSync(fd);
    try { unlinkSync(tmp); } catch { /* nothing to clean */ }
    throw e;
  }
}

/** realpath of the deepest existing ancestor plus the segments below it, so a path that does not exist yet still resolves. */
function resolveReal(path) {
  const rest = [];
  let cur = resolve(path);
  for (;;) {
    try { return join(realpathSync(cur), ...[...rest].reverse()); } catch (e) { if (e.code !== "ENOENT") throw e; }
    rest.push(basename(cur));
    const up = dirname(cur);
    if (up === cur) return resolve(path);
    cur = up;
  }
}

/**
 * The repo layer must not be, or write through to, anything else: not the user layer file (a `.jev` symlink to the user's
 * config directory would otherwise let a repo-layer write skip the user layer's --yes gate and rewrite its mode), and with
 * the default location no directory under the repo root may be a symlink. Returns a message, or null when fine.
 */
export function repoPathProblem(p) {
  if (resolveReal(p.repo) === resolveReal(p.user)) return "the repo layer path resolves to the user layer file";
  if (!p.repoExplicit) {
    let cur = p.repoRoot;
    for (const seg of relative(p.repoRoot, dirname(p.repo)).split(sep).filter(Boolean)) {
      cur = join(cur, seg);
      try { if (lstatSync(cur).isSymbolicLink()) return `a directory in the repo layer path (${seg}) is a symlink`; } catch { break; }
    }
  }
  return null;
}

const jsonArg = (name, v) => {
  if (v === undefined) return undefined;
  try { return JSON.parse(v); } catch { return usage(`--${name} is not valid JSON`); }
};
const layerName = (v) => (["user", "repo"].includes(v) ? v : usage("--layer must be user or repo"));
const stringify = (doc) => `${JSON.stringify(doc, null, 2)}\n`;

/**
 * Load every existing layer; returns {layers: [{origin, path, text}], problems: [string], userBroken}. Only locally valid
 * layers are returned. `userBroken` is true when the user file exists but cannot be used: callers must not carry on with the
 * repo layer alone, because a repo layer is never allowed to stand in for the user's.
 */
export function loadLayers(p, only) {
  const layers = [], problems = [];
  let userBroken = false;
  for (const origin of ["user", "repo"]) {
    if (only && only !== "all" && only !== origin) continue;
    if (origin === "repo") { const bad = repoPathProblem(p); if (bad) { if (readLayerFile(p.repo).exists) problems.push(`repo layer ${p.repo}: ${bad}; not read`); continue; } }
    const r = readLayerFile(p[origin]);
    if (!r.exists) continue;
    if (r.error) { problems.push(`${origin} layer ${p[origin]} ${r.error}`); if (origin === "user") userBroken = true; continue; }
    const v = parseLayer(r.text);
    if (!v.ok) { problems.push(`${origin} layer ${p[origin]} is invalid: ${v.errors.join("; ")}`); if (origin === "user") userBroken = true; continue; }
    layers.push({ origin, path: p[origin], text: r.text });
  }
  return { layers, problems, userBroken };
}

const describe = (entry) => `${entry.spec.id} v${entry.spec.version}: ${entry.spec.rules.length} rule(s) + default, ${entry.examples.length} example(s), fails ${failMode(entry.spec)} (${entry.spec.on_unavailable.decision})`;
/** A trigger in plain words: what fires it, which facts it computes and from where, and what each decision does. */
export function describeTrigger(entry) {
  const t = entry.trigger;
  if (!t) return null;
  const facts = Object.entries(t.facts).map(([n, f]) => `${n} from ${f.source}${f.marker ? ` (marker "${f.marker}", ${f.timeout_ms} ms)` : ""}`);
  const eff = Object.entries(effectMap(entry.spec, t)).map(([w, e]) => `${w} -> ${e}`);
  return `fires on ${t.tool} commands ${t.command.join(" ")}; facts: ${facts.length ? facts.join("; ") : "none"}; effects: ${eff.join(", ")}; if a fact provider fails: ${entry.spec.on_unavailable.decision} (${effectMap(entry.spec, t)[entry.spec.on_unavailable.decision]})`;
}

async function cmdInit(o, p, out) {
  const origin = layerName(o.layer);
  const path = p[origin];
  if (origin === "repo") { const bad = repoPathProblem(p); if (bad) { out.err(`nothing written: ${bad}`); return 1; } }
  if (readLayerFile(path).exists) { out.err(`${path} already exists; nothing written`); return 1; }
  writeAtomic(path, stringify({ v: 1, decisions: [] }), origin === "user" ? 0o600 : 0o644, origin === "user" ? 0o700 : 0o755);
  out.log(`created ${path} (an empty ${origin} policy layer)`);
  return 0;
}

async function cmdAdd(pos, o, p, out) {
  if (pos.length !== 1) usage("add needs one decision spec file");
  const origin = layerName(o.layer);
  const src = readLayerFile(resolve(pos[0]));
  if (!src.exists || src.error) { out.err(`${pos[0]} ${src.error ?? "does not exist"}`); return 2; }
  let spec;
  try { spec = JSON.parse(src.text); } catch { out.err(`${pos[0]} is not valid JSON`); return 1; }
  const target = p[origin];
  if (origin === "repo") { const bad = repoPathProblem(p); if (bad) { out.err(`NOT WRITTEN: ${bad}`); return 1; } }
  const cur = readLayerFile(target);
  let decisions = [];
  if (cur.exists) {
    if (cur.error) { out.err(`${origin} layer ${target} ${cur.error}; nothing written`); return 1; }
    const parsed = parseLayer(cur.text);
    if (!parsed.ok) { out.err(`the existing ${origin} layer is invalid (${parsed.errors[0]}); fix or move it first. Nothing written`); return 1; }
    decisions = JSON.parse(cur.text).decisions;
  }
  const id = spec && typeof spec === "object" ? spec.id : undefined;
  const at = decisions.findIndex((d) => d && d.id === id);
  if (at >= 0) {
    if (!o.replace) { out.err(`class "${id}" already exists in the ${origin} layer; pass --replace with a higher version. Nothing written`); return 1; }
    if (!(Number.isInteger(spec.version) && spec.version > decisions[at].version)) { out.err(`--replace needs version > ${decisions[at].version} (the old table keeps its version until the new one is better). Nothing written`); return 1; }
  }
  const next = at >= 0 ? decisions.map((d, i) => (i === at ? spec : d)) : [...decisions, spec];
  const doc = { v: 1, decisions: next };
  const v = validateDocument(doc);
  if (!v.ok) {
    out.err("NOT WRITTEN: the policy would not pass check:");
    for (const e of v.errors) out.err(`  - ${e}`);
    return 1;
  }
  const entry = v.decisions.find((d) => d.spec.id === id);
  const text = stringify(doc);
  const other = origin === "user" ? "repo" : "user";
  const pre = mergeLayers([{ origin, text }, ...loadLayers(p, other).layers.map(({ origin: oo, text: tt }) => ({ origin: oo, text: tt }))]);
  if (pre.error) { out.err(`NOT WRITTEN: with the ${other} layer as it is now, ${pre.error}; a call carrying both would be rejected. Shrink one of them`); return 1; }
  const ver = pre.classes.has(id) ? await policyVersion(pre.classes.get(id)) : "- (not resolved: no valid user layer defines this class)";
  out.log(`${at >= 0 ? "replace" : "add"} ${describe(entry)} in the ${origin} layer (${target})`);
  if (entry.trigger && origin !== "user") out.log("note: a trigger in the repo layer is ignored: triggers are read from the user layer only");
  if (describeTrigger(entry)) out.log(`trigger: ${describeTrigger(entry)}`);
  const results = runExamples(entry.spec, entry.examples);
  out.log(`examples: ${results.filter((r) => r.ok).length}/${results.length} pass offline; every rule and the default is reached`);
  out.log(`effective policy_version with the other layer as it is now: ${ver}`);
  for (const n of pre.notes.filter((n) => n.includes(`class "${id}"`))) out.log(`note: ${n}`);
  if (origin === "user" && !o.yes) {
    out.err("NOT WRITTEN: the user layer can loosen gates everywhere. Show the user the table above and re-run with --yes once they agree.");
    return 3;
  }
  writeAtomic(target, text, cur.mode ?? (origin === "user" ? 0o600 : 0o644), origin === "user" ? 0o700 : 0o755);
  out.log(`written ${target}${origin === "repo" ? " (commit it like any other reviewed change)" : ""}`);
  return 0;
}

async function cmdCheck(o, p, out) {
  if (o.spec !== undefined) {
    const src = readLayerFile(resolve(o.spec));
    if (!src.exists || src.error) { out.err(`${o.spec} ${src.error ?? "does not exist"}`); return 2; }
    let spec;
    try { spec = JSON.parse(src.text); } catch { out.err(`${o.spec} is not valid JSON`); return 1; }
    const v = validateDocument({ v: 1, decisions: [spec] });
    if (!v.ok) { for (const e of v.errors) out.err(`  - ${e}`); out.err("check FAILED"); return 1; }
    const e = v.decisions[0];
    out.log(`ok  ${describe(e)}`);
    if (describeTrigger(e)) out.log(`  trigger: ${describeTrigger(e)}`);
    for (const r of runExamples(e.spec, e.examples)) out.log(`  pass  ${sanitize(r.name, 60)}: ${r.got.decision}${r.got.rule_id ? ` (${r.got.rule_id})` : " (default or failure path)"}`);
    return 0;
  }
  const which = o.layer ?? "all";
  if (!["user", "repo", "all"].includes(which)) usage("--layer must be user, repo or all");
  let bad = 0, seen = 0;
  for (const origin of ["user", "repo"]) {
    if (which !== "all" && which !== origin) continue;
    const pathProblem = origin === "repo" ? repoPathProblem(p) : null;
    if (pathProblem && readLayerFile(p.repo).exists) { out.err(`repo: ${p.repo}: ${pathProblem}; not read`); seen++; bad++; continue; }
    const r = readLayerFile(p[origin]);
    if (!r.exists) { out.log(`${origin}: no file at ${p[origin]}`); continue; }
    seen++;
    if (r.error) { out.err(`${origin}: ${p[origin]} ${r.error}`); bad++; continue; }
    const v = parseLayer(r.text);
    if (!v.ok) { out.err(`${origin}: ${p[origin]} FAILED`); for (const e of v.errors) out.err(`  - ${e}`); bad++; continue; }
    out.log(`${origin}: ${p[origin]} ok, ${v.decisions.length} class(es)`);
    for (const d of v.decisions) { out.log(`  ${describe(d)}`); if (describeTrigger(d)) out.log(`    trigger: ${describeTrigger(d)}`); }
  }
  if (seen > 0 && bad === 0) {
    const { layers } = loadLayers(p, which);
    const m = mergeLayers(layers.map(({ origin, text }) => ({ origin, text })));
    for (const n of m.notes) out.log(`note: ${n}`);
  }
  return bad ? 1 : 0;
}

async function cmdTest(pos, o, p, out) {
  if (pos.length !== 1 || !CLASS.test(pos[0])) usage("test needs one class id");
  const { layers, problems, userBroken } = loadLayers(p, "all");
  for (const x of problems) out.err(`skipped: ${x}`);
  if (userBroken) { out.err("the user layer is invalid or unreadable: not testing against the remaining layers. Fix the user file first"); return 1; }
  const m = mergeLayers(layers.map(({ origin, text }) => ({ origin, text })));
  const entry = m.classes.get(pos[0]);
  for (const n of m.notes) out.log(`note: ${n}`);
  if (!entry) { out.err(`no trusted layer defines class "${pos[0]}" (a class only a repo layer defines is not resolved: put it in the user layer)`); return 1; }
  const ver = await policyVersion(entry);
  out.log(`${describe(entry)}; origins ${entry.origins.join("+")}; policy_version ${ver}`);
  if (o.facts !== undefined || o.answers !== undefined) {
    const facts = jsonArg("facts", o.facts) ?? {};
    const f = validateFacts(facts);
    if (!f.ok) { out.err(f.errors.join("; ")); return 2; }
    const r = decideOffline(entry.spec, { facts, rawAnswers: jsonArg("answers", o.answers) ?? {} });
    out.log(`decision ${r.decision}  rule ${r.rule_id ?? "-"}  decided_by ${r.decided_by}${r.fail_reason ? `  fail_reason ${r.fail_reason}` : ""}  reason: ${r.reason}`);
    return 0;
  }
  const results = runExamples(entry.spec, entry.examples);
  for (const r of results) out.log(`${r.ok ? "pass" : "FAIL"}  ${sanitize(r.name, 60)}${r.ok ? "" : `: expected ${JSON.stringify(r.expected)} got ${JSON.stringify(r.got)}`}`);
  const failed = results.filter((r) => !r.ok).length;
  out.log(`${results.length - failed}/${results.length} examples pass (offline, no model call)`);
  return failed ? 1 : 0;
}

async function cmdList(o, p, out) {
  const { layers, problems, userBroken } = loadLayers(p, "all");
  const m = mergeLayers(layers.map(({ origin, text }) => ({ origin, text })));
  const rows = [];
  for (const [id, e] of m.classes) rows.push({ class: id, version: e.spec.version, origins: e.origins, rules: e.spec.rules.length, tightened_by: e.lifted, trigger: e.trigger ?? null, examples: e.examples.length, fail_mode: failMode(e.spec), policy_version: await policyVersion(e) });
  if (o.json) { out.log(JSON.stringify({ classes: rows, notes: m.notes, problems, user_layer_broken: userBroken })); return userBroken ? 1 : 0; }
  for (const x of problems) out.err(`skipped: ${x}`);
  if (!rows.length) out.log("no policy classes (run: jev-policy init --layer repo)");
  for (const r of rows) out.log(`${r.class}  v${r.version}  ${r.origins.join("+")}  ${r.rules} rule(s)${r.tightened_by.length ? ` (${r.tightened_by.length} added by lower layers)` : ""}  ${r.examples} example(s)  fails ${r.fail_mode}  policy_version ${r.policy_version}${r.trigger ? `  trigger: ${r.trigger.tool} ${r.trigger.command.join(" ")}` : ""}`);
  for (const n of m.notes) out.log(`note: ${n}`);
  return userBroken ? 1 : 0;
}

async function cmdArgs(pos, o, p, out) {
  if (pos.length !== 1 || !CLASS.test(pos[0])) usage("args needs one class id");
  const { layers, problems, userBroken } = loadLayers(p, "all");
  for (const x of problems) out.err(`not forwarded: ${x}`);
  if (userBroken) { out.err("the user layer is invalid or unreadable: refusing to build a call. A repo layer is never allowed to stand in for it; fix the user file first"); return 1; }
  const total = layers.reduce((n, l) => n + byteLength(l.text), 0);
  if (total > POLICY_LIMITS.total_bytes) { out.err(`layers total ${total} bytes, over the ${POLICY_LIMITS.total_bytes} byte cap`); return 1; }
  const m = mergeLayers(layers.map(({ origin, text }) => ({ origin, text })));
  if (!m.classes.has(pos[0])) { for (const n of m.notes) out.err(`note: ${n}`); out.err(`no trusted layer defines class "${pos[0]}" (a class only a repo layer defines is not resolved: put it in the user layer)`); return 1; }
  const args = { class: pos[0], policy_layers: layers.map(({ origin, text }) => ({ origin, text })) };
  const facts = jsonArg("facts", o.facts), state = jsonArg("state", o.state);
  if (facts !== undefined) args.facts = facts;
  if (state !== undefined) args.state = state;
  if (o["budget-ms"] !== undefined) { const n = Number(o["budget-ms"]); if (!Number.isInteger(n)) usage("--budget-ms must be an integer"); args.budget_ms = n; }
  if (o.host !== undefined) args.host = o.host;
  if (o["correlation-id"] !== undefined) args.correlation_id = o["correlation-id"];
  out.log(JSON.stringify(args));
  return 0;
}

/** @returns exit code. `io` is injectable for tests; the default writes to the process streams. */
export async function main(argv, { env = process.env, cwd = process.cwd(), io } = {}) {
  const out = io ?? { log: (s) => process.stdout.write(`${s}\n`), err: (s) => process.stderr.write(`${s}\n`) };
  try {
    const [cmd, ...rest] = argv;
    const { pos, o } = parseArgs(rest);
    const p = paths(o, env, cwd);
    switch (cmd) {
      case "init": return await cmdInit(o, p, out);
      case "add": return await cmdAdd(pos, o, p, out);
      case "check": return await cmdCheck(o, p, out);
      case "test": return await cmdTest(pos, o, p, out);
      case "list": return await cmdList(o, p, out);
      case "args": return await cmdArgs(pos, o, p, out);
      default: return usage("usage: jev-policy init|add|check|test|list|args (see the header of this file)");
    }
  } catch (e) {
    if (e instanceof Usage) { out.err(`jev-policy: ${e.message}`); return 2; }
    out.err(`jev-policy: ${e && e.code ? e.code : "error"}: ${e && e.message ? String(e.message).slice(0, 200) : "failed"}`);
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}
