#!/usr/bin/env node
// jev-eval: measure a decision gate on a deployment's own labelled corpus.
//   jev-eval score     <suite.json> [--corpus f] [--kit <repo checkout>] [--out dir] [--cache f] [--max-calls N] [--dry-run] [--json]
//   jev-eval calibrate <suite.json> [--corpus f] [--out dir] [--state f] [--cache f] [--force-holdout "<reason>"] [--json]
//   jev-eval compare   --baseline a.json --current b.json [--allow-model-change] [--allow-corpus-change] [--json]
// Exit: 0 ok / recommended, 2 usage or suite error, 3 hard-zero violation (score) or flip into a hard-zero cell (compare),
//       4 calibration did not recommend (insufficient evidence, no feasible value, holdout violation),
//       5 refused: this holdout already failed (change split.salt or --force-holdout with a reason), 6 compare refused.
// The runner never spawns a process and never evaluates corpus content: rows are data passed to the target.
// Zero dependencies (Node >= 22).
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { LABEL_SOURCES, SuiteError, loadCorpus, loadSuite } from "./lib/suite.mjs";
import { DEFAULT_MAX_CALLS, makeTarget } from "./lib/target.mjs";
import { runRows, summarize } from "./lib/score.mjs";
import { calibrate } from "./lib/calibrate.mjs";
import { CompareError, compareResults } from "./lib/compare.mjs";
import { renderCalibration, renderCompare, renderScore } from "./lib/report.mjs";

export const RUNNER_VERSION = "1";

/** Commit of the checkout containing `dir`, read from .git without spawning anything; null if it cannot be read. */
export function gitCommit(dir) {
  try {
    let d = resolve(dir);
    for (let i = 0; i < 12; i++, d = dirname(d)) {
      const dot = join(d, ".git");
      if (!existsSync(dot)) continue;
      let gitDir = dot;
      if (statSync(dot).isFile()) gitDir = resolve(d, readFileSync(dot, "utf8").trim().replace(/^gitdir:\s*/, ""));
      const head = readFileSync(join(gitDir, "HEAD"), "utf8").trim();
      if (!head.startsWith("ref:")) return /^[0-9a-f]{40}$/.test(head) ? head : null;
      const ref = head.slice(4).trim();
      const common = existsSync(join(gitDir, "commondir")) ? resolve(gitDir, readFileSync(join(gitDir, "commondir"), "utf8").trim()) : gitDir;
      for (const base of [gitDir, common]) { const p = join(base, ref); if (existsSync(p)) return readFileSync(p, "utf8").trim(); }
      const packed = join(common, "packed-refs");
      if (existsSync(packed)) { const hit = readFileSync(packed, "utf8").split("\n").find((l) => l.endsWith(` ${ref}`)); if (hit) return hit.split(" ")[0]; }
      return null;
    }
  } catch { /* unreadable: provenance just lacks a commit */ }
  return null;
}

export function defaultStatePath(suiteId, env = process.env) {
  const xdg = (env.XDG_STATE_HOME ?? "").trim();
  return join(xdg && isAbsolute(xdg) ? xdg : join((env.HOME ?? "").trim() || homedir(), ".local", "state"), "jev", "eval", `${suiteId}.holdout.jsonl`);
}

function parseArgs(argv) {
  const o = { _: [] };
  const flags = new Set(["--dry-run", "--json", "--allow-model-change", "--allow-corpus-change", "--no-write"]);
  const valued = new Set(["--corpus", "--out", "--state", "--cache", "--force-holdout", "--baseline", "--current", "--kit", "--max-calls"]);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (flags.has(a)) o[a.slice(2)] = true;
    else if (valued.has(a)) { if (i + 1 >= argv.length) throw new SuiteError(`${a} needs a value`); o[a.slice(2)] = argv[++i]; }
    else if (a.startsWith("--")) throw new SuiteError(`unknown option ${a}`);
    else o._.push(a);
  }
  return o;
}

function writeJson(dir, name, obj) {
  mkdirSync(dir, { recursive: true, mode: 0o755 });
  const p = join(dir, name);
  writeFileSync(p, JSON.stringify(obj, null, 2));
  return p;
}
const stamp = (d = new Date()) => d.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");

async function setup(o, env) {
  if (!o._[1]) throw new SuiteError("a suite file is required");
  const { suite, suiteHash, dir } = loadSuite(o._[1]);
  const corpusPath = resolve(o.corpus ? process.cwd() : dir, o.corpus ?? suite.corpus);
  const corpus = loadCorpus(corpusPath, suite);
  const maxCalls = o["max-calls"] === undefined ? DEFAULT_MAX_CALLS : Number(o["max-calls"]);
  if (!Number.isInteger(maxCalls) || maxCalls < 1) throw new SuiteError("--max-calls must be a positive integer");
  const target = await makeTarget(suite, { env, cachePath: o.cache ?? null, suiteDir: dir, kitDir: o.kit ?? null, maxCalls });
  return { suite, suiteHash, dir, corpus, target, corpusPath };
}

const provenance = (rows) => Object.fromEntries(LABEL_SOURCES.map((s) => [s, rows.filter((r) => r.label_source === s).length]).filter(([, n]) => n));

export async function cmdScore(o, env = process.env, out = console.log) {
  const { suite, suiteHash, dir, corpus, target } = await setup(o, env);
  if (o["dry-run"]) {
    let det = 0, needs = 0, unknown = 0, chars = 0;
    for (const row of corpus.rows) {
      const p = await target.probe(row.input, {});
      if (p.needsJev === null) unknown++; else if (p.needsJev) { needs++; chars += JSON.stringify(row.input).length; } else det++;
    }
    out(`jev-eval dry run: suite ${suite.id}, ${corpus.rows.length} rows, target ${target.kind}${target.tool ? ` ${target.tool}` : ""}`);
    if (unknown) out(`  upstream calls: unknown (${unknown} rows; this target kind cannot be probed without calling it), at most ${unknown}`);
    else out(`  ${det} rows decided deterministically with no model call; ${needs} rows would call Jev (about ${Math.ceil(chars / 4)} input tokens from the brief text alone, a rough lower bound). No request was sent.`);
    return 0;
  }
  const results = await runRows(corpus.rows, suite, target, {});
  const fin = target.finish();
  const metrics = summarize(results, suite);
  const result = {
    runner_version: RUNNER_VERSION, kind: "score", ts: new Date().toISOString(), suite_id: suite.id, suite_hash: suiteHash, corpus_hash: corpus.corpusHash,
    target: { kind: target.kind, tool: target.tool ?? null, live: target.live, note: target.note, git: gitCommit(o.kit ?? dir), kit_override: Boolean(o.kit), ...fin }, models: metrics.models,
    harm: suite.harm, label_provenance: provenance(corpus.rows), metrics,
    rows: results.map((r) => ({ id: r.id, truth: r.truth, decision: r.decision, evaluated: r.evaluated, reason: r.reason, split: r.split, label_source: r.label_source })),
  };
  let path = null;
  if (!o["no-write"]) path = writeJson(o.out ?? "jev-eval-results", `${suite.id}-${stamp()}.json`, result);
  out(o.json ? JSON.stringify(result, null, 2) : renderScore(result));
  if (path && !o.json) out(`\nresults: ${path}`);
  return metrics.hard_zero_violations > 0 ? 3 : 0;
}

export async function cmdCalibrate(o, env = process.env, out = console.log) {
  const { suite, suiteHash, dir, corpus, target } = await setup(o, env);
  if (o["dry-run"]) {
    const eligible = corpus.rows.filter((r) => r.label_source !== "derived");
    const train = eligible.filter((r) => r.split === "train").length, hold = eligible.filter((r) => r.split === "holdout").length;
    const grid = suite.sweep.reduce((n, e) => n * e.values.length, 1);
    out(`jev-eval calibrate dry run: suite ${suite.id}, ${corpus.rows.length} rows (${corpus.rows.length - eligible.length} derived, excluded)`);
    out(`  would run the target on ${train} train rows x ${grid} sweep values + ${hold} holdout rows once = up to ${train * grid + hold} target calls. ${target.kind === "mcp" ? "Each is a real Worker call (no answer cache over mcp)." : "With Jev credentials the builtin answer cache makes most of them free."} No request was sent and no holdout row was run.`);
    return 0;
  }
  const force = o["force-holdout"];
  if (force !== undefined && (typeof force !== "string" || force.trim().length < 8)) throw new SuiteError("--force-holdout needs a reason of at least 8 characters; it is logged");
  const statePath = o.state ?? defaultStatePath(suite.id, env);
  const rec = await calibrate(suite, corpus, target, { statePath, force: force ?? null });
  const fin = target.finish();
  const full = { runner_version: RUNNER_VERSION, kind: "calibrate", ts: new Date().toISOString(), suite_hash: suiteHash, corpus_hash: corpus.corpusHash, target: { kind: target.kind, tool: target.tool ?? null, live: target.live, git: gitCommit(o.kit ?? dir), kit_override: Boolean(o.kit), ...fin }, ...rec };
  let path = null;
  if (!o["no-write"]) path = writeJson(o.out ?? "jev-eval-results", `${suite.id}.recommendation.json`, full);
  out(o.json ? JSON.stringify(full, null, 2) : renderCalibration(rec));
  if (path && !o.json) out(`\nrecommendation: ${path}\nholdout log: ${statePath}`);
  if (rec.status === "refused_failed_holdout") return 5;
  return rec.status === "recommended" ? 0 : 4;
}

export function cmdCompare(o, out = console.log) {
  if (!o.baseline || !o.current) throw new SuiteError("--baseline and --current are required");
  const read = (p) => { try { return JSON.parse(readFileSync(p, "utf8")); } catch { throw new SuiteError(`cannot read results file ${p}`); } };
  const b = read(o.baseline), c = read(o.current);
  let cmp;
  try { cmp = compareResults(b, c, { allowModelChange: Boolean(o["allow-model-change"]), allowCorpusChange: Boolean(o["allow-corpus-change"]), harm: c.harm }); }
  catch (e) { if (e instanceof CompareError) { out(`jev-eval compare: refused: ${e.message}`); return 6; } throw e; }
  out(o.json ? JSON.stringify(cmp, null, 2) : renderCompare(cmp));
  return cmp.hard_zero_flips > 0 ? 3 : 0;
}

export async function main(argv, env = process.env) {
  let o;
  try {
    o = parseArgs(argv);
    const cmd = o._[0];
    if (!cmd || cmd === "-h" || cmd === "--help") { console.log("usage: jev-eval score|calibrate|compare ... (see scripts/jev-eval/README.md)"); return cmd ? 0 : 2; }
    if (cmd === "score") return await cmdScore(o, env);
    if (cmd === "calibrate") return await cmdCalibrate(o, env);
    if (cmd === "compare") return cmdCompare(o);
    throw new SuiteError(`unknown command ${cmd}`);
  } catch (e) {
    if (e instanceof SuiteError) { console.error(`jev-eval: ${e.message}`); return 2; }
    console.error(`jev-eval: ${String(e?.message ?? e).slice(0, 300)}`);
    return 2;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(await main(process.argv.slice(2)));
