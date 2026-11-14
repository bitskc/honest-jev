#!/usr/bin/env node
// jev-policy-hook: the plan helper both PreToolUse hooks run (openspec change add-policy-hook-adapter).
//
//   echo '{"tool":"Bash","command":"gh pr merge 12","cwd":"/path/to/repo","host":"claude-code"}' | jev-policy-hook plan
//   jev-policy-hook plan --command 'gh pr merge 12' --cwd . [--host H] [--no-providers] [--pretty]
//
// It reads the policy layers the way `jev-policy args` does, matches user-layer triggers against the command with the guard's
// own shell parser, computes the facts the trigger declares, and prints ONE JSON object on stdout. It never talks to the
// Worker and never decides anything: the hook sends the `call` it prints to `kit_decide` and maps the answer through `effects`.
//
//   {"ok":true,"triggered":false}
//   {"ok":true,"triggered":true,"class","policy_version","call":{kit_decide arguments},"effects":{word:allow|ask|deny},
//    "on_unavailable":{"decision","effect","mode"},"extra":N,"provider_failure":null|{"name","code"},"notes":[...]}
//   {"ok":false,"problem":"user_layer_invalid"|"bad_input"|"error"}
//
// Subprocesses (`git`, `gh`) are started with argument arrays, no shell, no stdin, a timeout and a capped output buffer. The
// only values taken from the command that reach an argument list are a digits-only PR number, a validated owner/repo and a
// validated PR URL.
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { POLICY_LIMITS, byteLength, parseLayer } from "../server/src/policy/schema.mjs";
import { mergeLayers, policyVersion } from "../server/src/policy/merge.mjs";
import { effectMap, factNames, ghPrMergeTargets, matchCommand, TRIGGER_LIMITS } from "../server/src/policy/trigger.mjs";
import { failMode } from "../server/src/decide/core.mjs";
import { loadLayers, paths } from "./jev-policy.mjs";

const STATE_TEXT_CHARS = 4000;
const MAX_FACT_STRING = 200;
const EXEC_MAX_BUFFER = 1 << 20;

/** The one place a process is started: argv array, no shell, no stdin, timeout, bounded output. Resolves {code, stdout}; rejects with {kind}. */
export function defaultExec(file, args, { cwd, timeoutMs, env }) {
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, { cwd, env, timeout: timeoutMs, killSignal: "SIGKILL", maxBuffer: EXEC_MAX_BUFFER, windowsHide: true, encoding: "utf8" }, (err, stdout) => {
      if (!err) return resolve({ code: 0, stdout });
      if (err.code === "ENOENT") return reject({ kind: "missing" });
      if (err.killed || err.signal) return reject({ kind: "timeout" });
      if (typeof err.code === "number") return reject({ kind: "exit", code: err.code });
      return reject({ kind: "error" });
    });
    if (child.stdin) child.stdin.end();
  });
}

const quietEnv = (env) => ({ ...env, GH_PROMPT_DISABLED: "1", GH_NO_UPDATE_NOTIFIER: "1", NO_COLOR: "1", GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0" });
const CODE = { missing: "client_config", timeout: "client_timeout", exit: "client_network", parse: "client_parse", input: "client_input", error: "client_network" };

async function gitFact(exec, args, cwd, env) {
  try {
    const r = await exec("git", args, { cwd, timeoutMs: 800, env });
    const v = String(r.stdout).trim();
    return v && v.length <= MAX_FACT_STRING ? v : undefined;
  } catch { return undefined; }
}

/**
 * The `gh pr view` argument list for a target (see ghPrMergeTarget). Only a digits-only number, a validated owner/repo and a
 * validated PR URL ever reach it, and none of them can start with a dash. An ambiguous target has no argument list: the
 * provider cannot say which pull request is being merged, so it cannot answer.
 */
export function viewArgs(target) {
  const tail = ["--json", "comments,reviews"];
  if (target.kind === "number") return ["pr", "view", String(target.n), ...(target.repo ? ["--repo", target.repo] : []), ...tail];
  if (target.kind === "url") return ["pr", "view", target.url, ...tail];
  if (target.kind === "none") return ["pr", "view", ...tail]; // no PR named: gh resolves the current branch's
  return null;
}

/** One pull request: true when a comment or review body contains `marker`. Throws {kind} when it cannot answer. */
async function markerOn(exec, src, args, cwd, env) {
  const r = await exec("gh", args, { cwd, timeoutMs: src.timeout_ms ?? TRIGGER_LIMITS.timeout_default_ms, env });
  let doc;
  try { doc = JSON.parse(r.stdout); } catch { throw { kind: "parse" }; }
  if (!doc || typeof doc !== "object" || !Array.isArray(doc.comments) || !Array.isArray(doc.reviews)) throw { kind: "parse" };
  const bodies = [...doc.comments, ...doc.reviews].map((x) => (x && typeof x.body === "string" ? x.body : ""));
  return bodies.some((b) => b.includes(src.marker));
}

/**
 * gh_pr_review_marker over EVERY pull request the command merges: true only when all of them carry the marker. One that cannot
 * be named (an ambiguous target) or read makes the whole answer unavailable: "all targets resolve and pass" or the class's
 * failure rule. Throws {kind} when it cannot answer.
 */
async function reviewMarker(exec, src, targets, cwd, env, providers) {
  if (!providers) throw { kind: "skipped" };
  const argLists = targets.map(viewArgs);
  if (argLists.some((a) => !a)) throw { kind: "input" };
  const answers = await Promise.all(argLists.map((a) => markerOn(exec, src, a, cwd, env)));
  return answers.every(Boolean);
}

/**
 * @param input {tool, command, cwd, host}
 * @param opts  {env, exec (test seam), providers (false: do not run gh), layerPaths ({user, repo} overrides)}
 */
export async function plan(input, opts = {}) {
  const env = opts.env ?? process.env;
  const exec = opts.exec ?? defaultExec;
  const providers = opts.providers !== false;
  if (!input || input.tool !== "Bash" || typeof input.command !== "string" || typeof input.cwd !== "string" || !input.cwd.startsWith("/")) return { ok: false, problem: "bad_input" };
  const cwd = input.cwd;

  // 1. the user layer decides whether anything can fire; a repo layer is never read for triggers
  const p = paths({}, env, cwd);
  const userOnly = loadLayers(p, "user");
  if (userOnly.problems.length) return { ok: false, problem: "user_layer_invalid" };
  if (!userOnly.layers.length) return { ok: true, triggered: false };
  const parsed = parseLayer(userOnly.layers[0].text);
  if (!parsed.ok) return { ok: false, problem: "user_layer_invalid" };
  const matches = [];
  for (const d of parsed.decisions) {
    if (!d.trigger || d.trigger.tool !== input.tool) continue;
    const m = matchCommand(d.trigger, input.command);
    if (m.matched) matches.push({ d, m });
  }
  if (!matches.length) return { ok: true, triggered: false };
  const { d, m: matched } = matches[0];

  // 2. a class matched: now the repo layer (for tightening rules) and the repo root
  const gitRoot = await gitFact(exec, ["rev-parse", "--show-toplevel"], cwd, quietEnv(env));
  const repoRoot = gitRoot ?? cwd; // where to look for the repo layer; the repo_root FACT is only what git answered
  const all = loadLayers(paths({ "repo-root": repoRoot }, env, cwd), "all");
  if (all.userBroken) return { ok: false, problem: "user_layer_invalid" };
  const layers = all.layers.map(({ origin, text }) => ({ origin, text }));
  if (layers.reduce((n, l) => n + byteLength(l.text), 0) > POLICY_LIMITS.total_bytes) return { ok: false, problem: "user_layer_invalid" };
  const merged = mergeLayers(layers);
  const entry = merged.classes.get(d.spec.id);
  if (!entry) return { ok: false, problem: "user_layer_invalid" };
  const spec = entry.spec;

  // 3. facts, in dependency order: the PR target first, then local git, then the provider
  const read = new Set(factNames(spec));
  const values = {}; // every computed value, including inputs that only feed a provider
  let providerFailure = null;
  const entries = Object.entries(d.trigger.facts);
  const byKind = (k) => entries.filter(([, f]) => f.source === k);
  // which PRs the command merges (every matching segment, with gh's own flag arity); anything that can change what a target
  // means (cd, GH_REPO, a rewritten remote, xargs, a merge that is not the whole command and names no PR, ...) is ambiguous.
  // The fact itself is a number only for a lone merge of a plain PR number in this repo.
  const targets = {};
  for (const [name] of byKind("gh_pr_target")) {
    targets[name] = ghPrMergeTargets(matched, input.command);
    const only = targets[name].length === 1 ? targets[name][0] : null;
    if (only && only.kind === "number" && !only.repo) values[name] = only.n;
  }
  const qenv = quietEnv(env);
  for (const [name] of byKind("repo_root")) values[name] = gitRoot;
  for (const [name] of byKind("branch")) values[name] = await gitFact(exec, ["symbolic-ref", "--short", "-q", "HEAD"], cwd, qenv);
  for (const [name, f] of byKind("gh_pr_review_marker")) {
    try {
      values[name] = await reviewMarker(exec, f, targets[f.target_from], repoRoot, qenv, providers);
    } catch (e) {
      const kind = e && e.kind ? e.kind : "error";
      if (kind === "skipped") continue;
      providerFailure = providerFailure ?? { name: "gh_pr_review_marker", code: CODE[kind] ?? "client_network" };
    }
  }
  const facts = {};
  for (const [k, v] of Object.entries(values)) if (v !== undefined && read.has(k)) facts[k] = v;

  const effects = effectMap(spec, d.trigger);
  const od = spec.on_unavailable.decision;
  return {
    ok: true,
    triggered: true,
    class: spec.id,
    policy_version: await policyVersion(entry),
    call: {
      class: spec.id,
      policy_layers: layers,
      facts,
      state: { action: { tool: "Bash", text: input.command.slice(0, STATE_TEXT_CHARS) } },
      ...(typeof input.host === "string" && input.host ? { host: input.host } : {}),
    },
    effects,
    on_unavailable: { decision: od, effect: effects[od], mode: failMode(spec) },
    extra: matches.length - 1,
    provider_failure: providerFailure,
    notes: merged.notes,
  };
}

function parseArgs(argv) {
  const o = { pretty: false, providers: true };
  const pos = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--pretty") o.pretty = true;
    else if (a === "--no-providers") o.providers = false;
    else if (["--command", "--cwd", "--host"].includes(a)) { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); o[a.slice(2)] = argv[++i]; }
    else if (a.startsWith("--")) throw new Error(`unknown option ${a}`);
    else pos.push(a);
  }
  return { o, pos };
}

export async function main(argv, { env = process.env, stdinText, out = (s) => process.stdout.write(s), err = (s) => process.stderr.write(s) } = {}) {
  let parsed;
  try { parsed = parseArgs(argv); } catch (e) { err(`jev-policy-hook: ${e.message}\n`); return 2; }
  const { o, pos } = parsed;
  if (pos[0] !== "plan" || pos.length !== 1) { err("usage: jev-policy-hook plan [--command C --cwd D --host H] [--no-providers] [--pretty]  (or the hook event as JSON on stdin)\n"); return 2; }
  let input;
  if (o.command !== undefined) {
    const { resolve } = await import("node:path");
    input = { tool: "Bash", command: o.command, cwd: resolve(o.cwd ?? "."), host: o.host };
  } else {
    try { input = JSON.parse(stdinText ?? readFileSync(0, "utf8")); } catch { out(`${JSON.stringify({ ok: false, problem: "bad_input" })}\n`); return 0; }
  }
  let result;
  try { result = await plan(input, { env, providers: o.providers }); } catch { result = { ok: false, problem: "error" }; }
  out(`${o.pretty ? JSON.stringify(result, null, 2) : JSON.stringify(result)}\n`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = await main(process.argv.slice(2));
