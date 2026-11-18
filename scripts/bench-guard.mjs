#!/usr/bin/env node
// Where the guard's time goes on this machine. It measures; it asserts no timing. Not part of the CI timing path.
//
//   node scripts/bench-guard.mjs [--quick] [--json FILE] [--md FILE] [--url https://<worker>/mcp]
//
// Phases. Rows inside a phase are interleaved: each round starts from a different scenario, so drift hits all rows alike.
//   cold    Claude hook: one `python3 hooks/jev_guard_hook.py` process per call (local rules on; then JEV_GUARD_LOCAL=off with no
//           server, the fail-open process floor). omp hook: one `bun` process per sample; it reports the import time, the first
//           tool_call, and the median of 50 later calls in that process.
//   warm    guardCommand called in this process: the local rules alone, no hook or process overhead.
//   worker  only with --url: kit_guard_command ls (POST /mcp) and GET /health on a deployed Worker. Network round trips.
//
// N: cold rows 30 after 5 warmups; warm and worker rows 50 after 5 warmups. --quick is N=1 with no warmup: a smoke run, its numbers mean nothing.
// Secrets: the token is read only from JEV_MCP_TOKEN in this process's environment. It is never printed or written to a file.
// Children get a clean environment (PATH, a temp HOME and XDG dirs), so ~/.config/jev/env and any inherited token cannot reach them.
// Exit status: 1 if a row's observed decision is outside its expected set (a correctness check, not a timing one), or a child fails to run.

import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir, cpus, loadavg, release } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";

const REPO = join(dirname(fileURLToPath(import.meta.url)), "..");
const argv = process.argv.slice(2);
const flag = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : undefined; };
const QUICK = argv.includes("--quick");
const JSON_OUT = flag("--json");
const MD_OUT = flag("--md");
const URL_ARG = flag("--url");
if (argv.includes("--url") && !URL_ARG) fail("--url needs a value");
let workerUrl = null;
let TOKEN = "";
if (URL_ARG) {
  const u = new URL(URL_ARG);
  if (u.protocol !== "https:") fail("--url must be https://");
  TOKEN = process.env.JEV_MCP_TOKEN ?? "";
  if (!TOKEN) fail("--url needs JEV_MCP_TOKEN in the environment (it is not printed)");
  workerUrl = u;
}
const N_COLD = QUICK ? 1 : 30;
const N_WARM = QUICK ? 1 : 50;
const WARMUP = QUICK ? 0 : 5;
const STEADY_N = QUICK ? 1 : 50;

function fail(msg) { process.stderr.write(`bench-guard: ${msg}\n`); process.exit(2); }

const TMP = mkdtempSync(join(process.env.TMPDIR || tmpdir(), "jev-bench-"));
const HOME_TMP = join(TMP, "home");
const HOOK_PY = join(REPO, "hooks", "jev_guard_hook.py");
const HOOK_OMP = join(REPO, "hooks", "omp", "jev-guard.ts");
const GUARD_MJS = join(REPO, "server", "src", "kit", "guard.mjs");
const OMP_CHILD = join(TMP, "omp-child.ts");
const BENCH_HOME = "/home/bench";

// One child process env: nothing inherited except PATH and TMPDIR. Temp HOME and XDG dirs, so no real config or state is read or written.
function childEnv(extra = {}) {
  const env = {
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: HOME_TMP,
    XDG_STATE_HOME: join(HOME_TMP, "state"),
    XDG_CONFIG_HOME: join(HOME_TMP, "config"),
    XDG_DATA_HOME: join(HOME_TMP, "data"),
    JEV_LEDGER: join(HOME_TMP, "state", "ledger.jsonl"),
    LANG: "C.UTF-8",
    ...extra,
  };
  if (process.env.TMPDIR) env.TMPDIR = process.env.TMPDIR;
  return env;
}

const GUARD_ARGS = (command) => ({ tool: "Bash", command, cwd: REPO, home: BENCH_HOME });

// The omp child: stubs the omp import (same stub as tests/local-first-omp.test.ts), times import, first call, and 50 later calls.
const OMP_CHILD_SRC = `import { mock } from "bun:test";
mock.module("@oh-my-pi/pi-coding-agent", () => ({ isToolCallEventType: (name: string, e: { toolName?: string }) => e.toolName === name }));
const t0 = performance.now();
const mod = await import(process.env.JEV_HOOK_PATH as string);
let handler: any;
mod.default({ on(n: string, f: any) { if (n === "tool_call") handler = f; }, registerCommand() {}, sendMessage() {} });
const t1 = performance.now();
const event = { type: "tool_call", toolName: "bash", toolCallId: "1", input: { command: "ls" } };
const ctx = { hasUI: false, cwd: process.env.JEV_REPO as string, ui: { notify() {}, confirm: async () => false } };
const first = await handler(event, ctx);
const t2 = performance.now();
for (let i = 0; i < ${WARMUP}; i++) await handler(event, ctx);
const xs: number[] = [];
for (let i = 0; i < ${STEADY_N}; i++) { const a = performance.now(); await handler(event, ctx); xs.push(performance.now() - a); }
xs.sort((a, b) => a - b);
const mid = xs.length >> 1;
const steady = xs.length % 2 ? xs[mid] : (xs[mid - 1] + xs[mid]) / 2;
console.log(JSON.stringify({ import_ms: t1 - t0, first_ms: t2 - t1, steady_median_ms: steady, blocked: !!(first && first.block) }));
process.exit(0);
`;
writeFileSync(OMP_CHILD, OMP_CHILD_SRC);

function claudeRun(command, extra) {
  const event = JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command }, cwd: REPO, session_id: "bench" });
  const t = performance.now();
  const r = spawnSync("python3", [HOOK_PY], { input: event, env: childEnv(extra), cwd: REPO, timeout: 15000, encoding: "utf8" });
  const ms = performance.now() - t;
  if (r.error || r.status !== 0) return { error: `hook exited ${r.status}: ${r.error ? r.error.message : r.stderr.trim().slice(0, 200)}` };
  return { ms, observed: claudeDecision(r.stdout) };
}

// The hook prints nothing for allow (a one-time systemMessage may appear with no server), and hookSpecificOutput for ask/deny.
function claudeDecision(stdout) {
  const t = stdout.trim();
  if (!t) return "allow";
  let j;
  try { j = JSON.parse(t); } catch { return "unparsed"; }
  const d = j?.hookSpecificOutput?.permissionDecision;
  if (d === "deny") return "block";
  if (d) return d;
  return "allow";
}

function ompRun() {
  const r = spawnSync("bun", [OMP_CHILD], { env: childEnv({ JEV_REPO: REPO, JEV_HOOK_PATH: HOOK_OMP }), cwd: REPO, timeout: 60000, encoding: "utf8" });
  if (r.error || r.status !== 0) return { error: `bun child exited ${r.status}: ${r.error ? r.error.message : r.stderr.trim().slice(0, 200)}` };
  const last = r.stdout.trim().split("\n").pop();
  let j;
  try { j = JSON.parse(last); } catch { return { error: "bun child printed no JSON" }; }
  return {
    values: { import: [j.import_ms], first: [j.first_ms], steady: [j.steady_median_ms] },
    observed: j.blocked ? "block" : "allow",
  };
}

const guard = await import(pathToFileURL(GUARD_MJS).href);
const WARM_DEPS = { jevAvailable: true, ask: async () => { throw new Error("no model in the bench"); } };
async function warmRun(command) {
  const t = performance.now();
  const reply = await guard.guardCommand(GUARD_ARGS(command), WARM_DEPS);
  const ms = performance.now() - t;
  return { values: { wall: [ms] }, observed: reply.decision };
}

async function workerRun(kind) {
  const t = performance.now();
  const headers = { authorization: `Bearer ${TOKEN}`, "user-agent": "jev-bench/1.0" };
  let observed;
  try {
    let res;
    if (kind === "guard") {
      res = await fetch(workerUrl, {
        method: "POST",
        headers: { ...headers, "content-type": "application/json", accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "kit_guard_command", arguments: GUARD_ARGS("ls") } }),
        signal: AbortSignal.timeout(5000),
      });
    } else {
      res = await fetch(new URL("/health", workerUrl), { headers, signal: AbortSignal.timeout(5000) });
    }
    observed = `http ${res.status}`;
    await res.text();
  } catch (e) {
    observed = `error ${e.name}`;
  }
  return { values: { wall: [performance.now() - t] }, observed };
}

// Scenario: { title, expect: Set of observed values, metrics: [{ key, label }], run(), samples, observed, errors }.
function scenario(title, expect, metrics, run) {
  const samples = Object.fromEntries(metrics.map((m) => [m.key, []]));
  return { title, expect: new Set(expect), metrics, run, samples, observed: [], errors: [] };
}

const HAS_BUN = sh("bun", ["--version"]) !== "not found";
const COLD = [
  scenario("Claude hook: `ls` (local rules, allow)", ["allow"], [{ key: "wall", label: "process wall" }],
    async () => { const r = claudeRun("ls", {}); return r.error ? { error: r.error } : { values: { wall: [r.ms] }, observed: r.observed }; }),
  scenario("Claude hook: `cat .env` (local rules, block or ask)", ["block", "ask"], [{ key: "wall", label: "process wall" }],
    async () => { const r = claudeRun("cat .env", {}); return r.error ? { error: r.error } : { values: { wall: [r.ms] }, observed: r.observed }; }),
  scenario("Claude hook: `ls` with JEV_GUARD_LOCAL=off, no server (fail-open floor)", ["allow"], [{ key: "wall", label: "process wall" }],
    async () => { const r = claudeRun("ls", { JEV_GUARD_LOCAL: "off" }); return r.error ? { error: r.error } : { values: { wall: [r.ms] }, observed: r.observed }; }),
  ...(HAS_BUN ? [scenario("omp hook (stubbed omp import): `ls`", ["allow"],
    [{ key: "import", label: "import (in-process)" }, { key: "first", label: "first tool_call" }, { key: "steady", label: "steady median of 50 (per process)" }],
    async () => ompRun())] : []),
];
const WARM = [
  scenario("guardCommand in-process: `ls`", ["allow"], [{ key: "wall", label: "call" }], async () => warmRun("ls")),
  scenario("guardCommand in-process: `cat .env`", ["block", "ask"], [{ key: "wall", label: "call" }], async () => warmRun("cat .env")),
];
const WORKER = workerUrl ? [
  scenario("Worker: kit_guard_command `ls` (POST /mcp)", ["http 200"], [{ key: "wall", label: "round trip" }], async () => workerRun("guard")),
  scenario("Worker: GET /health", ["http 200"], [{ key: "wall", label: "round trip" }], async () => workerRun("health")),
] : [];

// Interleaved phase: each round runs every scenario once, starting from a different one; the first `warmup` rounds are discarded.
async function phase(scenarios, rounds, warmup) {
  for (let r = 0; r < warmup + rounds; r++) {
    for (let k = 0; k < scenarios.length; k++) {
      const sc = scenarios[(r + k) % scenarios.length];
      const out = await sc.run();
      if (r < warmup) continue;
      if (out.error) { sc.errors.push(out.error); continue; }
      for (const [key, xs] of Object.entries(out.values)) sc.samples[key].push(...xs);
      sc.observed.push(out.observed);
    }
  }
}

function summarize(xs) {
  const s = [...xs].sort((a, b) => a - b);
  if (!s.length) return null;
  const n = s.length;
  const med = n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
  const r = (v) => Math.round(v * 100) / 100;
  return { n, median: r(med), p90: r(s[Math.ceil(0.9 * n) - 1]), min: r(s[0]), max: r(s[n - 1]) };
}

function tally(xs) {
  const m = new Map();
  for (const x of xs) m.set(x, (m.get(x) ?? 0) + 1);
  return [...m].map(([k, v]) => `${k} x${v}`).join(", ") || "none";
}

function sh(cmd, a) {
  const r = spawnSync(cmd, a, { encoding: "utf8", timeout: 5000 });
  if (r.error || r.status !== 0) return "not found";
  return (r.stdout || r.stderr).trim().split("\n")[0];
}

const startLoad = loadavg();
const fp = {
  date: new Date().toISOString(),
  commit: sh("git", ["-C", REPO, "rev-parse", "--short", "HEAD"]),
  dirty_tree: !["", "not found"].includes(sh("git", ["-C", REPO, "status", "--porcelain"])),
  kernel: `${sh("uname", ["-s"])} ${release()} ${sh("uname", ["-m"])}`,
  cpu: cpus()[0]?.model ?? "unknown",
  cores: cpus().length,
  versions: {
    node: process.version,
    python3: sh("python3", ["--version"]),
    bun: sh("bun", ["--version"]),
    omp: sh("omp", ["--version"]),
  },
  load_before: startLoad.map((x) => Math.round(x * 100) / 100),
  workerHost: workerUrl ? workerUrl.host : null,
};

const mode = QUICK ? "quick (N=1, no warmup: smoke only)" : `N cold=${N_COLD}, N warm=${N_WARM}, warmup=${WARMUP}`;
process.stderr.write(`bench-guard: ${mode}\n`);

try {
  await phase(COLD, N_COLD, WARMUP);
  await phase(WARM, N_WARM, WARMUP);
  if (WORKER.length) await phase(WORKER, N_WARM, WARMUP);
} finally {
  rmSync(TMP, { recursive: true, force: true });
}

const endLoad = loadavg();
fp.load_after = endLoad.map((x) => Math.round(x * 100) / 100);
const limit = fp.cores / 2;
const reasons = [];
if (startLoad[0] > limit) reasons.push(`1-min load ${startLoad[0].toFixed(2)} before the run is above cores/2 (${limit})`);
if (endLoad[0] > limit) reasons.push(`1-min load ${endLoad[0].toFixed(2)} after the run is above cores/2 (${limit})`);
fp.noisy = reasons.length > 0;
fp.noisy_reasons = reasons;

const scenarios = [...COLD, ...WARM, ...WORKER];
const rows = [];
let unexpected = 0;
let childErrors = 0;
for (const sc of scenarios) {
  const bad = sc.observed.filter((o) => !sc.expect.has(o));
  if (bad.length) unexpected++;
  childErrors += sc.errors.length;
  for (const m of sc.metrics) {
    rows.push({
      title: sc.title,
      measure: m.label,
      ...(summarize(sc.samples[m.key]) ?? { n: 0 }),
      unit: "ms",
      observed: tally(sc.observed),
      expected: [...sc.expect].join(" or "),
      unexpected: bad.length > 0,
      errors: sc.errors.length,
    });
  }
}

const report = {
  fingerprint: fp,
  method: { quick: QUICK, n_cold: N_COLD, n_warm: N_WARM, warmup: WARMUP, steady_calls_per_process: STEADY_N, interleaved: true },
  rows,
};

function md(r) {
  const f = r.fingerprint;
  const L = [];
  L.push("# Guard latency: one run on this host", "");
  if (f.noisy) L.push(`> **NOISY RUN.** ${f.noisy_reasons.join("; ")}. Read these as upper bounds, not a clean baseline.`, "");
  L.push("## Host fingerprint", "");
  L.push(`- date: ${f.date}`);
  L.push(`- commit: ${f.commit}${f.dirty_tree ? " (working tree dirty: this run is not from a clean commit)" : ""}`);
  L.push(`- kernel: ${f.kernel}`);
  L.push(`- cpu: ${f.cpu}, ${f.cores} cores`);
  L.push(`- load average (1 / 5 / 15 min) before: ${f.load_before.join(" / ")}; after: ${f.load_after.join(" / ")}`);
  L.push(`- versions: node ${f.versions.node.replace(/^v/, "")}, ${f.versions.python3}, bun ${f.versions.bun}, ${f.versions.omp}`);
  L.push(`- method: ${r.method.quick ? "QUICK smoke run (N=1, no warmup); numbers are not a measurement" : `cold N=${r.method.n_cold}, warm and worker N=${r.method.n_warm}, ${r.method.warmup} warmups, rows interleaved, steady median of ${r.method.steady_calls_per_process} calls per omp process`}`);
  if (f.workerHost) L.push(`- worker: ${f.workerHost} (token from JEV_MCP_TOKEN, not printed)`);
  L.push("", "## Results (ms)", "");
  L.push("| Measurement | n | median | p90 | min | max | observed | expected |");
  L.push("|---|---:|---:|---:|---:|---:|---|---|");
  for (const row of r.rows) {
    const name = row.measure === "wall" || row.measure === "call" ? row.title : `${row.title} · ${row.measure}`;
    const flag = row.unexpected ? " **UNEXPECTED**" : "";
    const err = row.errors ? ` (${row.errors} child failures)` : "";
    L.push(`| ${name}${flag}${err} | ${row.n} | ${row.median ?? "-"} | ${row.p90 ?? "-"} | ${row.min ?? "-"} | ${row.max ?? "-"} | ${row.observed} | ${row.expected} |`);
  }
  L.push("", "A local decision is not a network round trip. The Claude `ls` and warm rows never open a socket; only the worker rows do.", "");
  return L.join("\n");
}

const text = md(report);
process.stdout.write(text);
if (JSON_OUT) writeFileSync(JSON_OUT, JSON.stringify(report, null, 2) + "\n");
if (MD_OUT) writeFileSync(MD_OUT, text);
if (unexpected || childErrors) {
  process.stderr.write(`bench-guard: ${unexpected} row(s) with an unexpected decision, ${childErrors} child failure(s)\n`);
  process.exit(1);
}
