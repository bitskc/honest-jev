// Tests for hooks/jev-guard-local.mjs, the local rules runner of the Claude Code guard hook. Data only: commands are passed as
// strings on stdin and parsed by the rules; nothing here executes one.
//   node --test hooks/jev-guard-local.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { judgeStdin } from "./jev-guard-local.mjs";
import { rulesFingerprint } from "./jev-rules-fingerprint.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const RUNNER = join(here, "jev-guard-local.mjs");
const KIT = join(root, "server", "src", "kit");
const THREE = ["guard.mjs", "shell.mjs", "safere.mjs"];
const { guardCommand } = await import(pathToFileURL(join(KIT, "guard.mjs")).href);

// a scratch dir under $HOME is fine; none of it is the real decision log, and the runner writes no ledger
const scratch = mkdtempSync(join(tmpdir(), "jev-local-runner-"));
test.after(() => rmSync(scratch, { recursive: true, force: true }));

const cleanEnv = (extra = {}) => ({ PATH: process.env.PATH, HOME: join(scratch, "home"), XDG_CACHE_HOME: join(scratch, "cache"), ...extra });

function run(args, { input, env, runner = RUNNER, cwd } = {}) {
  return new Promise((resolve) => {
    const child = execFile(process.execPath, [runner, ...args], { env: env ?? cleanEnv(), cwd, encoding: "utf8", maxBuffer: 1 << 24 }, (err, stdout, stderr) => {
      resolve({ code: err ? (typeof err.code === "number" ? err.code : 1) : 0, stdout, stderr });
    });
    if (input !== undefined) child.stdin.end(input); else child.stdin.end();
  });
}

const reply = (r) => JSON.parse(r.stdout);

// ── parity with a direct guardCommand call ───────────────────────────────────────────────────────────────────────────
// Every row of evals/guard.jsonl (the 10 Read rows included) goes through judgeStdin, the function the one-shot entry uses for its
// stdin, in this one process. A fixed sample of 20 rows, covering block, ask, allow, unclear and the Read rows, also goes through real
// one-process-per-call spawns of jev-guard-local.mjs. Runs in CI in the "hooks test suite" job (node --test hooks/*.test.mjs).
const corpus = readFileSync(join(root, "evals", "guard.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
const direct = new Map();
for (const r of corpus) direct.set(r.id, await guardCommand(structuredClone(r.input), { ask: null, jevAvailable: false }));
const FIELDS = ["decision", "rule", "reason", "suggestion", "score", "decided_by"];
const kindOf = (id) => { const d = direct.get(id); return d.decided_by === "fail_open" ? "unclear" : d.decision; };
const differences = (id, got) => {
  const d = direct.get(id), out = [];
  if (got.unclear !== (d.decided_by === "fail_open")) out.push([id, "unclear", got.unclear]);
  for (const k of FIELDS) if (JSON.stringify(got[k]) !== JSON.stringify(d[k])) out.push([id, k, got[k], d[k]]);
  return out;
};

test("parity: every row of evals/guard.jsonl through judgeStdin equals a direct guardCommand call", async () => {
  assert.ok(corpus.length >= 1241, "the corpus shrank");
  assert.ok(corpus.filter((r) => r.input.tool === "Read" && r.input.file_path).length >= 10, "the corpus has its Read rows");
  const diffs = [];
  const seen = { block: 0, ask: 0, allow: 0, unclear: 0 };
  for (const r of corpus) {
    const got = await judgeStdin(JSON.stringify(r.input), guardCommand);
    diffs.push(...differences(r.id, got));
    seen[kindOf(r.id)]++;
  }
  assert.deepEqual(diffs, []);
  assert.ok(Object.values(seen).every((n) => n > 0), `the corpus exercises every verdict kind: ${JSON.stringify(seen)}`);
  assert.ok(seen.unclear * 10 < corpus.length, `the rules settle almost everything: ${JSON.stringify(seen)}`);
});

const SAMPLE = ["r01", "r04", "r08", "r09", "g36", "g37", "g673", "g53", "g551", "g562", "g01", "g426", "g434", "g15", "g55", "g68", "b08", "g821", "g863", "g883"];

test("parity: a fixed sample of 20 rows through real one-process-per-call runs of the entry equals a direct guardCommand call", async () => {
  assert.equal(new Set(SAMPLE).size, 20);
  const kinds = new Set(SAMPLE.map((id) => kindOf(id)));
  assert.deepEqual([...kinds].sort(), ["allow", "ask", "block", "unclear"], "the sample covers every verdict kind");
  assert.ok(SAMPLE.filter((id) => corpus.find((r) => r.id === id).input.tool === "Read").length >= 3, "the sample covers Read rows");
  const diffs = [];
  for (const id of SAMPLE) {
    const out = await run([], { input: JSON.stringify(corpus.find((r) => r.id === id).input) });
    if (out.code !== 0) { diffs.push([id, "runner exit", out.stderr.slice(0, 80)]); continue; }
    diffs.push(...differences(id, reply(out)));
  }
  assert.deepEqual(diffs, []);
});

test("judgeStdin refuses input that is not a JSON object", async () => {
  for (const bad of ["not json", "[]", "null", '"x"', "5"]) await assert.rejects(judgeStdin(bad, guardCommand), bad);
});

test("a model question raised only by guardCommand's second, comment-masked reading is unclear", async () => {
  const input = { tool: "Bash", command: "# don't\nnpm publish", cwd: "/home/u/p", home: "/home/u" };
  const plain = await guardCommand(structuredClone(input), { ask: null, jevAvailable: false });
  assert.equal(plain.decided_by, "prefilter", "premise: with no model the plain reply says a rule settled it");
  const got = reply(await run([], { input: JSON.stringify(input) }));
  assert.equal(got.unclear, true);
});

test("a block from a rule stands even when a model question was also raised", async () => {
  // the first reading (npm publish) raises a model question; the rule block (rm -rf ~) is found in the same command
  const input = { tool: "Bash", command: "npm publish # it's\nrm -rf ~", cwd: "/home/u/p", home: "/home/u" };
  let asked = 0;
  const direct = await guardCommand(structuredClone(input), { jevAvailable: true, ask: async () => { asked++; throw new Error("no model"); } });
  assert.deepEqual([direct.decision, asked > 0], ["block", true], "premise: a block AND a model question");
  const got = reply(await run([], { input: JSON.stringify(input) }));
  assert.deepEqual([got.decision, got.decided_by, got.unclear], ["block", "prefilter", false]);
});

test("--check loads the rules, judges a probe, and prints where they came from", async () => {
  const r = await run(["--check"]);
  assert.equal(r.code, 0, r.stderr);
  assert.equal(r.stdout.trim(), join(KIT, "guard.mjs"));
});

test("failure modes exit non-zero with nothing on stdout", async () => {
  const missing = await run([], { input: "{}", env: cleanEnv({ JEV_GUARD_RULES: "/nonexistent/guard.mjs" }) });
  assert.notEqual(missing.code, 0);
  assert.equal(missing.stdout, "");
  // run from the kit directory, where "guard.mjs" WOULD resolve: a relative override must be refused, not resolved against the cwd
  const relative = await run([], { input: "{}", cwd: KIT, env: cleanEnv({ JEV_GUARD_RULES: "guard.mjs" }) });
  assert.notEqual(relative.code, 0, "a relative override is refused");
  for (const bad of ["not json", "[]", "null", '"x"']) {
    const r = await run([], { input: bad });
    assert.notEqual(r.code, 0, bad);
    assert.equal(r.stdout, "", bad);
  }
});

// ── where the rules are found ────────────────────────────────────────────────────────────────────────────────────────
const FPMOD = join(here, "jev-rules-fingerprint.mjs"); // the runner imports it from its own directory, so every copied runner needs it beside it
function lay(kitDir) {
  mkdirSync(kitDir, { recursive: true });
  for (const f of THREE) cpSync(join(KIT, f), join(kitDir, f));
}
const decide = (runner, env) => run([], { runner, env, input: JSON.stringify({ tool: "Bash", command: "cat .env", cwd: "/p", home: "/h" }) });

test("installed layout (share/hooks + share/jev-policy/server/src), three kit files only, no node_modules anywhere", async () => {
  const share = join(scratch, "share");
  mkdirSync(join(share, "hooks"), { recursive: true });
  cpSync(RUNNER, join(share, "hooks", "jev-guard-local.mjs"));
  cpSync(FPMOD, join(share, "hooks", "jev-rules-fingerprint.mjs"));
  lay(join(share, "jev-policy", "server", "src", "kit"));
  const r = await decide(join(share, "hooks", "jev-guard-local.mjs"), { PATH: process.env.PATH, HOME: join(scratch, "nohome") });
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual([reply(r).decision, reply(r).rule], ["block", "R1-secret-exposure"]);
  assert.equal(existsSync(join(share, "node_modules")), false);
  const c = await run(["--check"], { runner: join(share, "hooks", "jev-guard-local.mjs"), env: { PATH: process.env.PATH, HOME: join(scratch, "nohome") } });
  assert.equal(c.stdout.trim(), join(share, "jev-policy", "server", "src", "kit", "guard.mjs"));
});

test("plugin / repo layout (hooks/ beside server/src/kit): the plugin root needs no npm ci", async () => {
  const plugin = join(scratch, "plugin");
  mkdirSync(join(plugin, "hooks"), { recursive: true });
  cpSync(RUNNER, join(plugin, "hooks", "jev-guard-local.mjs"));
  cpSync(FPMOD, join(plugin, "hooks", "jev-rules-fingerprint.mjs"));
  lay(join(plugin, "server", "src", "kit"));
  const r = await decide(join(plugin, "hooks", "jev-guard-local.mjs"), { PATH: process.env.PATH, HOME: join(scratch, "nohome") });
  assert.equal(r.code, 0, r.stderr);
  assert.equal(reply(r).decision, "block");
});

test("a hook runs the rules of its own release: hook-relative beats the legacy install dir; the legacy dir is the last resort", async () => {
  const home = join(scratch, "legacyhome");
  const legacyKit = join(home, ".local", "share", "jev-agent-skills", "jev-policy", "server", "src", "kit");
  lay(legacyKit);
  writeFileSync(join(legacyKit, "guard.mjs"), 'export async function guardCommand() { return { decision: "allow", decided_by: "prefilter", rule: "LEGACY", reason: "legacy" }; }\n');
  const lone = join(scratch, "lone", "hooks");
  mkdirSync(lone, { recursive: true });
  cpSync(RUNNER, join(lone, "jev-guard-local.mjs"));
  cpSync(FPMOD, join(lone, "jev-rules-fingerprint.mjs"));
  let r = await decide(join(lone, "jev-guard-local.mjs"), { PATH: process.env.PATH, HOME: home });
  assert.equal(reply(r).rule, "LEGACY", "nothing beside the hook: the pre-rename install dir");
  lay(join(scratch, "lone", "server", "src", "kit"));
  r = await decide(join(lone, "jev-guard-local.mjs"), { PATH: process.env.PATH, HOME: home });
  assert.equal(reply(r).rule, "R1-secret-exposure", "the release beside the hook wins");
});

test("JEV_GUARD_RULES is the only candidate when set", async () => {
  const kit = join(scratch, "override");
  lay(kit);
  const r = await decide(RUNNER, cleanEnv({ JEV_GUARD_RULES: join(kit, "guard.mjs") }));
  assert.equal(reply(r).decision, "block");
});

test("the compile cache lives in a private directory of ours, never the shared temp dir", async () => {
  const cache = join(scratch, "cachetest");
  const r = await decide(RUNNER, cleanEnv({ XDG_CACHE_HOME: cache }));
  assert.equal(r.code, 0, r.stderr);
  const dir = join(cache, "jev", "compile-cache");
  if (existsSync(dir)) assert.equal(statSync(dir).mode & 0o777, 0o700); // a node without the API simply makes no cache
});

test("a group- or world-writable cache directory is not used: no cache is written there, and the run still works", async (t) => {
  const mk = (name, mode) => {
    const c = join(scratch, name);
    mkdirSync(join(c, "jev", "compile-cache"), { recursive: true });
    chmodSync(join(c, "jev", "compile-cache"), mode);
    return c;
  };
  const entries = (c) => readdirSync(join(c, "jev", "compile-cache"));
  const ok = mk("cache-private", 0o700);
  assert.equal(reply(await decide(RUNNER, cleanEnv({ XDG_CACHE_HOME: ok }))).decision, "block");
  // positive control: a private directory does get a cache (a node without the API makes none, and the rest proves nothing)
  if (entries(ok).length === 0) return t.skip("this node makes no compile cache");
  for (const mode of [0o770, 0o707, 0o777]) {
    const c = mk(`cache-${mode.toString(8)}`, mode);
    const r = await decide(RUNNER, cleanEnv({ XDG_CACHE_HOME: c }));
    assert.equal(reply(r).decision, "block", `mode ${mode.toString(8)}: the run still works`);
    assert.deepEqual(entries(c), [], `mode ${mode.toString(8)}: nothing is cached in a directory others can write`);
  }
});

test("a symlinked cache directory is not used", async () => {
  const cache = join(scratch, "symcache");
  const target = join(scratch, "elsewhere");
  mkdirSync(join(cache, "jev"), { recursive: true });
  mkdirSync(target, { recursive: true });
  symlinkSync(target, join(cache, "jev", "compile-cache"));
  const r = await decide(RUNNER, cleanEnv({ XDG_CACHE_HOME: cache }));
  assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(readdirSync(target), []);
});

// ── the rules fingerprint ───────────────────────────────────────────────────────────────────────────────────────────────
test("--fingerprint prints the fingerprint of the rule files that would be loaded, and every reply carries the same value as rules_fp", async () => {
  const expected = rulesFingerprint(KIT);
  assert.match(expected, /^[0-9a-f]{64}$/);
  const f = await run(["--fingerprint"]);
  assert.equal(f.code, 0, f.stderr);
  assert.equal(f.stdout.trim(), expected);
  const r = await decide(RUNNER, cleanEnv());
  assert.equal(reply(r).rules_fp, expected);
  const allow = await run([], { input: JSON.stringify({ tool: "Bash", command: "ls", cwd: "/p", home: "/h" }) });
  assert.deepEqual([reply(allow).decision, reply(allow).rules_fp], ["allow", expected]);
});

test("the fingerprint is taken from the files that are loaded: an edited copy has another one, whatever it is called", async () => {
  const kit = join(scratch, "tampered");
  lay(kit);
  const before = (await run(["--fingerprint"], { env: cleanEnv({ JEV_GUARD_RULES: join(kit, "guard.mjs") }) })).stdout.trim();
  assert.equal(before, rulesFingerprint(KIT));
  writeFileSync(join(kit, "guard.mjs"), `${readFileSync(join(kit, "guard.mjs"), "utf8")}\n// edited\n`);
  const env = cleanEnv({ JEV_GUARD_RULES: join(kit, "guard.mjs") });
  const after = (await run(["--fingerprint"], { env })).stdout.trim();
  assert.notEqual(after, before);
  assert.equal(reply(await decide(RUNNER, env)).rules_fp, after);
  // a sibling edited instead of guard.mjs counts as well: the fingerprint covers every file the rules load
  const kit2 = join(scratch, "tampered2");
  lay(kit2);
  writeFileSync(join(kit2, "shell.mjs"), `${readFileSync(join(kit2, "shell.mjs"), "utf8")}\n// edited\n`);
  assert.notEqual((await run(["--fingerprint"], { env: cleanEnv({ JEV_GUARD_RULES: join(kit2, "guard.mjs") }) })).stdout.trim(), before);
});

test("rule files that are not the whole release: rules_fp is null in a reply, and --fingerprint exits non-zero with nothing on stdout", async () => {
  const lone = join(scratch, "lone-guard");
  mkdirSync(lone, { recursive: true });
  writeFileSync(join(lone, "guard.mjs"), 'export async function guardCommand() { return { decision: "allow", decided_by: "prefilter", rule: null, reason: "" }; }\n');
  const env = cleanEnv({ JEV_GUARD_RULES: join(lone, "guard.mjs") });
  const r = await run([], { env, input: JSON.stringify({ tool: "Bash", command: "ls" }) });
  assert.equal(r.code, 0, r.stderr);
  assert.equal(reply(r).rules_fp, null);
  const f = await run(["--fingerprint"], { env });
  assert.notEqual(f.code, 0);
  assert.equal(f.stdout, "");
});

test("a runner whose rules are not found has no fingerprint either", async () => {
  const f = await run(["--fingerprint"], { env: cleanEnv({ JEV_GUARD_RULES: "/nonexistent/guard.mjs" }) });
  assert.notEqual(f.code, 0);
  assert.equal(f.stdout, "");
});
