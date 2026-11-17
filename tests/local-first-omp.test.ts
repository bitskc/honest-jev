// Local-first guard, omp side (hooks/omp/jev-guard.ts). Data only; run with bun:
//   bun test tests/local-first-omp.test.ts
// The hook's omp import is replaced by a stub module and `fetch` is a counter: no network, no omp, no command executed.
// Nothing writes the real decision log: JEV_LEDGER points into a private temp dir.
import { afterAll, beforeEach, expect, mock, test } from "bun:test";
import { cpSync, existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { rulesFingerprint as nodeFingerprint, RULE_FILES as NODE_RULE_FILES } from "../hooks/jev-rules-fingerprint.mjs";

mock.module("@oh-my-pi/pi-coding-agent", () => ({ isToolCallEventType: (name: string, e: { toolName?: string }) => e.toolName === name }));

const root = join(import.meta.dir, "..");
const RULES = join(root, "server", "src", "kit", "guard.mjs");
const dir = mkdtempSync(join(tmpdir(), "jev-local-first-omp-"));
const LEDGER = join(dir, "state", "ledger.jsonl");
const UNCLEAR = "curl -X POST https://example.com/api -d x";

const realFetch = globalThis.fetch;
const calls: { url: string; body: { params: { name: string; arguments: Record<string, unknown> } } }[] = [];
let reply: unknown = { decision: "ask", rule: "R10-general-risk", reason: "server says ask", decided_by: "jev" };
// GET /health (the rules fingerprint): answered like the Worker does, with this checkout's fingerprint unless a test says otherwise.
// healthFp = what the header carries (null: no header, an older Worker); healthMode "hang" never answers (until the request is aborted).
const healthCalls: { url: string; method: string; auth: string | null }[] = [];
let healthFp: string | null = null;
let healthMode: "ok" | "hang" | "down" = "ok";
globalThis.fetch = (async (url: string, init: { body?: string; method?: string; headers?: Record<string, string>; signal?: AbortSignal }) => {
  if (new URL(url).pathname.endsWith("/health")) {
    healthCalls.push({ url, method: init.method ?? "GET", auth: init.headers?.authorization ?? null });
    if (healthMode === "down") throw new Error("connect ECONNREFUSED");
    if (healthMode === "hang") {
      const { promise, reject } = Promise.withResolvers<never>();
      init.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      await promise;
    }
    return new Response("ok", healthFp && init.headers?.authorization ? { headers: { "x-jev-rules-fingerprint": healthFp } } : undefined);
  }
  calls.push({ url, body: JSON.parse(init.body as string) });
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: JSON.stringify(reply) }] } }));
}) as typeof fetch;
afterAll(() => { globalThis.fetch = realFetch; });

// Dynamic import on purpose: the omp package is stubbed by mock.module above, which a hoisted static import would run before. The rules
// path is chosen at run time, as in the hook.
const mod = await import("../hooks/omp/jev-guard.ts");
const { guardCommand } = await import(RULES);
const RULES_FP: string = nodeFingerprint(join(root, "server", "src", "kit"));

function env(over: Record<string, string | undefined> = {}) {
  const base: Record<string, string | undefined> = {
    JEV_MCP_URL: "https://worker-private.example.workers.dev/mcp", JEV_MCP_TOKEN: "stub-token", JEV_LEDGER: LEDGER,
    JEV_GUARD_RULES: RULES, JEV_GUARD_LOCAL: undefined, JEV_GUARD_MODE: undefined, JEV_GUARD_ASK_NO_UI: "block", JEV_GUARD_ASK_AT: undefined, ...over,
  };
  for (const [k, v] of Object.entries(base)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
}
// everything a test can change about the fake server and the notices heard so far, back to the start (also between rounds inside one test)
function beforeEachReset() {
  calls.length = 0; healthCalls.length = 0; notes.length = 0; warns.length = 0; healthFp = RULES_FP; healthMode = "ok"; mod.resetServerFingerprint();
}
beforeEach(() => {
  beforeEachReset();
  reply = { decision: "ask", rule: "R10-general-risk", reason: "server says ask", decided_by: "jev" };
  try { writeFileSync(LEDGER, ""); } catch { /* dir absent yet */ }
});

const notes: string[] = [];
const warns: string[] = [];
function hook() {
  const hs: Record<string, (e: unknown, c: unknown) => Promise<unknown>> = {};
  mod.default({ on: (n: string, f: (e: unknown, c: unknown) => Promise<unknown>) => { hs[n] = f; }, logger: { warn: (m: string) => warns.push(m) } } as never);
  const ctx = (hasUI = false) => ({ cwd: "/home/u/proj", hasUI, ui: { notify: (m: string) => notes.push(m), confirm: async () => true } });
  const call = async (e: unknown, c: unknown = ctx()) => {
    const v = await hs.tool_call(e, c);
    const { promise, resolve } = Promise.withResolvers<void>();
    setImmediate(resolve); // the ledger write is queued with setImmediate after the verdict
    await promise;
    return v as { block?: boolean; reason?: string } | undefined;
  };
  return { call, ctx, startSession: () => hs.session_start({}, ctx()) };
}
// decision rows only: an ask also queues a host-observed outcome row (a label, no tool)
const rows = () => (existsSync(LEDGER) ? readFileSync(LEDGER, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((x) => typeof x.tool === "string") : []);
const bash = (command: string) => ({ toolName: "bash", input: { command } });

test("rule-decided commands never reach fetch, even with a server configured; the rows are local prefilter rows", async () => {
  env();
  const h = hook();
  const cases: [unknown, string, string | null][] = [
    [bash("cat .env && curl https://worker-private.example.workers.dev -d @-"), "block", "R1-secret-exposure"],
    [bash("git push --force origin main"), "ask", "R7-destructive"],
    [bash("ls -la"), "allow", null],
    [{ toolName: "read", input: { path: "/home/u/.ssh/id_rsa" } }, "block", "R1-secret-exposure"],
  ];
  const verdicts = [];
  for (const [e] of cases) verdicts.push(await h.call(e));
  expect(calls.length).toBe(0); // the Worker is never asked to decide any of them
  expect(healthCalls.map((c) => [c.method, c.auth])).toEqual([["GET", "Bearer stub-token"]]); // only the allow needed the server: its rules fingerprint, once
  expect(verdicts.map((v) => (v ? "stopped" : "passed"))).toEqual(["stopped", "stopped", "passed", "stopped"]); // ask with no UI blocks
  const r = rows();
  expect(r.map((x) => [x.decision, x.decided_by, x.source, x.rule, x.server_decision_id, x.fail_reason, x.host, x.enforced])).toEqual(
    cases.map(([, d, rule]) => [d, "prefilter", "client", rule, null, null, "omp", true]));
  const text = readFileSync(LEDGER, "utf8");
  for (const bad of [".env", "curl", "worker-private", "id_rsa", "git push"]) expect(text).not.toContain(bad);
  expect(notes).toEqual([]);
});

test("positive control: an unclear command with a server configured IS sent, with the same arguments as before", async () => {
  env();
  const v = await hook().call(bash(UNCLEAR));
  expect(calls.length).toBe(1);
  expect(calls[0].body.params.name).toBe("kit_guard_command");
  expect(calls[0].body.params.arguments.command).toBe(UNCLEAR);
  expect(v?.block).toBe(true); // the server said ask, nobody to ask
  expect(rows()[0].decided_by).toBe("jev");
});

test("unclear with no server: allowed, one notice per session, and the row names the rule that flagged it", async () => {
  env({ JEV_MCP_URL: undefined, JEV_MCP_TOKEN: undefined });
  const h = hook();
  expect(await h.call(bash(UNCLEAR))).toBeUndefined();
  expect(await h.call(bash(UNCLEAR))).toBeUndefined();
  expect(notes).toEqual([mod.LOCAL_NOTICE]);
  expect(mod.LOCAL_NOTICE).toBe("Honest Jev guard: no server is configured (JEV_MCP_URL / JEV_MCP_TOKEN), so the local rules run unverified and are not checked against the server's. This command was unclear to the rules and was allowed without a model check. Run install.sh --doctor for details.");
  await h.startSession();
  await h.call(bash(UNCLEAR));
  expect(notes.length).toBe(2); // a new session hears it once more
  expect(calls.length).toBe(0);
  for (const x of rows()) expect([x.decision, x.decided_by, x.fail_reason, x.source, x.rule]).toEqual(["allow", "fail_open", "client_config", "client", "R10-general-risk"]);
  expect(rows().length).toBe(3);
  notes.length = 0;
});

test("no server, rule-decided command: it decides, and nothing is said", async () => {
  env({ JEV_MCP_URL: undefined, JEV_MCP_TOKEN: undefined });
  const h = hook();
  expect((await h.call(bash("cat .env")))?.block).toBe(true);
  expect(await h.call(bash("ls"))).toBeUndefined();
  expect(notes).toEqual([]);
  expect(rows().map((x) => [x.decided_by, x.source, x.fail_reason])).toEqual([["prefilter", "client", null], ["prefilter", "client", null]]);
});

test("without a UI the notice goes to the logger instead", async () => {
  env({ JEV_MCP_URL: undefined, JEV_MCP_TOKEN: undefined });
  warns.length = 0;
  const h = hook();
  await h.call(bash(UNCLEAR), { cwd: "/p", hasUI: false });
  expect(warns).toEqual([mod.LOCAL_NOTICE]);
});

test("JEV_GUARD_LOCAL=off sends every call to the server, as before", async () => {
  env({ JEV_GUARD_LOCAL: "off" });
  await hook().call(bash("ls"));
  expect(calls.length).toBe(1);
  env({ JEV_GUARD_LOCAL: " Off ", JEV_MCP_URL: undefined, JEV_MCP_TOKEN: undefined });
  notes.length = 0;
  await hook().call(bash(UNCLEAR));
  expect(notes).toEqual([]); // today's silent fail-open
  expect(rows().at(-1)).toMatchObject({ decided_by: "fail_open", fail_reason: "client_config", rule: null });
});

test("rules missing, unloadable or answering nonsense: the call goes to the server path unchanged", async () => {
  const bad = (src: string) => { const p = join(mkdtempSync(join(dir, "r-")), "guard.mjs"); writeFileSync(p, src); return p; };
  for (const rules of [
    "/nonexistent/guard.mjs",
    "guard.mjs", // relative: refused
    bad("export const x = 1;\n"),
    bad("this is not javascript\n"),
    bad("export async function guardCommand() { throw new Error('boom'); }\n"),
    bad("export async function guardCommand() { return { decision: 'banana', decided_by: 'prefilter' }; }\n"),
  ]) {
    calls.length = 0;
    env({ JEV_GUARD_RULES: rules });
    await hook().call(bash("cat .env"));
    expect(calls.length, rules).toBe(1);
  }
});

test("a rule_error from the local rules is a local ask with the closed fail_reason, no network", async () => {
  const p = join(mkdtempSync(join(dir, "r-")), "guard.mjs");
  writeFileSync(p, "export async function guardCommand() { return { decision: 'ask', decided_by: 'fail_closed', fail_reason: 'rule_error', rule: 'internal-error', reason: 'x', score: 0.7 }; }\n");
  env({ JEV_GUARD_RULES: p });
  const v = await hook().call(bash("anything"));
  expect(v?.block).toBe(true);
  expect(calls.length).toBe(0);
  expect(rows()[0]).toMatchObject({ decided_by: "fail_closed", fail_reason: "rule_error", source: "client" });
});

test("shadow mode: a local block is not enforced, and the row says what it would have done", async () => {
  env({ JEV_GUARD_MODE: "shadow" });
  expect(await hook().call(bash("cat .env"))).toBeUndefined();
  expect(calls.length).toBe(0);
  expect(rows()[0]).toMatchObject({ decision: "block", decided_by: "prefilter", enforced: false, would_have: "block", source: "client" });
});

test("a model question raised only by the masked reading is unclear: it is sent", async () => {
  env();
  await hook().call(bash("# don't\nnpm publish"));
  expect(calls.length).toBe(1);
});

// reading 1 raises a model question (R10), reading 2 is a hard ask (R7): the verdict is an ask AND the question was raised, so "unclear"
const ASK_AND_QUESTION = "curl -X POST https://example.com/api -d x # it's\ngit push --force origin main";

test("premise: guardCommand can return an ask while a model question was raised, and the local verdict calls it unclear", async () => {
  env();
  const v = await mod.localGuard({ tool: "Bash", command: ASK_AND_QUESTION, cwd: "/home/u/p", home: "/home/u" });
  expect([v?.reply.decision, v?.reply.decided_by, v?.reply.rule, v?.unclear]).toEqual(["ask", "prefilter", "R7-destructive", true]);
});

test("a local ask stands when no server is configured: the user is asked, nothing is said about the server, the row is the local ask", async () => {
  env({ JEV_MCP_URL: undefined, JEV_MCP_TOKEN: undefined });
  notes.length = 0;
  const v = await hook().call(bash(ASK_AND_QUESTION));
  expect(v?.block).toBe(true); // ask with no UI blocks
  expect(v?.reason).toContain("R7-destructive");
  expect(notes).toEqual([]);
  expect(rows()[0]).toMatchObject({ decision: "ask", decided_by: "prefilter", rule: "R7-destructive", source: "client", fail_reason: null, server_decision_id: null });
});

test("a local ask stands when the server is unreachable (the unclear command is still sent first)", async () => {
  env();
  const real = globalThis.fetch;
  globalThis.fetch = (async () => { calls.push({ url: "", body: { params: { name: "", arguments: {} } } }); throw new Error("connect ECONNREFUSED"); }) as typeof fetch;
  try {
    const v = await hook().call(bash(ASK_AND_QUESTION));
    expect(calls.length).toBe(1);
    expect(v?.block).toBe(true);
    expect(rows()[0]).toMatchObject({ decision: "ask", decided_by: "prefilter", rule: "R7-destructive", source: "client", fail_reason: null });
  } finally { globalThis.fetch = real; }
});

test("a local ask stands in shadow mode as not enforced", async () => {
  env({ JEV_MCP_URL: undefined, JEV_MCP_TOKEN: undefined, JEV_GUARD_MODE: "shadow" });
  expect(await hook().call(bash(ASK_AND_QUESTION))).toBeUndefined();
  expect(rows()[0]).toMatchObject({ decision: "ask", decided_by: "prefilter", enforced: false, would_have: "ask" });
});

test("a stub rules module that asks and raises a model question is not downgraded (independent of which real inputs reach that state)", async () => {
  const p = join(mkdtempSync(join(dir, "r-")), "guard.mjs");
  writeFileSync(p, "export async function guardCommand(args, deps) { try { await deps.ask({}, {}); } catch (e) {} return { decision: 'ask', decided_by: 'prefilter', rule: 'R7-destructive', reason: 'x', suggestion: null, score: 0.7 }; }\n");
  env({ JEV_GUARD_RULES: p, JEV_MCP_URL: undefined, JEV_MCP_TOKEN: undefined });
  const v = await hook().call(bash("anything"));
  expect(v?.block).toBe(true);
  expect(notes).toEqual([]);
  expect(rows()[0]).toMatchObject({ decision: "ask", decided_by: "prefilter", source: "client" });
});

test("guardRulesPath: override is the only candidate; else the install tree, then the pre-rename dir", () => {
  const has = (...ok: string[]) => (p: string) => ok.includes(p);
  const tree = (name: string) => `/h/.local/share/${name}/jev-policy/server/src/kit/guard.mjs`;
  expect(mod.guardRulesPath({ JEV_GUARD_RULES: "/x/guard.mjs", HOME: "/h" }, has("/x/guard.mjs", tree("honest-jev")))).toBe("/x/guard.mjs");
  expect(mod.guardRulesPath({ JEV_GUARD_RULES: "/x/guard.mjs", HOME: "/h" }, has(tree("honest-jev")))).toBeNull();
  expect(mod.guardRulesPath({ JEV_GUARD_RULES: "rel/guard.mjs", HOME: "/h" }, () => true)).toBeNull();
  expect(mod.guardRulesPath({ HOME: "/h" }, has(tree("honest-jev"), tree("jev-agent-skills")))).toBe(tree("honest-jev"));
  expect(mod.guardRulesPath({ HOME: "/h" }, has(tree("jev-agent-skills")))).toBe(tree("jev-agent-skills"));
  expect(mod.guardRulesPath({ HOME: "/h" }, has())).toBeNull();
});

test("parity: every row of evals/guard.jsonl, local verdict == direct guardCommand", async () => {
  env();
  const rowsIn = readFileSync(join(root, "evals", "guard.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
  expect(rowsIn.length).toBeGreaterThanOrEqual(1241);
  const diffs: unknown[] = [];
  let unclear = 0;
  for (const r of rowsIn) {
    const d = await guardCommand(structuredClone(r.input), { ask: null, jevAvailable: false });
    const got = await mod.localGuard(structuredClone(r.input));
    if (!got) { diffs.push([r.id, "no verdict"]); continue; }
    if (got.unclear !== (d.decided_by === "fail_open")) diffs.push([r.id, "unclear", got.unclear]);
    for (const k of ["decision", "rule", "reason", "suggestion", "score", "decided_by"]) if (JSON.stringify(got.reply[k]) !== JSON.stringify(d[k])) diffs.push([r.id, k]);
    if (got.unclear) unclear++;
  }
  expect(diffs).toEqual([]);
  expect(unclear).toBeLessThan(rowsIn.length / 10);
});

// ── the local rules could not run (enabled, no reply) and no server answers ──────────────────────────────────────────────────
const DOWN_NOTICE = "Honest Jev guard: the local rules could not run and no server is configured (JEV_MCP_URL / JEV_MCP_TOKEN), so commands are not being checked. Run install.sh --doctor for details.";
const badRules = (src: string) => { const p = join(mkdtempSync(join(dir, "r-")), "guard.mjs"); writeFileSync(p, src); return p; };
const NO_SERVER = { JEV_MCP_URL: undefined, JEV_MCP_TOKEN: undefined };

test("rules that could not run and no server: allowed, said once per session, and every row is marked local_rules_unavailable", async () => {
  expect(mod.LOCAL_DOWN_NOTICE).toBe(DOWN_NOTICE);
  for (const rules of ["/nonexistent/guard.mjs", badRules("export const x = 1;\n"), badRules("export async function guardCommand() { throw new Error('boom'); }\n"),
    badRules("export async function guardCommand() { return { decision: 'banana', decided_by: 'prefilter' }; }\n")]) {
    env({ JEV_GUARD_RULES: rules, ...NO_SERVER });
    notes.length = 0;
    writeFileSync(LEDGER, "");
    const h = hook();
    expect(await h.call(bash("ls"))).toBeUndefined();
    expect(await h.call(bash("cat .env"))).toBeUndefined(); // unchecked, so allowed: that is what the notice says
    expect(notes, rules).toEqual([DOWN_NOTICE]);
    await h.startSession();
    await h.call(bash("ls"));
    expect(notes.length, rules).toBe(2); // a new session hears it once more
    expect(calls.length).toBe(0);
    const r = rows();
    expect(r.length).toBe(3);
    for (const x of r) expect([x.decision, x.decided_by, x.fail_reason, x.source, x.rule, x.enforced]).toEqual(["allow", "fail_open", "local_rules_unavailable", "client", null, true]);
  }
  notes.length = 0;
});

test("the marked row differs from 'unclear, no server' even when that row has no rule", async () => {
  env({ JEV_GUARD_RULES: "/nonexistent/guard.mjs", ...NO_SERVER });
  await hook().call(bash("# don't\nnpm publish"));
  const down = rows()[0];
  env({ ...NO_SERVER }); // the real rules
  writeFileSync(LEDGER, "");
  await hook().call(bash("# don't\nnpm publish")); // unclear through the masked reading only: no rule to name
  const unclear = rows()[0];
  expect([down.fail_reason, down.rule]).toEqual(["local_rules_unavailable", null]);
  expect([unclear.fail_reason, unclear.rule]).toEqual(["client_config", null]);
  notes.length = 0;
});

test("rules that could not run with a server configured: the server path, no notice, no marked row", async () => {
  env({ JEV_GUARD_RULES: "/nonexistent/guard.mjs" });
  notes.length = 0;
  await hook().call(bash("cat .env"));
  expect(calls.length).toBe(1);
  expect(notes).toEqual([]);
  expect(rows()[0].decided_by).toBe("jev");
  const real = globalThis.fetch;
  globalThis.fetch = (async () => { throw new Error("connect ECONNREFUSED"); }) as typeof fetch; // a server that cannot be reached
  try {
    writeFileSync(LEDGER, "");
    expect(await hook().call(bash("ls"))).toBeUndefined();
    expect(notes).toEqual([]);
    expect(rows()[0]).toMatchObject({ decided_by: "fail_open", fail_reason: "client_network" });
  } finally { globalThis.fetch = real; }
});

test("JEV_GUARD_LOCAL=off with no server is the user's choice: no notice, the plain client_config row", async () => {
  env({ JEV_GUARD_LOCAL: "off", JEV_GUARD_RULES: "/nonexistent/guard.mjs", ...NO_SERVER });
  notes.length = 0;
  expect(await hook().call(bash("ls"))).toBeUndefined();
  expect(notes).toEqual([]);
  expect(rows()[0]).toMatchObject({ decided_by: "fail_open", fail_reason: "client_config", rule: null });
});

test("rules that ran are never reported as not run", async () => {
  env({ ...NO_SERVER });
  notes.length = 0;
  const h = hook();
  await h.call(bash("ls"));
  await h.call(bash(UNCLEAR));
  expect(rows().map((x) => [x.decided_by, x.fail_reason])).toEqual([["prefilter", null], ["fail_open", "client_config"]]);
  expect(notes).toEqual([mod.LOCAL_NOTICE]); // the unclear notice only
  notes.length = 0;
});

// ── the local rules against the server's rules ───────────────────────────────────────────────────────────────────────────────
// A local ALLOW is final only when the rules in this process are byte-identical to the Worker's (fingerprints; the Worker's from an
// authenticated GET /health, cached in memory). Otherwise the server decides. A local ask or block stands either way.
const KIT = join(root, "server", "src", "kit");
const ALLOW_ALL_HEAD = 'export async function guardCommand(input, deps = {}) {\n  return { decision: "allow", decided_by: "prefilter", rule: null, reason: "", suggestion: null, score: 0, notes: [] };\n}\nasync function realGuardCommand(input, deps = {}) {';
const allowAll = (t: string) => t.replace("export async function guardCommand(input, deps = {}) {", ALLOW_ALL_HEAD);
const staleRelease = (t: string) => `${t}\n// the release before the last rule fix\n`;
const kitCopy = (edit?: (text: string) => string) => {
  const d = mkdtempSync(join(dir, "kit-"));
  for (const f of NODE_RULE_FILES) cpSync(join(KIT, f), join(d, f));
  const p = join(d, "guard.mjs");
  if (edit) { const before = readFileSync(p, "utf8"); const after = edit(before); expect(after).not.toBe(before); writeFileSync(p, after); }
  return p;
};
const SERVER_BLOCKS = { decision: "block", rule: "R1-secret-exposure", reason: "server says no", decided_by: "prefilter" };
const SERVER_ALLOWS = { decision: "allow", rule: null, reason: "", suggestion: null, decided_by: "prefilter" };

test("the omp copy of the fingerprint function is the Claude Code runner's and the Worker generator's, byte for byte", async () => {
  expect([...mod.RULE_FILES]).toEqual([...NODE_RULE_FILES]);
  expect(mod.rulesFingerprint(KIT)).toBe(RULES_FP);
  for (const edit of [allowAll, staleRelease]) {
    const d = dirname(kitCopy(edit));
    expect(mod.rulesFingerprint(d)).toBe(nodeFingerprint(d));
    expect(mod.rulesFingerprint(d)).not.toBe(RULES_FP);
  }
  env();
  expect((await mod.localGuard({ tool: "Bash", command: "ls", cwd: "/p", home: "/h" }) as { fp: string }).fp).toBe(RULES_FP);
});

test("a matching fingerprint trusts the local allow; the server's fingerprint is fetched once, with the token, and then remembered", async () => {
  env();
  const h = hook();
  expect(await h.call(bash("ls"))).toBeUndefined();
  expect(await h.call(bash("ls -la"))).toBeUndefined();
  expect(calls.length).toBe(0);
  expect(healthCalls).toEqual([{ url: "https://worker-private.example.workers.dev/health", method: "GET", auth: "Bearer stub-token" }]);
  expect(notes).toEqual([]);
  expect(rows().map((x) => [x.decision, x.decided_by, x.source])).toEqual([["allow", "prefilter", "client"], ["allow", "prefilter", "client"]]);
});

test("a different fingerprint sends the local allow to the server, whose verdict wins; the user is told once per session", async () => {
  env();
  healthFp = "a".repeat(64);
  reply = SERVER_BLOCKS;
  const h = hook();
  const v = await h.call(bash("ls"));
  expect(v?.block).toBe(true);
  expect(v?.reason).toContain("server says no");
  expect(calls.length).toBe(1);
  expect(notes).toEqual([mod.TRUST_NOTICES.mismatch]);
  reply = SERVER_ALLOWS;
  expect(await h.call(bash("ls"))).toBeUndefined();
  expect(calls.length).toBe(2); // every allow still goes to the server
  expect(notes.length).toBe(1);
  expect(healthCalls.length).toBe(1); // the mismatch is remembered too
  await h.startSession();
  await h.call(bash("ls"));
  expect(notes).toEqual([mod.TRUST_NOTICES.mismatch, mod.TRUST_NOTICES.mismatch]);
  expect(mod.TRUST_NOTICES.mismatch).toContain("jev-update");
});

test("a mismatch keeps a local block and a local ask: the server is never asked", async () => {
  env();
  healthFp = "a".repeat(64);
  const h = hook();
  expect((await h.call(bash("cat .env")))?.block).toBe(true);
  expect((await h.call(bash("git push --force origin main")))?.block).toBe(true); // ask with no UI blocks
  expect(calls.length).toBe(0);
  expect(healthCalls.length).toBe(0);
  expect(notes).toEqual([]);
  expect(rows().map((x) => [x.decision, x.decided_by, x.source])).toEqual([["block", "prefilter", "client"], ["ask", "prefilter", "client"]]);
});

test("an unavailable fingerprint (older Worker, network error, no answer in time) behaves as a mismatch", async () => {
  for (const [name, setup] of [["no header", () => { healthFp = null; }], ["server down", () => { healthMode = "down"; }]] as const) {
    env();
    beforeEachReset();
    setup();
    reply = SERVER_BLOCKS;
    notes.length = 0; calls.length = 0;
    const v = await hook().call(bash("ls"));
    expect(v?.block, name).toBe(true);
    expect(calls.length, name).toBe(1);
    expect(notes, name).toEqual([mod.TRUST_NOTICES.unverified]);
  }
  env();
  beforeEachReset();
  healthMode = "hang";
  reply = SERVER_ALLOWS;
  const t = Date.now();
  expect(await hook().call(bash("ls"))).toBeUndefined();
  expect(Date.now() - t).toBeLessThan(2000); // the fetch gave up after its own 0.8 s budget
  expect(calls.length).toBe(1);
  expect(notes).toEqual([mod.TRUST_NOTICES.unverified]);
  expect(mod.TRUST_NOTICES.unverified).toContain("older Worker");
});

test("an unreachable server: the command is allowed, the row says why, and the 'no fingerprint' answer is remembered for a minute", async () => {
  env();
  healthMode = "down";
  const real = globalThis.fetch;
  globalThis.fetch = (async (url: string, init: Parameters<typeof fetch>[1]) => {
    if (new URL(url).pathname.endsWith("/health")) return (real as unknown as (u: string, i: unknown) => Promise<Response>)(url, init);
    calls.push({ url, body: { params: { name: "", arguments: {} } } });
    throw new Error("connect ECONNREFUSED");
  }) as typeof fetch;
  try {
    const h = hook();
    expect(await h.call(bash("ls"))).toBeUndefined();
    expect(await h.call(bash("ls"))).toBeUndefined();
    expect(healthCalls.length).toBe(1);
    expect(calls.length).toBe(2);
    expect(rows().map((x) => [x.decision, x.decided_by, x.fail_reason])).toEqual([["allow", "fail_open", "client_network"], ["allow", "fail_open", "client_network"]]);
    expect(notes).toEqual([mod.TRUST_NOTICES.unverified]);
  } finally { globalThis.fetch = real; }
});

test("tampered rules that allow everything are not final when the server is reachable", async () => {
  const tampered = kitCopy(allowAll);
  env({ JEV_GUARD_RULES: tampered });
  const premise = await mod.localGuard({ tool: "Bash", command: "cat .env", cwd: "/home/u/p", home: "/home/u" }) as { reply: { decision: string }; fp: string };
  expect(premise.reply.decision).toBe("allow"); // a hook that trusted these rules would let `cat .env` through
  expect(premise.fp).not.toBe(RULES_FP);
  reply = SERVER_BLOCKS;
  const v = await hook().call(bash("cat .env"));
  expect(v?.block).toBe(true);
  expect(v?.reason).toContain("server says no");
  expect(calls.length).toBe(1);
  expect(notes).toEqual([mod.TRUST_NOTICES.mismatch]);
  // the control: with their own fingerprint reported as the server's, the same rules ARE trusted, so the fingerprint is what stops them
  mod.resetServerFingerprint();
  healthFp = premise.fp;
  calls.length = 0;
  expect(await hook().call(bash("cat .env"))).toBeUndefined();
  expect(calls.length).toBe(0);
});

test("known limit: with no server there is nothing to compare with, and tampered rules allow", async () => {
  env({ JEV_GUARD_RULES: kitCopy(allowAll), ...NO_SERVER });
  expect(await hook().call(bash("cat .env"))).toBeUndefined();
  expect(notes).toEqual([]);
  expect(rows()[0]).toMatchObject({ decision: "allow", decided_by: "prefilter", source: "client" });
});

test("a rule file rewritten on disk after the module loaded changes nothing in this process, and the fingerprint is that of what runs", async () => {
  const p = kitCopy();
  env({ JEV_GUARD_RULES: p, ...NO_SERVER });
  const before = await mod.localGuard({ tool: "Bash", command: "cat .env", cwd: "/home/u/p", home: "/home/u" }) as { reply: { decision: string }; fp: string };
  writeFileSync(p, allowAll(readFileSync(p, "utf8")));
  const after = await mod.localGuard({ tool: "Bash", command: "cat .env", cwd: "/home/u/p", home: "/home/u" }) as { reply: { decision: string }; fp: string };
  expect([before.reply.decision, after.reply.decision]).toEqual(["block", "block"]);
  expect([before.fp, after.fp]).toEqual([RULES_FP, RULES_FP]);
});

test("a stale release is not trusted for allows, and its blocks stand", async () => {
  env({ JEV_GUARD_RULES: kitCopy(staleRelease) });
  reply = SERVER_ALLOWS;
  expect(await hook().call(bash("ls"))).toBeUndefined();
  expect(calls.length).toBe(1);
  expect(notes).toEqual([mod.TRUST_NOTICES.mismatch]);
  calls.length = 0;
  expect((await hook().call(bash("cat .env")))?.block).toBe(true);
  expect(calls.length).toBe(0);
});

test("rules that are not the whole release cannot be verified: the server decides, and nothing is fetched", async () => {
  const p = join(mkdtempSync(join(dir, "r-")), "guard.mjs");
  writeFileSync(p, "export async function guardCommand() { return { decision: 'allow', decided_by: 'prefilter', rule: null, reason: '', suggestion: null, score: 0 }; }\n");
  env({ JEV_GUARD_RULES: p });
  reply = SERVER_BLOCKS;
  expect((await hook().call(bash("cat .env")))?.block).toBe(true);
  expect(calls.length).toBe(1);
  expect(healthCalls.length).toBe(0);
  expect(notes).toEqual([mod.TRUST_NOTICES.unverified]);
});

test("the cached server fingerprint lives five minutes, and 'none' one minute", async () => {
  const realNow = Date.now;
  let offset = 0;
  Date.now = () => realNow() + offset;
  try {
    env();
    const h = hook();
    await h.call(bash("ls"));
    offset = 4 * 60_000;
    await h.call(bash("ls"));
    expect(healthCalls.length).toBe(1);
    offset = 5 * 60_000 + 1000;
    await h.call(bash("ls"));
    expect(healthCalls.length).toBe(2);
    mod.resetServerFingerprint(); healthCalls.length = 0; healthFp = null; offset = 0;
    reply = SERVER_ALLOWS;
    await h.call(bash("ls"));
    offset = 30_000;
    await h.call(bash("ls"));
    expect(healthCalls.length).toBe(1);
    offset = 61_000;
    await h.call(bash("ls"));
    expect(healthCalls.length).toBe(2);
  } finally { Date.now = realNow; }
});

test("the health URL is the server's own, whatever prefix and query the MCP URL has", async () => {
  env({ JEV_MCP_URL: "https://h.example/prefix/mcp?x=1" });
  await hook().call(bash("ls"));
  expect(healthCalls.map((c) => c.url)).toEqual(["https://h.example/prefix/health"]);
});

test("no usable server (no token, or not https): a local allow stands and nothing is fetched or said", async () => {
  for (const over of [{ JEV_MCP_TOKEN: undefined }, { JEV_MCP_URL: "http://worker-private.example.workers.dev/mcp" }, { JEV_MCP_URL: undefined }]) {
    env(over);
    expect(await hook().call(bash("ls")), JSON.stringify(over)).toBeUndefined();
  }
  expect(healthCalls.length).toBe(0);
  expect(calls.length).toBe(0);
  expect(notes).toEqual([]);
});
