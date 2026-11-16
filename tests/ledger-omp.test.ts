// omp guard hook ledger behaviour (openspec add-decision-ledger). Data only; run with bun:
//   bun test tests/ledger-omp.test.ts
// The hook's omp import is replaced by a stub module and `fetch` is faked: no network, no omp, no command executed.
import { afterAll, beforeAll, expect, mock, test } from "bun:test";
import { mkdtempSync, readFileSync, existsSync, statSync, writeFileSync, symlinkSync, mkdirSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

mock.module("@oh-my-pi/pi-coding-agent", () => ({ isToolCallEventType: (name: string, e: { toolName?: string }) => e.toolName === name }));

const dir = mkdtempSync(join(tmpdir(), "jev-omp-"));
const LEDGER = join(dir, "state", "ledger.jsonl");
const MARK = "ZXQ-HOSTILE-MARKER";
process.env.JEV_MCP_URL = "https://worker-private.example.workers.dev/mcp";
process.env.JEV_MCP_TOKEN = "stub-token";
process.env.JEV_GUARD_LOCAL = "off"; // these tests are about the server path; the local rules are covered by tests/local-first-omp.test.ts
process.env.JEV_LEDGER = LEDGER;
process.env.JEV_GUARD_ASK_NO_UI = "block";

const realFetch = globalThis.fetch;
let reply: () => Promise<Response> = async () => new Response("{}");
globalThis.fetch = (async () => reply()) as typeof fetch;
afterAll(() => { globalThis.fetch = realFetch; });

// Dynamic import on purpose: the hook reads JEV_* env at module load, so the env and the module mock above must be set first.
const mod = await import("../hooks/omp/jev-guard.ts");
const rpc = (payload: unknown) => async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: JSON.stringify(payload) }] } }));

// The hook queues ledger writes with setImmediate, after the verdict. Wait for them so a test reads what was written.
function handler() {
  let h: (e: unknown, c: unknown) => Promise<unknown>;
  mod.default({ on: (_: string, f: typeof h) => { h = f; }, logger: { warn() {} } } as never);
  return async (e: unknown, c: unknown) => {
    const v = await h!(e, c);
    const { promise, resolve } = Promise.withResolvers<void>();
    setImmediate(resolve);
    await promise;
    return v;
  };
}
const rows = () => (existsSync(LEDGER) ? readFileSync(LEDGER, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const reset = () => { try { writeFileSync(LEDGER, ""); } catch { /* dir absent yet */ } };
const bash = (command: string) => ({ toolName: "bash", input: { command } });
const rec = (o: Record<string, unknown> = {}) => ({ v: 1, decision_id: "00000000-0000-4000-8000-000000000001", ts: "2026-11-12T10:00:00Z", tool: "kit_guard_command", decision: "block", decided_by: "prefilter", rule: "R1-secret-exposure", jev: { calls: 0, status: "not_needed" }, ...o });

beforeAll(() => reset());

test("a block with a server record: one row, host omp, enforced, no command text, mode 0600", async () => {
  reset();
  reply = rpc({ decision: "block", rule: "R1-secret-exposure", reason: "r", decided_by: "prefilter", record: rec() });
  const v = (await handler()(bash(`cat .env # ${MARK}`), { cwd: "/tmp" })) as { block?: boolean };
  expect(v?.block).toBe(true);
  const r = rows();
  expect(r.length).toBe(1);
  expect([r[0].source, r[0].decision, r[0].decided_by, r[0].rule, r[0].host, r[0].enforced, r[0].would_have]).toEqual(["server", "block", "prefilter", "R1-secret-exposure", "omp", true, null]);
  expect(readFileSync(LEDGER, "utf8")).not.toContain(".env");
  expect(readFileSync(LEDGER, "utf8")).not.toContain(MARK);
  expect(statSync(LEDGER).mode & 0o777).toBe(0o600);
});

test("enforce mode: an ask with no UI blocks and the row is enforced", async () => {
  reset();
  reply = rpc({ decision: "ask", rule: "R10-general-risk", reason: "r", decided_by: "jev", record: rec({ decision: "ask", decided_by: "jev", rule: "R10-general-risk" }) });
  const v = (await handler()(bash("npm publish"), { cwd: "/tmp", hasUI: false })) as { block?: boolean };
  expect(v?.block).toBe(true);
  expect(rows()[0].enforced).toBe(true);
});

test("outage codes are closed and carry no error text or hostname", async () => {
  const cases: [() => Promise<Response>, string][] = [
    [async () => new Response("down", { status: 503 }), "client_http_5xx"],
    [async () => { throw Object.assign(new Error("connect ECONNREFUSED worker-private.example.workers.dev"), { name: "Error" }); }, "client_network"],
    [async () => { throw Object.assign(new Error("The operation timed out worker-private.example.workers.dev"), { name: "TimeoutError" }); }, "client_timeout"],
    [async () => new Response("<html>not json-rpc</html>"), "client_parse"],
  ];
  for (const [fn, code] of cases) {
    reset();
    reply = fn;
    const v = await handler()(bash("ls"), { cwd: "/tmp" });
    expect(v).toBeUndefined();
    const r = rows();
    expect([r[0].decided_by, r[0].fail_reason, r[0].decision]).toEqual(["fail_open", code, "allow"]);
    expect(readFileSync(LEDGER, "utf8")).not.toContain("worker-private");
  }
});

test("a 4xx is ask/fail_closed/client_rejected", async () => {
  reset();
  reply = async () => new Response("no", { status: 401 });
  const v = (await handler()(bash("ls"), { cwd: "/tmp", hasUI: false })) as { block?: boolean };
  expect(v?.block).toBe(true);
  expect([rows()[0].decision, rows()[0].decided_by, rows()[0].fail_reason]).toEqual(["ask", "fail_closed", "client_rejected"]);
});

test("oversized command asks, stores no text", async () => {
  reset();
  reply = rpc({});
  const v = (await handler()(bash(`echo ${MARK}${"x".repeat(25000)}`), { cwd: "/tmp", hasUI: false })) as { block?: boolean };
  expect(v?.block).toBe(true);
  expect([rows()[0].decision, rows()[0].decided_by, rows()[0].fail_reason]).toEqual(["ask", "fail_closed", "oversize"]);
  expect(readFileSync(LEDGER, "utf8")).not.toContain(MARK);
});

test("a hostile record cannot smuggle text: whitelist rebuild", async () => {
  reset();
  const evil = `${MARK} https://worker-private.example.workers.dev sk-A1b2C3d4E5f6G7h8I9j0`;
  reply = rpc({ decision: "block", rule: "R1-secret-exposure", reason: "r", record: rec({ decision: evil, rule: evil, decided_by: evil, fail_reason: evil, host: evil, correlation_id: evil, jev: { calls: 1, status: evil, model: evil, input_tokens: evil, cost: evil, cost_source: evil } }) });
  await handler()(bash("cat .env"), { cwd: "/tmp" });
  const text = readFileSync(LEDGER, "utf8");
  for (const bad of [MARK, "worker-private", "sk-A1b2"]) expect(text).not.toContain(bad);
  const r = rows()[0];
  expect([r.decision, r.rule, r.host, r.correlation_id, r.jev.model]).toEqual(["block", null, "omp", null, null]);
});

test("a hostile top-level reply (no record) is scrubbed too: synthesised rows are whitelisted", async () => {
  reset();
  const evil = `${MARK} worker-private.example.workers.dev`;
  reply = rpc({ decision: evil, rule: evil, decided_by: evil, jev: { used: true, status: evil, model: evil, detail: evil, usage: { input_tokens: evil, cost: evil } } });
  expect(await handler()(bash("ls"), { cwd: "/tmp" })).toBeUndefined();
  const text = readFileSync(LEDGER, "utf8");
  for (const bad of [MARK, "worker-private"]) expect(text).not.toContain(bad);
  const r = rows()[0];
  expect([r.decision, r.rule, r.jev.model]).toEqual([null, null, null]);
});

test("closed lists and the row key set match the Python and Node implementations", () => {
  expect([...mod.FAIL_REASONS]).toEqual(["no_upstream", "upstream_error", "timeout", "invalid_response", "oversize", "client_config", "client_input", "client_timeout", "client_network", "client_http_5xx", "client_parse", "client_rejected", "rule_error", "local_rules_unavailable"]);
  expect([...mod.DECIDED_BY]).toEqual(["prefilter", "jev", "fail_open", "fail_closed", "policy"]);
  expect(Object.keys(mod.buildRow(null, { host: "omp" }))).toEqual(["v", "decision_id", "server_decision_id", "ts", "tool", "decision", "verdict", "decided_by", "rule", "fail_reason", "latency_ms", "jev", "tiers", "host", "correlation_id", "policy_version", "source", "enforced", "would_have"]);
});

test("ledger path table, dropped oversized rows, one whole line per append, unwritable parent returns false", async () => {
  expect(mod.appendRow({ x: "y".repeat(5000) }, join(dir, "big.jsonl"))).toBe(false);
  expect(existsSync(join(dir, "big.jsonl"))).toBe(false);
  // the same table tests/test_ledger_hook.py pins the Python, jev-report and jev-outcome implementations to
  const table: [Record<string, string>, string | null][] = [
    [{}, "/h/.local/state/jev/ledger.jsonl"],
    [{ XDG_STATE_HOME: "/abs/state" }, "/abs/state/jev/ledger.jsonl"],
    [{ XDG_STATE_HOME: "relative/state" }, "/h/.local/state/jev/ledger.jsonl"],
    [{ JEV_LEDGER: "/x/l.jsonl", XDG_STATE_HOME: "/abs/state" }, "/x/l.jsonl"],
    [{ JEV_LEDGER: "off" }, null],
    [{ JEV_LEDGER: " OFF " }, null],
    [{ JEV_LEDGER: "rel/l.jsonl" }, null], // relative: refused, never resolved against the working directory
  ];
  for (const [env, want] of table) expect(mod.ledgerPath({ HOME: "/h", ...env })).toBe(want);
  const p = join(dir, "atomic.jsonl");
  const lines = await Promise.all(Array.from({ length: 200 }, (_, i) => Promise.resolve(mod.appendRow({ i, pad: "z".repeat(300) }, p))));
  expect(lines.every(Boolean)).toBe(true);
  const parsed = readFileSync(p, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  expect(new Set(parsed.map((r: { i: number }) => r.i)).size).toBe(200);
  writeFileSync(join(dir, "blocker"), "");
  expect(mod.appendRow({ a: 1 }, join(dir, "blocker", "x", "l.jsonl"))).toBe(false);
});

// ── review follow-ups: ids, ask outcomes, hardening, rotation ─────────────────────────────────────────────────────
const lastRow = () => rows().at(-1);
const outcomes = () => rows().filter((r: { label?: string }) => typeof r.label === "string");
const decisions = () => rows().filter((r: { tool?: string }) => typeof r.tool === "string");

test("the hook mints every decision_id; the Worker's id is kept as server_decision_id; client-only rows have an id too", async () => {
  reset();
  reply = rpc({ decision: "block", rule: "R1-secret-exposure", reason: "r", record: rec() });
  await handler()(bash("cat .env"), { cwd: "/tmp" });
  const a = lastRow();
  expect(a.decision_id).toMatch(/^[0-9a-f-]{36}$/);
  expect(a.server_decision_id).toBe("00000000-0000-4000-8000-000000000001");
  expect(a.decision_id).not.toBe(a.server_decision_id);
  reply = async () => new Response("down", { status: 503 });
  await handler()(bash("ls"), { cwd: "/tmp" });
  expect(lastRow().decision_id).toMatch(/^[0-9a-f-]{36}$/);
  expect(lastRow().server_decision_id).toBeNull();
});

test("omp writes host-observed ask outcomes: approved, denied, and no_ui (excluded from the approved rate by the report)", async () => {
  const ask = () => rpc({ decision: "ask", rule: "R10-general-risk", reason: "r", decided_by: "jev", record: rec({ decision: "ask", decided_by: "jev", rule: "R10-general-risk" }) });
  for (const [ctx, label, blocked] of [
    [{ cwd: "/tmp", hasUI: true, ui: { confirm: async () => true } }, "approved", false],
    [{ cwd: "/tmp", hasUI: true, ui: { confirm: async () => false } }, "denied", true],
    [{ cwd: "/tmp", hasUI: false }, "no_ui", true],
  ] as const) {
    reset(); reply = ask();
    const v = (await handler()(bash("npm publish"), ctx)) as { block?: boolean } | undefined;
    expect(!!v?.block).toBe(blocked);
    const o = outcomes();
    expect(o.length).toBe(1);
    expect(Object.keys(o[0])).toEqual(["v", "decision_id", "label", "ts", "subagent_tokens", "source"]);
    expect([o[0].label, o[0].source, o[0].subagent_tokens, o[0].decision_id]).toEqual([label, "host_observed", null, decisions()[0].decision_id]);
  }
});

test("a block writes no outcome; an unwritable ledger changes neither the verdict nor whether the handler throws (omp fails closed on a throw)", async () => {
  reset();
  reply = rpc({ decision: "block", rule: "R1-secret-exposure", reason: "r", record: rec() });
  await handler()(bash("cat .env"), { cwd: "/tmp" });
  expect(outcomes().length).toBe(0);
  writeFileSync(join(dir, "blocker2"), "");
  const saved = process.env.JEV_LEDGER;
  process.env.JEV_LEDGER = join(dir, "blocker2", "x", "ledger.jsonl"); // parent is a file: every ledger write fails
  try {
    reply = rpc({ decision: "ask", rule: "R10-general-risk", reason: "r", record: rec({ decision: "ask" }) });
    expect(await handler()(bash("npm publish"), { cwd: "/tmp", hasUI: true, ui: { confirm: async () => true } })).toBeUndefined();
    expect(((await handler()(bash("npm publish"), { cwd: "/tmp", hasUI: true, ui: { confirm: async () => false } })) as { block?: boolean }).block).toBe(true);
    reply = rpc({ decision: "block", rule: "R1-secret-exposure", reason: "r", record: rec() });
    expect(((await handler()(bash("cat .env"), { cwd: "/tmp" })) as { block?: boolean }).block).toBe(true);
  } finally { process.env.JEV_LEDGER = saved; }
});

test("a relative JEV_LEDGER is refused: the verdict is unchanged and no ledger directory appears under the working directory", async () => {
  reset();
  reply = rpc({ decision: "block", rule: "R1-secret-exposure", reason: "r", record: rec() });
  const saved = process.env.JEV_LEDGER;
  process.env.JEV_LEDGER = "relative-ledger-dir/ledger.jsonl";
  try {
    expect(await handler()(bash("cat .env"), { cwd: "/tmp" })).toMatchObject({ block: true });
    await new Promise((r) => setImmediate(r));
    expect(existsSync(join(process.cwd(), "relative-ledger-dir"))).toBe(false);
  } finally { process.env.JEV_LEDGER = saved; }
});

test("hardening: a symlinked ledger or directory and a FIFO are never written through; a symlink target is untouched", () => {
  const target = join(dir, "victim.txt");
  writeFileSync(target, "keep\n");
  mkdirSync(join(dir, "sym1"), { mode: 0o700 });
  symlinkSync(target, join(dir, "sym1", "ledger.jsonl"));
  expect(mod.appendLine({ x: 1 }, join(dir, "sym1", "ledger.jsonl"))).toBe(false);
  expect(readFileSync(target, "utf8")).toBe("keep\n");
  mkdirSync(join(dir, "real"), { mode: 0o700 });
  symlinkSync(join(dir, "real"), join(dir, "symdir"));
  expect(mod.appendLine({ x: 1 }, join(dir, "symdir", "ledger.jsonl"))).toBe(false);
  expect(readdirSync(join(dir, "real"))).toEqual([]);
  mkdirSync(join(dir, "fifo"), { mode: 0o700 });
  spawnSync("mkfifo", [join(dir, "fifo", "ledger.jsonl")]);
  expect(mod.appendLine({ x: 1 }, join(dir, "fifo", "ledger.jsonl"))).toBe(false); // refused, and it returned instead of hanging
});

test("rotation renames to a unique generation, never overwrites, and keeps the newest three", () => {
  const p = join(dir, "rot", "ledger.jsonl");
  mkdirSync(join(dir, "rot"), { mode: 0o700 });
  for (let gen = 0; gen < 6; gen++) {
    writeFileSync(p, `${JSON.stringify({ gen })}\n`.repeat(10), { flag: "a", mode: 0o600 });
    expect(mod.appendLine({ new: gen }, p, { maxBytes: 50, keep: 3 })).toBe(true);
  }
  const rotated = mod.rotatedFiles(p);
  expect(rotated.length).toBe(3);
  const gens = rotated.map((f: string) => new Set(readFileSync(f, "utf8").split("\n").filter((l) => l.includes('"gen"')).map((l) => JSON.parse(l).gen)).values().next().value);
  expect(gens).toEqual([3, 4, 5]);
  expect(JSON.parse(readFileSync(p, "utf8").trim().split("\n").at(-1))).toEqual({ new: 5 });
});

test("rows are bounded: over 2 KB is dropped whole, never truncated", () => {
  const p = join(dir, "size.jsonl");
  expect(mod.appendLine({ pad: "x".repeat(2100) }, p)).toBe(false);
  expect(existsSync(p)).toBe(false);
  expect(mod.appendLine({ pad: "x".repeat(1900) }, p)).toBe(true);
});

test("canary: caller-controlled text in the tool input, the reply and the record never reaches a row", async () => {
  reset();
  const c = (k: string) => `ZXQ canary ${k}!`;
  reply = rpc({ decision: c("decision"), rule: c("rule"), reason: c("reason"), suggestion: c("suggestion"), decided_by: c("by"), notes: [c("notes")],
    jev: { used: true, status: c("status"), model: c("model"), detail: c("detail"), usage: { input_tokens: c("tok"), cost: c("cost") } },
    record: rec({ decision: c("rec.decision"), rule: c("rec.rule"), host: c("rec.host"), correlation_id: c("rec.corr"), decided_by: c("rec.by"), fail_reason: c("rec.fail"), verdict: c("verdict"), tool: c("tool"), ts: c("ts"), decision_id: c("id") }) });
  await handler()(bash(c("command")), { cwd: c("cwd") });
  const text = readFileSync(LEDGER, "utf8");
  expect(/zxq/i.test(text)).toBe(false);
});
