// kit_decide through a fake MCP server with a stubbed upstream. No network, no real credentials; spec and state text are
// only ever data.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { registerDecideTool, runDecide, failCodeFor, prepareState, clampBudget, DEFAULT_BUDGET_MS, MAX_BUDGET_MS } from "../src/decide/tool.mjs";
import { specHash, validateFacts, validateSpec } from "../src/decide/validate.mjs";
import { MAX_RECORD_BYTES, RECORD_KEYS, assembleRecord, deriveRecord, withRecord } from "../src/ledger/record.mjs";

const EX = new URL("../../examples/decisions/", import.meta.url);
const example = (n) => JSON.parse(readFileSync(new URL(`${n}.json`, EX), "utf8"));
const cases = (n) => JSON.parse(readFileSync(new URL(`${n}.cases.json`, EX), "utf8"));
const ENV = { AI_GATEWAY_API_KEY: "stub" };

function setup({ env = ENV, handler, ...opts } = {}) {
  const tools = {}, calls = [], logs = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) });
    return handler ? handler(init) : { ok: true, status: 200, json: async () => ({ answers: {} }), text: async () => "" };
  };
  registerDecideTool({ registerTool: (name, cfg, h) => { tools[name] = { cfg, h }; } }, () => env, { fetchImpl, log: (l) => logs.push(l), ...opts });
  const call = async (args) => {
    const parsed = tools.kit_decide.cfg.inputSchema.parse(args);
    const res = await tools.kit_decide.h(parsed);
    return { res, payload: JSON.parse(res.content[0].text) };
  };
  return { tools, calls, logs, call };
}
const reply = (answers, extra = {}) => async () => ({ ok: true, status: 200, json: async () => ({ answers, usage: { input_tokens: 120, output_tokens: 9, cost: 0.0004 }, model: "typesafe-ai/jev", ...extra }), text: async () => "" });
const noul = (v) => ({ type: "noul", noul: v });
const SPEC = () => example("ask-before-migration");

test("registers one strict kit_decide tool", () => {
  const { tools } = setup();
  assert.deepEqual(Object.keys(tools), ["kit_decide"]);
  const schema = tools.kit_decide.cfg.inputSchema;
  assert.throws(() => schema.parse({ spec: SPEC(), extra: 1 }));
  assert.throws(() => schema.parse({ spec: "text" }));
  assert.throws(() => schema.parse({ spec: SPEC(), budget_ms: 20001 }));
  assert.throws(() => schema.parse({ spec: SPEC(), budget_ms: 99 }));
  // spec is optional at the schema level (a class can stand in for it); the handler rejects a call with neither
  assert.doesNotThrow(() => schema.parse({ spec: SPEC() }));
});

test("fact-only decision: zero upstream calls, even with no credentials", async () => {
  for (const env of [ENV, {}]) {
    const { calls, call } = setup({ env });
    const { payload, res } = await call({ spec: SPEC(), facts: { environment: "production", has_backup: false }, state: { migration: { sql: "DROP TABLE t" } } });
    assert.equal(res.isError, undefined);
    assert.deepEqual([payload.decision, payload.rule_id, payload.decided_by, payload.jev.used], ["block", "R1-prod-no-backup", "prefilter", false]);
    assert.equal(calls.length, 0);
    assert.equal(payload.record.jev.calls, 0);
    assert.equal(payload.record.decided_by, "prefilter");
    assert.equal(payload.record.rule, "R1-prod-no-backup");
    assert.equal(payload.record.fail_reason, null);
  }
});

test("model path: exactly one upstream call carrying the spec's questions and the redacted state, never the facts", async () => {
  const token = "ghp_" + "a1B2".repeat(9);
  const { calls, call, logs } = setup({ handler: reply({ destructive: noul(0.01), additive_only: noul(0.99) }) });
  const { payload } = await call({ spec: SPEC(), facts: { environment: "staging", has_backup: true }, state: { migration: { sql: `ADD COLUMN x -- key ${token}`, tags: ["a", token] }, ok: true, n: 3, none: null } });
  assert.deepEqual([payload.decision, payload.rule_id, payload.decided_by, payload.jev.used, payload.jev.status], ["proceed", "R3-additive", "jev", true, "ok"]);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].body.questions, SPEC().questions);
  const sent = JSON.stringify(calls[0].body.state);
  assert.ok(!sent.includes(token) && sent.includes("<redacted>"), "state strings are redacted before they leave");
  assert.deepEqual(Object.keys(calls[0].body.state).sort(), ["migration", "n", "none", "ok"]);
  assert.ok(!JSON.stringify(calls[0].body).includes("production") && !JSON.stringify(calls[0].body).includes("has_backup"), "facts are not sent");
  assert.deepEqual(payload.answers.destructive, { noul: 0.01 });
  assert.deepEqual(payload.record.jev, { calls: 1, status: "ok", model: "typesafe-ai/jev", input_tokens: 120, output_tokens: 9, cost: 0.0004, cost_source: "upstream" });
  assert.equal(payload.spec.hash, await specHash(validateSpec(SPEC()).spec));
  assert.equal(payload.spec.id, "ask-before-migration");
  assert.equal(logs.length, 1);
});

test("the documented cases hold through the tool with a stubbed upstream", async () => {
  for (const name of ["route-read-or-full", "ask-before-migration", "support-reply-auto-send"]) {
    for (const c of cases(name)) {
      const { calls, call } = setup({ handler: reply(c.answers) });
      const { payload } = await call({ spec: example(name), facts: c.facts, state: { subject: "data only" } });
      assert.equal(payload.decision, c.expect.decision, `${name}: ${c.name}`);
      assert.equal(payload.rule_id, c.expect.rule_id, `${name}: ${c.name}`);
      assert.equal(payload.decided_by, c.expect.decided_by, `${name}: ${c.name}`);
      if (c.expect.fail_reason) assert.equal(payload.fail_reason, c.expect.fail_reason, c.name);
      assert.equal(calls.length, c.expect.decided_by === "prefilter" ? 0 : 1, `${name}: ${c.name} call count`);
    }
  }
});

test("failure paths follow the spec: open vs closed, with a closed fail_reason", async () => {
  const closed = SPEC(); closed.on_unavailable = { decision: "block", reason: "Fail closed." };
  const facts = { environment: "staging", has_backup: true };
  const run = async (spec, setupOpts) => (await setup(setupOpts).call({ spec, facts, state: { m: "x" } })).payload;
  const expectFail = (p, decision, by, reason) => {
    assert.deepEqual([p.decision, p.decided_by, p.fail_reason, p.rule_id], [decision, by, reason, null]);
    assert.equal(p.record.decided_by, by);
    assert.equal(p.record.fail_reason, reason);
    assert.equal(p.record.decision, decision);
  };
  // no upstream configured
  expectFail(await run(SPEC(), { env: {} }), "ask_user", "fail_open", "no_upstream");
  const nu = await run(closed, { env: {} });
  expectFail(nu, "block", "fail_closed", "no_upstream");
  assert.equal(nu.reason, "Fail closed.");
  assert.equal(nu.fail_mode_applied, "closed");
  assert.equal(nu.record.jev.calls, 0);
  // HTTP 4xx (no retry)
  expectFail(await run(closed, { handler: async () => ({ ok: false, status: 400, text: async () => "secret body", json: async () => ({}) }) }), "block", "fail_closed", "upstream_error");
  // fetch throws
  expectFail(await run(SPEC(), { handler: async () => { throw new Error("connect ECONNREFUSED 10.0.0.1:443"); }, }), "ask_user", "fail_open", "upstream_error");
  // malformed envelope / unparseable / omitted answer
  expectFail(await run(closed, { handler: async () => ({ ok: true, status: 200, json: async () => ({ nope: 1 }) }) }), "block", "fail_closed", "invalid_response");
  expectFail(await run(closed, { handler: async () => ({ ok: true, status: 200, json: async () => { throw new Error("bad json"); } }) }), "block", "fail_closed", "invalid_response");
  expectFail(await run(closed, { handler: reply({ destructive: noul(0.1) }) }), "block", "fail_closed", "invalid_response");
});

test("an invalid answer with no missing_as fails; with missing_as the spec decides", async () => {
  const s = SPEC();
  delete s.rules[1].when.missing_as; // destructive: invalid -> no stand-in
  const bad = { destructive: { type: "noul", noul: "high" }, additive_only: noul(0.99) };
  const facts = { environment: "staging", has_backup: true };
  const p = (await setup({ handler: reply(bad) }).call({ spec: s, facts })).payload;
  assert.deepEqual([p.decided_by, p.fail_reason, p.decision, p.jev.status], ["fail_open", "invalid_response", "ask_user", "invalid_response"]);
  assert.equal(p.record.jev.calls, 1);
  const q = (await setup({ handler: reply(bad) }).call({ spec: SPEC(), facts })).payload;
  assert.deepEqual([q.decided_by, q.rule_id], ["jev", "R2-destructive"]);
});

test("budget_ms is a hard deadline even when the upstream never answers", async () => {
  const { call, calls } = setup({
    handler: (init) => new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true })),
  });
  const p = (await call({ spec: SPEC(), facts: { environment: "staging", has_backup: true }, budget_ms: 100 })).payload;
  assert.deepEqual([p.decided_by, p.fail_reason], ["fail_open", "timeout"]);
  assert.equal(calls.length, 1);
  // a fetch that ignores the abort signal entirely still returns within the budget
  const hung = setup({ handler: () => new Promise(() => {}) });
  const q = (await hung.call({ spec: SPEC(), facts: { environment: "staging", has_backup: true }, budget_ms: 100 })).payload;
  assert.equal(q.fail_reason, "timeout");
  assert.equal(DEFAULT_BUDGET_MS, 5000);
});

test("caller bugs return an error result and no decision (never a fail-open decision)", async () => {
  const { call, calls } = setup();
  for (const args of [
    { spec: { id: "x" } },
    { spec: SPEC(), facts: { "bad key": 1 } },
    { spec: SPEC(), facts: { nested: { a: 1 } } },
    { spec: SPEC(), state: { "bad key": 1 } },
    { spec: SPEC(), state: { big: "x".repeat(13_000) } },
  ]) {
    const { res, payload } = await call(args);
    assert.equal(res.isError, true, JSON.stringify(args).slice(0, 60));
    assert.equal(payload.decision, undefined);
    assert.match(payload.note, /No decision was made/);
    assert.ok(payload.errors.length > 0);
  }
  assert.equal(calls.length, 0);
});

test("prepareState: shapes, caps, redaction of every string leaf", () => {
  assert.equal(prepareState(undefined).ok, true);
  for (const bad of [null, [], "x", 3]) assert.equal(prepareState(bad).ok, false);
  assert.equal(prepareState({ a: Number.NaN }).ok, false);
  assert.equal(prepareState({ a: { b: { c: { d: { e: { f: { g: { h: { i: 1 } } } } } } } } }).ok, false, "depth");
  assert.equal(prepareState({ a: Array.from({ length: 601 }, () => 1) }).ok, false, "node cap");
  const token = "ghp_" + "a1B2".repeat(9);
  const r = prepareState({ a: [{ b: token }], c: `password=hunter2hunter2` });
  assert.equal(r.ok, true);
  assert.ok(!JSON.stringify(r.state).includes(token) && !JSON.stringify(r.state).includes("hunter2"));
});

test("records: canonical key order, content-free shapes, under the byte cap, one log line (or none when off)", async () => {
  const { call, logs } = setup({ handler: reply({ destructive: noul(0.01), additive_only: noul(0.99) }) });
  const { payload } = await call({ spec: SPEC(), facts: { environment: "staging", has_backup: true }, host: "claude-code", correlation_id: "abc_123-X" });
  assert.deepEqual(Object.keys(payload.record), [...RECORD_KEYS]);
  assert.ok(JSON.stringify(payload.record).length <= MAX_RECORD_BYTES);
  assert.equal(payload.record.tool, "kit_decide");
  assert.equal(payload.record.host, "claude-code");
  assert.equal(payload.record.correlation_id, "abc_123-X");
  assert.equal(payload.record.policy_version, null);
  assert.equal(payload.record.source, "server");
  assert.equal(payload.record.verdict, null);
  assert.equal(typeof payload.record.latency_ms, "number");
  assert.equal(logs.length, 1);
  const line = JSON.parse(logs[0]);
  assert.equal(line.kind, "jev.decision");
  assert.equal("event" in line, false);
  assert.deepEqual({ ...line, kind: undefined }, { ...payload.record, kind: undefined });
  const off = setup({ env: { ...ENV, JEV_DECISION_LOG: " OFF " }, handler: reply({ destructive: noul(0.01), additive_only: noul(0.99) }) });
  const o = await off.call({ spec: SPEC(), facts: { environment: "staging", has_backup: true } });
  assert.equal(off.logs.length, 0);
  assert.ok(o.payload.record, "the record is still returned");
});

test("cost: a configured per-token price is the fallback when the upstream reports none", async () => {
  const env = { ...ENV, JEV_PRICE_PER_INPUT_TOKEN_USD: "0.000001", JEV_PRICE_PER_OUTPUT_TOKEN_USD: "0.000002" };
  const h = async () => ({ ok: true, status: 200, json: async () => ({ answers: { destructive: noul(0.01), additive_only: noul(0.99) }, usage: { input_tokens: 1000, output_tokens: 10 } }), text: async () => "" });
  const { payload } = await setup({ env, handler: h }).call({ spec: SPEC(), facts: { environment: "staging", has_backup: true } });
  assert.equal(payload.record.jev.cost_source, "configured");
  assert.ok(Math.abs(payload.record.jev.cost - 0.00102) < 1e-12);
});

test("canary: no input text reaches a record or a log line, and every schema key is covered", async () => {
  const CANARY = "CANARY secret text, with spaces & punctuation!";
  // class and policy_layers are covered in policy.test.mjs (layer text canary, class-id shape check)
  const covered = new Set(["spec", "class", "policy_layers", "state", "facts", "budget_ms", "host", "correlation_id"]);
  const { tools } = setup();
  const keys = Object.keys(tools.kit_decide.cfg.inputSchema.shape);
  for (const k of keys) assert.ok(covered.has(k), `schema key "${k}" has no canary coverage: add it here`);
  for (const k of covered) assert.ok(keys.includes(k), `covered key "${k}" is not in the schema`);

  const base = () => ({ spec: SPEC(), facts: { environment: "staging", has_backup: true }, state: { migration: "x" } });
  const variants = {
    "spec.description": (a) => { a.spec.description = CANARY; },
    "spec.question.instructions": (a) => { a.spec.questions.destructive.instructions = CANARY; },
    "spec.question.criteria": (a) => { a.spec.questions.destructive.criteria.true = CANARY; },
    "spec.rule.reason": (a) => { a.spec.rules[2].reason = CANARY; },
    "spec.default.reason": (a) => { a.spec.default.reason = CANARY; },
    "spec.on_unavailable.reason": (a) => { a.spec.on_unavailable.reason = CANARY; },
    "state.string": (a) => { a.state = { migration: CANARY, list: [CANARY] }; },
    "facts.string": (a) => { a.spec.rules[0].when = { fact: "note", eq: CANARY }; a.facts = { note: CANARY }; },
    "host": (a) => { a.host = CANARY; },
    "correlation_id": (a) => { a.correlation_id = CANARY; },
  };
  const paths = [
    { answers: { destructive: noul(0.01), additive_only: noul(0.99) } },
    { answers: { destructive: noul(0.9), additive_only: noul(0.1) } },
    { fail: true },
  ];
  for (const [name, mut] of Object.entries(variants)) {
    for (const p of paths) {
      const handler = p.fail ? async () => ({ ok: false, status: 400, text: async () => CANARY, json: async () => ({ error: CANARY }) }) : reply(p.answers, { model: `${CANARY}` });
      const { call, logs } = setup({ handler });
      const args = base(); mut(args);
      const { payload, res } = await call(args);
      assert.equal(res.isError, undefined, `${name}: ${JSON.stringify(payload.errors)}`);
      const rec = JSON.stringify(payload.record);
      assert.ok(!rec.includes("CANARY"), `${name}: record leaked`);
      assert.ok(logs.every((l) => !l.includes("CANARY")), `${name}: log leaked`);
      assert.ok(rec.length <= MAX_RECORD_BYTES);
      if (name === "host" || name === "correlation_id") assert.equal(payload.record[name], null, `${name} non-conforming -> null`);
    }
  }
  // a hostile model label from the upstream is dropped, never recorded
  const { call } = setup({ handler: reply({ destructive: noul(0.01), additive_only: noul(0.99) }, { model: "not a model!" }) });
  assert.equal((await call(base())).payload.record.jev.model, null);
});

test("canary: spec words that break the allow-list shapes are rejected up front, not recorded", async () => {
  const s = SPEC();
  s.vocabulary = ["proceed", "ask_user", "block", "rm -rf /"];
  assert.equal(validateSpec(s).ok, false);
  const t = SPEC(); t.rules[0].id = "R1 prod: do thing";
  assert.equal(validateSpec(t).ok, false);
});

test("failCodeFor maps upstream errors to the closed list, never keeping the message", () => {
  assert.equal(failCodeFor(new Error("Jev request timed out")), "timeout");
  assert.equal(failCodeFor(new DOMException("aborted", "AbortError")), "timeout");
  assert.equal(failCodeFor(new Error("x returned a malformed answers envelope")), "invalid_response");
  assert.equal(failCodeFor(new Error("x omitted the answer for q")), "invalid_response");
  assert.equal(failCodeFor(new Error("x returned HTTP 500")), "upstream_error");
  assert.equal(failCodeFor("weird"), "upstream_error");
});

test("runDecide works without the MCP wrapper (host embedding and tests)", async () => {
  const r = await runDecide({ spec: SPEC(), facts: { environment: "production", has_backup: false } }, { env: {}, log: () => {} });
  assert.equal(r.payload.decision, "block");
});

test("clampBudget: default when absent, floor 100, ceiling MAX_BUDGET_MS", () => {
  assert.equal(clampBudget(undefined), DEFAULT_BUDGET_MS);
  assert.equal(clampBudget(Number.NaN), DEFAULT_BUDGET_MS);
  assert.equal(clampBudget(1), 100);
  assert.equal(clampBudget(1234.6), 1235);
  assert.equal(clampBudget(MAX_BUDGET_MS + 1), MAX_BUDGET_MS);
  assert.equal(clampBudget(10 ** 9), MAX_BUDGET_MS);
});

test("the payload's jev block carries only shape-checked values, whatever the upstream sends", async () => {
  const h = async () => ({ ok: true, status: 200, text: async () => "", json: async () => ({ answers: { destructive: noul(0.01), additive_only: noul(0.99) }, model: "bad model text!", usage: { input_tokens: "lots", output_tokens: { x: 1 }, cost: "free" } }) });
  const { payload } = await setup({ handler: h }).call({ spec: SPEC(), facts: { environment: "staging", has_backup: true } });
  assert.deepEqual(payload.jev, { used: true, status: "ok", model: null, usage: { input_tokens: null, output_tokens: null, cost: null } });
});

test("question text is redacted like state before it goes upstream", async () => {
  const token = "ghp_" + "a1B2".repeat(9);
  const s = SPEC();
  s.questions.destructive.instructions = `Does the migration drop data? (ticket key ${token})`;
  s.questions.destructive.criteria.true = { what: `Removes data, token=${token}`, examples: [`DROP TABLE x -- ${token}`] };
  s.questions.additive_only.criteria.false = `password=hunter2hunter2 at least one statement is not additive`;
  const { calls, call } = setup({ handler: reply({ destructive: noul(0.01), additive_only: noul(0.99) }) });
  const { payload } = await call({ spec: s, facts: { environment: "staging", has_backup: true } });
  assert.equal(calls.length, 1);
  const body = JSON.stringify(calls[0].body.questions);
  assert.ok(!body.includes(token) && !body.includes("hunter2"), "no secret shape in question text upstream");
  assert.ok(body.includes("<redacted>") && body.includes("Does the migration drop data?"), "text is redacted, not dropped");
  assert.equal(payload.decided_by, "jev");
  assert.deepEqual(Object.keys(calls[0].body.questions), Object.keys(s.questions));
});

test("state size is checked on the input before any redaction", () => {
  const secret = "ghp_" + "A1b2".repeat(4000); // 16k characters that redact to a few
  const r = prepareState({ s: secret });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /over 12000 characters/);
  assert.equal(prepareState({ s: "x".repeat(11_900) }).ok, true);
  assert.equal(prepareState({ s: "x".repeat(12_001) }).ok, false);
  const cyc = {}; cyc.self = cyc;
  assert.deepEqual(prepareState(cyc), { ok: false, errors: ["state is not JSON-serializable"] });
});

test("error lists are capped at 20 plus a count; an over-cap facts object is rejected before per-key work", () => {
  const bad = (n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`Bad Key ${i}`, 1]));
  const f = validateFacts(bad(30));
  assert.equal(f.ok, false);
  assert.equal(f.errors.length, 21);
  assert.equal(f.errors[20], "and 10 more");
  assert.deepEqual(validateFacts(bad(33)), { ok: false, errors: ["facts: at most 32 keys"] });
  assert.deepEqual(validateFacts(bad(5)).errors.length, 5, "under the cap nothing is summarised");
  const st = prepareState(Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`bad key ${i}`, 1])));
  assert.equal(st.errors.length, 21);
  assert.equal(st.errors[20], "and 30 more");
  const spec = SPEC();
  spec.rules = Array.from({ length: 33 }, (_, i) => ({ id: `bad id ${i}`, when: { noul: "nope", gte: 2 }, decision: "x", reason: "" }));
  const v = validateSpec(spec);
  assert.equal(v.ok, false);
  assert.ok(v.errors.length <= 21 && /^and \d+ more$/.test(v.errors[20]));
});

test("one record module: kit_decide and the fixed tools log the same line shape and honour the same opt-out", async () => {
  const fixed = [];
  await withRecord("kit_guard_command", { command: "ls", host: "claude-code" }, async () => ({ decision: "allow", decided_by: "prefilter", jev: { used: false, status: "not_needed" } }), { log: (l) => fixed.push(l) });
  const { call, logs } = setup({ handler: reply({ destructive: noul(0.01), additive_only: noul(0.99) }) });
  await call({ spec: SPEC(), facts: { environment: "staging", has_backup: true }, host: "claude-code" });
  const a = JSON.parse(fixed[0]), b = JSON.parse(logs[0]);
  assert.equal(a.kind, "jev.decision");
  assert.equal(b.kind, "jev.decision");
  assert.deepEqual(Object.keys(b), Object.keys(a), "same key set and order");
  assert.deepEqual(Object.keys(b), ["kind", ...RECORD_KEYS]);
  for (const v of ["off", "OFF", " Off "]) {
    const quiet = [];
    await withRecord("kit_guard_command", { command: "ls" }, async () => ({ decision: "allow", jev: { used: false } }), { env: { JEV_DECISION_LOG: v }, log: (l) => quiet.push(l) });
    const s = setup({ env: { ...ENV, JEV_DECISION_LOG: v }, handler: reply({ destructive: noul(0.01), additive_only: noul(0.99) }) });
    await s.call({ spec: SPEC(), facts: { environment: "staging", has_backup: true } });
    assert.deepEqual([quiet.length, s.logs.length], [0, 0], JSON.stringify(v));
  }
});

test("deriveRecord reads kit_decide's decision and keeps an explicit closed fail_reason on fail_closed rows", async () => {
  const closed = SPEC(); closed.on_unavailable = { decision: "block" };
  const { payload } = await setup({ env: {} }).call({ spec: closed, facts: { environment: "staging", has_backup: true } });
  assert.deepEqual([payload.decided_by, payload.fail_reason, payload.decision], ["fail_closed", "no_upstream", "block"]);
  const d = deriveRecord("kit_decide", payload, { latency_ms: payload.record.latency_ms });
  const strip = ({ decision_id, ts, ...r }) => r;
  assert.deepEqual(strip(d), strip(payload.record), "payload-derived record equals the explicit-field record");
  assert.equal(d.decision, "block");
  assert.equal(d.fail_reason, "no_upstream");
  // a code outside the closed list is dropped, never copied
  assert.equal(deriveRecord("kit_decide", { ...payload, fail_reason: "boom at 10.0.0.1" }).fail_reason, null);
  // the fixed tools are unchanged: dispatch still reads `action`, and a stray fail_reason on a prefilter row stays out
  assert.equal(deriveRecord("kit_size_dispatch", { action: "allow", decision: "ignored", jev: { used: false } }).decision, "allow");
});

test("assembleRecord emits exactly RECORD_KEYS in order and rejects off-shape fields to null", () => {
  const r = assembleRecord({ tool: "kit_decide", decision: "Not A Word", verdict: "x y", decided_by: "root", rule: "has space", fail_reason: "boom", latency_ms: -1, jev_used: true, jev_status: "A B", model: "bad model", usage: { cost: -1, input_tokens: "1" }, host: "UPPER", correlation_id: "a b" });
  assert.deepEqual(Object.keys(r), [...RECORD_KEYS]);
  assert.deepEqual([r.decision, r.verdict, r.decided_by, r.rule, r.fail_reason, r.latency_ms, r.host, r.correlation_id], [null, null, null, null, null, null, null, null]);
  assert.deepEqual(r.jev, { calls: 1, status: null, model: null, input_tokens: null, output_tokens: null, cost: null, cost_source: "unknown" });
});

test("state size is also checked on what will be sent, because redaction can lengthen short secrets", () => {
  const s = "password=a ".repeat(1000); // 11,000 characters in, 20,000 out
  const r = prepareState({ s });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /over 12000 characters/);
});

test("assembleRecord: policy_version is a 12-hex hash or null, never text", () => {
  assert.equal(assembleRecord({ tool: "kit_decide", policy_version: "0123456789ab" }).policy_version, "0123456789ab");
  for (const bad of ["not hex!", "0123456789abc", "0123456789A", 5, null, undefined, "CANARY text"]) assert.equal(assembleRecord({ tool: "kit_decide", policy_version: bad }).policy_version, null, String(bad));
});
