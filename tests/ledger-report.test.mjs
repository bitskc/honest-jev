// jev-report and jev-outcome (openspec add-decision-ledger). Synthetic, content-free ledgers only.
//   node --test tests/ledger-report.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { buildReport, renderText, readLedgerFiles, ledgerFiles, ledgerEnvError } from "../scripts/jev-report.mjs";
import { hasDecision } from "../scripts/jev-outcome.mjs";

const REPORT = new URL("../scripts/jev-report.mjs", import.meta.url).pathname;
const OUTCOME = new URL("../scripts/jev-outcome.mjs", import.meta.url).pathname;
const dir = mkdtempSync(join(tmpdir(), "jev-report-test-"));
let n = 0;
const id = () => `00000000-0000-4000-8000-${String(++n).padStart(12, "0")}`;

const row = (o = {}) => ({
  v: 1, decision_id: id(), server_decision_id: null, ts: "2026-11-12T10:00:00Z", tool: "kit_guard_command", decision: "allow", verdict: null, decided_by: "prefilter", rule: null,
  fail_reason: null, latency_ms: 100, jev: { calls: 0, status: "not_needed", model: null, input_tokens: null, output_tokens: null, cost: null, cost_source: null },
  tiers: null, host: "claude-code", correlation_id: null, policy_version: null, source: "server", enforced: true, would_have: null, ...o,
});
const jevRow = (o = {}) => row({ decided_by: "jev", jev: { calls: 1, status: "ok", model: "typesafe-ai/jev", input_tokens: 400, output_tokens: 2, cost: 0.00002, cost_source: "upstream" }, ...o });
const dispatch = (o = {}) => row({ tool: "kit_size_dispatch", decision: "block", verdict: "over_tiered", tiers: { chosen: "workerO", recommended: "scout-find" }, ...o });
const file = (name, rows, raw = "") => { const p = join(dir, name); writeFileSync(p, rows.map((r) => JSON.stringify(r)).join("\n") + (rows.length ? "\n" : "") + raw); return p; };
const outcome = (decision_id, label, subagent_tokens = null, source = "self_reported", ts = "2026-11-12T11:00:00Z") => ({ v: 1, decision_id, label, ts, subagent_tokens, source });
const rep = (rows, outs = [], opts) => buildReport(rows, outs, opts);
const PRICES = { usd_per_mtok: { workerO: 15, "scout-find": 1 } };

test("coverage: a guard-only ledger says verify and dispatch have no ledger writer, and prints no savings figure", () => {
  const r = rep([row(), row()]);
  assert.equal(r.coverage.kit_guard_command.rows, 2);
  assert.match(r.coverage.kit_verify_done.note, /no ledger writer in v1/);
  assert.match(r.coverage.kit_size_dispatch.note, /no ledger writer in v1.*opt-in dispatch shadow hook/);
  const text = renderText(r);
  assert.match(text, /kit_verify_done: 0 row\(s\) \(no ledger writer in v1/);
  assert.match(text, /kit_size_dispatch: 0 row\(s\) \(no ledger writer in v1/);
  assert.doesNotMatch(text, /\$\d/);
});

test("coverage: a tool with rows has no excuse note", () => {
  const r = rep([row(), dispatch()]);
  assert.equal(r.coverage.kit_size_dispatch.note, null);
  assert.match(renderText(r), /kit_size_dispatch: 1 row\(s\)\n/);
});

test("coverage: kit_decide is listed; no rows says why, and a ledger row for it counts and loses the note", () => {
  const none = rep([row()]);
  assert.equal(none.coverage.kit_decide.rows, 0);
  assert.match(none.coverage.kit_decide.note, /^no rows:.*jev\.decision.*only when the call goes through `jev-call`.*native MCP connection/);
  assert.match(renderText(none), /kit_decide: 0 row\(s\) \(no rows: the content-free record/);
  const some = rep([row(), row({ tool: "kit_decide", decision: "ask_user", decided_by: "jev" })]);
  assert.equal(some.coverage.kit_decide.rows, 1);
  assert.equal(some.coverage.kit_decide.note, null);
  assert.deepEqual(Object.keys(some.coverage), ["kit_guard_command", "kit_verify_done", "kit_size_dispatch", "kit_decide"]);
});

test("every report states the two lower bounds (fail-open rate, Jev spend)", () => {
  const text = renderText(rep([row()]));
  assert.match(text, /LOWER BOUND: a missing interpreter, a host-level hook timeout and a crashed hook leave no row/);
  assert.match(text, /LOWER BOUND: upstream usage comes from the final successful response; retried or timed-out attempts are invisible/);
});

test("no outcomes: the Estimated section says not measurable and prints no figure", () => {
  const r = rep(Array.from({ length: 5 }, () => dispatch()));
  const e = r.estimated.dispatch_downshift;
  assert.equal(e.measurable, false); assert.equal(e.note, "not measurable: no outcome reports");
  const text = renderText(r);
  assert.match(text, /cost-equivalent downshift \(estimated\): not measurable: no outcome reports/);
  assert.doesNotMatch(text, /sub-agent tokens|\$\d/);
});

test("estimate: computed only from followed outcomes with integer tokens and both tiers priced; prints n, unpriced, assumptions", () => {
  const d = [dispatch(), dispatch(), dispatch({ tiers: { chosen: "mystery", recommended: "scout-find" } }), dispatch()];
  const outs = [outcome(d[0].decision_id, "followed", 100000), outcome(d[1].decision_id, "overridden"), outcome(d[2].decision_id, "followed", 5000), outcome(d[3].decision_id, "followed", null)];
  const e = rep(d, outs, { priceTable: PRICES }).estimated.dispatch_downshift;
  assert.equal(e.measurable, true); assert.equal(e.name, "cost-equivalent downshift (estimated)"); assert.equal(e.label, "estimated");
  assert.deepEqual([e.n, e.unpriced, e.missing_tokens, e.deduped], [1, 1, 1, 0]);
  assert.equal(e.subagent_tokens, 100000); assert.equal(e.usd, 1.4); // 0.1M tokens x ($15 - $1)
  for (const a of [/self-selected/, /agent's own proposed tier/, /same work at the same token count/, /not a token count/]) assert.match(e.assumptions, a);
  const text = renderText(rep(d, outs, { priceTable: PRICES }));
  assert.match(text, /cost-equivalent downshift \(estimated\) \[n=1, low n, 1 unpriced, 1 without tokens, 0 deduplicated\]/);
  assert.match(text, /assumptions: counts only followed/);
  assert.doesNotMatch(text, /token-equivalents/);
});

test("estimate: repeated advice for one spawn (same correlation_id) counts once", () => {
  const d = [dispatch({ correlation_id: "spawn_1" }), dispatch({ correlation_id: "spawn_1" }), dispatch({ correlation_id: "spawn_2" })];
  const outs = d.map((x) => outcome(x.decision_id, "followed", 1000000));
  const e = rep(d, outs, { priceTable: PRICES }).estimated.dispatch_downshift;
  assert.deepEqual([e.n, e.deduped, e.usd], [2, 1, 28]);
});

test("estimate: followed outcomes without tokens or without a price table stay not measurable", () => {
  const d = [dispatch()];
  assert.match(rep(d, [outcome(d[0].decision_id, "followed")], { priceTable: PRICES }).estimated.dispatch_downshift.note, /^not measurable: of 1 followed outcome\(s\), 1 lack subagent_tokens/);
  assert.match(rep(d, [outcome(d[0].decision_id, "followed", 10)]).estimated.dispatch_downshift.note, /no price table/);
  assert.match(rep([dispatch({ tiers: { chosen: "x", recommended: "y" } })].map((x) => x), []).estimated.dispatch_downshift.note, /no outcome reports/);
  assert.equal(rep(d, [outcome(d[0].decision_id, "followed", 1.5)], { priceTable: PRICES }).estimated.dispatch_downshift.measurable, false); // non-integer tokens rejected
});

test("prefilter share is descriptive: verify rows with nothing judged are excluded and the text says it is not a saving", () => {
  const d = [...Array.from({ length: 6 }, () => row()), ...Array.from({ length: 4 }, () => jevRow()),
    row({ tool: "kit_verify_done", verdict: "not_applicable", decision: "allow" }), row({ tool: "kit_verify_done", verdict: "unknown" })];
  const r = rep(d);
  const s = r.observed.decided_without_model_call;
  assert.deepEqual([s.k, s.n, s.pct, s.excluded_nothing_judged], [6, 10, 60, 2]);
  const text = renderText(r);
  assert.match(text, /decided without a model call: 60% \(6\/10\)/); assert.match(text, /NOT a saving/);
});

test("rates under 30 rows are marked low n; 30 or more are not", () => {
  assert.equal(rep(Array.from({ length: 29 }, () => row())).observed.fail_open.low_n, true);
  assert.equal(rep(Array.from({ length: 30 }, () => row())).observed.fail_open.low_n, false);
  assert.match(renderText(rep([row(), row()])), /low n/);
});

test("cost is summed per source and never merged into one total", () => {
  const d = [jevRow(), jevRow(), jevRow({ jev: { calls: 1, status: "ok", model: "m", input_tokens: 1000, output_tokens: 0, cost: 0.000042, cost_source: "configured" } }),
    jevRow({ jev: { calls: 1, status: "ok", model: "m", input_tokens: 10, output_tokens: 1, cost: null, cost_source: "unknown" } })];
  const j = rep(d).observed.jev;
  assert.deepEqual(Object.keys(j.cost_by_source).sort(), ["configured", "upstream"]);
  assert.ok(Math.abs(j.cost_by_source.upstream - 0.00004) < 1e-12); assert.ok(Math.abs(j.cost_by_source.configured - 0.000042) < 1e-12);
  assert.equal(j.calls_without_cost, 1); assert.equal(j.calls, 4);
  const text = renderText(rep(d));
  assert.match(text, /upstream=\$0\.000040, configured=\$0\.000042/); assert.match(text, /1 call\(s\) with unknown cost/);
});

test("fail-open and fail-closed are counted with their closed reason codes; not-enforced rows show would_have", () => {
  const d = [row({ decided_by: "fail_open", fail_reason: "client_timeout" }), row({ decided_by: "fail_open", fail_reason: "client_timeout" }), row({ decided_by: "fail_open", fail_reason: "client_config" }),
    row({ decided_by: "fail_closed", fail_reason: "client_rejected", decision: "ask" }), row({ decision: "block", enforced: false, would_have: "block", rule: "R1-secret-exposure" })];
  const o = rep(d).observed;
  assert.deepEqual(o.fail_open.reasons, { client_timeout: 2, client_config: 1 }); assert.equal(o.fail_open.k, 3); assert.equal(o.fail_open.lower_bound, true);
  assert.deepEqual(o.fail_closed.reasons, { client_rejected: 1 });
  assert.deepEqual(o.not_enforced, { count: 1, would_have: { block: 1 } });
  assert.deepEqual(o.by_rule, { "R1-secret-exposure": 1 });
});

test("latest outcome wins; orphan outcomes are counted, not joined; sources are labelled", () => {
  const a = row({ decision: "ask", rule: "R10-general-risk" });
  const r = rep([a], [outcome(a.decision_id, "denied", null, "self_reported", "2026-11-12T11:00:00Z"), outcome(a.decision_id, "approved", null, "host_observed", "2026-11-12T12:00:00Z"), outcome(id(), "approved")]);
  assert.equal(r.outcome_linked.ask.labels.approved, 1); assert.equal(r.outcome_linked.ask.labels.denied, undefined);
  assert.deepEqual(r.outcome_linked.ask.sources, { "host-observed": 1 });
  assert.equal(r.outcome_linked.orphan_outcome_rows, 1);
  assert.deepEqual(r.outcome_linked.ask.by_rule, { "R10-general-risk": { n: 1, approved: 1 } });
  const text = renderText(r);
  assert.match(text, /sources: host-observed=1/); assert.match(text, /self-reported labels come from jev-outcome/);
});

test("ask outcomes: no_ui is shown but excluded from the approved rate", () => {
  const asks = [row({ decision: "ask" }), row({ decision: "ask" }), row({ decision: "ask" })];
  const r = rep(asks, [outcome(asks[0].decision_id, "approved", null, "host_observed"), outcome(asks[1].decision_id, "denied", null, "host_observed"), outcome(asks[2].decision_id, "no_ui", null, "host_observed")]);
  assert.deepEqual([r.outcome_linked.ask.approved.k, r.outcome_linked.ask.approved.n, r.outcome_linked.ask.labels.no_ui], [1, 2, 1]);
});

test("ask outcomes are unavailable unless a host wrote them", () => {
  const r = rep([row({ decision: "ask" }), row({ decision: "ask" })]);
  assert.equal(r.outcome_linked.ask.available, false);
  assert.match(renderText(r), /unavailable \(no Pre\/Post correlation\) \(2 ask decision/);
});

test("a ledger is parsed tolerantly: malformed lines skipped and counted; rotated generations and the current file are all read, oldest first", () => {
  const base = join(dir, "rot.jsonl");
  const old1 = file("rot.jsonl.20261112T100000000001Z-1", [row()]), old2 = file("rot.jsonl.20261112T100000000002Z-2", [row(), row()]);
  file("rot.jsonl.unrelated", [row()]); // not a rotated generation: ignored
  const cur = file("rot.jsonl", [row(), jevRow()], "not json\n{\"no\":\"id\"}\n");
  assert.deepEqual(ledgerFiles(base), [old1, old2, cur]);
  const { decisions, skipped } = readLedgerFiles(ledgerFiles(base));
  assert.equal(decisions.length, 5); assert.equal(skipped, 2);
});

test("CLI: jev-report reads a ledger file and its rotated generations, --json parses, a missing file exits non-zero", () => {
  const f = file("cli.jsonl", [row(), jevRow(), row({ decided_by: "fail_open", fail_reason: "client_timeout" })]);
  file("cli.jsonl.20261112T100000000001Z-9", [row()]);
  const out = spawnSync("node", [REPORT, ...ledgerFiles(f)], { encoding: "utf8" });
  assert.equal(out.status, 0); assert.match(out.stdout, /4 decision\(s\)/); assert.match(out.stdout, /COVERAGE/);
  const env = { PATH: process.env.PATH, HOME: dir, JEV_LEDGER: f };
  assert.match(spawnSync("node", [REPORT], { encoding: "utf8", env }).stdout, /4 decision\(s\) from 2 file\(s\)/); // default path picks up the rotated file
  const js = JSON.parse(spawnSync("node", [REPORT, "--json", f], { encoding: "utf8" }).stdout);
  assert.equal(js.observed.decisions, 3); assert.ok(js.coverage.kit_verify_done);
  assert.notEqual(spawnSync("node", [REPORT, join(dir, "absent.jsonl")], { encoding: "utf8" }).status, 0);
  assert.notEqual(spawnSync("node", [REPORT], { encoding: "utf8", env: { PATH: process.env.PATH, HOME: dir, JEV_LEDGER: "off" } }).status, 0);
});

test("jev-outcome: allow-listed self_reported row keyed by decision_id; unknown id exits non-zero and appends nothing", () => {
  const a = row({ decision: "ask" });
  const f = file("o.jsonl", [a]);
  const before = readFileSync(f, "utf8");
  const bad = spawnSync("node", [OUTCOME, "00000000-0000-4000-8000-ffffffffffff", "approved", "--ledger", f], { encoding: "utf8" });
  assert.equal(bad.status, 1); assert.equal(readFileSync(f, "utf8"), before);
  const ok = spawnSync("node", [OUTCOME, a.decision_id, "approved", "--ledger", f], { encoding: "utf8" });
  assert.equal(ok.status, 0); assert.match(ok.stdout, /self-reported/);
  const last = JSON.parse(readFileSync(f, "utf8").trim().split("\n").at(-1));
  assert.deepEqual(Object.keys(last), ["v", "decision_id", "label", "ts", "subagent_tokens", "source"]);
  assert.deepEqual([last.decision_id, last.label, last.subagent_tokens, last.source, last.v], [a.decision_id, "approved", null, "self_reported", 1]);
  spawnSync("node", [OUTCOME, a.decision_id, "denied", "--ledger", f], { encoding: "utf8" }); // relabel: the later row wins
  const { decisions, outcomes } = readLedgerFiles([f]);
  assert.equal(rep(decisions, outcomes).outcome_linked.ask.labels.denied, 1);
});

test("jev-outcome rejects bad input without writing: non-uuid, bad label, bad --tokens; accepts integer tokens", () => {
  const a = row();
  const f = file("o2.jsonl", [a]);
  const before = readFileSync(f, "utf8");
  for (const args of [["not-a-uuid", "approved"], [a.decision_id, "Has Space"], [a.decision_id, "followed", "--tokens", "-3"], [a.decision_id, "followed", "--tokens", "1.5"], [a.decision_id]]) {
    assert.equal(spawnSync("node", [OUTCOME, ...args, "--ledger", f], { encoding: "utf8" }).status, 2, args.join(" "));
  }
  assert.equal(readFileSync(f, "utf8"), before);
  assert.equal(spawnSync("node", [OUTCOME, a.decision_id, "followed", "--tokens", "123", "--ledger", f], { encoding: "utf8" }).status, 0);
  assert.equal(JSON.parse(readFileSync(f, "utf8").trim().split("\n").at(-1)).subagent_tokens, 123);
  assert.equal(hasDecision(f, a.decision_id), true);
});

test("jev-outcome finds a decision that was rotated into an older generation", () => {
  const a = row({ decision: "ask" });
  const f = file("o3.jsonl", [row()]);
  file("o3.jsonl.20261112T100000000001Z-1", [a]);
  assert.equal(spawnSync("node", [OUTCOME, a.decision_id, "approved", "--ledger", f], { encoding: "utf8" }).status, 0);
});

test("jev-outcome never writes through a symlink and never creates a file for an unknown id", () => {
  const home = mkdtempSync(join(tmpdir(), "jev-home-"));
  const r = spawnSync("node", [OUTCOME, "00000000-0000-4000-8000-000000000999", "approved"], { encoding: "utf8", env: { PATH: process.env.PATH, HOME: home } });
  assert.equal(r.status, 1);
  assert.ok(!existsSync(join(home, ".local", "state", "jev", "ledger.jsonl")));
  const a = row({ decision: "ask" });
  const real = file("real-target.jsonl", [a]);
  const before = readFileSync(real, "utf8");
  const link = join(dir, "linked.jsonl");
  symlinkSync(real, link);
  assert.equal(spawnSync("node", [OUTCOME, a.decision_id, "approved", "--ledger", link], { encoding: "utf8" }).status, 1);
  assert.equal(readFileSync(real, "utf8"), before);
});

test("jev-outcome refuses a relative JEV_LEDGER: exit 2, nothing created under the working directory", () => {
  const cwd = mkdtempSync(join(tmpdir(), "jev-outcome-cwd-"));
  const r = spawnSync("node", [OUTCOME, "00000000-0000-4000-8000-000000000999", "approved"], { encoding: "utf8", cwd, env: { PATH: process.env.PATH, HOME: dir, JEV_LEDGER: "rel/ledger.jsonl" } });
  assert.equal(r.status, 2); assert.match(r.stderr, /must be an absolute path/);
  assert.ok(!existsSync(join(cwd, "rel")));
});

test("sanitize: control characters and ANSI escapes in row-derived strings never reach the terminal", () => {
  const text = renderText(rep([row({ rule: "evil\x1b[2J\x07name" })]));
  assert.doesNotMatch(text, /\x1b|\x07/);
  assert.match(text, /evilname=1/);
});

for (const ch of ["\u0080", "\u0085", "\u009b", "\u009f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "\u2028", "\u2029"]) {
  test(`sanitize: U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")} is stripped from row-derived strings`, () => {
    const text = renderText(rep([row({ rule: `evil${ch}name` })]));
    assert.equal(text.includes(ch), false);
    assert.match(text, /evilname=1/);
  });
}

test("estimate: a non-positive figure prints 'no saving', never a negative dollar amount", () => {
  const d = [dispatch({ tiers: { chosen: "scout-find", recommended: "workerO" } })];
  const text = renderText(rep(d, [outcome(d[0].decision_id, "followed", 1000000)], { priceTable: PRICES }));
  assert.match(text, /no saving \(estimate ≤ 0\)/);
  assert.doesNotMatch(text, /\$-/);
});

test("ESTIMATED header says the inputs are self-reported", () => {
  assert.match(renderText(rep([row()])), /^ESTIMATED \(inputs are self-reported/m);
});

test("a relative JEV_LEDGER is refused with a message and exit 2; absolute, off, unset and explicit files are not", () => {
  const env = { PATH: process.env.PATH, HOME: dir, JEV_LEDGER: "rel/ledger.jsonl" };
  const refused = spawnSync("node", [REPORT], { encoding: "utf8", env });
  assert.equal(refused.status, 2); assert.match(refused.stderr, /must be an absolute path/);
  const f = file("rel-ok.jsonl", [row()]);
  assert.equal(spawnSync("node", [REPORT, f], { encoding: "utf8", env }).status, 0);
  assert.notEqual(ledgerEnvError({ JEV_LEDGER: "rel/ledger.jsonl" }), null);
  assert.equal(ledgerEnvError({ JEV_LEDGER: "/abs/ledger.jsonl" }), null);
  assert.equal(ledgerEnvError({ JEV_LEDGER: "OFF" }), null);
  assert.equal(ledgerEnvError({}), null);
});
