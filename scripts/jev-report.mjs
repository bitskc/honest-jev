#!/usr/bin/env node
// jev-report: read decision-ledger JSONL (hooks write it; see hooks/jev_ledger.py) and print four sections.
//   Coverage        which kit tools have rows in this ledger, and why a tool may have none
//   Observed        exact quantities computed from row fields only (the fail-open rate and Jev spend are LOWER BOUNDS)
//   Outcome-linked  only rows that have an outcome label, with n and the label's source (self-reported / host-observed)
//   Estimated       every figure prints its inputs and assumptions on the same line; never computed without inputs
// Usage: jev-report [--json] [--price-table <file.json>] [ledger.jsonl ...]
//   default input: $JEV_LEDGER, else $XDG_STATE_HOME/jev/ledger.jsonl, else ~/.local/state/jev/ledger.jsonl,
//   plus every rotated generation next to it (ledger.jsonl.<UTC stamp>-<pid>)
//   price table: {"usd_per_mtok": {"<tier name>": <number>, ...}}  (only used for the dispatch estimate)
// Zero dependencies. Reads files only; never writes, never calls the network.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";

const LOW_N = 30;
const ASK_LABELS = ["approved", "denied", "abandoned", "no_ui"];
const DISPATCH_LABELS = ["followed", "overridden"];
const ROTATED_RE = /\.\d{8}T\d{12}Z-\d+$/;
const KIT_TOOLS = {
  kit_guard_command: "no rows (no decisions went through a guard hook that writes the ledger)",
  kit_verify_done: "no ledger writer in v1 (the Stop gate, the stop-gate release, would be the writer); its decisions exist only in the Worker response and log line",
  kit_size_dispatch: "no ledger writer in v1 unless the opt-in dispatch shadow hook is installed; skill-driven dispatch calls are not recorded",
  kit_decide: "no rows: the content-free record is returned in the response and logged as a `jev.decision` line by the Worker; the local ledger gets a row only when the call goes through `jev-call` (or a hook that triggers it), so a call over a native MCP connection is not recorded here",
};

/** Same resolution as hooks/jev_ledger.py and hooks/omp/jev-guard.ts (a parity test pins all four). */
export function ledgerPath(env = process.env) {
  const p = (env.JEV_LEDGER ?? "").trim();
  if (p.toLowerCase() === "off") return null;
  if (p) return isAbsolute(p) ? p : null; // a relative path is refused (ledgerEnvError explains it to the user)
  const xdg = (env.XDG_STATE_HOME ?? "").trim();
  return join(xdg && isAbsolute(xdg) ? xdg : join((env.HOME ?? "").trim() || homedir(), ".local", "state"), "jev", "ledger.jsonl");
}

/** Control characters, C1 controls, every Unicode format character (category Cf: soft hyphen, Arabic letter mark, zero-width and bidi marks, word joiner and invisible operators, deprecated format controls, interlinear annotation, Mongolian vowel separator, BOM, tag characters, ...), bidi overrides and isolates, and U+2028/U+2029 are removed from every row-derived string before it is printed. ANSI escapes are removed first. The explicit ranges stay so the sweep does not depend on the engine's Unicode tables. */
const clean = (s) => String(s).replace(/\x1b\[[0-9;]*[A-Za-z]/g, "").replace(/[\x00-\x1f\x7f-\x9f\u00ad\u061c\u180e\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\u206a-\u206f\ufeff\ufff9-\ufffb\u{e0000}-\u{e007f}\p{Cf}]/gu, "");

/** Object.groupBy needs Node 21+; this runs on Node 18+. Null-prototype, so a rule named "__proto__" is an ordinary key. */
const groupBy = (xs, key) => xs.reduce((m, x) => { const k = key(x); (m[k] ??= []).push(x); return m; }, Object.create(null));

/** A relative JEV_LEDGER is refused: it would write into the working directory. Returns the message, or null when fine. */
export function ledgerEnvError(env = process.env) {
  const p = (env.JEV_LEDGER ?? "").trim();
  if (!p || p.toLowerCase() === "off" || isAbsolute(p)) return null;
  return `jev-report: JEV_LEDGER must be an absolute path (got "${clean(p)}"); set it to an absolute path or unset it`;
}

/** The current ledger file plus every rotated generation, oldest first. */
export function ledgerFiles(base) {
  let rotated = [];
  try { rotated = readdirSync(dirname(base)).filter((n) => n.startsWith(`${basename(base)}.`) && ROTATED_RE.test(n)).sort().map((n) => join(dirname(base), n)); } catch { /* no directory yet */ }
  return [...rotated, ...(existsSync(base) ? [base] : [])];
}

export function defaultLedgerFiles(env = process.env) {
  const base = ledgerPath(env);
  return base ? ledgerFiles(base) : [];
}

/** Parse JSONL files into decision rows and outcome rows. Malformed lines are counted, never fatal. */
export function readLedgerFiles(files) {
  const decisions = [], outcomes = [];
  let skipped = 0;
  for (const f of files) {
    for (const line of readFileSync(f, "utf8").split("\n")) {
      if (!line.trim()) continue;
      let row;
      try { row = JSON.parse(line); } catch { skipped++; continue; }
      if (!row || typeof row !== "object" || typeof row.decision_id !== "string") { skipped++; continue; }
      if (typeof row.tool === "string") decisions.push(row);
      else if (typeof row.label === "string") outcomes.push(row);
      else skipped++;
    }
  }
  return { decisions, outcomes, skipped };
}

const count = (rows, key) => rows.reduce((m, r) => { const k = String(key(r) ?? "none"); m[k] = (m[k] ?? 0) + 1; return m; }, {});
const pct = (k, n) => (n === 0 ? null : Math.round((1000 * k) / n) / 10);
const rate = (k, n) => ({ k, n, pct: pct(k, n), low_n: n < LOW_N });
const finite = (v) => (typeof v === "number" && Number.isFinite(v) ? v : null);
function quantile(sorted, q) { if (!sorted.length) return null; return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil(q * sorted.length) - 1))]; }
const sourceOf = (o) => (o.source === "host_observed" ? "host-observed" : "self-reported");

export function buildReport(decisions, outcomes, { priceTable = null } = {}) {
  const n = decisions.length;
  const byId = new Map(decisions.map((d) => [d.decision_id, d]));
  const latest = new Map(); // latest outcome per decision_id wins (file order breaks timestamp ties)
  let orphan = 0;
  for (const o of outcomes) {
    if (!byId.has(o.decision_id)) { orphan++; continue; }
    const prev = latest.get(o.decision_id);
    if (!prev || String(o.ts ?? "") >= String(prev.ts ?? "")) latest.set(o.decision_id, o);
  }

  // ── Coverage ──
  const perTool = count(decisions, (d) => d.tool);
  const coverage = Object.fromEntries(Object.entries(KIT_TOOLS).map(([t, why]) => [t, { rows: perTool[t] ?? 0, note: (perTool[t] ?? 0) === 0 ? why : null }]));

  // ── Observed ──
  const judged = (d) => !(d.tool === "kit_verify_done" && (d.verdict === "not_applicable" || d.verdict === "unknown"));
  const judgedRows = decisions.filter(judged);
  const prefilter = judgedRows.filter((d) => d.decided_by === "prefilter").length;
  const failOpen = decisions.filter((d) => d.decided_by === "fail_open");
  const failClosed = decisions.filter((d) => d.decided_by === "fail_closed");
  const lat = decisions.map((d) => finite(d.latency_ms)).filter((v) => v !== null).sort((a, b) => a - b);
  const cost = {};
  let calls = 0, inTok = 0, outTok = 0, unknownCost = 0;
  for (const d of decisions) {
    const j = d.jev ?? {};
    calls += finite(j.calls) ?? 0; inTok += finite(j.input_tokens) ?? 0; outTok += finite(j.output_tokens) ?? 0;
    if ((finite(j.calls) ?? 0) > 0) {
      const src = j.cost_source ?? "unknown";
      if (finite(j.cost) !== null) cost[src] = (cost[src] ?? 0) + j.cost; else if (src === "unknown") unknownCost++;
    }
  }
  const observed = {
    decisions: n,
    by_tool: perTool,
    by_source: count(decisions, (d) => d.source),
    by_decision: count(decisions, (d) => `${d.tool}:${d.decision}`),
    decided_by: count(decisions, (d) => d.decided_by),
    decided_without_model_call: { ...rate(prefilter, judgedRows.length), excluded_nothing_judged: n - judgedRows.length },
    fail_open: { ...rate(failOpen.length, n), reasons: count(failOpen, (d) => d.fail_reason), lower_bound: true },
    fail_closed: { ...rate(failClosed.length, n), reasons: count(failClosed, (d) => d.fail_reason) },
    not_enforced: { count: decisions.filter((d) => d.enforced === false).length, would_have: count(decisions.filter((d) => d.enforced === false), (d) => d.would_have) },
    by_rule: count(decisions.filter((d) => d.rule), (d) => d.rule),
    latency_ms: { n: lat.length, p50: quantile(lat, 0.5), p95: quantile(lat, 0.95) },
    jev: { calls, input_tokens: inTok, output_tokens: outTok, cost_by_source: cost, calls_without_cost: unknownCost, lower_bound: true },
  };

  // ── Outcome-linked ──
  const withOutcome = (pred) => [...latest.values()].map((o) => ({ o, d: byId.get(o.decision_id) })).filter(({ o, d }) => pred(d, o));
  const askRows = decisions.filter((d) => d.tool === "kit_guard_command" && d.decision === "ask");
  const askOutcomes = withOutcome((d, o) => d.tool === "kit_guard_command" && d.decision === "ask" && ASK_LABELS.includes(o.label));
  const answered = askOutcomes.filter(({ o }) => o.label !== "no_ui");
  const dispatchRows = decisions.filter((d) => d.tool === "kit_size_dispatch");
  const dispatchOutcomes = withOutcome((d, o) => d.tool === "kit_size_dispatch" && DISPATCH_LABELS.includes(o.label));
  const outcomeLinked = {
    outcome_rows: latest.size, orphan_outcome_rows: orphan,
    ask: askOutcomes.length === 0
      ? { available: false, ask_decisions: askRows.length, note: "unavailable (no Pre/Post correlation)" }
      : { available: true, n: askOutcomes.length, labels: count(askOutcomes, ({ o }) => o.label), sources: count(askOutcomes, ({ o }) => sourceOf(o)),
          approved: rate(answered.filter(({ o }) => o.label === "approved").length, answered.length),
          by_rule: Object.fromEntries(Object.entries(groupBy(answered, ({ d }) => d.rule ?? "none")).map(([r, xs]) => [r, { n: xs.length, approved: xs.filter(({ o }) => o.label === "approved").length }])) },
    dispatch: dispatchOutcomes.length === 0
      ? { available: false, dispatch_decisions: dispatchRows.length, note: "unavailable (no outcome reports)" }
      : { available: true, n: dispatchOutcomes.length, labels: count(dispatchOutcomes, ({ o }) => o.label), sources: count(dispatchOutcomes, ({ o }) => sourceOf(o)),
          followed: rate(dispatchOutcomes.filter(({ o }) => o.label === "followed").length, dispatchOutcomes.length) },
  };

  // ── Estimated: cost-equivalent downshift ──
  const NAME = "cost-equivalent downshift (estimated)";
  const prices = priceTable && typeof priceTable === "object" ? priceTable.usd_per_mtok ?? null : null;
  const followed = dispatchOutcomes.filter(({ o }) => o.label === "followed");
  let estimated;
  if (dispatchOutcomes.length === 0) {
    estimated = { dispatch_downshift: { name: NAME, measurable: false, note: "not measurable: no outcome reports" } };
  } else if (!prices) {
    estimated = { dispatch_downshift: { name: NAME, measurable: false, note: `not measurable: ${followed.length} followed outcome(s) but no price table` } };
  } else {
    let usd = 0, tokens = 0, priced = 0, unpriced = 0, missingTokens = 0, deduped = 0;
    const seen = new Set();
    for (const { d, o } of followed) {
      const cid = typeof d.correlation_id === "string" ? d.correlation_id : null;
      if (cid && seen.has(cid)) { deduped++; continue; }   // advice repeated for one spawn counts once
      const t = Number.isInteger(o.subagent_tokens) && o.subagent_tokens >= 0 ? o.subagent_tokens : null;
      if (t === null) { missingTokens++; continue; }
      const pc = finite(prices[d.tiers?.chosen]), pr = finite(prices[d.tiers?.recommended]);
      if (pc === null || pr === null) { unpriced++; continue; }
      if (cid) seen.add(cid);
      priced++; tokens += t; usd += (t / 1e6) * (pc - pr);
    }
    estimated = priced === 0
      ? { dispatch_downshift: { name: NAME, measurable: false, note: `not measurable: of ${followed.length} followed outcome(s), ${missingTokens} lack subagent_tokens and ${unpriced} have an unpriced tier` } }
      : { dispatch_downshift: { name: NAME, measurable: true, label: "estimated", n: priced, unpriced, missing_tokens: missingTokens, deduped, subagent_tokens: tokens, usd: Math.round(usd * 1e6) / 1e6,
          assumptions: "counts only followed recommendations (a self-selected subset); the baseline is the agent's own proposed tier, not what it would have done without the advice; assumes the recommended tier does the same work at the same token count; a cost-equivalent from the price table, not a token count" } };
  }
  return { coverage, observed, outcome_linked: outcomeLinked, estimated };
}

const fmtRate = (r) => (r.n === 0 ? "n/a (n=0)" : `${r.pct}% (${r.k}/${r.n})${r.low_n ? " low n" : ""}`);
const fmtMap = (m) => (Object.keys(m).length ? Object.entries(m).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${clean(k)}=${v}`).join(", ") : "none");

export function renderText(r, { skipped = 0, files = [] } = {}) {
  const o = r.observed, L = [];
  L.push(`jev-report: ${o.decisions} decision(s) from ${files.length} file(s)${skipped ? `, ${skipped} unreadable line(s) skipped` : ""}`);
  L.push("", "COVERAGE (what this ledger can and cannot see)");
  for (const [t, c] of Object.entries(r.coverage)) L.push(`  ${t}: ${c.rows} row(s)${c.note ? ` (${c.note})` : ""}`);
  L.push("", "OBSERVED (exact, from row fields)");
  L.push(`  by source:      ${fmtMap(o.by_source)}`);
  L.push(`  decided_by:     ${fmtMap(o.decided_by)}`);
  L.push(`  decisions:      ${fmtMap(o.by_decision)}`);
  L.push(`  decided without a model call: ${fmtRate(o.decided_without_model_call)}; ${o.decided_without_model_call.excluded_nothing_judged} row(s) where nothing was judged excluded`);
  L.push("    descriptive, NOT a saving: most of these calls (ls, git status) would never have been sent to a model");
  L.push(`  fail-open:      ${fmtRate(o.fail_open)}  reasons: ${fmtMap(o.fail_open.reasons)}`);
  L.push("    LOWER BOUND: a missing interpreter, a host-level hook timeout and a crashed hook leave no row");
  L.push(`  fail-closed:    ${fmtRate(o.fail_closed)}  reasons: ${fmtMap(o.fail_closed.reasons)}`);
  L.push(`  not enforced:   ${o.not_enforced.count} (would have: ${fmtMap(o.not_enforced.would_have)})`);
  L.push(`  rules fired:    ${fmtMap(o.by_rule)}`);
  L.push(`  latency ms:     p50=${o.latency_ms.p50 ?? "n/a"} p95=${o.latency_ms.p95 ?? "n/a"} (n=${o.latency_ms.n}${o.latency_ms.n < LOW_N ? ", low n" : ""})`);
  const c = o.jev;
  L.push(`  Jev:            ${c.calls} call(s), ${c.input_tokens} input / ${c.output_tokens} output tokens`);
  const srcs = Object.entries(c.cost_by_source);
  L.push(`  Jev cost by source: ${srcs.length ? srcs.map(([k, v]) => `${clean(k)}=$${v.toFixed(6)}`).join(", ") : "none recorded"}${c.calls_without_cost ? `; ${c.calls_without_cost} call(s) with unknown cost` : ""}`);
  L.push("    LOWER BOUND: upstream usage comes from the final successful response; retried or timed-out attempts are invisible");
  const ol = r.outcome_linked;
  L.push("", `OUTCOME-LINKED (rows with an outcome label; ${ol.outcome_rows} outcome row(s)${ol.orphan_outcome_rows ? `, ${ol.orphan_outcome_rows} orphaned` : ""})`);
  if (ol.ask.available) {
    L.push(`  guard ask outcomes (n=${ol.ask.n}; sources: ${fmtMap(ol.ask.sources)}): ${fmtMap(ol.ask.labels)}; approved ${fmtRate(ol.ask.approved)} of answered (no_ui excluded)`);
    for (const [rule, v] of Object.entries(ol.ask.by_rule)) L.push(`    ${clean(rule)}: approved ${v.approved}/${v.n}`);
  } else L.push(`  guard ask outcomes: ${ol.ask.note} (${ol.ask.ask_decisions} ask decision(s) in ledger)`);
  if (ol.dispatch.available) L.push(`  dispatch recommendations (n=${ol.dispatch.n}; sources: ${fmtMap(ol.dispatch.sources)}): ${fmtMap(ol.dispatch.labels)}; followed ${fmtRate(ol.dispatch.followed)}`);
  else L.push(`  dispatch recommendations: ${ol.dispatch.note} (${ol.dispatch.dispatch_decisions} dispatch decision(s) in ledger)`);
  L.push("  self-reported labels come from jev-outcome, which any process on this host (including the audited agent) can run; host-observed labels were written by a hook from an event it saw");
  L.push("", "ESTIMATED (inputs are self-reported; assumptions printed with each figure)");
  const e = r.estimated.dispatch_downshift;
  if (e.measurable) {
    const figure = e.usd > 0 ? `$${e.usd} cost-equivalent` : "no saving (estimate ≤ 0)";
    L.push(`  ${e.name} [n=${e.n}${e.n < LOW_N ? ", low n" : ""}, ${e.unpriced} unpriced, ${e.missing_tokens} without tokens, ${e.deduped} deduplicated]: ${e.subagent_tokens} sub-agent tokens, ${figure}`);
    L.push(`    assumptions: ${e.assumptions}`);
  } else L.push(`  ${e.name}: ${e.note}`);
  L.push("  guard and verify deliver quality, not token savings; no token figure is estimated for them.");
  return L.join("\n");
}

function main(argv) {
  const files = [];
  let json = false, priceFile = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--json") json = true;
    else if (argv[i] === "--price-table") priceFile = argv[++i];
    else if (argv[i] === "-h" || argv[i] === "--help") { console.log("usage: jev-report [--json] [--price-table file.json] [ledger.jsonl ...]"); return 0; }
    else files.push(argv[i]);
  }
  const envErr = files.length ? null : ledgerEnvError();
  if (envErr) { console.error(envErr); return 2; }
  const inputs = files.length ? files : defaultLedgerFiles();
  if (inputs.length === 0) { console.error("jev-report: no ledger found (set JEV_LEDGER or pass a file)"); return 1; }
  for (const f of inputs) if (!existsSync(f)) { console.error(`jev-report: no such file: ${f}`); return 1; }
  let priceTable = null;
  if (priceFile) { try { priceTable = JSON.parse(readFileSync(priceFile, "utf8")); } catch { console.error("jev-report: price table is not valid JSON"); return 2; } }
  const { decisions, outcomes, skipped } = readLedgerFiles(inputs);
  const report = buildReport(decisions, outcomes, { priceTable });
  console.log(json ? JSON.stringify({ ...report, skipped_lines: skipped }, null, 2) : renderText(report, { skipped, files: inputs }));
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(main(process.argv.slice(2)));
