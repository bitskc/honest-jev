// node --test "hooks/jev-stop-verify-p2.test.mjs" (also covered by `node --test "hooks/**/*.test.mjs"`)
// Stop-gate P2s: #64/#93/#165 (the evidence fit is bounded by the kept runs, not the transcript), #28 (hook/server parity for the
// connection-error rule), #105 (the fail-open statuses 401/403 leave one stderr line). Data only: transcripts are text, nothing is executed.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const stopGate = require("./jev-stop-verify.js");
const cpu = () => { const u = process.cpuUsage(); return (u.user + u.system) / 1000; };

const ISOLATED = ["HOME", "CLAUDE_CONFIG_DIR", "XDG_STATE_HOME", "JEV_STOP_GATE", "JEV_MCP_URL", "JEV_MCP_TOKEN", "JEV_GUARD_TIMEOUT", "JEV_GUARD_DEBUG", "JEV_HONEST_DEFAULT_LEVEL"];
let saved;
test.beforeEach(() => { saved = Object.fromEntries(ISOLATED.map((k) => [k, process.env[k]])); process.env.XDG_STATE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), "state-")); process.env.HOME = process.env.XDG_STATE_HOME; process.env.CLAUDE_CONFIG_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "cfgdir-")); delete process.env.JEV_GUARD_DEBUG; });
test.afterEach(() => { for (const k of ISOLATED) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });
const setEnv = (gate) => { process.env.JEV_MCP_URL = "https://stub.invalid/mcp"; process.env.JEV_MCP_TOKEN = "super-secret-token-value"; process.env.JEV_GUARD_TIMEOUT = "3"; process.env.JEV_STOP_GATE = gate; };
const U = (t) => ({ type: "user", message: { role: "user", content: t } });
const A = (id, name, input) => ({ type: "assistant", message: { role: "assistant", content: [{ type: "tool_use", id, name, input }] } });
const R = (id, c) => ({ type: "user", toolUseResult: { stdout: c }, message: { role: "user", content: [{ type: "tool_result", tool_use_id: id, content: c, is_error: false }] } });
const writeLines = (lines) => { const p = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "transcript-")), "s.jsonl"); fs.writeFileSync(p, lines.map((l) => JSON.stringify(l)).join("\n") + "\n"); return p; };
const edit = () => [U("Fix."), A("e1", "Edit", { file_path: "src/a.js" }), R("e1", "ok")];

// ── #64 / #93 / #165 ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
// The reference is the fit as it was before the rewrite: re-render the kept set after every added run. It shares the evidence index (the priority
// order and the rendered lines), so what is compared is exactly the fill and the render.
function refEvidenceText(ev, budget) {
  const { header, line, afterIdx, staleIdx, priority, checkLine } = stopGate.evidenceIndex(ev);
  const section = (idxs, keep) => {
    const out = [];
    let gap = 0;
    for (const i of idxs) {
      if (!keep.has(i)) { gap += 1; continue; }
      if (gap) { out.push(`… ${gap} commands omitted`); gap = 0; }
      out.push(line(i));
    }
    if (gap) out.push(`… ${gap} commands omitted`);
    return out;
  };
  const render = (keep) => {
    const parts = [header];
    if (afterIdx.length) parts.push(checkLine, "Commands run after the edits:", ...section(afterIdx, keep));
    else parts.push("No commands were run after the edits.");
    if (staleIdx.length) {
      if (staleIdx.some((i) => keep.has(i))) parts.push("Commands run before the last edit (stale — do not count as verification of the edits):", ...section(staleIdx, keep));
      else parts.push(`… ${staleIdx.length} stale commands (run before the last edit) omitted`);
    }
    return parts.join("\n");
  };
  const keep = new Set();
  for (const i of priority) {
    keep.add(i);
    if (render(keep).length > budget) { keep.delete(i); break; }
  }
  return render(keep);
}
test("#64/#93: evidenceText equals the render-per-step fit on sampled evidence (seeded; every budget the gate uses and the extremes)", () => {
  let seed = 424242;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const pick = (a) => a[Math.floor(rnd() * a.length)];
  let cases = 0;
  for (let t = 0; t < 700; t++) {
    const nr = Math.floor(rnd() * (t % 50 === 0 ? 400 : 40));
    const runs = Array.from({ length: nr }, (_, i) => {
      const check = rnd() < 0.4;
      return { command: check ? pick(["npm test", "npx tsc --noEmit", "pytest -q", "cargo test", "make test", "npm run lint"]) + (rnd() < 0.3 ? ` -- x${i}` : "") : `${pick(["cat a.js", "ls", "grep x y", "git status"])} ${rnd() < 0.5 ? i : "z".repeat(Math.floor(rnd() * 400))}`,
        output: pick(["", "ok", "  12 passing", "1 failing", "x".repeat(Math.floor(rnd() * 1500))]), outcome: pick(["pass", "fail", "unknown"]), check, stale: rnd() < 0.3 };
    });
    const edits = Array.from({ length: Math.floor(rnd() * 60) }, (_, i) => `src/file${i}.js`);
    const ev = { edits, runs };
    for (const budget of [300, 800, 1135, 1500, 2000, 4500, 8000, 1e9]) {
      assert.equal(stopGate.evidenceText(ev, budget), refEvidenceText({ edits, runs: runs.map((r) => ({ ...r })) }, budget), `t=${t} budget=${budget}`);
      cases++;
    }
    assert.equal(stopGate.evidenceText(ev), refEvidenceText({ edits, runs: runs.map((r) => ({ ...r })) }, 8000)); // the default budget
  }
  assert.ok(cases >= 5600);
});
test("#93: the unbudgeted/default evidenceText over 2000 runs is fast (CPU time)", () => {
  const runs = Array.from({ length: 2000 }, (_, i) => ({ command: `cat src/f${i}.js`, output: `export const x = ${i};`, outcome: "pass", check: false, stale: false }));
  const ev = { edits: ["src/a.js"], runs };
  stopGate.evidenceText({ edits: ["a"], runs: runs.slice(0, 50).map((r) => ({ ...r })) }); // warm up
  const t = cpu();
  stopGate.evidenceText(ev);
  assert.ok(cpu() - t < 200, `${(cpu() - t).toFixed(0)} ms`);
});
// A synthetic Stop turn: one edit, `calls` Bash calls, a passing check last, a final message of `claims` claims (one jev_classify item each).
function bigTurn(calls, claims) {
  const noise = [];
  for (let i = 0; i < calls; i++) noise.push(A(`n${i}`, "Bash", { command: `cat src/f${i % 500}.js` }), R(`n${i}`, `export const x = ${i};`));
  const lines = [...edit(), ...noise, A("t1", "Bash", { command: "npm test" }), R("t1", "  42 passing (1s)")];
  return { transcript: writeLines(lines), message: Array.from({ length: claims }, (_, i) => `The module ${i} works and all tests pass.`).join(" ") };
}
const stubClassify = (calls) => (url, opts) => {
  const rpc = JSON.parse(opts.body);
  calls.push(rpc.params);
  const result = rpc.params.name === "kit_verify_done" ? { verified: true, verdict: "verified", answers: { discloses_unverified: { noul: 0.05 } } } : { results: rpc.params.arguments.items.map((i) => ({ id: i.id, classification: "verified", top_probability: 0.9, decision: "auto" })) };
  return Promise.resolve({ ok: true, status: 200, text: async () => JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: JSON.stringify(result) }] } }) });
};
test("#165: 763 claims over 28,000 tool calls (a 10 MB transcript) stay far under the 10 s Stop timeout (CPU time)", async () => {
  setEnv("both");
  const { transcript, message } = bigTurn(28000, 763);
  assert.ok(fs.statSync(transcript).size > 8_000_000, "the shape is a multi-megabyte transcript");
  const calls = [];
  const t = cpu();
  const out = await stopGate.decide({ transcript_path: transcript, last_assistant_message: message }, { fetchImpl: stubClassify(calls) });
  const ms = cpu() - t;
  assert.equal(out, null);
  assert.equal(calls.filter((c) => c.name === "jev_classify").flatMap((c) => c.arguments.items).length, 763, "every claim reached the classifier");
  assert.ok(ms < 5000, `${ms.toFixed(0)} ms CPU (measured ~1.1 s; it was 12.5 s with the render-per-step fit)`);
});
test("#64: 11,000 calls (about 4 MB) x 300 claims: every item still fits 2000 characters with the passing run and both markers", async () => {
  setEnv("both");
  const { transcript, message } = bigTurn(11000, 300);
  assert.ok(fs.statSync(transcript).size > 3_500_000);
  const calls = [];
  const t = cpu();
  await stopGate.decide({ transcript_path: transcript, last_assistant_message: message }, { fetchImpl: stubClassify(calls) });
  const ms = cpu() - t;
  const items = calls.filter((c) => c.name === "jev_classify").flatMap((c) => c.arguments.items);
  assert.equal(items.length, 300);
  for (const item of items) {
    assert.ok(item.text.length <= 2000, `item ${item.id} is ${item.text.length}`);
    assert.match(item.text, /`npm test` -> ok/);
    assert.match(item.text, /\[\/tool-log:[0-9a-f]{16}\]$/);
  }
  assert.ok(ms < 3000, `${ms.toFixed(0)} ms CPU`);
});
test("#64: the items are built before the first MCP call starts (no abort timer is armed during the build)", async () => {
  setEnv("both");
  const { transcript, message } = bigTurn(3000, 120);
  let firstFetchAt = null;
  const calls = [];
  const inner = stubClassify(calls);
  const t0 = cpu();
  await stopGate.decide({ transcript_path: transcript, last_assistant_message: message }, { fetchImpl: (u, o) => { if (firstFetchAt === null) firstFetchAt = cpu(); return inner(u, o); } });
  const total = cpu() - t0;
  // the verify call is the first fetch; every classify item was already built when it went out, so almost all of the CPU time precedes it
  assert.ok(firstFetchAt - t0 > total * 0.6, `first fetch at ${(firstFetchAt - t0).toFixed(0)} of ${total.toFixed(0)} ms CPU`);
});

// ── #28: hook and server share the rule ─────────────────────────────────────────────────────────────────────────────────────────────────
test("#28 parity: the hook's runOutcome equals the server's on the connection-error cases", async () => {
  const server = await import("../server/src/kit/verify.mjs");
  const out = "  12 passing (1s)\nscripts/e2e.js: connection refused";
  for (const [command, output, exit] of [["npm test", out, undefined], ["npm test", out, 0], ["npm test", out, 1], ["npm test | tail -5", out, 0], ["npm test", "  ✓ retries on ECONNREFUSED\n  12 passing", undefined],
    ["npm test", "  12 passing\nError: connect ECONNREFUSED 127.0.0.1:5432", undefined], ["npm test", "  12 passing", undefined], ["npm test", `${out}\n  1 failing`, undefined]]) {
    assert.equal(stopGate.runOutcome(command, output, exit), server.runOutcome(command, output, exit), `${command} | ${JSON.stringify(output).slice(0, 40)} | ${exit}`);
  }
  assert.equal(stopGate.runOutcome("npm test", out, undefined), "unknown");
});

// ── #105: 401/403 are the one fail-open class that gets a stderr line ───────────────────────────────────────────────────────────────────
async function stopWithStatus(status, body = "upstream says no") {
  setEnv("verify");
  const writes = [];
  const orig = process.stderr.write;
  process.stderr.write = (chunk, ...rest) => { writes.push(String(chunk)); return true; };
  let out;
  try {
    out = await stopGate.decide({ transcript_path: writeLines(edit()), last_assistant_message: "Fixed, all tests pass." }, { fetchImpl: async () => ({ ok: false, status, text: async () => body }) });
  } finally { process.stderr.write = orig; }
  return { out, writes };
}
test("#105: 401 and 403 fail open with ONE content-free stderr line that is not gated on JEV_GUARD_DEBUG", async () => {
  for (const status of [401, 403]) {
    const { out, writes } = await stopWithStatus(status, "Bearer super-secret-token-value is expired");
    assert.equal(out, null, `HTTP ${status} fails open`);
    assert.equal(writes.length, 1, `HTTP ${status}: ${JSON.stringify(writes)}`);
    assert.match(writes[0], new RegExp(`WARNING kit_verify_done was refused with HTTP ${status} \\(check JEV_MCP_TOKEN\\); the stop gate is NOT checking this turn\\n$`));
    assert.ok(!writes[0].includes("super-secret-token-value") && !writes[0].includes("expired"), "neither the token nor the response body is echoed");
  }
});
test("#105: 429, 408, 404 and 5xx stay silent (debug notes only); 400/413/422 still block", async () => {
  for (const status of [404, 408, 429, 500, 503, 504]) {
    const { out, writes } = await stopWithStatus(status);
    assert.equal(out, null, `HTTP ${status} fails open`);
    assert.deepEqual(writes, [], `HTTP ${status} is quiet without JEV_GUARD_DEBUG`);
  }
  for (const status of [400, 413, 422]) {
    const { out } = await stopWithStatus(status, "payload rejected");
    assert.ok(out && out.decision === "block", `HTTP ${status}`);
  }
});

// ── #182 P4: one warning per stop, however many calls are refused ───────────────────────────────────────────────────────────────────────
test("#182: 401 on every call (verify + three classify chunks for 150 claims) prints ONE warning line, not one per call", async () => {
  setEnv("both");
  const writes = [];
  const orig = process.stderr.write;
  process.stderr.write = (chunk) => { writes.push(String(chunk)); return true; };
  const calls = [];
  try {
    const message = Array.from({ length: 150 }, (_, i) => `The module ${i} works and all tests pass.`).join(" ");
    const out = await stopGate.decide({ transcript_path: writeLines(edit()), last_assistant_message: message }, { fetchImpl: async (u, o) => { calls.push(JSON.parse(o.body).params.name); return { ok: false, status: 401, text: async () => "expired" }; } });
    assert.equal(out, null, "401 fails open");
  } finally { process.stderr.write = orig; }
  assert.ok(calls.length >= 4, `verify and every classify chunk were refused: ${calls.join(",")}`);
  const warnings = writes.filter((w) => /WARNING/.test(w));
  assert.equal(warnings.length, 1, JSON.stringify(warnings));
  assert.match(warnings[0], /HTTP 401 \(check JEV_MCP_TOKEN\)/);
});
