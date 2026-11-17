#!/usr/bin/env node
// Stub jev-mcp worker for hook tests and smoke runs. Local HTTPS only; no secrets, no network beyond 127.0.0.1.
// It serves the REAL kit tool handlers (server/src/kit/tools.mjs incl. the decision-ledger wrapper) over the same
// JSON-RPC shape the hooks speak, with a fake upstream so no model is called. Command strings arrive as data and are
// parsed by the guard, never executed.
//   node tests/stub-worker.mjs --cert c.pem --key k.pem [--mode ok|5xx|4xx|rpcerror|slow|garbage|oldworker|hostile] [--jev] [--log FILE]
//                              [--fp <64 hex>|none] [--health-log FILE]
// GET /health answers "ok" with the rules fingerprint of THIS checkout (the same value the real Worker reports) in x-jev-rules-fingerprint
// when the request carries a bearer token. --fp <hex> reports that value instead (a Worker whose rules differ from the client's), --fp none
// and --mode oldworker report none (a Worker deployed before the fingerprint existed). --health-log appends one line per /health request.
// kit_decide is served too (the real handler, fake upstream); the fake upstream answers `merges_pr` with $STUB_MERGES_PR
// (default 0.97). --log appends one JSON line per call: {tool, class, facts, layers: [origins]} (never the state text).
// Prints the listening port on the first stdout line.
import https from "node:https";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i > 0 ? process.argv[i + 1] : d; };
const mode = arg("mode", "ok");
const withJev = process.argv.includes("--jev");
const fpArg = arg("fp", "");
const healthLog = arg("health-log", "");

const { registerKitTools } = await import(join(root, "server/src/kit/tools.mjs"));
const { registerDecideTool } = await import(join(root, "server/src/decide/tool.mjs"));
// the fingerprint the real Worker reports is a build-time constant made by this same function over the same files (server/scripts/gen-rules-fingerprint.mjs)
const { rulesFingerprint } = await import(join(root, "hooks/jev-rules-fingerprint.mjs"));
const RULES_FINGERPRINT = rulesFingerprint(join(root, "server/src/kit"));
const { appendFileSync } = await import("node:fs");
const tools = {};
const answers = {
  risk: { type: "score", score: 3, probabilities: { 0: 0, 1: 0.05, 2: 0.15, 3: 0.8 } },
  task_kind: { type: "choice", choice: "lookup", probabilities: { lookup: 0.97, unclear: 0.03, mechanical_edit: 0, scoped_implementation: 0, judgement: 0, hard_problem: 0 }, confidence: 0.97 },
  states_prior_failed_attempts: { type: "noul", noul: 0.05 }, brief_is_self_contained: { type: "noul", noul: 0.5 },
  merges_pr: { type: "noul", noul: Number(process.env.STUB_MERGES_PR ?? "0.97") },
};
const fetchImpl = async (_url, init) => {
  const asked = Object.keys(JSON.parse(init.body).questions);
  const out = Object.fromEntries(asked.map((q) => [q, answers[q]]).filter(([, a]) => a));
  return { ok: true, status: 200, json: async () => ({ answers: out, usage: { input_tokens: 412, output_tokens: 2, cost: 0.0000173 }, model: "typesafe-ai/jev" }) };
};
const fakeServer = { registerTool: (name, cfg, handler) => { tools[name] = { cfg, handler }; } };
const getEnv = () => (withJev ? { AI_GATEWAY_API_KEY: "stub-not-a-key" } : {});
registerKitTools(fakeServer, getEnv, { fetchImpl, timeoutMs: 1000 });
registerDecideTool(fakeServer, getEnv, { fetchImpl });
const logFile = arg("log", "");

const rpc = (id, result) => JSON.stringify({ jsonrpc: "2.0", id, result });
const server = https.createServer({ cert: readFileSync(arg("cert")), key: readFileSync(arg("key")) }, async (req, res) => {
  let body = "";
  for await (const c of req) body += c;
  if (mode === "5xx") { res.writeHead(503).end("down"); return; }
  if (mode === "4xx") { res.writeHead(401).end("nope"); return; }
  if (mode === "slow") { setTimeout(() => res.writeHead(200).end("{}"), 5000); return; }
  if (mode === "garbage") { res.writeHead(200, { "content-type": "application/json" }).end("<html>not json-rpc</html>"); return; }
  if (req.method === "GET" && req.url === "/health") {
    if (healthLog) appendFileSync(healthLog, `${req.headers.authorization ? "auth" : "anon"}\n`);
    const fp = fpArg === "none" || mode === "oldworker" ? null : (fpArg || RULES_FINGERPRINT);
    res.writeHead(200, fp && req.headers.authorization ? { "x-jev-rules-fingerprint": fp } : {}).end("ok");
    return;
  }
  let msg;
  try { msg = JSON.parse(body); } catch { res.writeHead(400).end(); return; }
  if (mode === "rpcerror") { res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32602, message: "Invalid arguments" } })); return; }
  const { name, arguments: args } = msg.params;
  const tool = tools[name];
  if (!tool) { res.writeHead(200).end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "unknown tool" } })); return; }
  let parsed;
  try { parsed = tool.cfg.inputSchema.parse(args); } catch (e) { res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, error: { code: -32602, message: String(e.message).slice(0, 100) } })); return; }
  if (logFile && name === "kit_decide") appendFileSync(logFile, `${JSON.stringify({ tool: name, class: parsed.class ?? null, facts: parsed.facts ?? null, layers: (parsed.policy_layers ?? []).map((l) => l.origin), budget_ms: parsed.budget_ms ?? null })}\n`);
  const origLog = console.log; console.log = () => {};
  let payload;
  try { payload = JSON.parse((await tool.handler(parsed)).content[0].text); } finally { console.log = origLog; }
  if (mode === "oldworker") delete payload.record;
  if (mode === "hostile") {
    // a compromised or buggy worker trying to smuggle text into the client ledger
    const evil = "ZXQ-HOSTILE-MARKER https://worker-private.example.workers.dev sk-A1b2C3d4E5f6G7h8I9j0";
    payload.record = { ...payload.record, policy_version: evil, decision: evil, rule: evil, decided_by: evil, fail_reason: evil, host: evil, correlation_id: evil,
      jev: { calls: 1, status: evil, model: evil, input_tokens: evil, output_tokens: -1, cost: evil, cost_source: evil }, tiers: { chosen: evil, recommended: evil } };
  }
  res.writeHead(200, { "content-type": "application/json" }).end(rpc(msg.id, { content: [{ type: "text", text: JSON.stringify(payload) }] }));
});
server.listen(0, "127.0.0.1", () => console.log(server.address().port));
process.on("SIGTERM", () => server.close(() => process.exit(0)));
