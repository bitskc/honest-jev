#!/usr/bin/env node
// Smoke run for kit_decide: calls the registered MCP tool handler (fake server, STUBBED upstream, no network, no
// credentials) with each shipped example and prints the decision and the content-free record for each path.
//   node tests/smoke-decide.mjs
// The upstream is a stub that returns fixed answer vectors; this proves the tool's plumbing, not Jev's accuracy.
import { readFileSync } from "node:fs";
import { registerDecideTool } from "../server/src/decide/tool.mjs";

const dir = new URL("../examples/decisions/", import.meta.url);
const read = (n) => JSON.parse(readFileSync(new URL(n, dir), "utf8"));
const tools = {};
let upstreamCalls = 0;
let answers = {};
const fetchImpl = async () => {
  upstreamCalls++;
  return { ok: true, status: 200, text: async () => "", json: async () => ({ answers, usage: { input_tokens: 210, output_tokens: 12, cost: 0.0006 }, model: "typesafe-ai/jev" }) };
};
const logs = [];
registerDecideTool({ registerTool: (name, cfg, h) => { tools[name] = { cfg, h }; } }, () => ({ AI_GATEWAY_API_KEY: "stub" }), { fetchImpl, log: (l) => logs.push(l) });

async function run(label, name, caseName) {
  const c = read(`${name}.cases.json`).find((x) => x.name === caseName);
  if (!c) throw new Error(`no case "${caseName}" in ${name}`);
  answers = c.answers;
  const before = upstreamCalls;
  const args = tools.kit_decide.cfg.inputSchema.parse({ spec: read(`${name}.json`), facts: c.facts, state: { note: "stub state" }, host: "smoke", correlation_id: "smoke-1" });
  const res = await tools.kit_decide.h(args);
  const p = JSON.parse(res.content[0].text);
  console.log(`\n== ${label}\n   decision=${p.decision} rule=${p.rule_id} decided_by=${p.decided_by} upstream_calls=${upstreamCalls - before} spec=${p.spec.id}@${p.spec.version}#${p.spec.hash}`);
  console.log(`   record ${JSON.stringify(p.record)}`);
}

await run("fact-only block (no model call)", "ask-before-migration", "production without backup is blocked from facts alone");
await run("model path: confident read", "route-read-or-full", "confident read");
await run("model path: held for tone", "support-reply-auto-send", "risky tone is held even when the rest is routine");
await run("failure path: omitted answer, fails open", "route-read-or-full", "omitted answer is a failure (open: equals baseline)");
console.log(`\nlog lines emitted: ${logs.length} (each is the record plus kind "jev.decision", the same line the fixed tools write)`);
