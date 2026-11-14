#!/usr/bin/env node
// Smoke run for policy layers: author a class with the jev-policy CLI from a spec an agent would derive from the request
// "always ask me before any PR merge if it isn't gstack reviewed", test it offline, then call kit_decide with `class`,
// resolving it from the layer files the CLI forwards, against a STUBBED upstream (no network, no credentials).
//   node tests/smoke-policy.mjs
// The stub upstream decides by a trivial substring check on the state text. It stands in for Jev; this proves the
// plumbing (files -> CLI -> args -> Worker merge -> decision -> record), not Jev's accuracy.
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { registerDecideTool } from "../server/src/decide/tool.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const CLI = join(here, "..", "scripts", "jev-policy.mjs");
const root = mkdtempSync(join(tmpdir(), "jev-policy-smoke-"));
const proj = join(root, "proj");
mkdirSync(proj);
const user = join(root, "user-policy.json");
const env = { PATH: process.env.PATH, HOME: root, JEV_POLICY_USER: user };
const cli = (...a) => { const r = spawnSync(process.execPath, [CLI, ...a], { cwd: proj, env, encoding: "utf8" }); return { code: r.status, out: r.stdout.trim(), err: r.stderr.trim() }; };
const show = (label, r) => { console.log(`\n$ jev-policy ${label}   (exit ${r.code})`); if (r.out) console.log(r.out.split("\n").map((l) => `  ${l.slice(0, 190)}`).join("\n")); if (r.err) console.log(r.err.split("\n").map((l) => `  ! ${l.slice(0, 190)}`).join("\n")); return r; };

try {
  // the spec the agent writes from the sentence (checked in as the shipped example)
  const draft = join(here, "..", "examples", "policies", "pr-merge-gate.json");
  // a repo-side copy with one extra restrictive rule, as a project might commit
  const spec = JSON.parse(readFileSync(draft, "utf8"));
  spec.rules.unshift({ id: "R0-ask-when-review-unknown", when: { all: [{ noul: "merges_pr", gte: 0.5, missing_as: 1 }, { fact: "gstack_reviewed", exists: false }] }, decision: "ask_user", reason: "Review status unknown: ask." });
  spec.examples = spec.examples.map((e) => (e.name.startsWith("review status not supplied") ? { ...e, expect: { decision: "ask_user", rule_id: "R0-ask-when-review-unknown" } } : e));
  const repoDraft = join(root, "repo-draft.json");
  writeFileSync(repoDraft, JSON.stringify(spec));

  show(`check --spec examples/policies/pr-merge-gate.json`, cli("check", "--spec", draft));
  show(`add ... --layer user   (no --yes)`, cli("add", draft, "--layer", "user"));
  show(`add ... --layer user --yes`, cli("add", draft, "--layer", "user", "--yes"));
  show(`add <repo copy + 1 restrictive rule> --layer repo`, cli("add", repoDraft, "--layer", "repo"));
  show(`list`, cli("list"));
  show(`test pr-merge-gate --facts '{"gstack_reviewed":true}' --answers merges_pr=0.95`, cli("test", "pr-merge-gate", "--facts", '{"gstack_reviewed":true}', "--answers", JSON.stringify({ merges_pr: { type: "noul", noul: 0.95 } })));

  // stub upstream: 0.97 when the action text looks like a merge, else 0.02
  const tools = {};
  let upstreamCalls = 0;
  const fetchImpl = async (_u, init) => {
    upstreamCalls++;
    const body = JSON.parse(init.body);
    const merge = /gh pr merge/.test(JSON.stringify(body.state));
    return { ok: true, status: 200, text: async () => "", json: async () => ({ answers: { merges_pr: { type: "noul", noul: merge ? 0.97 : 0.02 } }, usage: { input_tokens: 150, output_tokens: 4, cost: 0.0003 }, model: "typesafe-ai/jev" }) };
  };
  registerDecideTool({ registerTool: (name, cfg, h) => { tools[name] = { cfg, h }; } }, () => ({ AI_GATEWAY_API_KEY: "stub" }), { fetchImpl, log: () => {} });

  for (const [label, facts, text] of [
    ["unreviewed merge", { gstack_reviewed: false }, "gh pr merge 12 --squash"],
    ["reviewed merge", { gstack_reviewed: true }, "gh pr merge 12 --squash"],
    ["not a merge", { gstack_reviewed: false }, "gh pr view 12"],
    ["merge, review status not supplied", {}, "gh pr merge 12"],
  ]) {
    const a = cli("args", "pr-merge-gate", "--facts", JSON.stringify(facts), "--state", JSON.stringify({ action: { text } }), "--host", "smoke");
    const args = JSON.parse(a.out);
    const before = upstreamCalls;
    const res = await tools.kit_decide.h(tools.kit_decide.cfg.inputSchema.parse(args));
    const p = JSON.parse(res.content[0].text);
    console.log(`\n== kit_decide class=pr-merge-gate  [${label}]  facts=${JSON.stringify(facts)}`);
    console.log(`   decision=${p.decision} rule=${p.rule_id} decided_by=${p.decided_by} upstream_calls=${upstreamCalls - before} origins=${p.policy.origins.join("+")} tightened_by=${p.policy.tightened_by.join(",") || "-"} policy_version=${p.policy.version}`);
    console.log(`   record.policy_version=${p.record.policy_version} record=${JSON.stringify({ tool: p.record.tool, decision: p.record.decision, decided_by: p.record.decided_by, rule: p.record.rule, policy_version: p.record.policy_version })}`);
  }
  const unknown = JSON.parse((await tools.kit_decide.h({ class: "no-such-class", policy_layers: [] })).content[0].text);
  console.log(`\n== unknown class -> error=${unknown.error} (no decision, no upstream call)`);
} finally {
  rmSync(root, { recursive: true, force: true });
}
