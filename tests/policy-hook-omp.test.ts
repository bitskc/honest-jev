// omp guard hook, policy path (openspec add-policy-hook-adapter). Data only; run with bun:
//   bun test tests/policy-hook-omp.test.ts
// The omp import is stubbed and `fetch` is faked (it answers kit_guard_command and kit_decide separately): no network, no
// omp. The real plan helper (scripts/jev-policy-hook.mjs) runs against a temp user layer, a temp git repo and a stub `gh`
// on PATH. Command strings below are data: the hook never executes them, and the hostile-command test proves it.
import { afterAll, beforeEach, expect, mock, test } from "bun:test";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

mock.module("@oh-my-pi/pi-coding-agent", () => ({ isToolCallEventType: (name: string, e: { toolName?: string }) => e.toolName === name }));

const dir = mkdtempSync(join(tmpdir(), "jev-policy-omp-"));
afterAll(() => { globalThis.fetch = realFetch; rmSync(dir, { recursive: true, force: true }); });
const LEDGER = join(dir, "state", "ledger.jsonl");
mkdirSync(join(dir, "state"), { mode: 0o700 });
const REPO = join(dir, "repo");
mkdirSync(REPO);
spawnSync("git", ["init", "-q", REPO]);
const BIN = join(dir, "bin");
mkdirSync(BIN);
const ARGV_LOG = join(dir, "gh-argv.log");
const MARKER = join(dir, "helper-ran");
const TOUCHED = join(dir, "touched-by-command");
const HELPER = join(import.meta.dir, "..", "scripts", "jev-policy-hook.mjs");

// stub gh: STUB_GH picks the answer; every call's argv is appended to STUB_GH_ARGV
writeFileSync(join(BIN, "gh"), `#!/bin/sh
[ -n "$STUB_GH_ARGV" ] && printf '%s\\n' "$*" >> "$STUB_GH_ARGV"
case "$STUB_GH" in
  reviewed) printf '%s' '{"comments":[{"body":"gstack-review: pass"}],"reviews":[]}' ;;
  unreviewed) printf '%s' '{"comments":[{"body":"looks fine"}],"reviews":[]}' ;;
  by_pr) case " $STUB_GH_PRS " in *" $3 "*) printf '%s' '{"comments":[{"body":"gstack-review: pass"}],"reviews":[]}' ;; *) printf '%s' '{"comments":[{"body":"looks fine"}],"reviews":[]}' ;; esac ;;
  fail) exit 1 ;;
  garbage) printf 'this is not json' ;;
  hang) exec sleep 30 ;;
esac
`);
chmodSync(join(BIN, "gh"), 0o755);
// a "helper" that only proves it was started
const MARKER_HELPER = join(dir, "marker-helper.mjs");
writeFileSync(MARKER_HELPER, `import { writeFileSync } from "node:fs"; writeFileSync(${JSON.stringify(MARKER)}, "ran");\n`);

// ---- policy layers ------------------------------------------------------------------------------------------------
// the shipped example may already carry its own trigger: this file attaches its own, so strip any
const { trigger: _shipped, ...base } = JSON.parse(readFileSync(join(import.meta.dir, "..", "examples", "policies", "pr-merge-gate.json"), "utf8"));
const TRIGGER = { tool: "Bash", command: ["gh", "pr", "merge"], facts: { pr: { source: "gh_pr_target" }, gstack_reviewed: { source: "gh_pr_review_marker", marker: "gstack-review: pass", target_from: "pr" } }, effect: { ask_user: "ask" } };
const layerFile = (name: string, decisions: unknown[]) => {
  const p = join(dir, name);
  writeFileSync(p, JSON.stringify({ v: 1, decisions }));
  return p;
};
const withoutFailClosedExample = base.examples.filter((e: { expect: { decided_by?: string } }) => e.expect.decided_by !== "fail_closed");
const LAYERS = {
  one: layerFile("one.json", [{ ...base, trigger: TRIGGER }]),
  two: layerFile("two.json", [{ ...base, trigger: TRIGGER }, { ...base, id: "second-gate", trigger: { tool: "Bash", command: ["gh"] } }]),
  deny: layerFile("deny.json", [{ ...base, trigger: { ...TRIGGER, effect: { ask_user: "deny" } } }]),
  open: layerFile("open.json", [{ ...base, examples: withoutFailClosedExample, on_unavailable: { decision: "proceed", reason: "The model could not be consulted: proceed." }, trigger: TRIGGER }]),
  none: layerFile("none.json", [base]),
};

// ---- environment (the hook reads JEV_* at module load, so this precedes the dynamic import) --------------------------
process.env.JEV_MCP_URL = "https://worker-private.example.workers.dev/mcp";
process.env.JEV_MCP_TOKEN = "stub-token";
process.env.JEV_GUARD_LOCAL = "off"; // these tests are about the server path; the local rules are covered by tests/local-first-omp.test.ts
process.env.JEV_LEDGER = LEDGER;
process.env.JEV_GUARD_ASK_NO_UI = "block";
process.env.STUB_GH_ARGV = ARGV_LOG;
process.env.PATH = `${BIN}:${process.env.PATH}`;
delete process.env.JEV_POLICY_TIMEOUT;

const realFetch = globalThis.fetch;
type Call = { name: string; args: Record<string, any>; headers: Record<string, string>; redirect?: string; url: string };
let calls: Call[] = [];
let guardReply: unknown;
let decideReply: () => Promise<Response>;
const rpc = (payload: unknown) => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: JSON.stringify(payload) }] } }));
globalThis.fetch = (async (url: string, init: RequestInit) => {
  const body = JSON.parse(String(init.body));
  const name = body.params.name as string;
  calls.push({ name, args: body.params.arguments, headers: init.headers as Record<string, string>, redirect: init.redirect, url });
  return name === "kit_decide" ? decideReply() : rpc(guardReply);
}) as typeof fetch;

const mod = await import("../hooks/omp/jev-guard.ts");

const ALLOW = { decision: "allow", rule: null, reason: "", decided_by: "prefilter" };
const ASK_REPLY = {
  tool: "kit_decide", decision: "ask_user", rule_id: "R1-unreviewed-merge", reason: "A pull request merge that has not been gstack reviewed: ask the user first.", decided_by: "jev", fail_reason: null,
  record: { v: 1, tool: "kit_decide", decision: "ask_user", decided_by: "jev", rule: "R1-unreviewed-merge", fail_reason: null, jev: { calls: 0 }, policy_version: "0123456789ab", host: "omp", source: "server" },
};
const PROCEED_REPLY = { ...ASK_REPLY, decision: "proceed", rule_id: "R3-reviewed-merge", reason: "A merge, and it has been gstack reviewed.", record: { ...ASK_REPLY.record, decision: "proceed", rule: "R3-reviewed-merge" } };

let confirms: { title: string; message: string }[] = [];
const ctx = (answer?: boolean) => ({
  cwd: REPO, hasUI: answer !== undefined,
  ui: { confirm: async (title: string, message: string) => { confirms.push({ title, message }); return answer === true; } },
});
const makeHandler = (m: typeof mod) => {
  let h: (e: unknown, c: unknown) => Promise<any>;
  m.default({ on: (_: string, f: typeof h) => { h = f; }, logger: { warn() {} } } as never);
  return async (e: unknown, c: unknown) => {
    const v = await h!(e, c);
    const { promise, resolve } = Promise.withResolvers<void>(); // ledger writes are queued after the verdict
    setImmediate(resolve);
    await promise;
    return v;
  };
};
const run = makeHandler(mod);
const runShadow = async (...a: Parameters<typeof run>) => { // the mode is read per call
  process.env.JEV_GUARD_MODE = "shadow";
  try { return await run(...a); } finally { delete process.env.JEV_GUARD_MODE; }
};
const bash = (command: string) => ({ toolName: "bash", input: { command } });
const rows = () => (existsSync(LEDGER) ? readFileSync(LEDGER, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const policyRows = () => rows().filter((r) => r.tool === "kit_decide");
const guardRows = () => rows().filter((r) => r.tool === "kit_guard_command");
const decides = () => calls.filter((c) => c.name === "kit_decide");
const MERGE = "gh pr merge 12 --squash";

beforeEach(() => {
  for (const f of [LEDGER, ARGV_LOG, MARKER, TOUCHED]) rmSync(f, { force: true });
  calls = []; confirms = [];
  guardReply = ALLOW;
  decideReply = async () => rpc(ASK_REPLY);
  process.env.STUB_GH = "unreviewed";
  process.env.JEV_POLICY_USER = LAYERS.one;
  process.env.JEV_POLICY_HOOK = HELPER;
});

// ---- the path itself ----------------------------------------------------------------------------------------------
test("unreviewed merge asks: the user is asked once, with a reason naming the class and rule; one kit_decide call with the facts", async () => {
  const v = await run(bash(MERGE), ctx(false));
  expect(confirms.length).toBe(1);
  expect(confirms[0].message).toContain("Jev policy [pr-merge-gate/R1-unreviewed-merge]: A pull request merge that has not been gstack reviewed");
  expect(v.block).toBe(true);
  expect(v.reason.split("\n")[0]).toBe("Jev policy · declined");
  expect(v.reason.endsWith("Next: don't retry as-is; ask the user.")).toBe(true);
  const d = decides();
  expect(d.length).toBe(1);
  expect(d[0].args.class).toBe("pr-merge-gate");
  expect(d[0].args.facts).toEqual({ gstack_reviewed: false }); // the pr target only feeds the provider; the spec never reads it
  expect(d[0].args.host).toBe("omp");
  expect(d[0].args.state.action).toEqual({ tool: "Bash", text: MERGE });
  expect(d[0].args.policy_layers[0].origin).toBe("user");
  expect(Number.isInteger(d[0].args.budget_ms) && d[0].args.budget_ms >= 300 && d[0].args.budget_ms <= 3000).toBe(true);
  expect(d[0].headers.authorization).toBe("Bearer stub-token");
  expect(d[0].headers["user-agent"]).toBe("jev-guard-hook-omp/1.0");
  expect(d[0].redirect).toBe("error");
  expect(readFileSync(ARGV_LOG, "utf8").trim()).toBe("pr view 12 --json comments,reviews");
  // the outcome is recorded for the policy row
  const pr = policyRows();
  expect(pr.length).toBe(1);
  expect(rows().find((r) => r.label === "denied")?.decision_id).toBe(pr[0].decision_id);
});

test("an approved ask lets the command through", async () => {
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(confirms.length).toBe(1);
  expect(rows().find((r) => r.label === "approved")?.decision_id).toBe(policyRows()[0].decision_id);
});

test("no UI: the ask blocks with the usual needs-approval text", async () => {
  const v = await run(bash(MERGE), ctx());
  expect(v.block).toBe(true);
  expect(v.reason.split("\n")[0]).toBe("Jev policy · needs approval");
  expect(v.reason.endsWith("Next: don't retry as-is; ask the user.")).toBe(true);
  expect(rows().find((r) => r.label === "no_ui")?.decision_id).toBe(policyRows()[0].decision_id);
});

test("guard ask with suggestion: confirm shows Safer: route; decline tells the agent not to retry the same command", async () => {
  process.env.JEV_POLICY_USER = LAYERS.none; // no policy so only the guard speaks
  guardReply = {
    decision: "ask",
    rule: "R1-secret-exposure",
    reason: "`node` reads its script from stdin; confirm it is intended",
    suggestion: "Write the script to a file and run it as node path/script.js",
    decided_by: "prefilter",
  };
  const declined = await run(bash("cat x.js | node"), ctx(false));
  expect(confirms[0].title).toBe("Jev guard · R1-secret-exposure · ask");
  expect(confirms[0].message).toContain("Safer: Write the script to a file");
  expect(confirms[0].message).not.toContain("Next:");
  expect(declined.reason.split("\n")[0]).toBe("Jev guard · R1-secret-exposure · declined");
  expect(declined.reason).toContain("Safer: Write the script to a file");
  expect(declined.reason.endsWith("Next: don't retry as-is; use Safer or ask the user.")).toBe(true);
});

test("reviewed merge: the class proceeds, nothing is shown", async () => {
  process.env.STUB_GH = "reviewed";
  decideReply = async () => rpc(PROCEED_REPLY);
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(confirms.length).toBe(0);
  expect(decides()[0].args.facts).toEqual({ gstack_reviewed: true });
});

test("guard block + policy proceed: block (the stricter of the two)", async () => {
  process.env.STUB_GH = "reviewed";
  guardReply = { decision: "block", rule: "R1-secret-exposure", reason: "guard says no", decided_by: "prefilter" };
  decideReply = async () => rpc(PROCEED_REPLY);
  const v = await run(bash(MERGE), ctx(true));
  expect(v.block).toBe(true);
  expect(v.reason).toBe("Jev guard · R1-secret-exposure · block: guard says no\nNext: don't retry as-is; ask the user.");
  expect(confirms.length).toBe(0);
});

test("guard allow + policy ask: ask", async () => {
  const v = await run(bash(MERGE), ctx(true));
  expect(v).toBeUndefined();
  expect(confirms.length).toBe(1);
  expect(confirms[0].title).toBe("Jev policy · ask");
  expect(confirms[0].message.startsWith("Jev policy [")).toBe(true);
});

test("guard ask + policy ask: one prompt with both reasons, the outcome lands on both rows", async () => {
  guardReply = { decision: "ask", rule: "R9", reason: "guard wants a look", decided_by: "jev" };
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(confirms.length).toBe(1);
  expect(confirms[0].title).toBe("Jev guard · R9 · ask");
  expect(confirms[0].message).toBe("Why: guard wants a look\n\nJev policy [pr-merge-gate/R1-unreviewed-merge]: A pull request merge that has not been gstack reviewed: ask the user first.");
  const approved = rows().filter((r) => r.label === "approved").map((r) => r.decision_id).sort();
  expect(approved).toEqual([guardRows()[0].decision_id, policyRows()[0].decision_id].sort());
});

test("guard block + policy ask: the guard's block wins and nobody is asked", async () => {
  guardReply = { decision: "block", rule: "R1-secret-exposure", reason: "guard says no", decided_by: "prefilter" };
  const v = await run(bash(MERGE), ctx(true));
  expect(v.block).toBe(true);
  expect(v.reason).toContain("Jev guard · R1-secret-exposure · block");
  expect(confirms.length).toBe(0);
});

test("policy deny blocks with the policy's reason", async () => {
  process.env.JEV_POLICY_USER = LAYERS.deny;
  const v = await run(bash(MERGE), ctx(true));
  expect(v.block).toBe(true);
  expect(v.reason).toContain("Jev policy [pr-merge-gate/R1-unreviewed-merge]");
  expect(confirms.length).toBe(0);
});

test("a decision word the plan does not map asks", async () => {
  decideReply = async () => rpc({ ...ASK_REPLY, decision: "something_else", record: null });
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(confirms.length).toBe(1);
});

test("a command that does not trigger (gh pr view) makes no kit_decide call and no gh call", async () => {
  expect(await run(bash("gh pr view 3"), ctx(true))).toBeUndefined();
  expect(decides().length).toBe(0);
  expect(calls.filter((c) => c.name === "kit_guard_command").length).toBe(1);
  expect(existsSync(ARGV_LOG)).toBe(false);
  expect(policyRows().length).toBe(0);
});

test("two classes match: ask, say another gate applies, evaluate neither", async () => {
  process.env.JEV_POLICY_USER = LAYERS.two;
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(confirms.length).toBe(1);
  expect(confirms[0].message).toContain("another policy gate also applies");
  expect(decides().length).toBe(0);
  expect(policyRows()[0]).toMatchObject({ tool: "kit_decide", decision: "ask", decided_by: "policy" });
});

// ---- opt-in gate ---------------------------------------------------------------------------------------------------
test("no trigger text in the user layer: no process, no kit_decide call (positive control: with a trigger the helper runs)", async () => {
  process.env.JEV_POLICY_HOOK = MARKER_HELPER;
  process.env.JEV_POLICY_USER = LAYERS.none;
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(existsSync(MARKER)).toBe(false);
  expect(decides().length).toBe(0);
  expect(policyRows().length).toBe(0);
  process.env.JEV_POLICY_USER = LAYERS.one;
  await run(bash(MERGE), ctx(true));
  expect(existsSync(MARKER)).toBe(true);
});

test("no user layer file at all: nothing starts", async () => {
  process.env.JEV_POLICY_HOOK = MARKER_HELPER;
  process.env.JEV_POLICY_USER = join(dir, "does-not-exist.json");
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(existsSync(MARKER)).toBe(false);
  expect(decides().length).toBe(0);
});

test("only the bash tool takes the policy path", async () => {
  process.env.JEV_POLICY_HOOK = MARKER_HELPER;
  await run({ toolName: "read", input: { path: "/tmp/x" } }, ctx(true));
  expect(existsSync(MARKER)).toBe(false);
});

test("userLayerHasTrigger / policyDeadlineMs", () => {
  const env = (o: Record<string, string>) => o;
  expect(mod.userLayerHasTrigger(env({ JEV_POLICY_USER: LAYERS.one }), REPO)).toBe(true);
  expect(mod.userLayerHasTrigger(env({ JEV_POLICY_USER: LAYERS.none }), REPO)).toBe(false);
  expect(mod.userLayerHasTrigger(env({ JEV_POLICY_USER: join(dir, "nope.json") }), REPO)).toBe(false);
  const link = join(dir, "link.json");
  symlinkSync(LAYERS.one, link);
  expect(mod.userLayerHasTrigger(env({ JEV_POLICY_USER: link }), REPO)).toBe(false); // never through a symlink
  const big = join(dir, "big.json");
  writeFileSync(big, `{"trigger":1,"pad":"${"x".repeat(17000)}"}`);
  expect(mod.userLayerHasTrigger(env({ JEV_POLICY_USER: big }), REPO)).toBe(false); // over 16 KB
  expect(mod.userLayerHasTrigger(env({ XDG_CONFIG_HOME: dir, HOME: dir }), REPO)).toBe(false); // default path, absent
  expect(mod.policyDeadlineMs({})).toBe(3000);
  expect(mod.policyDeadlineMs({ JEV_POLICY_TIMEOUT: "2" })).toBe(2000);
  expect(mod.policyDeadlineMs({ JEV_POLICY_TIMEOUT: "99" })).toBe(4000);
  expect(mod.policyDeadlineMs({ JEV_POLICY_TIMEOUT: "0.2" })).toBe(1000);
  expect(mod.policyDeadlineMs({ JEV_POLICY_TIMEOUT: "soon" })).toBe(3000);
});

// ---- failures ------------------------------------------------------------------------------------------------------
for (const [mode, code] of [["fail", "client_network"], ["garbage", "client_parse"], ["hang", "client_timeout"]] as const) {
  test(`provider failure (gh ${mode}): the class's on_unavailable ask applies locally, no kit_decide call`, async () => {
    process.env.STUB_GH = mode;
    expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
    expect(confirms.length).toBe(1);
    expect(confirms[0].message).toContain("Jev policy [pr-merge-gate/default]");
    expect(decides().length).toBe(0);
    expect(policyRows()[0]).toMatchObject({ tool: "kit_decide", decision: "ask_user", decided_by: "fail_closed", fail_reason: code, enforced: true });
  }, 15000);
}

test("Worker 5xx on kit_decide, closed class: ask", async () => {
  decideReply = async () => new Response("down", { status: 503 });
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(confirms.length).toBe(1);
  expect(policyRows()[0]).toMatchObject({ decision: "ask_user", decided_by: "fail_closed", fail_reason: "client_http_5xx" });
});

test("Worker unreachable on kit_decide, closed class: ask", async () => {
  decideReply = async () => { throw new TypeError("fetch failed"); };
  const v = await run(bash(MERGE), ctx());
  expect(v.block).toBe(true);
  expect(policyRows()[0]).toMatchObject({ decided_by: "fail_closed", fail_reason: "client_network" });
});

test("Worker 5xx on kit_decide, open class: the policy path allows and records fail_open", async () => {
  process.env.JEV_POLICY_USER = LAYERS.open;
  decideReply = async () => new Response("down", { status: 502 });
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(confirms.length).toBe(0);
  expect(policyRows()[0]).toMatchObject({ decision: "proceed", decided_by: "fail_open", fail_reason: "client_http_5xx" });
});

test("Worker 401 on kit_decide: ask, whatever on_unavailable says", async () => {
  process.env.JEV_POLICY_USER = LAYERS.open; // open class: still asks on a rejection
  decideReply = async () => new Response("no", { status: 401 });
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(confirms.length).toBe(1);
  expect(confirms[0].message).toContain("rejected");
  expect(policyRows()[0]).toMatchObject({ decision: "ask", decided_by: "fail_closed", fail_reason: "client_rejected" });
});

test("a JSON-RPC error or isError result from kit_decide asks", async () => {
  decideReply = async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, error: { code: -32602, message: "bad spec" } }));
  await run(bash(MERGE), ctx(true));
  decideReply = async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { isError: true, content: [{ type: "text", text: "nope" }] } }));
  await run(bash(MERGE), ctx(true));
  expect(confirms.length).toBe(2);
  expect(policyRows().map((r) => r.fail_reason)).toEqual(["client_rejected", "client_rejected"]);
});

test("helper missing: the policy path fails open, a ledger row records it, the guard decision is unaffected", async () => {
  process.env.JEV_POLICY_HOOK = join(dir, "no-such-helper.mjs");
  guardReply = { decision: "block", rule: "R1", reason: "guard says no", decided_by: "prefilter" };
  const v = await run(bash(MERGE), ctx(true));
  expect(v.block).toBe(true);
  expect(v.reason).toBe("Jev guard · R1 · block: guard says no\nNext: don't retry as-is; ask the user.");
  expect(decides().length).toBe(0);
  expect(policyRows()[0]).toMatchObject({ tool: "kit_decide", decision: "allow", decided_by: "fail_open", fail_reason: "client_config" });
  guardReply = ALLOW;
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(confirms.length).toBe(0);
});

test("a helper path with spaces works because the helper is started with an argv array, not a shell", async () => {
  const base = join(dir, "My Tools (v2)");
  mkdirSync(join(base, "scripts"), { recursive: true });
  for (const n of ["jev-policy-hook.mjs", "jev-policy.mjs"]) writeFileSync(join(base, "scripts", n), readFileSync(join(import.meta.dir, "..", "scripts", n)));
  if (!existsSync(join(base, "server"))) symlinkSync(join(import.meta.dir, "..", "server"), join(base, "server"));
  process.env.JEV_POLICY_HOOK = join(base, "scripts", "jev-policy-hook.mjs");
  const v = await run(bash(MERGE), ctx(false));
  expect(v.block).toBe(true);
  expect(decides().length).toBe(1);
});

test("helper that crashes or prints junk: fail open with client_parse", async () => {
  process.env.JEV_POLICY_HOOK = MARKER_HELPER; // prints nothing
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(policyRows()[0]).toMatchObject({ decision: "allow", decided_by: "fail_open", fail_reason: "client_parse" });
});

test("an invalid user layer fails the policy path open (a repo layer never stands in)", async () => {
  const p = join(dir, "broken.json");
  writeFileSync(p, '{"v":1,"decisions":"trigger"}');
  process.env.JEV_POLICY_USER = p;
  expect(await run(bash(MERGE), ctx(true))).toBeUndefined();
  expect(decides().length).toBe(0);
  expect(policyRows()[0]).toMatchObject({ decision: "allow", decided_by: "fail_open", fail_reason: "client_config" });
});

// ---- shadow --------------------------------------------------------------------------------------------------------
test("shadow: the policy never asks or blocks; the row is enforced=false with would_have", async () => {
  expect(await runShadow(bash(MERGE), ctx(false))).toBeUndefined();
  expect(confirms.length).toBe(0);
  expect(policyRows()[0]).toMatchObject({ tool: "kit_decide", decision: "ask_user", enforced: false, would_have: "ask" });
  process.env.JEV_POLICY_USER = LAYERS.deny;
  expect(await runShadow(bash(MERGE), ctx(false))).toBeUndefined();
  expect(policyRows()[1]).toMatchObject({ enforced: false, would_have: "block" });
  process.env.STUB_GH = "reviewed";
  process.env.JEV_POLICY_USER = LAYERS.one;
  decideReply = async () => rpc(PROCEED_REPLY);
  await runShadow(bash(MERGE), ctx(false));
  expect(policyRows()[2]).toMatchObject({ decision: "proceed", enforced: true, would_have: null });
});

// ---- ledger --------------------------------------------------------------------------------------------------------
test("policy row: tool kit_decide, 12-hex policy_version, rule, source; the command text, facts and reason appear nowhere in the ledger", async () => {
  const cmd = "gh pr merge 12 --subject ZXQ-HOSTILE-CMD-TEXT";
  await run(bash(cmd), ctx(true));
  const r = policyRows();
  expect(r.length).toBe(1);
  expect(r[0]).toMatchObject({ tool: "kit_decide", decision: "ask_user", rule: "R1-unreviewed-merge", decided_by: "jev", source: "server", host: "omp", enforced: true });
  expect(r[0].policy_version).toMatch(/^[0-9a-f]{12}$/);
  const text = readFileSync(LEDGER, "utf8");
  for (const s of ["ZXQ-HOSTILE-CMD-TEXT", "gh pr merge", "gstack", "pull request", "gstack_reviewed", "gh_pr_target"]) expect(text).not.toContain(s);
});

test("a reply without a record: the row is client-built, carries the plan's 12-hex policy_version and the reply's rule", async () => {
  decideReply = async () => rpc({ ...ASK_REPLY, record: null });
  await run(bash(MERGE), ctx(true));
  const r = policyRows()[0];
  expect(r).toMatchObject({ tool: "kit_decide", decision: "ask_user", rule: "R1-unreviewed-merge", source: "client" });
  expect(r.policy_version).toMatch(/^[0-9a-f]{12}$/);
});

test("hostile policy_version in a reply record never reaches the row: the plan's own hash is used", async () => {
  for (const hostile of ["ABCDEF012345", "0123456789a", "0123456789abc", "0123456789ab\nrm -rf", "../../etc/passwd", 123456789012]) {
    rmSync(LEDGER, { force: true });
    decideReply = async () => rpc({ ...ASK_REPLY, record: { ...ASK_REPLY.record, policy_version: hostile } });
    await run(bash(MERGE), ctx(true));
    const pv = policyRows()[0].policy_version as string;
    expect(pv).toMatch(/^[0-9a-f]{12}$/);
    expect(pv).not.toBe(String(hostile));
  }
  for (const hostile of ["ABCDEF012345", "0123456789a", "0123456789ab\nrm -rf", 123456789012]) expect(mod.buildRow({ policy_version: hostile }, { host: "omp", tool: "kit_decide" }).policy_version).toBeNull();
});

test("buildRow: tool defaults to kit_guard_command, is validated, and policy_version passes only as 12 hex", () => {
  expect(mod.buildRow(null, { host: "omp" }).tool).toBe("kit_guard_command");
  expect(mod.buildRow(null, { host: "omp", tool: "kit_decide" }).tool).toBe("kit_decide");
  expect(mod.buildRow(null, { host: "omp", tool: "Bad Tool; x" }).tool).toBeNull();
  expect(mod.buildRow({ policy_version: "0123456789ab" }, { host: "omp" }).policy_version).toBe("0123456789ab");
  expect(mod.buildRow(null, { host: "omp", policyVersion: "fedcba987654" }).policy_version).toBe("fedcba987654");
  expect(mod.buildRow(null, { host: "omp", policyVersion: "FEDCBA987654" }).policy_version).toBeNull();
  expect(mod.buildRow({ policy_version: "zzzzzzzzzzzz" }, { host: "omp" }).policy_version).toBeNull();
});

// ---- hostile commands ----------------------------------------------------------------------------------------------
test("hostile command: `gh pr merge 12; touch <file>` creates no file and only the digits reach gh", async () => {
  await run(bash(`gh pr merge 12; touch ${TOUCHED}`), ctx(true));
  expect(existsSync(TOUCHED)).toBe(false);
  expect(readFileSync(ARGV_LOG, "utf8").trim()).toBe("pr view 12 --json comments,reviews");
  expect(confirms.length).toBe(1);
});

test("hostile command: $(...) in an operand and a hostile PR-number word reach no argv", async () => {
  await run(bash(`gh pr merge "$(touch ${TOUCHED})" --body '$(touch ${TOUCHED})'`), ctx(true));
  expect(existsSync(TOUCHED)).toBe(false);
  const log = existsSync(ARGV_LOG) ? readFileSync(ARGV_LOG, "utf8") : "";
  expect(log).not.toContain("touch");
});


// ---- which PR the provider asks about --------------------------------------------------------------------------------
const ghCalls = () => (existsSync(ARGV_LOG) ? readFileSync(ARGV_LOG, "utf8").trim().split("\n").filter(Boolean) : []);

test("the provider asks about the PR named by the command, with gh's flag arity", async () => {
  for (const [cmd, view] of [
    ["gh pr merge --subject 12 99", "pr view 99 --json comments,reviews"],
    ["gh pr merge -b 12 99", "pr view 99 --json comments,reviews"],
    ["gh pr merge --match-head-commit 123 99", "pr view 99 --json comments,reviews"],
    ["gh pr merge 99 --repo other/repo", "pr view 99 --repo other/repo --json comments,reviews"],
    ["gh pr merge https://github.com/o/r/pull/99", "pr view https://github.com/o/r/pull/99 --json comments,reviews"],
  ] as const) {
    rmSync(ARGV_LOG, { force: true });
    await run(bash(cmd), ctx(false));
    expect(ghCalls(), cmd).toEqual([view]);
  }
});

test("an ambiguous target asks through the class's failure rule without asking gh or the model", async () => {
  process.env.STUB_GH = "reviewed"; // a reviewed answer must not be able to clear a PR the command did not name
  for (const cmd of ["gh pr merge feature-x", "gh pr merge #99", "gh pr merge 1234567890", "gh pr merge 12 99", "cd ../other && gh pr merge 99", "GH_REPO=other/repo gh pr merge 99", "gh pr merge --repo $(id)/x 5"]) {
    rmSync(ARGV_LOG, { force: true }); rmSync(LEDGER, { force: true }); calls = []; confirms = [];
    const v = await run(bash(cmd), ctx(false));
    expect(v?.block, cmd).toBe(true);
    expect(confirms.length, cmd).toBe(1);
    expect(ghCalls(), cmd).toEqual([]);
    expect(decides().length, cmd).toBe(0);
    expect(policyRows().map((r) => [r.decided_by, r.fail_reason]), cmd).toEqual([["fail_closed", "client_input"]]);
  }
});

// ---- the fail-open notice --------------------------------------------------------------------------------------------
const notices = (answer = false) => {
  const sent: string[] = [];
  return { sent, c: { cwd: REPO, hasUI: true, ui: { confirm: async () => answer, notify: (m: string) => { sent.push(m); } } } };
};

test("a fail-closed class that fails open because the machinery is down tells the user, in fixed words", async () => {
  const hang = join(dir, "hang-helper.mjs");
  writeFileSync(hang, "setTimeout(() => {}, 20000);\n");
  const broken = join(dir, "broken-layer.json");
  writeFileSync(broken, '{"v":1,"decisions":"trigger"}');
  for (const [label, helper, layer, timeout] of [["helper missing", join(dir, "nope.mjs"), LAYERS.one, undefined], ["helper too slow", hang, LAYERS.one, "1"], ["layer unusable", HELPER, broken, undefined]] as const) {
    process.env.JEV_POLICY_HOOK = helper; process.env.JEV_POLICY_USER = layer;
    if (timeout) process.env.JEV_POLICY_TIMEOUT = timeout; else delete process.env.JEV_POLICY_TIMEOUT;
    const n = notices();
    expect(await run(bash(MERGE), n.c), label).toBeUndefined();
    expect(n.sent, label).toEqual([mod.POLICY_NOTICE]);
    expect(n.sent[0]).not.toContain("gh pr merge");
    expect(n.sent[0]).not.toContain(dir);
    expect(policyRows().map((r) => r.decided_by), label).toContain("fail_open");
    rmSync(LEDGER, { force: true });
  }
  delete process.env.JEV_POLICY_TIMEOUT;
});

test("no notice for an open class, in shadow mode, or when nothing failed", async () => {
  process.env.JEV_POLICY_HOOK = join(dir, "nope.mjs");
  process.env.JEV_POLICY_USER = LAYERS.open;
  let n = notices();
  await run(bash(MERGE), n.c);
  expect(n.sent).toEqual([]);
  process.env.JEV_POLICY_USER = LAYERS.one;
  n = notices();
  await runShadow(bash(MERGE), n.c);
  expect(n.sent).toEqual([]);
  process.env.JEV_POLICY_HOOK = HELPER;
  process.env.STUB_GH = "reviewed";
  decideReply = async () => rpc(PROCEED_REPLY);
  n = notices();
  await run(bash(MERGE), n.c);
  expect(n.sent).toEqual([]);
});

test("policyGateMayBeClosed: closed when a triggered class fails closed or the layer is unreadable; open only when every triggered class fails open", () => {
  const withEnv = (file: string) => ({ ...process.env, JEV_POLICY_USER: file });
  expect(mod.policyGateMayBeClosed(withEnv(LAYERS.one))).toBe(true);
  expect(mod.policyGateMayBeClosed(withEnv(LAYERS.open))).toBe(false);
  expect(mod.policyGateMayBeClosed(withEnv(LAYERS.none))).toBe(false);
  expect(mod.policyGateMayBeClosed(withEnv(join(dir, "does-not-exist.json")))).toBe(true);
  const typo = join(dir, "typo.json"); writeFileSync(typo, '{"v":1,"decisions":"trigger"}');
  expect(mod.policyGateMayBeClosed(withEnv(typo))).toBe(true);
  const notJson = join(dir, "not-json.json"); writeFileSync(notJson, '{"v":1,"decisions":[{"trigger": ');
  expect(mod.policyGateMayBeClosed(withEnv(notJson))).toBe(true);
  const mixed = join(dir, "mixed.json"); writeFileSync(mixed, JSON.stringify({ v: 1, decisions: [{ ...base, examples: withoutFailClosedExample, on_unavailable: { decision: "proceed", reason: "open" }, trigger: TRIGGER }, { ...base, id: "second-gate", trigger: { tool: "Bash", command: ["gh"] } }] }));
  expect(mod.policyGateMayBeClosed(withEnv(mixed))).toBe(true);
});

// ---- the runtime that runs the helper ---------------------------------------------------------------------------------
test("policyRuntime: this process when it is node, else node from PATH, else bun, else nothing", () => {
  const bin = mkdtempSync(join(dir, "rt-"));
  const exe = (name: string) => { const f = join(bin, name); writeFileSync(f, "#!/bin/sh\n"); chmodSync(f, 0o755); return f; };
  const emptyDir = mkdtempSync(join(dir, "empty-"));
  expect(mod.policyRuntime({ PATH: emptyDir }, "/usr/local/bin/node")).toBe("/usr/local/bin/node");
  expect(mod.policyRuntime({ PATH: emptyDir }, "/usr/local/bin/nodejs")).toBe("/usr/local/bin/nodejs");
  const node = exe("node");
  expect(mod.policyRuntime({ PATH: bin }, "/opt/bun/bin/bun")).toBe(node);
  rmSync(node);
  const bun = exe("bun");
  expect(mod.policyRuntime({ PATH: bin }, "/opt/omp/bin/omp")).toBe(bun);
  expect(mod.policyRuntime({ PATH: emptyDir }, "/opt/bun/bin/bun")).toBe("/opt/bun/bin/bun");
  expect(mod.policyRuntime({ PATH: emptyDir }, "/opt/omp/bin/omp")).toBeNull();
  expect(mod.policyRuntime({}, "/opt/omp/bin/omp")).toBeNull();
});

test("with no node on PATH the helper runs under the host's bun and the policy still fires", async () => {
  if (!/^bun(\.exe)?$/i.test(String(process.execPath).split("/").pop())) return; // only meaningful when this test runs under bun
  const savedPath = process.env.PATH;
  process.env.PATH = BIN; // the stub gh only: no node anywhere
  try {
    const v = await run(bash(MERGE), ctx(false));
    expect(v?.block).toBe(true);
    expect(decides().length).toBe(1);
  } finally { process.env.PATH = savedPath; }
});

// ---- every merge in the command; a merge that is not the whole command cannot borrow the current branch's review -------------
test("every merge is read: a second, unreviewed merge no longer rides on the first one's review", async () => {
  process.env.STUB_GH = "by_pr";
  process.env.STUB_GH_PRS = "1 --json"; // reviewed: PR 1 and the current branch; not reviewed: everything else
  try {
    for (const cmd of ["gh pr merge 1 && gh pr merge 2", "gh pr merge 1; gh pr merge 2 --squash", "gh pr merge 2 && gh pr merge 1"]) {
      rmSync(ARGV_LOG, { force: true }); rmSync(LEDGER, { force: true }); calls = []; confirms = [];
      decideReply = async () => rpc(ASK_REPLY);
      const v = await run(bash(cmd), ctx(false));
      expect(ghCalls().sort(), cmd).toEqual(["pr view 1 --json comments,reviews", "pr view 2 --json comments,reviews"]);
      expect(decides()[0].args.facts, cmd).toEqual({ gstack_reviewed: false });
      expect(v?.block, cmd).toBe(true);
      expect(confirms.length, cmd).toBe(1);
    }
    process.env.STUB_GH_PRS = "1 2";
    rmSync(ARGV_LOG, { force: true }); calls = []; confirms = [];
    decideReply = async () => rpc(PROCEED_REPLY);
    expect(await run(bash("gh pr merge 1 && gh pr merge 2"), ctx(false))).toBeUndefined();
    expect(decides()[0].args.facts).toEqual({ gstack_reviewed: true });
  } finally { delete process.env.STUB_GH_PRS; }
});

test("a merge that is not the whole command and names no PR is ambiguous, however reviewed the current branch is", async () => {
  process.env.STUB_GH = "by_pr";
  process.env.STUB_GH_PRS = "1 --json";
  try {
    for (const cmd of [
      "gh pr checkout 2 && gh pr merge --squash", "git checkout other && gh pr merge", "echo 2 | xargs gh pr merge", "xargs -a prs.txt gh pr merge", "gh pr merge 1 && gh pr merge",
      "git remote set-url origin https://example.com/o/other.git && gh pr merge 1", "gh repo set-default o/other && gh pr merge 1",
      "git config remote.origin.url https://example.com/o/other.git && gh pr merge 1", "env GH_RE''PO=o/r gh pr merge 1", "X=GH_; export ${X}REPO=o/r; gh pr merge 1",
    ]) {
      rmSync(ARGV_LOG, { force: true }); rmSync(LEDGER, { force: true }); calls = []; confirms = [];
      const v = await run(bash(cmd), ctx(false));
      expect(v?.block, cmd).toBe(true);
      expect(confirms.length, cmd).toBe(1);
      expect(ghCalls(), cmd).toEqual([]);
      expect(decides().length, cmd).toBe(0);
      expect(policyRows().map((r) => [r.decided_by, r.fail_reason]), cmd).toEqual([["fail_closed", "client_input"]]);
    }
    rmSync(ARGV_LOG, { force: true }); calls = [];
    decideReply = async () => rpc(PROCEED_REPLY);
    expect(await run(bash("gh pr merge --auto"), ctx(false))).toBeUndefined();
    expect(ghCalls()).toEqual(["pr view --json comments,reviews"]);
  } finally { delete process.env.STUB_GH_PRS; }
});
