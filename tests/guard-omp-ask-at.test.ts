// omp guard hook: JEV_GUARD_ASK_AT is sent as arguments.ask_at, the same way hooks/jev_guard_hook.py does it.
// Data only; run with bun:
//   bun test tests/guard-omp-ask-at.test.ts
// The hook's omp import is replaced by a stub module and `fetch` is faked: no network, no omp, no command executed.
// The hook reads JEV_GUARD_ASK_AT per call, so the end-to-end cases could share a process; they still run a fresh bun process per value to keep each case isolated.
import { expect, mock, test } from "bun:test";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

mock.module("@oh-my-pi/pi-coding-agent", () => ({ isToolCallEventType: (name: string, e: { toolName?: string }) => e.toolName === name }));

const hook = join(import.meta.dir, "..", "hooks", "omp", "jev-guard.ts");
const { parseAskAt } = await import(hook);

test.each([
  ["0.4", 0.4],
  [" 0.9 ", 0.9],
  ["0", 0],
  ["", undefined],
  ["   ", undefined],
  ["nope", undefined],
  ["nan", undefined],
  ["inf", undefined],
  [undefined, undefined],
  ["0x10", undefined],
  ["0b1", undefined],
  ["0o7", undefined],
  ["0X10", undefined],
  ["1_0", undefined],
])("parseAskAt(%p) -> %p", (raw, want) => {
  expect(parseAskAt(raw as string | undefined)).toBe(want as number | undefined);
});

const dir = mkdtempSync(join(tmpdir(), "jev-askat-"));
const child = join(dir, "child.test.ts");
const out = join(dir, "bodies.json");
writeFileSync(child, `
import { expect, mock, test } from "bun:test";
import { writeFileSync } from "node:fs";
mock.module("@oh-my-pi/pi-coding-agent", () => ({ isToolCallEventType: (name: string, e: { toolName?: string }) => e.toolName === name }));
const bodies: unknown[] = [];
globalThis.fetch = (async (_url: unknown, init: { body: string }) => {
  bodies.push(JSON.parse(init.body));
  return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: JSON.stringify({ decision: "allow", decided_by: "prefilter", rule: "", reason: "" }) }] } }));
}) as typeof fetch;
const mod = await import(${JSON.stringify(hook)});
test("send one guard call and record the wire body", async () => {
  let h: (e: unknown, c: unknown) => Promise<unknown>;
  mod.default({ on: (_: string, f: typeof h) => { h = f; }, logger: { warn() {} } } as never);
  await h!({ toolName: "bash", input: { command: "ls" } }, { cwd: "/tmp", hasUI: false });
  writeFileSync(${JSON.stringify(out)}, JSON.stringify(bodies));
  expect(bodies.length).toBe(1);
});
`);

function wireBodies(askAt: string | undefined): Array<{ params: { arguments: Record<string, unknown> } }> {
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    JEV_MCP_URL: "https://worker-private.example.workers.dev/mcp",
    JEV_MCP_TOKEN: "stub-token",
    JEV_LEDGER: join(dir, `ledger-${askAt ?? "unset"}.jsonl`),
    JEV_GUARD_ASK_NO_UI: "block",
    JEV_GUARD_LOCAL: "off", // this test is about what the server call carries; a rule-decided `ls` would otherwise never be sent
  };
  if (askAt === undefined) delete env.JEV_GUARD_ASK_AT; else env.JEV_GUARD_ASK_AT = askAt;
  try { writeFileSync(out, ""); } catch { /* first run */ }
  const r = spawnSync(process.execPath, ["test", child], { env, encoding: "utf8" });
  expect(r.status, r.stderr || r.stdout).toBe(0);
  return JSON.parse(readFileSync(out, "utf8"));
}

test("JEV_GUARD_ASK_AT=0.4 is sent as arguments.ask_at", () => {
  const [b] = wireBodies("0.4");
  expect(b.params.arguments.ask_at).toBe(0.4);
});

test("unset JEV_GUARD_ASK_AT: no ask_at key, server default applies", () => {
  const [b] = wireBodies(undefined);
  expect("ask_at" in b.params.arguments).toBe(false);
});

test("non-numeric JEV_GUARD_ASK_AT is ignored, as in the python hook", () => {
  const [b] = wireBodies("nope");
  expect("ask_at" in b.params.arguments).toBe(false);
});

test("JEV_GUARD_ASK_AT=1 (inclusive upper bound) is sent as arguments.ask_at", () => {
  const [b] = wireBodies("1");
  expect(b.params.arguments.ask_at).toBe(1);
});

test("out-of-range, non-finite and unparsable JEV_GUARD_ASK_AT fall back to the server default, as in the python hook", () => {
  for (const bad of ["-0.1", "1.5", "2", "1e400", "NaN", "Infinity", "-Infinity", "0x1", "0_5", "0.5abc"]) {
    const [b] = wireBodies(bad);
    expect({ bad, sent: "ask_at" in b.params.arguments }).toEqual({ bad, sent: false });
  }
});
