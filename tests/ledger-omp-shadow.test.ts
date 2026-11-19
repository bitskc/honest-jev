// omp guard hook in JEV_GUARD_MODE=shadow (read at module load, hence its own file). Data only; run with bun:
//   bun test tests/ledger-omp-shadow.test.ts
import { expect, mock, test } from "bun:test";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

mock.module("@oh-my-pi/pi-coding-agent", () => ({ isToolCallEventType: (name: string, e: { toolName?: string }) => e.toolName === name }));
const LEDGER = join(mkdtempSync(join(tmpdir(), "jev-omp-shadow-")), "ledger.jsonl");
process.env.JEV_MCP_URL = "https://worker-private.example.workers.dev/mcp";
process.env.JEV_MCP_TOKEN = "stub-token";
process.env.JEV_GUARD_LOCAL = "off"; // these tests are about the server path; the local rules are covered by tests/local-first-omp.test.ts
process.env.JEV_LEDGER = LEDGER;
process.env.JEV_GUARD_MODE = "shadow";
globalThis.fetch = (async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: JSON.stringify({ decision: "block", rule: "R1-secret-exposure", reason: "r", decided_by: "prefilter" }) }] } }))) as typeof fetch;

// Dynamic import on purpose: the hook reads JEV_GUARD_MODE at module load.
const mod = await import("../hooks/omp/jev-guard.ts");

test("shadow: the block is recorded as not enforced with would_have, and the call is not blocked", async () => {
  let h: (e: unknown, c: unknown) => Promise<unknown>;
  mod.default({ on: (_: string, f: typeof h) => { h = f; }, logger: { warn() {} } } as never);
  const v = await h!({ toolName: "bash", input: { command: "cat .env" } }, { cwd: "/tmp" });
  const { promise, resolve } = Promise.withResolvers<void>(); // the ledger write is queued after the verdict
  setImmediate(resolve);
  await promise;
  expect(v).toBeUndefined();
  const r = JSON.parse(readFileSync(LEDGER, "utf8").trim());
  expect([r.decision, r.enforced, r.would_have, r.source]).toEqual(["block", false, "block", "client"]);
  expect(readFileSync(LEDGER, "utf8")).not.toContain(".env");
});
