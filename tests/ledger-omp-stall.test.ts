// omp guard hook with a stalled ledger write: the verdict must not wait for the disk. Data only. Own file because it
// mocks node:fs for the whole process (tests/test-ledger.sh runs it as its own `bun test`):
//   bun test tests/ledger-omp-stall.test.ts
import { expect, mock, test } from "bun:test";
import * as realFs from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const STALL_MS = 3000;
const VERDICT_BUDGET_MS = 1000; // the verdict must come back well before the stalled write finishes
const origWriteSync = realFs.writeSync; // captured before the mock: calling realFs.writeSync would reach the mock again
let stallsPending = 0;
let stallsSeen = 0;
mock.module("node:fs", () => ({
  ...realFs,
  writeSync: (...args: Parameters<typeof realFs.writeSync>) => {
    if (stallsPending > 0) { stallsPending -= 1; stallsSeen += 1; Bun.sleepSync(STALL_MS); }
    return origWriteSync(...args);
  },
}));
mock.module("@oh-my-pi/pi-coding-agent", () => ({ isToolCallEventType: (name: string, e: { toolName?: string }) => e.toolName === name }));

process.env.JEV_MCP_URL = "https://worker-private.example.workers.dev/mcp";
process.env.JEV_MCP_TOKEN = "stub-token";
process.env.JEV_GUARD_LOCAL = "off"; // these tests are about the server path; the local rules are covered by tests/local-first-omp.test.ts
process.env.JEV_LEDGER = join(mkdtempSync(join(tmpdir(), "jev-omp-stall-")), "ledger.jsonl");
delete process.env.JEV_GUARD_MODE;
globalThis.fetch = (async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: JSON.stringify({ decision: "block", rule: "R1-secret-exposure", reason: "r", decided_by: "prefilter" }) }] } }))) as typeof fetch;

// Dynamic import on purpose: the hook reads JEV_* env at module load, and the fs mock must be in place first.
const mod = await import("../hooks/omp/jev-guard.ts");

test("stalled ledger write: the block verdict is returned within budget, not after the stall", async () => {
  let h: (e: unknown, c: unknown) => Promise<unknown>;
  mod.default({ on: (_: string, f: typeof h) => { h = f; }, logger: { warn() {} } } as never);
  stallsPending = 1;
  const t0 = performance.now();
  const v = (await h!({ toolName: "bash", input: { command: "cat .env" } }, { cwd: "/tmp" })) as { block?: boolean };
  const elapsed = performance.now() - t0;
  expect(v.block).toBe(true);
  expect(elapsed).toBeLessThan(VERDICT_BUDGET_MS);
  // The verdict is back; the ledger write was queued after it. Let that write run now, so the stall really happened.
  const { promise, resolve } = Promise.withResolvers<void>();
  setImmediate(resolve);
  await promise;
  expect(stallsSeen).toBe(1);
}, STALL_MS + 5000);
