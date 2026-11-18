// Client conformance for the deployed Worker surface, run in-process through the real default export (no network, no deploy).
// Covers what the docs/CLIENTS.md recipes depend on: bearer auth on /mcp, the Streamable HTTP POST path, the tool list, and /health.
// It needs server/vendor (the upstream jev tools, built by `npm run vendor`). It skips when vendor/ is absent, so jobs that run the whole test glob without building the vendor (the ledger job) stay green; the server job builds the vendor before its test run.
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

const vendored = existsSync(new URL("../vendor/server.js", import.meta.url));
const skip = vendored ? false : "server/vendor not built (run npm run vendor)";

const worker = vendored ? (await import("../src/index.mjs")).default : null;

// Throwaway, generated per run and never a real credential.
const TOKEN = `conformance-${randomUUID()}`;
const env = { MCP_BEARER_TOKEN: TOKEN };
const MCP_URL = "http://worker.test/mcp";
const call = (input, init) => worker.fetch(new Request(input, init), env);

const EXPECTED_TOOLS = [
  "jev_verify", "jev_screen", "jev_noul", "jev_find", "jev_classify", "jev_decide", "jev_rerank", "jev_compare",
  "jev_extract", "jev_audit", "jev_review", "jev_gate",
  "kit_guard_command", "kit_size_dispatch", "kit_verify_done", "kit_decide",
];

const postHeaders = (token) => ({
  "content-type": "application/json",
  accept: "application/json, text/event-stream",
  ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
});

test("/mcp answers 401 with a Bearer challenge when the token is missing", { skip }, async () => {
  const res = await call(MCP_URL, { method: "POST", headers: postHeaders(undefined), body: "{}" });
  assert.equal(res.status, 401);
  assert.match(res.headers.get("www-authenticate") ?? "", /^Bearer/);
});

test("/mcp answers 401 when the token is wrong", { skip }, async () => {
  const res = await call(MCP_URL, { method: "POST", headers: postHeaders("not-the-token"), body: "{}" });
  assert.equal(res.status, 401);
});

test("GET /mcp with a valid token is 405 (Streamable HTTP is POST-only here)", { skip }, async () => {
  const res = await call(MCP_URL, { method: "GET", headers: { authorization: `Bearer ${TOKEN}`, accept: "text/event-stream" } });
  assert.equal(res.status, 405);
});

test("unknown paths are 404", { skip }, async () => {
  const res = await call("http://worker.test/elsewhere", { method: "GET" });
  assert.equal(res.status, 404);
});

test("/health is ok; the rules fingerprint header appears only for the bearer holder", { skip }, async () => {
  const anon = await call("http://worker.test/health", { method: "GET" });
  assert.equal(anon.status, 200);
  assert.equal(await anon.text(), "ok");
  assert.equal(anon.headers.get("x-jev-rules-fingerprint"), null);

  const authed = await call("http://worker.test/health", { method: "GET", headers: { authorization: `Bearer ${TOKEN}` } });
  assert.equal(authed.status, 200);
  assert.ok(authed.headers.get("x-jev-rules-fingerprint"), "authorized health reports the fingerprint");
});

test("an MCP client with the right token lists exactly the 16 documented tools", { skip }, async () => {
  const client = new Client({ name: "conformance", version: "0.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(MCP_URL), {
    requestInit: { headers: { authorization: `Bearer ${TOKEN}` } },
    fetch: call,
  });
  await client.connect(transport);
  try {
    const { tools } = await client.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(), [...EXPECTED_TOOLS].sort());
  } finally {
    await client.close();
  }
});

test("an MCP client with a wrong token cannot connect", { skip }, async () => {
  const client = new Client({ name: "conformance", version: "0.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(MCP_URL), {
    requestInit: { headers: { authorization: "Bearer not-the-token" } },
    fetch: call,
  });
  await assert.rejects(client.connect(transport));
  await client.close().catch(() => {});
});

test("kit_guard_command over the MCP client returns allow for a benign command", { skip }, async () => {
  const client = new Client({ name: "conformance", version: "0.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(MCP_URL), {
    requestInit: { headers: { authorization: `Bearer ${TOKEN}` } },
    fetch: call,
  });
  await client.connect(transport);
  try {
    const res = await client.callTool({ name: "kit_guard_command", arguments: { command: "ls" } });
    const body = JSON.parse(res.content[0].text);
    assert.equal(body.decision, "allow");
  } finally {
    await client.close();
  }
});
