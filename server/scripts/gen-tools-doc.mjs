#!/usr/bin/env node
// Generates ../../docs/TOOLS.md from the Worker's own tools/list: the vendored jkudish/jev-mcp tools
// plus the kit_* tools, in-process through src/index.mjs's composeServer — the exact registration
// chain the deployed Worker uses (no network, no bearer token, no Jev key).
//
//   cd server && npm run gen:tools
//
// server/test/tools-doc.test.mjs fails when docs/TOOLS.md is not exactly this output, when a vendor
// pin bump adds, drops or renames a tool, or when README/install.sh stop matching the live tool list.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { createMcpHandler } from "@modelcontextprotocol/server";

export const TOOLS_MD_URL = new URL("../../docs/TOOLS.md", import.meta.url);
const VENDOR_JS_URL = new URL("../vendor/server.js", import.meta.url);

// Lazy on purpose: this module must import cleanly without server/vendor so the drift test can skip
// with the remedy printed instead of failing at load. Nothing touches the bundle until a list is asked.
let composer;
async function composeServer() {
  if (!composer) {
    if (!existsSync(VENDOR_JS_URL)) {
      throw new Error("server/vendor is missing - run `npm run vendor` first (build-vendor.sh clones jkudish/jev-mcp at the pinned commit)");
    }
    try {
      ({ composeServer: composer } = await import("../src/index.mjs"));
    } catch (cause) {
      throw new Error(`the Worker's tool chain failed to load - run \`npm run vendor\` to rebuild server/vendor (${cause.message})`, { cause });
    }
  }
  return composer;
}

let cachedTools;
/** The live tools/list, in registration order — one round trip per process, so a caller that both
 *  lists and renders (the drift test) does not spin up a second handler. */
export async function listTools() {
  if (cachedTools) return cachedTools;
  const compose = await composeServer();
  const handler = createMcpHandler(() => compose({}), { maxSubscriptions: 0 });
  const response = await handler.fetch(new Request("http://localhost/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  }));
  if (!response.ok) throw new Error(`tools/list failed with HTTP ${response.status}`);
  // Event-stream framing: take every parseable data payload and keep the one that carries a tools
  // array, so a keepalive or an extra frame can neither be mistaken for the result nor cached.
  const payloads = (await response.text()).split("\n")
    .filter((line) => line.startsWith("data: "))
    .flatMap((line) => { try { return [JSON.parse(line.slice(6))]; } catch { return []; } });
  const tools = payloads.map((payload) => payload?.result?.tools).find(Array.isArray);
  if (!tools) {
    const rpcError = payloads.find((payload) => payload?.error)?.error;
    throw new Error(rpcError ? `tools/list returned a JSON-RPC error: ${rpcError.message ?? JSON.stringify(rpcError)}` : "tools/list returned no message with a tools array");
  }
  cachedTools = tools;
  return tools;
}

// The vendor pin, stamped into the bundle by build-vendor.sh: the header can only name the commit the
// tools beside it were actually built from (a JEV_MCP_REF/REF tag resolves to its checkout SHA).
function vendorPin() {
  const bundle = readFileSync(VENDOR_JS_URL, "utf8");
  const ref = /\/\/ vendorRef: (\S+)/.exec(bundle)?.[1];
  if (!ref) throw new Error("server/vendor has no vendorRef stamp - run `npm run vendor` (this bundle predates the stamp)");
  const version = /const packageVersion = "([^"]+)"/.exec(bundle)?.[1];
  if (!version) throw new Error("server/vendor has no packageVersion - run `npm run vendor`");
  return { ref, version };
}

const inputNames = (tool) => {
  const properties = tool.inputSchema?.properties ?? {};
  const required = new Set(tool.inputSchema?.required ?? []);
  const names = Object.keys(properties);
  return {
    required: names.filter((name) => required.has(name)),
    optional: names.filter((name) => !required.has(name)),
  };
};

const backticked = (names) => (names.length ? names.map((n) => `\`${n}\``).join(", ") : "none");

/** The exact contents of docs/TOOLS.md for the live tool list. */
export async function renderToolsDoc() {
  const tools = await listTools();
  const { ref, version } = vendorPin();
  const lines = [
    "<!-- GENERATED FILE - do not edit by hand.",
    `     Source: jkudish/jev-mcp@${ref} (v${version}), vendored by server/build-vendor.sh, plus the kit_* tools of server/src/kit/tools.mjs and the spec-driven kit_decide.`,
    "     Regenerate: cd server && npm run gen:tools",
    "     Checked by: server/test/tools-doc.test.mjs -->",
    "",
    "# Tool reference",
    "",
    `All ${tools.length} tools the Worker serves, verbatim from \`tools/list\`. The descriptions are the upstream text; the inputs come from each tool's JSON schema (required first).`,
    "",
  ];
  for (const tool of tools) {
    const { required, optional } = inputNames(tool);
    lines.push(`## \`${tool.name}\` - ${tool.title ?? "(no title)"}`, "");
    lines.push(String(tool.description ?? "").trim(), "");
    lines.push(`**Required inputs:** ${backticked(required)}`);
    lines.push(`**Optional inputs:** ${backticked(optional)}`);
    lines.push(`**Annotations:** ${tool.annotations == null ? "none" : JSON.stringify(tool.annotations)}`, "");
  }
  // The prose above pins names, titles, descriptions, input names and annotations; these digests pin
  // the schema constraints (types, enums, bounds) the prose does not spell out, so a breaking input
  // schema change also turns docs/TOOLS.md stale.
  lines.push("<!-- inputSchema sha256 (full, canonical JSON of each tool's schema):");
  for (const tool of tools) lines.push(`${tool.name} ${createHash("sha256").update(JSON.stringify(tool.inputSchema ?? null)).digest("hex")}`);
  lines.push("-->", "");
  return lines.join("\n");
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const out = await renderToolsDoc();
  writeFileSync(TOOLS_MD_URL, out);
  console.log(`wrote ${TOOLS_MD_URL.pathname} (${out.length} bytes)`);
}
