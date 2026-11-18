#!/usr/bin/env node
// Generates ../../docs/TOOLS.md from the Worker's own tools/list: the vendored jkudish/jev-mcp tools
// plus the kit_* tools, in-process through the same handler factory src/index.mjs uses (no network,
// no bearer token, no Jev key).
//
//   cd server && npm run gen:tools
//
// server/test/tools-doc.test.mjs fails when docs/TOOLS.md is not exactly this output, when a vendor
// pin bump adds or renames a tool, or when README/install.sh stop matching the live tool list.
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { createMcpHandler } from "@modelcontextprotocol/server";
import { registerKitTools } from "../src/kit/tools.mjs";
import { registerDecideTool } from "../src/decide/tool.mjs";

export const TOOLS_MD_URL = new URL("../../docs/TOOLS.md", import.meta.url);
const VENDOR_SH_URL = new URL("../build-vendor.sh", import.meta.url);
const VENDOR_JS_URL = new URL("../vendor/server.js", import.meta.url);

async function importVendor() {
  try {
    return await import("../vendor/server.js");
  } catch {
    throw new Error("server/vendor is missing - run `npm run vendor` first (build-vendor.sh clones jkudish/jev-mcp at the pinned commit)");
  }
}

// The same factory chain as src/index.mjs: vendored upstream tools, then the kit tools, then kit_decide.
const { createServer } = await importVendor();
function factory() {
  const server = createServer();
  registerKitTools(server, () => ({}));
  registerDecideTool(server, () => ({}));
  return server;
}

/** The live tools/list, in registration order. @returns {Promise<Array<{name,title,description,inputSchema,annotations}>>} */
export async function listTools() {
  const handler = createMcpHandler(factory, { maxSubscriptions: 0 });
  const response = await handler.fetch(new Request("http://localhost/mcp", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  }));
  if (!response.ok) throw new Error(`tools/list failed with HTTP ${response.status}`);
  const data = (await response.text()).split("\n").find((line) => line.startsWith("data: "));
  if (!data) throw new Error("tools/list returned no event-stream data line");
  return JSON.parse(data.slice("data: ".length)).result.tools;
}

// The vendor pin, read from the script that enforces it and the bundle it produced: a pin bump changes
// both, so regenerating docs/TOOLS.md updates the header without a second place to remember.
function vendorPin() {
  const sh = readFileSync(VENDOR_SH_URL, "utf8");
  const ref = /JEV_MCP_REF:-([0-9a-f]{7,40})/.exec(sh)?.[1];
  if (!ref) throw new Error("build-vendor.sh: no JEV_MCP_REF pin found");
  const version = /const packageVersion = "([^"]+)"/.exec(readFileSync(VENDOR_JS_URL, "utf8"))?.[1];
  if (!version) throw new Error("vendor/server.js: no packageVersion found");
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
    lines.push(tool.description.trim(), "");
    lines.push(`**Required inputs:** ${backticked(required)}`);
    lines.push(`**Optional inputs:** ${backticked(optional)}`);
    lines.push(`**Annotations:** ${tool.annotations == null ? "none" : JSON.stringify(tool.annotations)}`, "");
  }
  return lines.join("\n");
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const out = await renderToolsDoc();
  writeFileSync(TOOLS_MD_URL, out);
  console.log(`wrote ${TOOLS_MD_URL.pathname} (${out.length} bytes)`);
}
