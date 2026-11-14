// Target adapters: how jev-eval turns a corpus input into a tool output. Three kinds:
//   builtin  the kit's own guard / verify / dispatch modules, run in process (offline when no upstream credentials are
//            present: rows that needed Jev come back with jev.status "unavailable" and are marked NOT EVALUATED, never
//            scored as right or wrong)
//   module   any exported function (input, params) -> output, from a file next to the suite
//   mcp      a tool on a deployed Worker over JSON-RPC (URL and token from env, never argv)
// `kitDir` points the builtin kind at another checkout of this repo (for example a PR branch) so one corpus can be run
// against the code under review.
// Corpus content is only ever passed as data (a function argument or a JSON body). Nothing is spawned or evaluated.
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

/** Thrown when a run would exceed the upstream call cap. runRows lets it through (it is not a per-row failure). */
export class BudgetExceeded extends Error {
  constructor(cap) { super(`upstream call cap (${cap}) reached; check the expected call count with --dry-run, then raise --max-calls`); this.name = "BudgetExceeded"; }
}
export const DEFAULT_MAX_CALLS = 2000;

const clone = (v) => JSON.parse(JSON.stringify(v ?? null));
const usageOf = (output) => {
  const u = output?.jev?.usage ?? output?.usage;
  return u && typeof u === "object" ? { input_tokens: Number.isFinite(u.input_tokens) ? u.input_tokens : 0, output_tokens: Number.isFinite(u.output_tokens) ? u.output_tokens : 0, cost: Number.isFinite(u.cost) ? u.cost : null } : null;
};
const modelOf = (output) => (typeof output?.jev?.model === "string" ? output.jev.model : typeof output?.model === "string" ? output.model : null);

function splitParams(suite, params) {
  const inputExtras = {}, moduleParams = {};
  for (const e of suite.sweep) {
    if (!(e.name in params)) continue;
    (e.apply === "input" ? inputExtras : moduleParams)[e.name] = params[e.name];
  }
  return { inputExtras, moduleParams };
}

async function builtinTarget(suite, { env, cachePath, kitDir, maxCalls }) {
  // Dynamic import on purpose: only the builtin kind needs the server modules, so module/mcp suites keep working when
  // scripts/jev-eval is used outside this repo layout.
  const kit = kitDir ? pathToFileURL(`${resolve(kitDir, "server/src/kit")}/`) : new URL("../../../server/src/kit/", import.meta.url);
  const [{ guardCommand }, { verifyDone }, { sizeDispatch }, { resolveUpstream, askUpstream }] = await Promise.all(
    ["guard.mjs", "verify.mjs", "tier.mjs", "jev.mjs"].map((f) => import(new URL(f, kit).href)));
  const fn = { kit_guard_command: guardCommand, kit_verify_done: verifyDone, kit_size_dispatch: sizeDispatch }[suite.target.tool];
  const upstream = resolveUpstream(env);
  const cache = new Map(cachePath && existsSync(cachePath) ? Object.entries(JSON.parse(readFileSync(cachePath, "utf8"))) : []);
  let fresh = 0, hits = 0, inFlight = 0, blown = false;
  const key = (state, questions) => createHash("sha256").update(JSON.stringify([state, questions, upstream?.model ?? null])).digest("hex");

  return {
    kind: "builtin", tool: suite.target.tool, live: Boolean(upstream),
    note: upstream ? `Jev upstream configured (${upstream.name}); answers are cached per (state, questions, model)` : "no Jev credentials: Jev-dependent rows are NOT EVALUATED",
    async run(input, params) {
      const { inputExtras } = splitParams(suite, params);
      const meta = { cached: false, usage: null };
      const deps = upstream
        ? { jevAvailable: true, ask: async (state, questions) => {
            const k = key(state, questions);
            if (cache.has(k)) { hits++; meta.cached = true; return { ...cache.get(k), usage: null }; }
            // Reserve before calling: concurrent rows must not overshoot the cap. The tools swallow an error thrown here
            // (they fail open), so it only sets `blown`; run() turns that into an abort once the tool returns.
            if (fresh + inFlight >= maxCalls) { blown = true; throw new Error("upstream call cap reached"); }
            inFlight++;
            try {
              const r = await askUpstream(upstream, state, questions);
              fresh++; cache.set(k, { answers: r.answers, model: r.model, usage: r.usage });
              return r;
            } finally { inFlight--; }
          } }
        : { ask: null, jevAvailable: false };
      const output = clone(await fn({ ...input, ...inputExtras }, deps));
      if (blown) throw new BudgetExceeded(maxCalls);
      return { output, usage: usageOf(output), model: modelOf(output), cached: meta.cached };
    },
    /** Would this input need Jev? Runs with no upstream at all, so it never calls out. */
    async probe(input, params) {
      const { inputExtras } = splitParams(suite, params);
      const out = clone(await fn({ ...input, ...inputExtras }, { ask: null, jevAvailable: false }));
      return { needsJev: out?.jev?.status === "unavailable" || out?.jev?.status === "invalid_response" };
    },
    finish() {
      if (cachePath && cache.size) writeFileSync(cachePath, JSON.stringify(Object.fromEntries(cache)), { mode: 0o600 });
      return { upstream_calls: fresh, cache_hits: hits };
    },
  };
}

async function moduleTarget(suite, { suiteDir }) {
  const abs = resolve(suiteDir, suite.target.path);
  // Dynamic import on purpose: the module path is runtime data from the manifest. This runs the deployment's own code,
  // never corpus content.
  const mod = await import(pathToFileURL(abs).href);
  const fn = mod[suite.target.export];
  if (typeof fn !== "function") throw new Error(`target.export ${suite.target.export} is not a function in ${suite.target.path}`);
  return {
    kind: "module", tool: suite.target.export, live: false, note: `module ${suite.target.path}#${suite.target.export}`,
    async run(input, params) {
      const { inputExtras, moduleParams } = splitParams(suite, params);
      const output = clone(await fn({ ...(input && typeof input === "object" && !Array.isArray(input) ? input : { value: input }), ...inputExtras }, moduleParams));
      return { output, usage: usageOf(output), model: modelOf(output), cached: false };
    },
    async probe() { return { needsJev: null }; },
    finish() { return { upstream_calls: 0, cache_hits: 0 }; },
  };
}

function mcpTarget(suite, { env, fetchImpl, maxCalls }) {
  const urlEnv = suite.target.url_env ?? "JEV_MCP_URL", tokenEnv = suite.target.token_env ?? "JEV_MCP_TOKEN";
  const url = (env[urlEnv] ?? "").trim(), token = (env[tokenEnv] ?? "").trim();
  if (!url || !token) throw new Error(`mcp target needs ${urlEnv} and ${tokenEnv} in the environment`);
  const u = new URL(url);
  const loopback = u.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname);
  if (u.protocol !== "https:" && !loopback) throw new Error(`${urlEnv} must be https:// (plain http is allowed only for loopback)`);
  let id = 0;
  return {
    kind: "mcp", tool: suite.target.tool, live: true, note: `deployed worker via ${urlEnv} (host not recorded)`,
    async run(input, params) {
      const { inputExtras } = splitParams(suite, params);
      if (id >= maxCalls) throw new BudgetExceeded(maxCalls);
      const res = await fetchImpl(url, {
        method: "POST", redirect: "error", signal: AbortSignal.timeout(60_000),
        headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}`, "user-agent": "jev-eval/1" },
        body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method: "tools/call", params: { name: suite.target.tool, arguments: { ...input, ...inputExtras } } }),
      });
      if (!res.ok) throw new Error(`worker answered HTTP ${res.status}`);
      const raw = await res.text();
      let msg = null;
      for (const line of raw.split("\n")) {
        const l = line.trim().replace(/^data:\s*/, "");
        if (l.startsWith("{")) { try { msg = JSON.parse(l); break; } catch { /* keep scanning */ } }
      }
      if (!msg) throw new Error("unparseable worker response");
      if (msg.error) throw new Error(`worker rejected the call: ${String(msg.error.message ?? "error").slice(0, 100)}`);
      if (msg.result?.isError) throw new Error("tool error");
      const output = JSON.parse(msg.result.content[0].text);
      return { output, usage: usageOf(output), model: modelOf(output), cached: false };
    },
    async probe() { return { needsJev: null }; },
    finish() { return { upstream_calls: null, cache_hits: 0 }; },
  };
}

export async function makeTarget(suite, { env = process.env, cachePath = null, suiteDir = ".", fetchImpl = fetch, kitDir = null, maxCalls = DEFAULT_MAX_CALLS } = {}) {
  if (suite.target.kind === "builtin") return builtinTarget(suite, { env, cachePath, kitDir, maxCalls });
  if (suite.target.kind === "module") return moduleTarget(suite, { suiteDir });
  return mcpTarget(suite, { env, fetchImpl, maxCalls });
}
