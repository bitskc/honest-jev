// omp (oh-my-pi) hook: the guard rules before every bash/read/grep tool call. The deterministic rules run locally, in this
// process, first (see "local rules" below); only a command they cannot settle goes to jev-mcp kit_guard_command, if a server is configured.
// Install:  cp jev-guard.ts ~/.omp/agent/hooks/pre/jev-guard.ts   (user)   or   .omp/hooks/pre/   (project)
// Try once: omp --hook /abs/path/jev-guard.ts
//
// CONFIRMED from omp docs (omp.sh/docs/hooks): hooks are .ts/.js modules in hooks/pre|post/ that default-export
// a factory(pi: ExtensionAPI); pi.on("tool_call", (event, ctx) => ...) may return { block: true, reason };
// isToolCallEventType("bash", event) narrows event.input.command; tool_call exceptions/timeouts FAIL CLOSED
// in omp (default 30 s, extensionHandlers.toolCallTimeoutMs), so everything below is wrapped to fail OPEN.
// ASSUMED (not verified; this file has not been run inside omp):
//   - ctx.ui.confirm(title, message) exists and returns Promise<boolean> (used for "ask"; guarded by typeof check)
//   - the built-in read tool is named "read" with event.input.path (only used for secret-file reads)
// Endpoint and token come from the env vars JEV_MCP_URL and JEV_MCP_TOKEN; never hardcode them.
import { isToolCallEventType, type ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import { createHash, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { accessSync, closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, renameSync, statSync, unlinkSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

// Env is read per call, never at module load: one module instance is shared by every test file in a `bun test` process,
// so a load-time read freezes whichever file imported the hook first.
const mcpUrl = (): string => (process.env.JEV_MCP_URL ?? "").trim(); // e.g. https://<your-worker>.workers.dev/mcp
const timeoutMs = (): number => Number(process.env.JEV_GUARD_TIMEOUT ?? "2") * 1000;
const shadow = (): boolean => process.env.JEV_GUARD_MODE === "shadow";
const askNoUi = (): string => process.env.JEV_GUARD_ASK_NO_UI ?? "block"; // "block" | "allow" when "ask" but nobody can answer
// JEV_GUARD_ASK_AT: risk threshold sent as ask_at, same as hooks/jev_guard_hook.py. Unset, not a plain decimal literal,
// NaN/Infinity, or outside [0, 1] = server default (the server schema is min 0, max 1).
const ASK_AT_RE = /^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$/;
export function parseAskAt(raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  const s = raw.trim();
  if (!ASK_AT_RE.test(s)) return undefined;
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 && n <= 1 ? n : undefined;
}
const askAt = (): number | undefined => parseAskAt(process.env.JEV_GUARD_ASK_AT);

// ── local rules (local-first guard) ─────────────────────────────────────────────────────────────────────────────────
// The deterministic rules (server/src/kit/guard.mjs, shell.mjs, safere.mjs: no npm package) run IN THIS PROCESS before any
// network call. A command a rule settles is answered from that result and never leaves the machine; only a command the rules
// cannot settle without a model ("unclear") goes on to the server, and only if one is configured. This file is copied alone
// into ~/.omp/agent/hooks/pre/, so the rules are found by path at run time: $JEV_GUARD_RULES (an absolute path to guard.mjs;
// when set it is the only candidate; tests use it), else the install.sh tree ~/.local/share/honest-jev/jev-policy/server/src/kit,
// else the pre-rename install dir. The module is imported once per path and cached. JEV_GUARD_LOCAL=off skips all of this.
// Not preemptable: a rule run is synchronous CPU in this process (measured at most about 0.25 s on the 1,241-row corpus).
export const LOCAL_NOTICE = "Honest Jev guard: no server is configured (JEV_MCP_URL / JEV_MCP_TOKEN), so the local rules run unverified and are not checked against the server's. This command was unclear to the rules and was allowed without a model check. Run install.sh --doctor for details.";
export const LOCAL_DOWN_NOTICE = "Honest Jev guard: the local rules could not run and no server is configured (JEV_MCP_URL / JEV_MCP_TOKEN), so commands are not being checked. Run install.sh --doctor for details.";
export const TRUST_NOTICES: Record<"mismatch" | "unverified", string> = {
  mismatch: "Honest Jev guard: the rules on this machine differ from the server's, so commands the local rules would allow are being sent to the server to decide. Run jev-update (or deploy the Worker, if this machine is the newer one), then restart the agent. install.sh --doctor shows which.",
  unverified: "Honest Jev guard: could not confirm that the rules on this machine match the server's (the server did not answer, or is an older Worker that does not report its rules), so commands the local rules would allow are being sent to the server to decide. Run install.sh --doctor for details.",
};

export function guardRulesPath(env: Record<string, string | undefined> = process.env, exists: (p: string) => boolean = existsSync): string | null {
  const custom = (env.JEV_GUARD_RULES ?? "").trim();
  if (custom) return isAbsolute(custom) && exists(custom) ? custom : null;
  const home = (env.HOME ?? "").trim() || homedir();
  for (const dir of ["honest-jev", "jev-agent-skills"]) {
    const p = join(home, ".local", "share", dir, "jev-policy", "server", "src", "kit", "guard.mjs");
    if (exists(p)) return p;
  }
  return null;
}

type GuardFn = (args: Record<string, unknown>, deps: { ask: () => Promise<never>; jevAvailable: boolean }) => Promise<Record<string, unknown>>;

// The rules fingerprint: sha256 over the rule files the local guard runs (the same function as hooks/jev-rules-fingerprint.mjs, which the
// Claude Code runner and the Worker's generator use; this file is copied alone, so it carries its own copy and tests/local-first-omp.test.ts
// pins the two to the same value). Each file is hashed as `<name> NUL <byte length> NUL <bytes>`.
export const RULE_FILES = ["guard.mjs", "safere.mjs", "shell.mjs"] as const;
export function rulesFingerprint(kitDir: string): string {
  const h = createHash("sha256");
  for (const name of RULE_FILES) {
    const bytes = readFileSync(join(kitDir, name));
    h.update(`${name}\0${bytes.length}\0`);
    h.update(bytes);
  }
  return h.digest("hex");
}

// The module is imported once per path and kept for the life of the process, and its fingerprint is taken just before that import, so it
// describes the rules that actually run here: a rule file rewritten on disk afterwards changes nothing in this process, and a `jev-update`
// does not reach it either until omp restarts. The server's fingerprint then no longer matches, and the server decides (see rulesTrust).
type Loaded = { guardCommand: GuardFn | null; fp: string | null };
const rulesByPath = new Map<string, Promise<Loaded>>();
function loadRules(path: string): Promise<Loaded> {
  let p = rulesByPath.get(path);
  if (!p) {
    let fp: string | null = null;
    try { fp = rulesFingerprint(dirname(path)); } catch { /* not the whole release (a test's single stub module): nothing to verify */ }
    p = import(pathToFileURL(path).href).then((m: { guardCommand?: unknown }) => ({ guardCommand: typeof m.guardCommand === "function" ? (m.guardCommand as GuardFn) : null, fp }), () => ({ guardCommand: null, fp }));
    rulesByPath.set(path, p);
  }
  return p;
}

export type LocalVerdict = { reply: Record<string, unknown>; unclear: boolean; fp: string | null };
/** The rules were enabled and did not run (not found, would not load, threw, answered nonsense). In process there is no time budget to miss. */
export type LocalNotRun = { notRun: true };
/**
 * Judge `args` with the local rules. null = switched off (JEV_GUARD_LOCAL=off: the user chose server-only). `{ notRun: true }` = enabled
 * but did not run: the caller takes the server path unchanged, and says so if no server answers either. `unclear` = the rules would have
 * asked a model and no rule blocked; `ask` is never answered, it only records the question (reading `decided_by: "fail_open"` alone
 * misses a question raised only by guardCommand's second, comment-masked reading). `fp` = the fingerprint of the rules that ran (null when
 * the rule files are not the whole release). Never throws.
 */
export async function localGuard(args: Record<string, unknown>): Promise<LocalVerdict | LocalNotRun | null> {
  if ((process.env.JEV_GUARD_LOCAL ?? "").trim().toLowerCase() === "off") return null;
  try {
    const path = guardRulesPath();
    if (!path) return { notRun: true };
    const { guardCommand, fp } = await loadRules(path);
    if (!guardCommand) return { notRun: true };
    let consulted = 0;
    const reply = await guardCommand({ ...args }, { jevAvailable: true, ask: async () => { consulted++; throw new Error("no model in the local runner"); } });
    const by = reply.decided_by;
    if (!["allow", "ask", "block"].includes(String(reply.decision)) || !["prefilter", "fail_closed", "fail_open"].includes(String(by))) return { notRun: true };
    return { reply, unclear: by === "fail_open" || (consulted > 0 && reply.decision !== "block"), fp };
  } catch { return { notRun: true }; }
}

// ── local rules against the server's ────────────────────────────────────────────────────────────────────────────────
// A local ALLOW is final only when the rules in this process are byte-identical to the rules the server runs: the Worker reports the
// fingerprint of its own rules in the x-jev-rules-fingerprint header of an authenticated GET /health (server/src/health.mjs). It is cached in
// memory for FP_TTL_MS, so the common command costs no network call. A different fingerprint, or none (an older Worker, no network, a slow
// answer, this machine's rules not the whole release), means the server decides; a local ask or block is honoured either way.
const FP_RE = /^[0-9a-f]{64}$/;
const FP_TTL_MS = 5 * 60_000;
const FP_TTL_DOWN_MS = 60_000; // "the server gave none" is remembered for a minute, so an offline or older server costs one fetch a minute
const FP_FETCH_MS = 800;
export const FP_HEADER = "x-jev-rules-fingerprint";
export type RulesTrust = "match" | "mismatch" | "unverified";
let serverFp: { key: string; fp: string | null; at: number } | null = null;
/** Forget the cached server fingerprint (tests). */
export function resetServerFingerprint(): void { serverFp = null; }

async function fetchServerFingerprint(): Promise<string | null> {
  try {
    const u = new URL(mcpUrl());
    u.pathname = `${u.pathname.replace(/\/mcp$/, "").replace(/\/+$/, "")}/health`;
    u.search = ""; u.hash = "";
    const res = await fetch(u.href, {
      method: "GET",
      redirect: "error", // a 3xx would re-send the bearer wherever it points
      signal: AbortSignal.timeout(FP_FETCH_MS),
      headers: { authorization: `Bearer ${(process.env.JEV_MCP_TOKEN ?? "").trim()}`, "user-agent": "jev-guard-hook-omp/1.0" },
    });
    const got = (res.headers.get(FP_HEADER) ?? "").trim().toLowerCase();
    return res.ok && FP_RE.test(got) ? got : null;
  } catch { return null; }
}

async function serverRulesFingerprint(): Promise<string | null> {
  const key = mcpUrl(), now = Date.now();
  if (serverFp && serverFp.key === key && now >= serverFp.at && now - serverFp.at < (serverFp.fp ? FP_TTL_MS : FP_TTL_DOWN_MS)) return serverFp.fp;
  const fp = await fetchServerFingerprint();
  serverFp = { key, fp, at: Date.now() };
  return fp;
}

/** "match": the rules here are byte-identical to the server's. "mismatch": both known, different. "unverified": this machine's rules are not
 * the whole release, or the server's fingerprint is unavailable. Anything but "match" means the server decides a local allow. */
export async function rulesTrust(local: LocalVerdict): Promise<RulesTrust> {
  if (local.fp === null || !FP_RE.test(local.fp)) return "unverified";
  const theirs = await serverRulesFingerprint();
  if (theirs === null) return "unverified";
  return theirs === local.fp ? "match" : "mismatch";
}

// Server-side input caps (server/src/kit/tools.mjs): over these the schema rejects the call, and a rejection must
// become "ask", never a silent allow.
const CAPS: Record<string, number> = { command: 20000, file_path: 2000, cwd: 1000, home: 500 };

// ── local decision ledger (openspec add-decision-ledger; mirrors hooks/jev_ledger.py) ───────────────────────────────
// One content-free JSONL row per decision. Rebuilt from allow-list shapes (a value that does not fit becomes null; it
// is rejected, never redacted and kept), so no command, path, prompt or exception text can reach it. One atomic append
// (O_APPEND|O_NOFOLLOW, a single write of one whole line of at most 2 KB), a regular file we own in a 0700 directory
// we own, rotated at 20 MB to a unique name (never overwritten, newest three kept). JEV_LEDGER=<path> overrides,
// JEV_LEDGER=off disables. A ledger failure never changes a decision: every call below is wrapped and synchronous, because
// a throwing tool_call handler fails closed in omp.
const LEDGER_MAX_BYTES = 20 * 1024 * 1024;
const LEDGER_MAX_LINE = 2048;
export const LEDGER_KEEP_ROTATED = 3;
export const DECIDED_BY = ["prefilter", "jev", "fail_open", "fail_closed", "policy"] as const;
export const FAIL_REASONS = [
  "no_upstream", "upstream_error", "timeout", "invalid_response", "oversize",
  "client_config", "client_input", "client_timeout", "client_network", "client_http_5xx", "client_parse", "client_rejected", "rule_error",
  "local_rules_unavailable", // the hook's local rules did not run (and no server answered)
] as const;
const WORD = /^[a-z][a-z_]{0,31}$/, RULE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$/, TOOL = /^[a-z][a-z0-9_]{0,31}$/;
const TIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/, HOST = /^[a-z0-9][a-z0-9._-]{0,31}$/;
const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:\/-]{0,63}$/, CORRELATION = /^[A-Za-z0-9_-]{1,64}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$/;
const ROTATED_RE = /\.\d{8}T\d{12}Z-\d+$/;
const POLICY_V = /^[0-9a-f]{12}$/; // policy_version: 12 lower-case hex, anything else is dropped
const pick = (re: RegExp, v: unknown): string | null => (typeof v === "string" && re.test(v) ? v : null);
const nonneg = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) && v >= 0 ? v : null);
const obj = (v: unknown): Record<string, unknown> => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {});

export function ledgerPath(env: Record<string, string | undefined> = process.env): string | null {
  const p = (env.JEV_LEDGER ?? "").trim();
  if (p.toLowerCase() === "off") return null;
  if (p) return isAbsolute(p) ? p : null; // relative would land in the working directory: refused, no row written
  const xdg = (env.XDG_STATE_HOME ?? "").trim();
  return join(xdg && isAbsolute(xdg) ? xdg : join((env.HOME ?? "").trim() || homedir(), ".local", "state"), "jev", "ledger.jsonl"); // HOME first, as python expanduser and node homedir do
}

/** A worker that predates the ledger sends no `record`: rebuild what we can from the reply's own fields. */
function synthFromReply(reply: Record<string, unknown>): Record<string, unknown> {
  const jev = obj(reply.jev), used = jev.used === true, status = jev.status;
  const failed = status === "unavailable" || status === "invalid_response";
  const by = (DECIDED_BY as readonly unknown[]).includes(reply.decided_by) ? reply.decided_by : failed ? "fail_open" : used ? "jev" : "prefilter";
  const detail = typeof jev.detail === "string" ? jev.detail : "";
  const code = status === "invalid_response" || /returned an invalid/i.test(detail) ? "invalid_response" : /no jev credentials/i.test(detail) ? "no_upstream" : /timed out|timeout|abort/i.test(detail) ? "timeout" : "upstream_error";
  return { decision: reply.decision, decided_by: by, rule: reply.rule, fail_reason: by === "fail_open" ? code : null, jev: { used, status, model: jev.model, usage: obj(jev.usage) } };
}

export function buildRow(rec: unknown, o: { host: string; decision?: string; decidedBy?: string; failReason?: string; latencyMs?: number; enforced?: boolean; wouldHave?: string | null; source?: "server" | "client"; tool?: string; rule?: string; policyVersion?: string | null }): Record<string, unknown> {
  const r = obj(rec), j = obj(r.jev);
  const used = "calls" in j ? j.calls === 1 : j.used === true, u = obj(j.usage);
  const cost = "cost" in j ? nonneg(j.cost) : nonneg(u.cost);
  const cs = j.cost_source;
  const by = o.decidedBy ?? r.decided_by;
  const decidedBy = (DECIDED_BY as readonly unknown[]).includes(by) ? (by as string) : null;
  const fr = o.failReason ?? r.fail_reason;
  let failReason = (FAIL_REASONS as readonly unknown[]).includes(fr) ? (fr as string) : null;
  if (decidedBy === "fail_open" && failReason === null) failReason = "upstream_error";
  return {
    v: 1,
    decision_id: randomUUID(), // the hook mints every row's id; the Worker's is kept apart so client-only rows are first-class
    server_decision_id: typeof r.decision_id === "string" && UUID_RE.test(r.decision_id) ? r.decision_id : null,
    ts: typeof r.ts === "string" && TS_RE.test(r.ts) ? r.ts : new Date().toISOString(),
    tool: pick(TOOL, o.tool ?? "kit_guard_command"),
    decision: pick(WORD, o.decision ?? r.decision),
    verdict: pick(WORD, r.verdict),
    decided_by: decidedBy,
    rule: pick(RULE, o.rule ?? r.rule),
    fail_reason: failReason,
    latency_ms: nonneg(o.latencyMs) === null ? null : Math.round(o.latencyMs as number),
    jev: {
      calls: used ? 1 : 0,
      status: pick(WORD, j.status),
      model: used ? pick(MODEL, j.model) : null,
      input_tokens: used ? nonneg(j.input_tokens ?? u.input_tokens) : null,
      output_tokens: used ? nonneg(j.output_tokens ?? u.output_tokens) : null,
      cost: used ? cost : null,
      cost_source: used ? (cs === "upstream" || cs === "configured" || cs === "unknown" ? cs : cost !== null ? "upstream" : "unknown") : null,
    },
    tiers: null,
    host: pick(HOST, o.host),
    correlation_id: pick(CORRELATION, r.correlation_id),
    policy_version: pick(POLICY_V, o.policyVersion ?? r.policy_version),
    source: o.source ?? "client",
    enforced: o.enforced !== false,
    would_have: pick(WORD, o.wouldHave),
  };
}

let rotationSeq = 0;
const O_APPEND_FLAGS = constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK; // NONBLOCK: a FIFO must fail to open, not hang
const euid = () => (typeof process.geteuid === "function" ? process.geteuid() : -1);

function ownedDir(d: string): boolean {
  mkdirSync(d, { recursive: true, mode: 0o700 });
  const st = lstatSync(d);
  return st.isDirectory() && (euid() === -1 || st.uid === euid());
}
function openLedger(path: string): number {
  try { if (!lstatSync(path).isFile()) throw new Error("ledger path is not a regular file"); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e; }
  const fd = openSync(path, O_APPEND_FLAGS, 0o600);
  const st = fstatSync(fd);
  if (!st.isFile() || (euid() !== -1 && st.uid !== euid())) { closeSync(fd); throw new Error("ledger is not a regular file owned by this user"); }
  return fd;
}
export function rotatedFiles(path: string): string[] {
  const d = dirname(path), base = basename(path);
  try { return readdirSync(d).filter((n) => n.startsWith(`${base}.`) && ROTATED_RE.test(n)).sort().map((n) => join(d, n)); } catch { return []; }
}

/** One atomic append of one whole line. Returns true if written. Never throws. */
export function appendLine(row: Record<string, unknown>, path: string | null = ledgerPath(), opts: { maxBytes?: number; keep?: number } = {}): boolean {
  let fd = -1;
  try {
    if (!path) return false;
    const line = Buffer.from(JSON.stringify(row).replace(/[\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`) + "\n", "ascii");
    if (line.length > LEDGER_MAX_LINE) return false;
    if (!ownedDir(dirname(path))) return false;
    fd = openLedger(path);
    const st = fstatSync(fd);
    if (st.size > (opts.maxBytes ?? LEDGER_MAX_BYTES)) {
      // rotate: rename (never overwrite) to a unique name, only if the path still refers to the file we measured
      try {
        const cur = lstatSync(path);
        if (cur.ino === st.ino && cur.dev === st.dev) {
          const now = Date.now(), d = new Date(now);
          const pad = (n: number, w = 2) => String(n).padStart(w, "0");
          const stamp = `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}T${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}${pad((now % 1000) * 1000 + (rotationSeq++ % 1000), 6)}Z`; // sortable and unique within this process even inside one millisecond
          const target = `${path}.${stamp}-${process.pid}`;
          if (!existsSync(target)) renameSync(path, target);
        }
      } catch { /* another writer rotated first */ }
      closeSync(fd); fd = -1;
      fd = openLedger(path);
      for (const old of rotatedFiles(path).slice(0, -(opts.keep ?? LEDGER_KEEP_ROTATED))) { try { unlinkSync(old); } catch { /* ignore */ } }
    }
    return writeSync(fd, line) === line.length;
  } catch { return false; } finally { if (fd !== -1) { try { closeSync(fd); } catch { /* ignore */ } } }
}
export const appendRow = appendLine;

/** Build one row synchronously. Returns the row and its decision_id, or null. Never throws. No I/O. */
export function prepareDecision(reply: unknown, o: Parameters<typeof buildRow>[1]): { row: Record<string, unknown>; id: string } | null {
  try {
    const rp = obj(reply);
    const hasRec = Object.keys(obj(rp.record)).length > 0;
    const rec = hasRec ? rp.record : reply === undefined || reply === null ? null : synthFromReply(rp);
    const row = buildRow(rec, { ...o, source: o.source ?? (hasRec ? "server" : "client") });
    return { row, id: row.decision_id as string };
  } catch { return null; }
}

/** Build and append one row; `reply` is the worker's parsed payload (may carry `record`). Returns the row's decision_id, or null if nothing was written. Never throws. */
export function recordDecision(reply: unknown, o: Parameters<typeof buildRow>[1], path?: string | null): string | null {
  const p = prepareDecision(reply, o);
  return p && appendLine(p.row, path) ? p.id : null;
}

/** A host-observed outcome for a row this hook wrote. Allow-listed shape; never throws. */
export function recordOutcome(decisionId: string, label: "approved" | "denied" | "no_ui", path?: string | null): boolean {
  try {
    if (!UUID_RE.test(decisionId) || !WORD.test(label)) return false;
    return appendLine({ v: 1, decision_id: decisionId, label, ts: new Date().toISOString(), subagent_tokens: null, source: "host_observed" }, path);
  } catch { return false; }
}

/** Map a thrown error to a closed code. The message text is never copied. */
export function failCodeFor(e: unknown): (typeof FAIL_REASONS)[number] {
  const name = e instanceof Error ? e.name : "";
  if (name === "TimeoutError" || name === "AbortError") return "client_timeout";
  if (name === "SyntaxError" || (name === "TypeError" && e instanceof Error && /json/i.test(e.message))) return "client_parse";
  return "client_network";
}

type GuardReply = { decision?: string; rule?: string; reason?: string; suggestion?: string; decided_by?: string; fail_reason?: string };
type McpResult<T> = { kind: "reply"; reply: T } | { kind: "rejected"; detail: string } | { kind: "unavailable"; code: (typeof FAIL_REASONS)[number] };

// One JSON-RPC tools/call over the same transport for the guard and the policy call: https only, bearer from the
// environment, redirects refused, a hard timeout.
async function mcpCall<T>(tool: string, args: Record<string, unknown>, timeoutMs: number): Promise<McpResult<T>> {
  const token = (process.env.JEV_MCP_TOKEN ?? "").trim();
  if (!token || !mcpUrl().startsWith("https://")) return { kind: "unavailable", code: "client_config" };
  try {
    const res = await fetch(mcpUrl(), {
      method: "POST",
      redirect: "error", // a 3xx would re-send the bearer wherever it points
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: `Bearer ${token}`,
        "user-agent": "jev-guard-hook-omp/1.0",
      },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 1, method: "tools/call",
        params: { name: tool, arguments: args },
      }),
    });
    // 4xx (bad/revoked token, Cloudflare block, bad request): the server answered and refused the call, same
    // class as a JSON-RPC error -- ask, never a silent allow. 5xx stays an outage: fail open.
    if (!res.ok) return res.status >= 400 && res.status < 500 ? { kind: "rejected", detail: `HTTP ${res.status}` } : { kind: "unavailable", code: res.status >= 500 ? "client_http_5xx" : "client_network" };
    const raw = await res.text();
    for (let line of raw.split("\n")) {
      line = line.trim();
      if (line.startsWith("data:")) line = line.slice(5).trim();
      if (!line.startsWith("{")) continue;
      const msg = JSON.parse(line) as { error?: { message?: string }; result?: { isError?: boolean; content?: { text?: string }[] } };
      if (msg.error) return { kind: "rejected", detail: String(msg.error.message ?? "error").slice(0, 200) };
      if (msg.result?.isError) return { kind: "rejected", detail: String(msg.result.content?.[0]?.text ?? "tool error").slice(0, 200) };
      const text = msg.result?.content?.[0]?.text;
      if (typeof text !== "string") return { kind: "unavailable", code: "client_parse" };
      return { kind: "reply", reply: JSON.parse(text) as T };
    }
  } catch (e) {
    let msg = "";
    if (e instanceof Error) {
      msg = e.message.toLowerCase();
      if (e.cause instanceof Error) msg += ` ${e.cause.message.toLowerCase()}`;
      if ("code" in e && typeof e.code === "string") msg += ` ${e.code.toLowerCase()}`;
    }
    if (msg.includes("redirect")) {
      // A 3xx would re-send the bearer wherever it points; the endpoint answered, so this is a refusal to
      // judge, not an outage — same class as a JSON-RPC error, never a silent allow.
      return { kind: "rejected", detail: "redirect refused" };
    }
    return { kind: "unavailable", code: failCodeFor(e) }; /* timeout, network, parse: fail open */
  }
  return { kind: "unavailable", code: "client_parse" };
}

// ── policy path (openspec add-policy-hook-adapter, D5-D10) ─────────────────────────────────────────────────────────
// A user-authored policy class fires when a bash command matches a `trigger` in the user layer. The plan helper
// (scripts/jev-policy-hook.mjs) is the only code that parses triggers; this file runs it, sends ONE kit_decide call and
// maps the answer through the plan's effects. Opt-in and zero cost: no user layer, or no `"trigger"` in its text, starts
// no process. The command text only ever travels on the helper's stdin and inside `state`; it is never an argv word, and
// it never reaches the ledger.
type Effect = "allow" | "ask" | "deny";
const EFFECT_RANK: Record<Effect, number> = { allow: 0, ask: 1, deny: 2 };
const POLICY_USER_MAX_BYTES = 16384;
type FailReason = (typeof FAIL_REASONS)[number];

/** JEV_POLICY_TIMEOUT seconds, default 3, clamped to [1, 4]; returned in ms. */
export function policyDeadlineMs(env: Record<string, string | undefined> = process.env): number {
  const raw = (env.JEV_POLICY_TIMEOUT ?? "").trim();
  const s = raw === "" ? 3 : Number(raw);
  return Math.min(4, Math.max(1, Number.isFinite(s) ? s : 3)) * 1000;
}

/** Cheap opt-in gate: the user layer is a regular file (never a symlink) of at most 16 KB whose text contains `"trigger"`. Never throws. */
function readUserLayerText(env: Record<string, string | undefined>, cwd: string): string | null {
  let fd = -1;
  try {
    const custom = (env.JEV_POLICY_USER ?? "").trim();
    const xdg = (env.XDG_CONFIG_HOME ?? "").trim();
    const path = resolve(cwd, custom || join(xdg || join((env.HOME ?? "").trim() || homedir(), ".config"), "jev", "policy.json"));
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK); // a symlink or FIFO fails to open
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > POLICY_USER_MAX_BYTES) return null;
    const buf = Buffer.alloc(st.size);
    const n = readSync(fd, buf, 0, st.size, 0);
    return buf.subarray(0, n).toString("utf8");
  } catch { return null; } finally { if (fd !== -1) { try { closeSync(fd); } catch { /* ignore */ } } }
}

export function userLayerHasTrigger(env: Record<string, string | undefined> = process.env, cwd: string = process.cwd()): boolean {
  const text = readUserLayerText(env, cwd);
  return text !== null && text.includes('"trigger"');
}

/**
 * True when a class with a trigger fails closed (its on_unavailable decision is not its baseline), or when the layer cannot be
 * read well enough to tell (unknown counts as closed). Only decides whether a silent fail-open deserves a notice for the user;
 * it never changes a decision. Never throws.
 */
export function policyGateMayBeClosed(env: Record<string, string | undefined> = process.env, cwd: string = process.cwd()): boolean {
  try {
    const text = readUserLayerText(env, cwd);
    if (text === null) return true;
    const doc = JSON.parse(text) as { decisions?: unknown };
    if (!Array.isArray(doc.decisions)) return true;
    let closed = false;
    for (const d of doc.decisions as Record<string, unknown>[]) {
      if (!d || typeof d !== "object" || !("trigger" in d)) continue;
      const un = d.on_unavailable as { decision?: unknown } | undefined;
      if (!un || typeof un !== "object" || un.decision === undefined || un.decision !== d.baseline) closed = true;
    }
    return closed;
  } catch { return true; }
}

/** Fixed words for the USER (never the model): no command, no path, no instruction. */
export const POLICY_NOTICE = "Jev policy: a policy gate was not evaluated for this command (the helper is unavailable, the policy file is unusable, or it ran out of time). The reason is in the decision ledger.";

/** The JavaScript runtime that runs the plan helper: this process when it is node, else node from PATH, else bun (the helper uses only node: APIs both provide). */
export function policyRuntime(env: Record<string, string | undefined> = process.env, execPath: string = process.execPath): string | null {
  const base = basename(execPath).toLowerCase();
  if (/^node(js)?(\.exe)?$/.test(base)) return execPath;
  const onPath = (name: string): string | null => {
    for (const dir of (env.PATH ?? "").split(":")) {
      if (!dir) continue;
      const f = join(dir, name);
      try { if (statSync(f).isFile()) { accessSync(f, constants.X_OK); return f; } } catch { /* next */ }
    }
    return null;
  };
  const node = onPath("node");
  if (node) return node;
  if (/^bun(\.exe)?$/.test(base)) return execPath;
  return onPath("bun");
}

type Plan = {
  ok?: boolean; problem?: string; triggered?: boolean; class?: string; policy_version?: string;
  call?: Record<string, unknown>; effects?: Record<string, unknown>;
  on_unavailable?: { decision?: string; effect?: string; mode?: string };
  extra?: number; provider_failure?: { name?: string; code?: string } | null;
};
type PlanResult = { kind: "plan"; plan: Plan } | { kind: "failed"; code: FailReason };

/** Run the plan helper: `node <helper> plan`, event JSON on stdin, argv array, no shell, hard timeout. Never rejects. */
/**
 * The plan helper: $JEV_POLICY_HOOK, else the installed copy under ~/.local/share/honest-jev, else (for one release) the
 * pre-rename install dir ~/.local/share/jev-agent-skills when only that one exists. With neither present the new path is
 * returned, so the failure the hook reports names the current location.
 */
export function policyHelperPath(env: Record<string, string | undefined> = process.env, exists: (p: string) => boolean = existsSync): string {
  const custom = (env.JEV_POLICY_HOOK ?? "").trim();
  if (custom) return custom;
  const home = (env.HOME ?? "").trim() || homedir();
  const at = (dir: string) => join(home, ".local", "share", dir, "jev-policy", "scripts", "jev-policy-hook.mjs");
  const current = at("honest-jev");
  return exists(current) ? current : exists(at("jev-agent-skills")) ? at("jev-agent-skills") : current;
}

function runPlan(helper: string, event: Record<string, unknown>, timeoutMs: number): Promise<PlanResult> {
  const { promise, resolve: done } = Promise.withResolvers<PlanResult>();
  try {
    if (!statSync(helper).isFile()) { done({ kind: "failed", code: "client_config" }); return promise; }
  } catch { done({ kind: "failed", code: "client_config" }); return promise; }
  try {
    const runtime = policyRuntime();
    if (!runtime) { done({ kind: "failed", code: "client_config" }); return promise; }
    const child = execFile(runtime, [helper, "plan"], { timeout: timeoutMs, killSignal: "SIGKILL", maxBuffer: 1 << 20, windowsHide: true, encoding: "utf8", env: process.env }, (err, stdout) => {
      try {
        if (err && (err.killed || err.signal)) return done({ kind: "failed", code: "client_timeout" });
        if (err && err.code === "ENOENT") return done({ kind: "failed", code: "client_config" });
        const doc: unknown = JSON.parse(String(stdout ?? "").trim().split("\n").pop() ?? "");
        if (!doc || typeof doc !== "object" || Array.isArray(doc)) return done({ kind: "failed", code: "client_parse" });
        done({ kind: "plan", plan: doc as Plan });
      } catch { done({ kind: "failed", code: "client_parse" }); }
    });
    child.stdin?.on("error", () => { /* the helper exited before reading: the callback reports it */ });
    child.stdin?.end(JSON.stringify(event));
  } catch (e) { done({ kind: "failed", code: failCodeFor(e) }); }
  return promise;
}

type PolicyOutcome = { effect: Effect; reason: string; rowId: string | null; notice?: string };
type DecideReply = { decision?: unknown; rule_id?: unknown; reason?: unknown; record?: unknown };
const asEffect = (v: unknown): Effect => (v === "allow" || v === "ask" || v === "deny" ? v : "ask");

/**
 * The whole policy path for one bash call. Resolves null when nothing applies (no trigger matched, or the path failed
 * open); otherwise the effect the policy wants, the reason to show, and the ledger row id for ask outcomes. Writes its
 * own ledger row (deferred by `rec`, like every other row) and never throws.
 */
async function policyDecide(
  command: string, cwd: string, tStart: number,
  rec: (reply: unknown, o: Omit<Parameters<typeof buildRow>[1], "host" | "latencyMs">) => string | null,
  note: (m: string) => void,
): Promise<PolicyOutcome | null> {
  try {
    const deadlineMs = policyDeadlineMs();
    const deadlineAt = tStart + deadlineMs;
    // One row per decision. Shadow: never enforced; would_have names what enforcing would have done.
    const row = (effect: Effect, reply: unknown, o: Omit<Parameters<typeof buildRow>[1], "host" | "latencyMs" | "tool" | "enforced" | "wouldHave">): string | null => {
      const shadowed = shadow() && effect !== "allow";
      return rec(reply, { ...o, tool: "kit_decide", enforced: !shadowed, wouldHave: shadowed ? (effect === "deny" ? "block" : "ask") : null });
    };

    const helper = policyHelperPath(process.env);
    const planned = await runPlan(helper, { tool: "Bash", command, cwd, host: "omp" }, Math.max(500, deadlineMs - 1000));
    // fails open (the hook cannot know which class it would have been), leaves a ledger row, and tells the USER when a fail-closed
    // class may be unprotected
    const failOpen = (code: FailReason): PolicyOutcome | null => {
      row("allow", undefined, { decision: "allow", decidedBy: "fail_open", failReason: code });
      note(`jev policy path failed open (${code})`);
      return !shadow() && policyGateMayBeClosed(process.env, cwd) ? { effect: "allow", reason: "", rowId: null, notice: POLICY_NOTICE } : null;
    };
    if (planned.kind === "failed") return failOpen(planned.code);
    const plan = planned.plan;
    if (plan.ok !== true) return failOpen(plan.problem === "bad_input" ? "client_input" : "client_config");
    if (plan.triggered !== true) return null;
    const cls = typeof plan.class === "string" ? plan.class.slice(0, 64) : "";
    const effects = plan.effects && typeof plan.effects === "object" ? plan.effects : null;
    const od = plan.on_unavailable && typeof plan.on_unavailable === "object" ? plan.on_unavailable : null;
    if (!cls || !plan.call || typeof plan.call !== "object" || !effects || !od) return failOpen("client_parse");
    const tag = (rule?: unknown) => `Jev policy [${cls}/${typeof rule === "string" && rule ? rule : "default"}]`;
    const pv = typeof plan.policy_version === "string" ? plan.policy_version : null;
    const closed = od.mode === "closed";
    // the class's own answer to "the decision could not be made": applied locally, no model call
    const unavailable = (code: FailReason, why: string): PolicyOutcome => {
      const effect = asEffect(od.effect);
      return { effect, reason: `${tag()}: ${why}`, rowId: row(effect, undefined, { decision: od.decision, decidedBy: closed ? "fail_closed" : "fail_open", failReason: code, policyVersion: pv }) };
    };

    if (plan.provider_failure && typeof plan.provider_failure === "object") {
      const code = (FAIL_REASONS as readonly unknown[]).includes(plan.provider_failure.code) ? (plan.provider_failure.code as FailReason) : "client_network";
      return unavailable(code, "a fact this gate needs could not be read; confirm it by hand.");
    }
    if (typeof plan.extra === "number" && plan.extra > 0) {
      return { effect: "ask", reason: `${tag()}: another policy gate also applies to this command; run them separately.`, rowId: row("ask", undefined, { decision: "ask", decidedBy: "policy", policyVersion: pv }) };
    }

    const remaining = deadlineAt - Date.now();
    if (remaining <= 0) return unavailable("client_timeout", "the policy check ran out of time; confirm it by hand.");
    const res = await mcpCall<DecideReply>("kit_decide", { ...plan.call, budget_ms: Math.max(300, remaining - 300) }, Math.max(100, remaining));
    if (res.kind === "unavailable") return unavailable(res.code, "the policy service could not be reached; confirm it by hand.");
    if (res.kind === "rejected") {
      return { effect: "ask", reason: `${tag()}: the server rejected the policy call (${res.detail}); confirm it by hand.`, rowId: row("ask", undefined, { decision: "ask", decidedBy: "fail_closed", failReason: "client_rejected", policyVersion: pv }) };
    }
    const rp = res.reply && typeof res.reply === "object" ? res.reply : {};
    const word = typeof rp.decision === "string" ? rp.decision : "";
    const effect = Object.hasOwn(effects, word) ? asEffect(effects[word]) : "ask";
    const rowId = row(effect, rp, { decision: word, rule: typeof rp.rule_id === "string" ? rp.rule_id : undefined, policyVersion: pv ?? undefined }); // the plan's own hash (computed locally from the user's layers) wins over the reply's
    return { effect, reason: `${tag(rp.rule_id)}: ${typeof rp.reason === "string" && rp.reason ? rp.reason : "the policy decision needs review."}`, rowId };
  } catch {
    return !shadow() && policyGateMayBeClosed(process.env, cwd) ? { effect: "allow", reason: "", rowId: null, notice: POLICY_NOTICE } : null; // never let the policy path break the session
  }
}

type ToolCallEvent = { toolName?: string; input?: Record<string, unknown> };
type ToolCallCtx = { cwd?: string; hasUI?: boolean; ui?: { confirm?: (title: string, message: string) => Promise<boolean>; notify?: (message: string, level?: string) => void } };
type Verdict = { block: true; reason: string } | undefined;

export default function jevGuard(pi: ExtensionAPI) {
  let noticed = false; // the "no server configured" notice goes out once per session, kept in memory
  let downNoticed = false; // so does the "local rules could not run and no server" notice, with its own flag
  const trustNoticed = new Set<RulesTrust>(); // and each of the two "local rules vs the server's" notices
  // `rowId` is the ledger row for this ask (or null). omp hands us the user's answer, so the outcome is host-observed:
  // approved, denied, or no_ui when nobody could be asked. Ledger writes are deferred with setImmediate: the verdict
  // is returned before any ledger I/O, so a slow filesystem cannot delay the decision. Writes keep FIFO order (the
  // decision row is queued before its outcome). Residual: a synchronous write still blocks the event loop after the
  // verdict has been delivered. recordOutcome never throws.
  const ask = async (ctx: ToolCallCtx, why: string, rowId: string | null = null, alsoRowId: string | null = null): Promise<Verdict> => {
    if (shadow()) { pi.logger?.warn?.(`(shadow) would ask: ${why}`); return; }
    const ids = [rowId, alsoRowId].filter((x): x is string => !!x); // the guard's row, the policy's row, or both
    if (ctx.hasUI && typeof ctx.ui?.confirm === "function") {
      const ok = await ctx.ui.confirm("Jev guard: run this command?", why);
      for (const id of ids) setImmediate(() => recordOutcome(id, ok ? "approved" : "denied"));
      return ok ? undefined : { block: true, reason: `${why} (declined by user)` };
    }
    for (const id of ids) setImmediate(() => recordOutcome(id, "no_ui"));
    return askNoUi() === "allow" ? undefined : { block: true, reason: `${why} Needs human approval; ask the user and retry.` };
  };
  const led = (t0: number, reply: unknown, o: Omit<Parameters<typeof buildRow>[1], "host" | "latencyMs">): string | null => {
    const p = prepareDecision(reply, { ...o, host: "omp", latencyMs: Date.now() - t0 });
    if (!p || ledgerPath() === null) return null;
    setImmediate(() => appendLine(p.row));
    return p.id;
  };

  // a new session may be told once again that the guard has no server
  pi.on("session_start", async () => { noticed = false; downNoticed = false; trustNoticed.clear(); });

  pi.on("tool_call", async (event: ToolCallEvent, ctx: ToolCallCtx): Promise<Verdict> => {
    try {
      const tStart = Date.now(); // the policy deadline runs from here
      let args: Record<string, unknown> | null = null;
      let bash = false;
      if (isToolCallEventType("bash", event)) {
        bash = true;
        args = { tool: "Bash", command: String(event.input?.command ?? ""), cwd: ctx.cwd, home: process.env.HOME };
      } else if (event.toolName === "read" && (event.input?.path || event.input?.file_path)) {
        args = { tool: "Read", file_path: String(event.input.path ?? event.input.file_path), cwd: ctx.cwd, home: process.env.HOME };
      } else if (event.toolName === "grep" && event.input?.pattern && event.input?.output_mode === "content") {
        // output_mode defaults to files_with_matches (paths only, no content); only "content" mode prints
        // matching lines verbatim, so only that mode is judged as the grep command it is (R1 secret reader)
        args = { tool: "Bash", command: `grep -r ${JSON.stringify(String(event.input.pattern))} ${JSON.stringify(String(event.input.path ?? "."))}`, cwd: ctx.cwd, home: process.env.HOME };
      }
      if (!args) return;
      const t0 = Date.now();
      for (const [key, cap] of Object.entries(CAPS)) {
        const v = args[key];
        if (typeof v !== "string" || v.length <= cap) continue;
        if (key === "command" || key === "file_path") {
          const rowId = led(t0, undefined, { decision: "ask", decidedBy: "fail_closed", failReason: "oversize", enforced: !shadow(), wouldHave: shadow() ? "ask" : null });
          return ask(ctx, `Jev guard: ${key} is ${v.length} chars, over the ${cap}-char limit the guard can judge; confirm it by hand.`, rowId);
        }
        args[key] = v.slice(0, cap);
      }
      const at = askAt();
      if (at !== undefined) args.ask_at = at;
      const localRaw = await localGuard(args); // a command the rules settle never reaches mcpCall
      const local = localRaw !== null && "reply" in localRaw ? localRaw : null;
      const localNotRun = localRaw !== null && !("reply" in localRaw); // enabled, and it did not run
      // The policy path runs concurrently with the guard call. It is opt-in: without a `"trigger"` in the user layer
      // nothing starts. policyDecide never rejects, so a policy failure cannot take the guard's answer down with it.
      const policyCwd = ctx.cwd ?? process.cwd();
      const pending = bash && userLayerHasTrigger(process.env, policyCwd)
        ? policyDecide(String(args.command), policyCwd, tStart, (reply, o) => led(tStart, reply, o), (m) => pi.logger?.warn?.(m)).catch(() => null)
        : Promise.resolve(null);
      const ruleSettled = local !== null && !local.unclear && (local.reply.decided_by === "prefilter" || local.reply.decided_by === "fail_closed");
      // A local ask or block stands whatever the server's rules are (stricter than the server is safe). A local allow stands when there is no
      // server to ask, or when the rules in this process are the ones the server runs; otherwise the server decides, and the user is told once.
      let trust: RulesTrust | null = null;
      if (ruleSettled && local!.reply.decision === "allow" && (process.env.JEV_MCP_TOKEN ?? "").trim() !== "" && mcpUrl().startsWith("https://")) trust = await rulesTrust(local!);
      const settled = ruleSettled && (trust === null || trust === "match");
      if ((trust === "mismatch" || trust === "unverified") && !trustNoticed.has(trust)) {
        trustNoticed.add(trust);
        try { if (typeof ctx.ui?.notify === "function") ctx.ui.notify(TRUST_NOTICES[trust], "warning"); else pi.logger?.warn?.(TRUST_NOTICES[trust]); } catch { /* a notice never changes a decision */ }
      }
      const [answered, pol] = await Promise.all([
        settled ? Promise.resolve<McpResult<GuardReply>>({ kind: "reply", reply: local!.reply as GuardReply }) : mcpCall<GuardReply>("kit_guard_command", args, timeoutMs()),
        pending,
      ]);
      // `unclear` can hold while the local reply is already an ask (a rule asked on one reading, the model question came from the other):
      // if the server cannot be consulted, that ask is the decision, through the same branch a settled local reply takes. Never an
      // allow only because nobody answered the model question.
      const g: McpResult<GuardReply> = answered.kind === "unavailable" && local?.unclear && local.reply.decision !== "allow" ? { kind: "reply", reply: local.reply as GuardReply } : answered;

      // the guard's own effect and reason (rows and shadow notes exactly as before)
      let ge: Effect = "allow", gWhy = "", gRow: string | null = null;
      if (g.kind === "unavailable") {
        // fail open. A command the local rules flagged keeps the rule id on its row (an id, never text).
        const flagged = local?.unclear && typeof local.reply.rule === "string" ? local.reply.rule : undefined;
        // the local step was on and did not run, and there is no server either: nothing checked this command. Its own closed reason, so the log
        // tells it from "unclear, no server" (those rows come with a reply from the rules; these have none).
        const nothingRan = localNotRun && g.code === "client_config";
        led(t0, undefined, { decision: "allow", decidedBy: "fail_open", failReason: nothingRan ? "local_rules_unavailable" : g.code, rule: flagged });
        // once per session each, for the user: fixed words, never the model
        const say = nothingRan ? (downNoticed ? null : LOCAL_DOWN_NOTICE) : local?.unclear && g.code === "client_config" && !noticed ? LOCAL_NOTICE : null;
        if (say !== null) {
          if (nothingRan) downNoticed = true; else noticed = true;
          try { if (typeof ctx.ui?.notify === "function") ctx.ui.notify(say, "warning"); else pi.logger?.warn?.(say); } catch { /* a notice never changes a decision */ }
        }
      } else if (g.kind === "rejected") {
        gRow = led(t0, undefined, { decision: "ask", decidedBy: "fail_closed", failReason: "client_rejected", enforced: !shadow(), wouldHave: shadow() ? "ask" : null });
        gWhy = `Jev guard could not judge this call (server rejected it: ${g.detail}); confirm it by hand.`;
        if (shadow()) pi.logger?.warn?.(`(shadow) would ask: ${gWhy}`); else ge = "ask";
      } else {
        const r = g.reply;
        const would = shadow() && (r.decision === "ask" || r.decision === "block") ? r.decision : null;
        const ruleError = r.decided_by === "fail_closed" && r.fail_reason === "rule_error" ? "rule_error" : undefined; // a server reply carries this in its record; a local reply has none
        gRow = led(t0, r, { decision: r.decision, enforced: would === null, wouldHave: would, failReason: ruleError });
        if (r.decision === "ask" || r.decision === "block") {
          gWhy = `Jev guard${r.rule ? ` [${r.rule}]` : ""}: ${r.reason}${r.suggestion ? ` ${r.suggestion}` : ""}`;
          if (shadow()) pi.logger?.warn?.(`(shadow) would ${r.decision}: ${gWhy}`); else ge = r.decision === "block" ? "deny" : "ask";
        }
      }

      // stricter wins (allow < ask < deny); the policy never enforces in shadow mode
      if (shadow() && pol && pol.effect !== "allow") pi.logger?.warn?.(`(shadow) would ${pol.effect}: ${pol.reason}`);
      if (pol?.notice) { // for the user: fixed words, never the model
        try { if (typeof ctx.ui?.notify === "function") ctx.ui.notify(pol.notice, "warning"); else pi.logger?.warn?.(pol.notice); } catch { /* a notice never changes a decision */ }
      }
      const pe: Effect = shadow() || !pol ? "allow" : pol.effect;
      const gRank = EFFECT_RANK[ge], pRank = EFFECT_RANK[pe];
      if (pRank === 0 || gRank > pRank) return ge === "deny" ? { block: true, reason: gWhy } : ge === "ask" ? ask(ctx, gWhy, gRow) : undefined;
      if (pRank > gRank) return pe === "deny" ? { block: true, reason: pol!.reason } : ask(ctx, pol!.reason, pol!.rowId);
      if (pe === "deny") return { block: true, reason: pol!.reason }; // equal and non-allow: the policy's reason
      return ask(ctx, `${gWhy} ${pol!.reason}`, gRow, pol!.rowId); // both ask: one prompt, both reasons, both rows get the outcome
    } catch {
      return; // never let the guard itself break the session
    }
  });
}
