#!/usr/bin/env node
// jev-outcome: attach an outcome label to a decision in the local ledger. Append-only; the report uses the latest
// label per decision_id. The row is allow-listed and content-free: {v, decision_id, label, ts, subagent_tokens, source}
// with source "self_reported" (this CLI is unauthenticated, so any process on the host, including the audited agent,
// could run it: the report labels these outcomes self-reported).
//   jev-outcome <decision_id> <label> [--tokens N] [--ledger <path>]
//   labels the report understands: approved | denied | abandoned | no_ui (guard ask), followed | overridden (dispatch)
// Exit: 0 written, 1 unknown decision_id (nothing appended), 2 bad input. Zero dependencies.
import { closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, readdirSync, writeSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join } from "node:path";
import { pathToFileURL } from "node:url";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const LABEL = /^[a-z][a-z_]{0,31}$/;
const ROTATED_RE = /\.\d{8}T\d{12}Z-\d+$/;
const MAX_LINE = 2048;

export function ledgerPath(env = process.env) {
  const p = (env.JEV_LEDGER ?? "").trim();
  if (p.toLowerCase() === "off") return null;
  if (p) return isAbsolute(p) ? p : null; // relative would land in the working directory: refused (parity with hooks/jev_ledger.py)
  const xdg = (env.XDG_STATE_HOME ?? "").trim();
  return join(xdg && isAbsolute(xdg) ? xdg : join((env.HOME ?? "").trim() || homedir(), ".local", "state"), "jev", "ledger.jsonl");
}

function ledgerFiles(base) {
  let rotated = [];
  try { rotated = readdirSync(dirname(base)).filter((n) => n.startsWith(`${basename(base)}.`) && ROTATED_RE.test(n)).sort().map((n) => join(dirname(base), n)); } catch { /* none */ }
  return [...rotated, ...(existsSync(base) ? [base] : [])];
}

export function hasDecision(path, id) {
  for (const f of ledgerFiles(path)) {
    for (const line of readFileSync(f, "utf8").split("\n")) {
      if (!line.includes(id)) continue;
      try { const r = JSON.parse(line); if (r && r.decision_id === id && typeof r.tool === "string") return true; } catch { /* skip */ }
    }
  }
  return false;
}

export function appendOutcome(path, id, label, tokens) {
  const row = { v: 1, decision_id: id, label, ts: new Date().toISOString(), subagent_tokens: tokens ?? null, source: "self_reported" };
  const line = Buffer.from(`${JSON.stringify(row)}\n`, "ascii");
  if (line.length > MAX_LINE) throw new Error("outcome row too large");
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const dir = lstatSync(dirname(path)), me = typeof process.geteuid === "function" ? process.geteuid() : -1;
  if (!dir.isDirectory() || (me !== -1 && dir.uid !== me)) throw new Error("ledger directory is not a real directory owned by this user");
  const fd = openSync(path, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600); // one write; no symlink; a FIFO fails instead of hanging
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || (me !== -1 && st.uid !== me)) throw new Error("ledger is not a regular file owned by this user");
    if (writeSync(fd, line) !== line.length) throw new Error("short write");
  } finally { closeSync(fd); }
  return row;
}

function main(argv) {
  const pos = [];
  let tokens, path = ledgerPath();
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--tokens") { tokens = Number(argv[++i]); if (!Number.isInteger(tokens) || tokens < 0) { console.error("jev-outcome: --tokens must be a non-negative integer"); return 2; } }
    else if (argv[i] === "--ledger") path = argv[++i];
    else if (argv[i] === "-h" || argv[i] === "--help") { console.log("usage: jev-outcome <decision_id> <label> [--tokens N] [--ledger path]"); return 0; }
    else pos.push(argv[i]);
  }
  if (pos.length !== 2) { console.error("usage: jev-outcome <decision_id> <label> [--tokens N] [--ledger path]"); return 2; }
  const [id, label] = pos;
  if (!UUID.test(id)) { console.error("jev-outcome: decision_id must be a UUID"); return 2; }
  if (!LABEL.test(label)) { console.error("jev-outcome: label must match [a-z][a-z_]{0,31}"); return 2; }
  if (!path) { const env = (process.env.JEV_LEDGER ?? "").trim(); console.error(env && env.toLowerCase() !== "off" ? "jev-outcome: JEV_LEDGER must be an absolute path" : "jev-outcome: ledger is disabled (JEV_LEDGER=off)"); return 2; }
  if (!hasDecision(path, id)) { console.error("jev-outcome: decision_id not found in the ledger; nothing written"); return 1; }
  try { appendOutcome(path, id, label, tokens); } catch (e) { console.error(`jev-outcome: ${e.message}`); return 1; }
  console.log(`recorded ${label} for ${id} (self-reported)`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exit(main(process.argv.slice(2)));
