#!/usr/bin/env node
// Local rules runner for the Claude Code guard hook (hooks/jev_guard_hook.py).
//
//   stdin : the already-shaped guard args as one JSON object, the same object the hook would send to kit_guard_command
//   stdout: guardCommand's reply as one JSON object (decision, rule, reason, decided_by, ...) plus `unclear` (boolean); nothing else
//   exit  : 0 with a reply; non-zero with empty stdout when the rules cannot be found, loaded or run (the hook then
//           falls through to the server path unchanged)
//   --check: load the rules, judge one harmless probe, print the path they were loaded from (install.sh --doctor)
//
// The rules are the deterministic prefilter in server/src/kit (guard.mjs, shell.mjs, safere.mjs): no npm package, nothing
// but node:path. This file imports no other module of the kit and never calls a model. `unclear: true` means the rules
// would have asked the model (R10 risk, an ambiguous secret path): the reply is then not a decision to act on.
//
// Rules are looked up next to THIS file, so a hook always runs the rules of its own release:
//   $JEV_GUARD_RULES (an absolute path to guard.mjs; when set it is the only candidate; tests use it)
//   <hookdir>/../server/src/kit/guard.mjs                    repo or Claude plugin checkout (the plugin root is the repo)
//   <hookdir>/../jev-policy/server/src/kit/guard.mjs         install.sh layout (~/.local/share/honest-jev)
//   ~/.local/share/jev-agent-skills/jev-policy/server/src/kit/guard.mjs   pre-rename install dir
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync } from "node:fs";
import * as nodeModule from "node:module";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

function rulesCandidates(env) {
  const custom = (env.JEV_GUARD_RULES ?? "").trim();
  if (custom) return isAbsolute(custom) ? [custom] : [];
  const home = (env.HOME ?? "").trim() || homedir();
  return [
    resolve(here, "..", "server", "src", "kit", "guard.mjs"),
    resolve(here, "..", "jev-policy", "server", "src", "kit", "guard.mjs"),
    join(home, ".local", "share", "jev-agent-skills", "jev-policy", "server", "src", "kit", "guard.mjs"),
  ];
}

// V8 compile cache for the 5,000 lines of rules, kept in a private directory of ours (never the shared temp dir, never a directory
// someone else can write to). Optional: any failure, or a node without the API, just means no cache.
function enableCache(env) {
  try {
    if (typeof nodeModule.enableCompileCache !== "function") return;
    const xdg = (env.XDG_CACHE_HOME ?? "").trim();
    const home = (env.HOME ?? "").trim() || homedir();
    const dir = join(xdg && isAbsolute(xdg) ? xdg : join(home, ".cache"), "jev", "compile-cache");
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const st = lstatSync(dir);
    if (!st.isDirectory() || (typeof process.geteuid === "function" && st.uid !== process.geteuid())) return;
    if ((st.mode & 0o022) !== 0) return; // group- or world-writable: anyone it names could plant compiled code the guard would then load
    nodeModule.enableCompileCache(dir);
  } catch { /* no cache */ }
}

/**
 * The runner's whole stdin handling: one JSON object of guard args in, guardCommand's reply plus `unclear` out. The one-shot entry
 * below and the tests both go through this function. Throws when `text` is not a JSON object.
 *
 * `ask` is never answered: it only records that the rules WOULD have consulted the model, then throws, so guardCommand fails
 * open exactly as with no model. Reading `decided_by: "fail_open"` alone is not enough: guardCommand judges a command twice
 * when a comment holds a quote character, and a model question raised only by the second reading ends up as a plain allow.
 */
export async function judgeStdin(text, guardCommand) {
  const args = JSON.parse(text);
  if (!args || typeof args !== "object" || Array.isArray(args)) throw new TypeError("input is not a JSON object");
  let consulted = 0;
  const reply = await guardCommand(args, { jevAvailable: true, ask: async () => { consulted++; throw new Error("no model in the local runner"); } });
  // unclear = a model question was raised and no rule blocked. A block stands whatever the model would have said.
  reply.unclear = consulted > 0 && reply.decision !== "block";
  return reply;
}

async function main() {
  const env = process.env;
  const path = rulesCandidates(env).find((p) => existsSync(p));
  if (!path) { process.stderr.write("jev-guard-local: rules not found\n"); return 3; }
  enableCache(env);
  const { guardCommand } = await import(pathToFileURL(path).href);
  if (typeof guardCommand !== "function") { process.stderr.write("jev-guard-local: rules module has no guardCommand\n"); return 4; }
  if (process.argv[2] === "--check") {
    const r = await judgeStdin(JSON.stringify({ tool: "Bash", command: "cat .env", cwd: "/", home: "/" }), guardCommand);
    if (r.decision !== "block") { process.stderr.write("jev-guard-local: probe was not judged as expected\n"); return 5; }
    process.stdout.write(`${path}\n`);
    return 0;
  }
  let reply;
  try { reply = await judgeStdin(readFileSync(0, "utf8"), guardCommand); } catch { process.stderr.write("jev-guard-local: input is not a JSON object\n"); return 6; }
  process.stdout.write(`${JSON.stringify(reply)}\n`);
  return 0;
}

// Run only as the entry point, so a test can import judgeStdin without starting a run.
let isEntry = false;
try { isEntry = realpathSync(process.argv[1]) === fileURLToPath(import.meta.url); } catch { /* imported, or no argv[1] */ }
if (isEntry) main().then((code) => { process.exitCode = code; }, () => { process.stderr.write("jev-guard-local: failed\n"); process.exitCode = 1; });
