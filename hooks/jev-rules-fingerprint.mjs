// The rules fingerprint: one sha256 over the rule files the local guard runs (guard.mjs and the two modules it imports, shell.mjs and
// safere.mjs; no other file of the kit is loaded). The hooks compare the fingerprint of the rules THEY are about to run with the one
// the Worker reports for the rules IT runs: equal means the same bytes, so the local verdict is the one the server would give.
//
// Three places compute it and must agree:
//   hooks/jev-guard-local.mjs          the runner of the Claude Code hook (this module)
//   server/scripts/gen-rules-fingerprint.mjs   writes server/src/rules-fingerprint.mjs, the constant the Worker reports (this module)
//   hooks/omp/jev-guard.ts             the omp hook, which is copied alone into ~/.omp/agent/hooks/pre/ and so carries its own copy
//                                      (tests/local-first-omp.test.ts pins it to this function)
// RULE_FILES is the fixed list, sorted; server/test/rules-fingerprint.test.mjs checks it against the real import graph of guard.mjs.
// Each file is hashed as `<name> NUL <byte length> NUL <bytes>`, so no byte can move from one file to the next unnoticed.
//
// The hash and the import must look at the SAME files. Node resolves a symlinked guard.mjs to its real path and loads ./shell.mjs and
// ./safere.mjs from there, so a link in the kit directory would let the three names here hash as genuine while other bytes run. Therefore a
// rule file that is not a regular file (a symlink, a directory, a device) is an error here, not a fingerprint, and callers hash and import
// from one resolved directory (see resolveRules).
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, join } from "node:path";

export const RULE_FILES = Object.freeze(["guard.mjs", "safere.mjs", "shell.mjs"]);

/** Fingerprint (64 lower-case hex) of the rule files in `kitDir`. Throws when one of them cannot be read or is not a regular file. */
export function rulesFingerprint(kitDir) {
  const h = createHash("sha256");
  for (const name of RULE_FILES) {
    const file = join(kitDir, name);
    if (!lstatSync(file).isFile()) throw new Error(`${name} is not a regular file`);
    const bytes = readFileSync(file);
    h.update(`${name}\0${bytes.length}\0`);
    h.update(bytes);
  }
  return h.digest("hex");
}

/**
 * Where to import `guardPath` from, and the fingerprint of what will run there: `{ path, fp }`. When `guardPath` is a guard.mjs in a kit
 * directory whose three rule files are regular files, the directory is resolved (realpath: the kit directory itself, or a parent of it, may
 * legitimately be a link) and BOTH the hash and `path` come from that resolved directory. Otherwise `fp` is null (the rules are not
 * verifiable: a link among the rule files, an incomplete kit, a file not named guard.mjs) and `path` is `guardPath` unchanged.
 */
export function resolveRules(guardPath) {
  try {
    if (basename(guardPath) !== "guard.mjs") return { path: guardPath, fp: null };
    const dir = realpathSync(dirname(guardPath));
    return { path: join(dir, "guard.mjs"), fp: rulesFingerprint(dir) };
  } catch {
    return { path: guardPath, fp: null };
  }
}
