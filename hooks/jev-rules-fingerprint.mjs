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
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

export const RULE_FILES = Object.freeze(["guard.mjs", "safere.mjs", "shell.mjs"]);

/** Fingerprint (64 lower-case hex) of the rule files in `kitDir`. Throws when one of them cannot be read. */
export function rulesFingerprint(kitDir) {
  const h = createHash("sha256");
  for (const name of RULE_FILES) {
    const bytes = readFileSync(join(kitDir, name));
    h.update(`${name}\0${bytes.length}\0`);
    h.update(bytes);
  }
  return h.digest("hex");
}
