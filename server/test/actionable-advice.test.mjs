// Actionable advice: rule-specific suggestions, stdin vs bare-word wording, and bare-word printer gate.
import test from "node:test";
import assert from "node:assert/strict";
import {
  guardCommand,
  R1_SUGGESTION,
  R1_STDIN_SCRIPT_SUGGESTION,
  R1_BARE_WORD_SUGGESTION,
  R10_OPAQUE_SUGGESTION,
} from "../src/kit/guard.mjs";

const noJev = { ask: null, jevAvailable: false };
const g = (command, extra = {}) => guardCommand({ command, cwd: "/home/u/proj", home: "/home/u", ...extra }, noJev);

test("stdin-fed interpreter soft-ask uses the stdin-script suggestion, not the secret-print one", async () => {
  for (const c of ["cat script.js | node", "python < x.py", "bun < foo.ts"]) {
    const r = await g(c);
    assert.equal(r.decision, "ask", c);
    assert.equal(r.rule, "R1-secret-exposure", c);
    assert.equal(r.suggestion, R1_STDIN_SCRIPT_SUGGESTION, c);
    assert.notEqual(r.suggestion, R1_SUGGESTION, c);
  }
});

test("bare credential word on a content printer asks with the bare-word suggestion", async () => {
  for (const c of ["cat token", "less TOKEN", "sort credentials", "npx vitest run credentials"]) {
    const r = await g(c);
    assert.equal(r.decision, "ask", c);
    assert.equal(r.suggestion, R1_BARE_WORD_SUGGESTION, c);
  }
});

test("Capitalized known printers/wrappers/interpreters ask (UI carve-out is an allowlist, not a denylist)", async () => {
  for (const c of [
    "Cat token",
    "CAT token",
    "Less TOKEN",
    "Head secrets",
    "Paste token",
    "Paste credentials",
    "Open secrets",
    "paste token",
    "Sudo cat token",
    "Npm test credentials",
    "Rename token",
    "Python3 token",
    "Node token",
    "Ruby token",
    "Perl token",
    "Php token",
    "Sqlite3 token",
    "Lua token",
    "Deno token",
    "Wl-copy token",
    "Xclip token",
  ]) {
    const r = await g(c);
    assert.equal(r.decision, "ask", c);
    assert.equal(r.suggestion, R1_BARE_WORD_SUGGESTION, c);
  }
});

test("Capitalized UI-verb allowlist still allows Collect/Confirm/Approve", async () => {
  for (const c of ["Collect token", "Confirm password", "Approve secrets"]) {
    assert.equal((await g(c)).decision, "allow", c);
  }
});

test("lowercase unknown tools and editors still ask on a bare credential word", async () => {
  for (const c of ["vim token", "nano token", "nvim password", "python3 token", "node token"]) {
    assert.equal((await g(c)).decision, "ask", c);
  }
});

test("NON_CONTENT / echo / true with a bare credential word still allow", async () => {
  for (const c of ["echo token", "ls token", "true token", "printf password"]) {
    assert.equal((await g(c)).decision, "allow", c);
  }
});

test("copy/install onto a print device with a bare credential word asks (copiesToTerminal)", async () => {
  for (const c of [
    "cp token /dev/stdout",
    "install token /dev/stdout",
    "cp password /dev/stderr",
    "mv credentials /dev/tty",
    "cp token /proc/self/fd/1",
  ]) {
    const r = await g(c);
    assert.equal(r.decision, "ask", c);
    assert.equal(r.suggestion, R1_BARE_WORD_SUGGESTION, c);
  }
  // Ordinary copy destinations stay NON_CONTENT (no print device) → allow.
  for (const c of ["cp token /tmp/out", "install token /tmp/out", "mv credentials /tmp/out"]) {
    assert.equal((await g(c)).decision, "allow", c);
  }
});

test("shape matches still block for any program, including unknown verbs", async () => {
  for (const c of ["Paste .env", "Open ~/.ssh/id_rsa", "cat .env"]) {
    const r = await g(c);
    assert.equal(r.decision, "block", c);
    assert.equal(r.suggestion, R1_SUGGESTION, c);
  }
});

test("R10 opaque soft-asks carry a simplify-or-confirm suggestion", async () => {
  // Nesting past MAX_GROUPING_DEPTH (64) forces the opaque R10 soft ask.
  const deep = "(" + "(".repeat(70) + "true" + ")".repeat(70) + ")";
  const r = await g(deep);
  assert.equal(r.decision, "ask", deep);
  assert.equal(r.rule, "R10-general-risk");
  assert.equal(r.suggestion, R10_OPAQUE_SUGGESTION);
});
