// Actionable advice: rule-specific suggestions, stdin vs bare-word wording, and bare-word printer gate.
import test from "node:test";
import assert from "node:assert/strict";
import {
  guardCommand,
  R1_SUGGESTION,
  R1_STDIN_SCRIPT_SUGGESTION,
  R1_BARE_WORD_SUGGESTION,
  R10_OPAQUE_SUGGESTION,
  R1_SECRET_SEARCH_SUGGESTION,
  R1_SOURCE_SUGGESTION,
} from "../src/kit/guard.mjs";

const noJev = { ask: null, jevAvailable: false };
const g = (command, extra = {}) => guardCommand({ command, cwd: "/home/u/proj", home: "/home/u", ...extra }, noJev);

test("stdin-fed interpreter soft-ask uses the stdin-script suggestion, not the secret-print one", async () => {
  for (const c of ["cat script.js | node", "python < x.py", "bun < foo.ts"]) {
    const r = await g(c);
    assert.equal(r.decision, "allow", c);
    assert.equal(r.rule, "R1-secret-exposure", c);
    assert.equal(r.suggestion, R1_STDIN_SCRIPT_SUGGESTION, c);
    assert.notEqual(r.suggestion, R1_SUGGESTION, c);
  }
});

test("an env-file load that asks for what else is on the line does not advise the same load again", async () => {
  for (const c of [`. ./.env; ./deploy.sh "$TARGET"`, "set -a; . ./.env; set +a; echo $HOME"]) {
    const r = await g(c);
    assert.equal(r.decision, "allow", c);
    assert.equal(r.suggestion, R1_SOURCE_SUGGESTION, c);
    assert.notEqual(r.suggestion, R1_SUGGESTION, c);
  }
  assert.ok(!/set -a/.test(R1_SOURCE_SUGGESTION), "the load is what the command already did");
  // its alternative is a real one: the program takes the env file itself, and that is an allow
  assert.equal((await g("node --env-file=.env app.js")).decision, "allow");
});

test("bare credential word on a content printer asks with the bare-word suggestion", async () => {
  for (const c of ["cat token", "less TOKEN", "sort credentials", "npx vitest run credentials"]) {
    const r = await g(c);
    assert.equal(r.decision, "allow", c);
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
    assert.equal(r.decision, "allow", c);
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
    assert.equal((await g(c)).decision, "allow", c);
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
    assert.equal(r.decision, "allow", c);
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

// --- A search for a secret NAME: the advice is about searching, and every command it names is itself an allow ---

test("recursive / find-fed secret-name search asks with the search suggestion and a reason a human can decide on", async () => {
  for (const c of [
    "grep -rn API_KEY .",
    "find . -type f | xargs grep -n API_KEY",
    "find . -type f -exec grep -n API_KEY {} +",
    "rg -n API_KEY",
    "rg API_KEY",
    "ag API_KEY",
    "grep -rn --exclude='.env*' --exclude-dir=.git API_KEY .", // --exclude alone does not allow: other config files hold values
    "grep -rn API_KEY . | sed -E 's/((KEY|TOKEN|SECRET|PASSWORD)[A-Z_]*[=:]).*/\\1[redacted]/'", // a redaction filter is not provable
  ]) {
    const r = await g(c);
    assert.equal(r.decision, "allow", c);
    assert.equal(r.rule, "R1-secret-exposure", c);
    assert.equal(r.suggestion, R1_SECRET_SEARCH_SUGGESTION, c);
    assert.notEqual(r.suggestion, R1_SUGGESTION, c);
    // what is risky, in words the human can weigh: the matching line carries the value
    assert.match(r.reason, /prints every line matching a secret name/, c);
    assert.match(r.reason, /\.env/, c);
    assert.match(r.reason, /NAME=value/, c);
    // reason and suggestion stay two fields: the suggestion text is not mashed into the reason
    assert.ok(!r.reason.includes(R1_SECRET_SEARCH_SUGGESTION), c);
    assert.ok(!/Do not print a secret|set -a/.test(r.suggestion), "the load-a-secret advice does not belong to a search");
  }
});

test("the reason names the real program (rg, ag), not always grep", async () => {
  assert.match((await g("rg -n API_KEY")).reason, /^`rg` prints/);
  assert.match((await g("ag API_KEY")).reason, /^`ag` prints/);
  assert.match((await g("grep -rn API_KEY .")).reason, /^`grep` prints/);
});

test("every command the search suggestion names is itself an allow", async () => {
  const named = [...R1_SECRET_SEARCH_SUGGESTION.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
  assert.deepEqual(named, ["grep -rl NAME .", "rg -l NAME", "grep -n NAME src/app.js"]);
  for (const name of ["API_KEY", "SECRET_X", "DB_PASS", "DATABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"]) {
    for (const tpl of named) {
      const c = tpl.replace("NAME", name);
      const r = await g(c);
      assert.equal(r.decision, "allow", c);
    }
  }
});

test("output modes that print no line content allow a recursive secret-name search", async () => {
  for (const c of [
    "grep -rl API_KEY .",
    "grep -rL API_KEY .",
    "grep -rc API_KEY .",
    "grep -rq API_KEY .",
    "grep -r --files-with-matches API_KEY .",
    "grep -r --files-without-match API_KEY .",
    "grep -r --count API_KEY .",
    "grep -r --quiet API_KEY .",
    "grep -R -L SECRET_X ~",
    "find . -type f | xargs grep -l API_KEY",
    "find . -type f | xargs grep -L API_KEY",
    "find . -type f | xargs grep -c API_KEY",
    "rg -l API_KEY",
    "rg -c API_KEY",
    "rg --files-with-matches API_KEY",
    "rg --count API_KEY",
    "ag -l API_KEY",
    "ag -L API_KEY",
    "git grep -l API_KEY",
    "git grep -c API_KEY",
  ]) {
    assert.equal((await g(c)).decision, "allow", c);
  }
});

test("-L is a quiet mode for grep and ag only: rg's -L is --follow and still prints lines", async () => {
  for (const c of ["rg -L API_KEY", "rg -nL API_KEY"]) {
    const r = await g(c);
    assert.equal(r.decision, "allow", c);
    assert.equal(r.suggestion, R1_SECRET_SEARCH_SUGGESTION, c);
  }
});

test("a quiet letter that is really pattern text or a value does not make a printing search quiet", async () => {
  // `-e` takes the pattern, so the `l`/`c`/`L` after it are pattern letters, not modes
  for (const c of ["grep -reAPI_KEY_L .", "grep -rnecl_API_KEY .", "grep -rn -e API_KEY -e L ."]) {
    assert.equal((await g(c)).decision, "allow", c);
  }
});

test("line-printing searches that name a secret keep asking in the tree; --exclude alone is not an allow; the NAME=value file is still a block", async () => {
  for (const c of ["grep -rn API_KEY .", "grep -rin api_key .", "rg -n API_KEY .", "grep -rn --exclude-dir=.git API_KEY ."]) {
    assert.equal((await g(c)).decision, "allow", c);
  }
  assert.equal((await g("grep API_KEY .env")).decision, "block");
  assert.equal((await g("grep -n API_KEY src/app.js")).decision, "allow");
  // main allows this (tracked files only) and it still prints matching lines, committed secrets included; the suggestion says so
  assert.equal((await g("git grep -n API_KEY")).decision, "allow");
});

test("the search suggestion leads with names-only commands and does not recommend a line-printing tracked-file search", () => {
  const s = R1_SECRET_SEARCH_SUGGESTION;
  assert.match(s, /^Names only: `grep -rl NAME \.` or `rg -l NAME`\. Then read lines in source: `grep -n NAME src\/app\.js`\.$/);
  assert.ok(!s.includes("git grep"));
});

test("-L on a secret-store operand prints names only, like -l/-c/-q: allow; line-printing and rg -L still block", async () => {
  for (const c of [
    "grep -L API_KEY .env", "grep -rL API_KEY .env", "ag -L API_KEY .env", "grep -L API_KEY ~/.ssh/id_rsa",
    "ag -L API_KEY ~/.aws/credentials", "grep -L SECRET_X credentials.json",
    // parity: main already allows the same operands under the other quiet modes
    "grep -l API_KEY .env", "grep -c API_KEY .env", "rg -l API_KEY .env",
  ]) {
    assert.equal((await g(c)).decision, "allow", c);
  }
  for (const c of ["grep -n API_KEY .env", "rg -L API_KEY .env", "grep -n API_KEY ~/.ssh/id_rsa"]) {
    assert.equal((await g(c)).decision, "block", c);
  }
});

test("every command a suggestion recommends is itself allowed (advice never recommends a form that asks or blocks)", async () => {
  const guard = await import("../src/kit/guard.mjs");
  const names = Object.keys(guard).filter((k) => /_SUGGESTION$/.test(k));
  assert.ok(names.length >= 12, `found ${names.join(",")}`);
  let spansChecked = 0;
  for (const name of names) {
    const spans = [...guard[name].matchAll(/`([^`]+)`/g)].map((m) => m[1]);
    for (const span of spans) {
      for (const c of [span.replace("NAME", "API_KEY"), span.replace("NAME", "SUPABASE_SERVICE_ROLE_KEY")]) {
        assert.equal((await g(c)).decision, "allow", `${name}: ${c}`);
        spansChecked++;
      }
    }
  }
  assert.ok(spansChecked >= 14, `only ${spansChecked} spans checked`);
  // the R1 advice is the load-and-check pair; run as one line it is allowed too
  assert.equal((await g("set -a; . ./.env; set +a; [ -n \"$KEY\" ] && echo set")).decision, "allow");
});
