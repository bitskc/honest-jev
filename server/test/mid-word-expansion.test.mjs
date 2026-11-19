import test from "node:test";
import assert from "node:assert/strict";
import { guardCommand } from "../src/kit/guard.mjs";

// Issues 97 and 89 (regression from the non-program-word exemption): a command word holding `(`, `)`, `;` or `=` is source text and skips the
// bare-credential-word ask, but only if bash cannot run it. A word with an expansion ANYWHERE (`cat$(true)`, `/bin/$(echo cat)`) or a path
// with `=` (`./a=b`) is a real program and keeps asking. Every string is DATA handed to guardCommand(); nothing is executed.
const noJev = { ask: null, jevAvailable: false };
const HOME = "/home/u";
const g = (command) => guardCommand({ command, cwd: `${HOME}/proj`, home: HOME, tool: "Bash" }, noJev);

test("a mid-word expansion or a path with `=` is a program: the bare credential word asks", async () => {
  for (const c of ["cat$(true) token", "cat$() token", "/bin/$(echo cat) token", "cat$(: ) credentials", "cp$(true) token /dev/stdout",
    "cat`true` token", "cat${x} token", "./a=b token", "/usr/bin/a=b token"]) {
    const r = await g(c);
    assert.equal(r.decision, "ask", `${c} -> ${r.decision} ${r.reason}`);
  }
});

test("a word that is source text, not a program, still skips the ask", async () => {
  for (const c of ["getSession() token", "fn(a, b) password", "a=b token", "session.get(x) token"]) {
    const r = await g(c);
    assert.equal(r.decision, "allow", `${c} -> ${r.decision} ${r.reason}`);
  }
});

test("a mid-word expansion does not hide a secret-store shape", async () => {
  const r = await g("cat$(true) .env");
  assert.equal(r.decision, "block");
});

// `env` takes every word holding `=` as an assignment, a path included, so what follows still runs: the `./a=b` fix must not hide it.
test("env ./a=b is an assignment: the command behind it is judged", async () => {
  for (const c of ["env ./a=b rm -rf ~", "env /x/a=b rm -rf ~", "env -i ./a=b rm -rf ~", "env -u Z ./a=b rm -rf ~", "env -S './a=b rm -rf ~'",
    "\\env ./a=b rm -rf ~", "command env ./a=b rm -rf ~", "nohup env ./a=b rm -rf ~", "timeout 5 env ./a=b rm -rf ~", "bash -c 'env ./a=b rm -rf ~'"]) {
    const r = await g(c);
    assert.equal(r.decision, "block", `${c} -> ${r.decision} ${r.reason}`);
  }
  assert.equal((await g("env ./a=b cat token")).decision, "ask");
  assert.equal((await g("env ./a=b token")).decision, "allow"); // env runs the program `token`, no operand (evals/diff-allowlist.json closure exemption)
});

test("nice, time, command and nohup really run ./a=b as the program", async () => {
  for (const c of ["nice ./a=b token", "time ./a=b token", "command ./a=b token", "nohup ./a=b token"]) {
    const r = await g(c);
    assert.equal(r.decision, "ask", `${c} -> ${r.decision} ${r.reason}`);
  }
});
