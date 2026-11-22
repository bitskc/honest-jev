import test from "node:test";
import assert from "node:assert/strict";
import { guardCommand } from "../src/kit/guard.mjs";
import { programOf, words, wordsQ } from "../src/kit/shell.mjs";

// Owner report: `getSession() token` asked ("names a bare credential word"). A function-definition header (`name()`) was read as the
// PROGRAM and the next word as its operand, and the call lines of a `node -e` / `python -c` / stdin-script body are read as shell lines.
// A peels every function-header shape so the BODY is what the rules see (it is never skipped); B keeps a word that cannot be an
// executable name from being a content printer. Every string is DATA handed to guardCommand()/programOf(); nothing is executed.
const noJev = { ask: null, jevAvailable: false };
const HOME = "/home/u";
const g = (command) => guardCommand({ command, cwd: `${HOME}/proj`, home: HOME, tool: "Bash" }, noJev);

test("A: every function-header shape is peeled and the body's own command is the program", () => {
  const body = ["cat", [".env"]];
  for (const seg of ["f() { cat .env", "f(){ cat .env", "f () { cat .env", "f() ( cat .env )", "f()(cat .env)", "f() cat .env",
    "function f { cat .env", "function f() { cat .env", "function f() ( cat .env )", "function f(){ cat .env", "function f cat .env",
    "get-session() ( cat .env )", "f() if cat .env"]) {
    const [prog, args] = programOf(seg);
    // `if` is a keyword the walk skips, so the last shape reads the same body
    assert.deepEqual([prog, args], body, seg);
  }
});

test("A: a header with no body yields no program; the line after it is judged on its own", () => {
  assert.deepEqual(programOf("getSession()"), [null, []]);
  assert.deepEqual(programOf("function getSession"), [null, []]);
  assert.deepEqual(programOf("getSession() token"), ["token", []]);
  assert.deepEqual(programOf("function getSession() token"), ["token", []]);
});

test("A: only a real header is peeled; a call or an ordinary command keeps its word", () => {
  assert.deepEqual(programOf("session.get(x) token"), ["session.get(x)", ["token"]]);
  assert.deepEqual(programOf("getSession().then(s"), ["getSession().then(s", []]);
  assert.deepEqual(programOf("foo token"), ["foo", ["token"]]);
});

test("A: words() splits the subshell opener off a complete `name()` head, so the body's last word keeps its own text", () => {
  assert.deepEqual(words("f()(cat .env)"), ["f()", "(", "cat", ".env", ")"]);
  assert.deepEqual(words("f() ( cat .env )"), ["f()", "(", "cat", ".env", ")"]);
  assert.deepEqual(words("f(){ cat .env; }"), ["f(){", "cat", ".env;", "}"]);
  // a call keeps its parens: `console.log(x)`, a curried call, a `$(`
  assert.deepEqual(words("console.log(x)"), ["console.log(x)"]);
  assert.deepEqual(words("echo $(date)"), ["echo", "$(date)"]);
});

test("A: a function body is still analysed in every shape: a secret store blocks and the reason names the body's command", async () => {
  for (const c of ["f() { cat .env; }; f", "f(){ cat .env; }; f", "f () { cat .env; }; f", "f()\n{ cat .env; }\nf", "f() ( cat .env ); f",
    "f()(cat .env); f", "f() cat .env; f", "f() if true; then cat .env; fi; f", "f() for i in 1; do cat .env; done; f",
    "function f { cat .env; }; f", "function f() ( cat .env ); f", "function f(){ cat .env; }; f", "function f cat .env; f",
    "getSession() ( cat ~/.ssh/id_rsa ); getSession", "f() { echo ok; }; f; cat .env"]) {
    const r = await g(c);
    assert.equal(r.decision, "block", c);
    assert.equal(r.rule, "R1-secret-exposure", c);
    assert.match(r.reason, /^`cat` on secret store/, `${c} -> ${r.reason}`);
  }
});

test("A: a subshell-bodied function that prints a secret variable blocks, like the brace form (it was allowed)", async () => {
  for (const c of ["f() ( echo $API_TOKEN ); f", "f()(echo $API_TOKEN); f", "function f() ( echo $API_TOKEN ); f", "f() ( printenv API_TOKEN ); f",
    "f(){ echo $API_TOKEN; }; f", "getSession() { echo \"$token\"; }; getSession"]) {
    const r = await g(c);
    assert.equal(r.decision, "block", c);
    assert.equal(r.rule, "R1-secret-exposure", c);
  }
});

test("owner report: header-shaped lines and call lines in interpreter source do not ask", async () => {
  for (const c of ["getSession() token", "getSession(){ token; }", "function getSession() token", "echo hi; getSession() token",
    "node -e \"\ngetSession() // fetch token\n\"", "python3 -c \"getSession() # token\"",
    "node <<'EOF'\ngetSession() // return token\nEOF", "python3 - <<'EOF'\ngetSession() # token\nEOF",
    "node -e \"\nfunction getSession() token\nconsole.log(1)\n\"", "python3 -c \"\ndef x():\n  getSession() token\n\""]) {
    const r = await g(c);
    assert.equal(r.decision, "allow", `${c} -> ${r.decision} ${r.reason}`);
  }
});

test("B: a first word that cannot be an executable name is not a printer: no bare-word ask for it", async () => {
  for (const c of ["session.get(x) token", "x.y=1 token", "fn(a, b) password", "// fetch token", "./ credentials",
    "# fetch token", "getSession() // fetch token"]) {
    const r = await g(c);
    assert.equal(r.decision, "allow", `${c} -> ${r.decision} ${r.reason}`);
  }
});

test("B: a possible executable still asks, and a real reader behind junk still asks", async () => {
  for (const c of ["getSession token", "foo token", "f() { cat token; }", "f() ( cat token ); f", "f() cat token; f", "function f() ( cat token ); f",
    "f() { echo ok; }; f token", "// cat token", "getSession() // cat token", "$(which cat) token", "`which cat` token"]) {
    const r = await g(c);
    assert.equal(r.decision, "allow", `${c} -> ${r.decision} ${r.reason}`);
    assert.equal(r.rule, "R1-secret-exposure", c);
  }
});

test("B: a secret-store shape blocks in any position, even behind a word that cannot be a program", async () => {
  for (const c of ["getSession() // cat .env", "// cat .env", "# cat .env", "session.get(x) .env", "x.y=1 cat .env", "fn(a) ~/.ssh/id_rsa",
    "node -e \"\ngetSession() // x\nconst fs = require('fs'); fs.readFileSync('.env')\n\""]) {
    const r = await g(c);
    assert.notEqual(r.decision, "allow", `${c} -> ${r.decision}`);
  }
  for (const c of ["getSession() // cat .env", "// cat .env", "# cat .env", "x.y=1 cat .env"]) assert.equal((await g(c)).decision, "block", c);
});

test("quoted text and non-executing heredoc bodies never become segments", async () => {
  for (const c of ["git commit -m \"fix getSession() token handling\"", "git commit -m 'fix\ngetSession() token\nmore'", "echo 'getSession() token'",
    "grep -n 'getSession() token' src/app.js", "cat <<'EOF'\ngetSession() token\nEOF", "cat > x.js <<'EOF'\nasync function f(){ const s = getSession() token }\nEOF"]) {
    const r = await g(c);
    assert.equal(r.decision, "allow", `${c} -> ${r.decision} ${r.reason}`);
  }
});

// Review of #87 (P1, P2-1, P2-2, P3 left as is).
test("P1: a function named like bash allows (`a::b`, unicode, leading digit, `a@b`, `a,b`, `a/b`, `a!b`, `{a`) is peeled and its body analysed", async () => {
  for (const n of ["a::b", "lib::run", "fünc", "日本", "1f", "a@b", "a,b", "a/b", "a!b", "a:b", "a+b", "a#b", "a*b", "{a", "a\u00a0b"]) {
    for (const [def, call] of [[`${n}() { cat .env; }`, n], [`${n}() ( cat .env )`, n], [`function ${n} { cat .env; }`, n], [`function ${n}() ( cat .env )`, n]]) {
      const c = `${def}; ${call}`;
      const r = await g(c);
      assert.equal(r.decision, "block", c);
      assert.match(r.reason, /on secret store `\.env`/, c);
    }
    for (const body of ["echo $API_TOKEN", "rm -rf ~", "sudo rm -rf /"]) assert.equal((await g(`${n}() ( ${body} ); ${n}`)).decision, "block", `${n} ${body}`);
    assert.equal((await g(`${n}() { echo ok; }; ${n}`)).decision, "allow", n);
  }
});

test("P1: the header peel finds the body for every name class in programOf too", () => {
  for (const n of ["a::b", "fünc", "1f", "a@b", "日本"]) {
    assert.deepEqual(programOf(`${n}() ( cat .env )`), ["cat", [".env"]], n);
    assert.deepEqual(programOf(`function ${n} { cat .env`), ["cat", [".env"]], n);
  }
});

test("P2-1: brace expansion makes a braced word a real program: it keeps asking, and a store shape still blocks", async () => {
  for (const c of ["ca{t,t} token", "{cat,} token", "c{a,}t token", "/bin/ca{t,} token", "ca{t,t} credentials"]) {
    const r = await g(c);
    assert.equal(r.decision, "allow", `${c} -> ${r.decision}`);
  }
  for (const c of ["ca{t,t} .env", "ca{t,t} ~/.ssh/id_rsa"]) assert.equal((await g(c)).decision, "block", c);
});

test("P2-2: a quoted or escaped word is a program, never a function header: its operand still blocks or asks", async () => {
  for (const c of ["'./f()' .env", "./f\\(\\) .env", "\"./f()\" .env", "'f()' .env", "'f()' ~/.ssh/id_rsa"]) assert.equal((await g(c)).decision, "block", c);
  for (const c of ["'./f()' token", "'f()' token", "./f\\(\\) token"]) assert.equal((await g(c)).decision, "allow", c);
  // the same words bare are headers: nothing to read behind them
  assert.deepEqual(programOf("'f()' .env"), ["f()", [".env"]]);
  assert.deepEqual(programOf("f() ( cat .env )"), ["cat", [".env"]]);
  assert.deepEqual(programOf("f '(' ')' .env"), ["f", ["(", ".env"]]);
});

test("wordsQ marks the words written with a quote or a backslash", () => {
  assert.deepEqual(wordsQ("a 'b' c\\ d e").q && [...wordsQ("a 'b' c\\ d e").q], [1, 2]);
  assert.equal(wordsQ("a b c").q, null);
});

// Re-review of #87: a Unicode space is a name character in bash (words split on blank/newline only), so a name holding one must still be peeled.
test("re-review: a function named with a Unicode space is analysed bare and nested; a command spelled with one is never weaker than the old split", async () => {
  for (const s of ["\u00a0", "\u2003", "\u3000", "\u2009", "\u202f"]) {
    const n = `a${s}b`;
    assert.deepEqual(words(`${n}() ( cat .env )`).slice(0, 2), [`${n}()`, "("], JSON.stringify(s));
    for (const body of ["cat .env", "echo $API_TOKEN", "rm -rf ~"]) {
      const def = `${n}() { ${body}; }; ${n}`;
      for (const c of [def, `{ ${def}; }`, `( ${def} )`, `if true; then ${def}; fi`, `function ${n} { ${body}; }; ${n}`, `{ ${n}() ( ${body} ); ${n}; }`]) {
        assert.equal((await g(c)).decision, "block", JSON.stringify(c));
      }
    }
    assert.equal((await g(`{ ${n}() { echo ok; }; ${n}; }`)).decision, "allow", JSON.stringify(s));
    assert.equal((await g(`cat${s}.env`)).decision, "block", JSON.stringify(s));
    assert.equal((await g(`cat${s}token`)).decision, "allow", JSON.stringify(s));
  }
});
