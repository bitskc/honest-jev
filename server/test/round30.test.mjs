import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { guardCommand } from "../src/kit/guard.mjs";
import { words, substitutedSegments } from "../src/kit/shell.mjs";
import { cpuNow } from "./helpers/cpu.mjs";

// Round 30: open guard issues #154 #126 #128 #122 #74 #77 #78 #118 #75 #81 on main d76fff3. Data only: every string is handed to
// guardCommand()/words()/substitutedSegments(); nothing is executed.
const noJev = { ask: null, jevAvailable: false };
const g = (command) => guardCommand({ command, cwd: "/home/u/proj", home: "/home/u", tool: "Bash" }, noJev);
const decisions = async (cmds) => Promise.all(cmds.map(async (c) => [c, (await g(c)).decision]));
const expectAll = async (cmds, want) => { for (const [c, d] of await decisions(cmds)) assert.equal(d, want, c); };

test("#154: a ${...} parameter expansion keeps its spaces and `#`, so the command after an assignment prefix is read", async () => {
  await expectAll(["x=${y%% #*} rm -rf ~", "x=${y%% #*} cat .env", "x=${y// #/-} rm -rf ~", "x=${y:-a b} chmod -R 777 /", "x=${y%% #*} y=${z%% #*} rm -rf ~", "echo ${y%% #*}; rm -rf ~", "FOO=${A:-x y} rm -rf /"], "block");
  await expectAll(["x=${y%% #*} ls", "echo ${#PATH}", "echo ${x:-a b} ok", "x=${y} ls -la"], "allow");
  assert.deepEqual(words("x=${y%% #*} rm -rf ~"), ["x=${y%% #*}", "rm", "-rf", "~"]);
  assert.deepEqual(words("x=${y rm -rf ~"), ["x=${y", "rm", "-rf", "~"]); // no closing brace: nothing is swallowed
  assert.deepEqual(words("echo ${a:-${b} c d } e"), ["echo", "${a:-${b} c d }", "e"]);
});
test("#126 #128: a substitution at a command position is read; one that is an assignment's value is not; nested subshells are found", async () => {
  await expectAll(["x=1; $(cat .env)", "x=1 && $(cat .env)", "x=1 $(cat .env)", "x=1\n$(cat .env)", "$( (cat .env) )", "echo $( (cat .env) )", "echo $( ( cat .env ) )", "echo $(echo $(cat .env))", "`cat .env`", "echo `echo \\`cat .env\\``", "echo `echo \\`echo \\\\\\`cat .env\\\\\\`\\``"], "block");
  await expectAll(["x=$(cat .env)", "export x=\"$(cat .env)\"", "x=$(echo $(cat .env))", "x=$(cat .env); echo hi"], "allow");
  assert.deepEqual(substitutedSegments("x=1; $(cat a)"), ["cat a"]);
  assert.deepEqual(substitutedSegments("$( (cat a) )"), ["(cat a)"]);
});
test("#122: sourcing a secrets file stays allowed (it is the form the guard's own suggestion recommends and prints nothing)", async () => {
  await expectAll(["source .env", ". ./.env", "set -a; . ./.env; set +a"], "allow");
});
test("#74 #78: xargs -a and cp onto a printing device are secret reads", async () => {
  await expectAll(["xargs -a .env cat", "xargs --arg-file=.env cat", "xargs -a.env cat", "xargs -n1 -a .env echo", "xargs -n 1 -a .env echo", "xargs -I {} -a .env echo {}", "xargs -P 4 -n 2 --arg-file .env echo", "cp .env /dev/stdout", "cp ~/.ssh/id_rsa /dev/stderr", "rsync .env /dev/fd/1", "install .env /dev/tty", "cp .env /proc/self/fd/1"], "block");
  await expectAll(["xargs -a .env.example cat", "xargs -a list.txt cat", "xargs echo -a .env", "xargs -n 1 echo -a .env", "cp a.txt /dev/stdout", "cp .env /tmp/x", "cp .env /dev/null"], "allow");
});
test("#77: connection-string variables are secret-named, endpoint variables are not", async () => {
  await expectAll(["echo $DATABASE_URL", "echo \"$REDIS_URL\"", "printenv MONGODB_URI", "echo $SENTRY_DSN", "echo ${POSTGRES_URL}", "node -e \"console.log(process.env.DATABASE_URL)\"", "python3 -c \"import os;print(os.environ['REDIS_URL'])\""], "block");
  await expectAll(["echo $API_URL", "echo $BASE_URL", "echo $CACHE_URL", "echo $DB_HOST", "echo $DATABASE_NAME", "echo $URL"], "allow");
});
test("#118: brace expansion is expanded before matching; an expansion the guard cannot evaluate reads as a wildcard", async () => {
  await expectAll(["cat {.env,x}", "cat .env{,.bak}", "cat .e{n,m}v", "cat .e$()nv", "cat .e${x}nv", "cat {.en,.ev}{v,x}", "cat ~/.ssh/id_{rsa,x}", "cat {a,{b,.env}}"], "block");
  await expectAll(["cat {a,b}.txt", "cat src/{a,b}/c.ts", "echo {1,2,3}", "cat file$N.txt", "ls {a,b}", "find . -name x -exec echo {} ;"], "allow");
});
test("#75 #81: a process environment and a path that resolves to a secret are secret reads", async () => {
  await expectAll(["cat /proc/self/environ", "cat /proc/1234/environ", "tr '\\0' '\\n' < /proc/self/environ", "cat /proc/self/task/1/environ", "cat .env.example/../.env", "cat src/../.env", "cat a//.env"], "block");
  await expectAll(["cat /proc/self/status", "cat .env.example", "cat docs/../README.md", "ls ../x"], "allow");
});

// A word-level prefix must not weaken a decision beyond what a plain `x=1 ` prefix already does (main's own limits with assignment
// prefixes, e.g. `x=1 echo / | xargs ...`, are not this round's): every block/ask corpus row behind assignment prefixes that carry `${...}`.
const rows = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "..", "..", "evals", "guard.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l))
  .filter((r) => typeof r.input.command === "string" && r.input.command.length < 600 && r.input.cwd === undefined && !/^\s*[({]|^(?:if|for|while|case|until)\b/.test(r.input.command));
const RANK = { allow: 0, ask: 1, block: 2 };
test("assignment prefixes with ${...} never weaken a corpus decision below what a plain `x=1 ` prefix gives", async () => {
  const prefixes = ["x=${y%% #*} ", "x=${y// #/-} ", "x=${y:-a b} ", "FOO=${A:-x y} BAR=${B%%.*} ", "x=${y} "];
  const weaker = [];
  let n = 0;
  for (let i = 0; i < rows.length; i++) {
    const base = (await g(rows[i].input.command)).decision;
    if (base === "allow") continue;
    const plain = (await g(`x=1 ${rows[i].input.command}`)).decision;
    for (let k = 0; k < 3; k++) {
      const p = prefixes[(i + k * 2) % prefixes.length];
      const got = (await g(p + rows[i].input.command)).decision;
      n++;
      if (RANK[got] < RANK[plain]) weaker.push(`${rows[i].id}: plain prefix ${plain}, ${p.trim()} ${got}  ${JSON.stringify(p + rows[i].input.command).slice(0, 110)}`);
    }
  }
  assert.ok(n > 900, `only ${n} cases ran`);
  assert.deepEqual(weaker, [], `\n${weaker.slice(0, 15).join("\n")}`);
});

test("the new scans stay linear at 20 KB: ${ floods, brace and substitution floods, nested subshells (CPU time)", async () => {
  const R = (s, n) => s.repeat(n);
  const shapes = [R("${", 10000), R("x=${a b} ", 2200), R("${a ", 5000) + "}", `cat ${R("{", 19000)}`, `cat ${R("{a,b}", 3000)}`, `cat ${R("{a,", 6000)}`, `cat .e${R("{x,y}", 3000)}nv`, `cat ${R("$x", 9000)}`,
    `cat ${R("$(", 9000)}`, R("$( (", 3000) + "cat .env" + R(") )", 3000), R("$(ls) ", 3300), R("x=1; $(a) ", 2000), R("`a` ", 4000), `cp ${R("a ", 9000)} /dev/stdout`, `xargs ${R("-a ", 6000)}`, R("../", 6000) + ".env", R("a/./", 5000) + ".env"];
  for (const c of ["${a b} x=${c}", "cat {a,b}{c,d}", "$( (cat a) ) `b` $(c)", "cp a b /dev/stdout"]) await g(c); // warm up: the first calls pay for JIT compilation, which a CPU bound must not count
  for (const c of shapes) {
    const t = cpuNow();
    await g(c);
    const ms = cpuNow() - t;
    assert.ok(ms < 900, `${ms.toFixed(0)} ms CPU on ${c.length} chars starting ${JSON.stringify(c.slice(0, 24))}`);
  }
  const pad = `${R("{a,b}", 3000)} ; rm -rf ~`;
  assert.equal((await g(pad)).decision, "block");
});
