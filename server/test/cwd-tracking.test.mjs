import test from "node:test";
import assert from "node:assert/strict";
import { guardCommand } from "../src/kit/guard.mjs";
import { trackCwds } from "../src/kit/shell.mjs";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { closureViolations, exemptionIssues, ISSUE_REF_RE, compareDecisions, expandAllow, withContexts, withWrappers, WRAPPERS } from "../../evals/diff-guard.mjs";
import { cpuNow } from "./helpers/cpu.mjs";

// Round 25 (#133, #132). Every command here is DATA handed to guardCommand()/trackCwds(); nothing is executed.
const noJev = { ask: null, jevAvailable: false };
const HOME = "/home/u";
const PROJ = `${HOME}/proj`;
const g = (command, cwd = PROJ) => guardCommand({ command, cwd, home: HOME, tool: "Bash" }, noJev);
const cwdsOf = (text, start = PROJ) => trackCwds(text, [start], HOME).cwds.map((c) => [...c].sort());

test("#133: chmod/chown -R after a cd resolves `.` and globs against the moved cwd, so the root/home/system-tree block fires again", async () => {
  for (const c of ["cd / && chmod -R 777 .", "cd /; chmod -R 777 *", "cd / && chown -R u .", "cd ~ && chmod -R 000 .",
    "cd /home/u && chmod -R 777 .", "cd /etc && chmod -R 777 *", "pushd / >/dev/null; chmod -R 777 .",
    "cd .. && chmod -R 777 .", "(cd / && chmod -R 777 .)", "bash -c 'cd / && chmod -R 777 .'",
    "pushd ~ >/dev/null && chmod -R 777 .", "cd /home/u/proj/sub && chmod -R 755 ../../..",
    "cd /nonexistent; cd / && chmod -R 777 ."]) {
    const r = await g(c);
    assert.equal(r.decision, "block", c);
    assert.equal(r.rule, "R7-irreversible", c);
  }
});

test("#133: the cwd the operand resolves against is the moved one, so a target that only looked like a system tree from the hook cwd is allowed", async () => {
  // `../..` is /home from the hook cwd but /tmp from /tmp/a/b
  assert.equal((await g("cd /tmp/a/b && chmod -R 755 ../..")).decision, "allow");
  for (const c of ["cd build && chmod -R 755 .", "cd src && cd .. && chmod -R 755 .", "pushd / >/dev/null; popd >/dev/null; chmod -R 755 .",
    "cd / | cat; chmod -R 755 .", "cd /home/u && chmod -R 755 proj", "chmod -R 755 ."]) {
    assert.equal((await g(c)).decision, "allow", c);
  }
});

test("#133: after a non-literal cd the cwd is unknown, and a dot/glob operand asks again (never blocks)", async () => {
  for (const c of ["cd $X && chmod -R 777 .", "cd - && chmod -R 777 *", "cd \"$(mktemp -d)\" && chmod -R 755 .", "cd ${DIR} && chown -R u ./*",
    "pushd && chmod -R 777 .", "popd && chmod -R 777 ."]) {
    assert.equal((await g(c)).decision, "ask", c);
  }
  for (const c of ["cd $X && rm -rf *", "cd \"$WORKDIR\" || exit 1; rm -rf *", "cd - && rm -rf ."]) {
    const whole = await g(c);
    assert.equal(whole.decision, "ask", c);
    assert.equal(whole.rule, "R7-destructive", c);
  }
  // no hook cwd at all is the same unknown start
  assert.equal((await g("chmod -R 777 .", "")).decision, "ask");
  assert.equal((await g("cd build && chmod -R 777 .", "")).decision, "ask");
  assert.equal((await g("cd / && chmod -R 777 .", "")).decision, "block");
});

test("#133: rm and recursive grep read the same effective cwd as chmod", async () => {
  const rm = await g("cd / && rm -rf usr");
  assert.equal(rm.decision, "block");
  assert.equal(rm.rule, "R7-root-delete");
  assert.equal((await g("cd /tmp/x && rm -rf ../..")).decision, "block"); // /tmp/x/../.. is /
  assert.equal((await g("cd /tmp/x && rm -rf build")).decision, "allow");
  assert.equal((await g("cd /home && grep -rn TOKEN u")).decision, "allow"); // /home/u is home
});

test("trackCwds: literal cd/pushd/popd apply in sequence, a failed-able cd keeps the start as a candidate", () => {
  assert.deepEqual(cwdsOf("cd / && ls"), [[PROJ], ["/"]]);
  assert.deepEqual(cwdsOf("cd /a; ls"), [[PROJ], ["/a"]]); // a bare `cd X;` is taken to succeed
  assert.deepEqual(cwdsOf("cd /a && ls; pwd"), [[PROJ], ["/a"], ["/a", PROJ].sort()]);
  assert.deepEqual(cwdsOf("cd /a || cd /b; ls"), [[PROJ], [PROJ], ["/a", "/b", PROJ].sort()]);
  assert.deepEqual(cwdsOf("cd sub; cd ..; ls"), [[PROJ], [`${PROJ}/sub`], [PROJ]]);
  assert.deepEqual(cwdsOf("cd ~/x && ls"), [[PROJ], [`${HOME}/x`]]);
  assert.deepEqual(cwdsOf("cd; ls"), [[PROJ], [HOME]]);
  assert.deepEqual(cwdsOf("pushd /a >/dev/null; pushd /b >/dev/null; popd; ls"), [[PROJ], ["/a"], ["/b"], ["/a"]]);
  assert.deepEqual(cwdsOf("pushd /a; popd; ls"), [[PROJ], ["/a"], [PROJ]]);
});

test("trackCwds: pipeline stages, background jobs and groups never leak a directory change they do not own", () => {
  assert.deepEqual(cwdsOf("cd /a | cat; ls"), [[PROJ], [PROJ], [PROJ]]);
  assert.deepEqual(cwdsOf("cd /a & ls"), [[PROJ], [PROJ]]);
  // a group's cd keeps the starting directory as a candidate (the text cannot say where the group closes)
  assert.deepEqual(cwdsOf("(cd /a && ls) && pwd"), [[PROJ], ["/a", PROJ].sort(), ["/a", PROJ].sort()]);
});

test("trackCwds: a non-literal cd (variable, `-`, substitution, glob, ~user, missing operand for popd) is unknown, not the old cwd", () => {
  for (const cmd of ["cd $X", "cd -", 'cd "$(mktemp -d)"', "cd /us*", "cd ~root", "cd /tmp/$X", "cd a b", "popd", "pushd", "pushd -n /a", "pushd +1"]) {
    assert.deepEqual(cwdsOf(`${cmd}; ls`).at(-1), [""], cmd);
  }
  // an absolute target recovers a known cwd; a relative one cannot be resolved from an unknown cwd
  assert.deepEqual(cwdsOf("cd $X; cd /a; ls").at(-1), ["/a"]);
  assert.deepEqual(cwdsOf("cd $X; cd sub; ls").at(-1), [""]);
  // no hook cwd: unknown start
  assert.deepEqual(cwdsOf("ls", "")[0], [""]);
  assert.deepEqual(cwdsOf("cd /a; ls", "").at(-1), ["/a"]);
});

test("trackCwds: more candidates than the cap fold in an unknown cwd, so the start alone is never trusted", () => {
  const cmd = Array.from({ length: 12 }, (_, i) => `cd /d${i} && true`).join("; ") + "; ls";
  assert.ok(cwdsOf(cmd).at(-1).includes(""));
});

// Review of 999e0f4 (P1): trackCwds copied the pushd stack and re-joined it into a key on every step, so 2000 `pushd a;`
// (18 KB, under the 20 KB tool cap) took 5.8 s, past the hook's 2 s timeout, which fails open and drops the block. These
// bounds are CPU time and generous (measured: <= ~20 ms for trackCwds, <= ~100 ms through the whole guard); they fail on
// a super-linear walk, and `scales` pins linearity directly (4x the input must not cost 10x).
const R = (s, n) => s.repeat(n);
const SHAPES = {
  "pushd a;": (n) => R("pushd a; ", n), "pushd /a;": (n) => R("pushd /a; ", n), "cd a;": (n) => R("cd a;", n),
  "cd a/b/c;": (n) => R("cd a/b/c;", n), "pushd a &&": (n) => R("pushd a && ", n), "pushd a || pushd b;": (n) => R("pushd a || pushd b; ", n),
  "cd a || cd b ||": (n) => R("cd a || cd b || ", n), "popd;": (n) => R("popd; ", n), "pushd a; popd;": (n) => R("pushd a; popd; ", n),
  "(cd a;": (n) => R("(cd a; ", n), "(cd a && true);": (n) => R("(cd a && true); ", n), "cd /d$i;": (n) => Array.from({ length: n }, (_, i) => `cd /d${i};`).join(""),
  "cd a |": (n) => R("cd a | ", n), "cd a &": (n) => R("cd a & ", n), "cd ..;": (n) => R("cd ..;", n), "cd ~;": (n) => R("cd ~;", n),
  "pushd ..;": (n) => R("pushd ..; ", n), "bash -c 'cd a';": (n) => R("bash -c 'cd a'; ", n), "echo $(cd a);": (n) => R("echo $(cd a); ", n),
};
const sized = (make, bytes) => { let n = 1; while (make(n * 2).length <= bytes) n *= 2; while (make(n + 1).length <= bytes) n++; return make(n); };
test("review P1: trackCwds and the whole guard stay linear on cd/pushd/popd chains at the 20 KB cap, and the verdict still lands", async () => {
  for (const [name, make] of Object.entries(SHAPES)) {
    const cmd = `${sized(make, 19950)} rm -rf ~`;
    const t0 = cpuNow();
    trackCwds(cmd, [PROJ], HOME);
    const track = cpuNow() - t0;
    assert.ok(track < 300, `${name}: trackCwds used ${track.toFixed(0)} ms CPU on ${cmd.length} chars`);
    const t1 = cpuNow();
    const r = await g(cmd);
    const took = cpuNow() - t1;
    assert.ok(took < 600, `${name}: guard used ${took.toFixed(0)} ms CPU on ${cmd.length} chars`);
    assert.equal(r.decision, "block", name);
    assert.equal(r.rule, "R7-root-delete", name);
  }
});
test("review P1: cost scales linearly, not quadratically, with the chain length", () => {
  for (const name of ["pushd a;", "cd a;", "pushd a || pushd b;", "popd;", "(cd a;"]) {
    const make = SHAPES[name];
    const cost = (n) => { const text = make(n); const t = cpuNow(); for (let i = 0; i < 3; i++) trackCwds(text, [PROJ], HOME); return cpuNow() - t; };
    cost(200); // warm up
    const small = Math.max(cost(500), 1);
    const big = cost(2000);
    assert.ok(big < small * 9 + 20, `${name}: 4x the chain cost ${(big / small).toFixed(1)}x (${small.toFixed(1)} -> ${big.toFixed(1)} ms)`);
  }
});
test("review P1: past a cap the cwd is UNKNOWN (a dot/glob operand asks), never the last known directory", async () => {
  // a pushd stack deeper than the cap, however it is popped again
  const deep = R("pushd a; ", 40) + R("popd; ", 40);
  assert.deepEqual(cwdsOf(`${deep}ls`).at(-1), [""]);
  assert.equal((await g(`${deep}chmod -R 777 .`)).decision, "ask");
  // a cwd path that grew past the length cap through a chain of relative `cd`s
  assert.equal((await g(`${R("cd a;", 3000)}chmod -R 777 .`)).decision, "ask");
  assert.deepEqual(cwdsOf(`cd ${R("a/", 9000)}; ls`).at(-1), [""]);
  // more distinct directories than the "seen" list holds: the list every substitution/alias copy is judged under falls back to unknown
  const many = Array.from({ length: 40 }, (_, i) => `cd /d${i};`).join("");
  assert.deepEqual(trackCwds(`${many} ls`, [PROJ], HOME).all, [""]);
  // under the caps nothing changes: 30 nested pushds and their pops return to the project
  assert.deepEqual(cwdsOf(`${R("pushd a; ", 30)}${R("popd; ", 30)}ls`).at(-1), [PROJ]);
  assert.equal((await g(`${R("pushd a; ", 30)}${R("popd; ", 30)}chmod -R 755 .`)).decision, "allow");
});

test("#132: public files in ~/.ssh read freely; config, private keys, globs and `..` detours stay blocked", async () => {
  for (const c of ["cat ~/.ssh/known_hosts", "tail ~/.ssh/known_hosts", "grep github ~/.ssh/known_hosts", "cat ~/.ssh/known_hosts.old",
    "cat ~/.ssh/authorized_keys", "cat /home/u/.ssh/authorized_keys2", "cat ~/.ssh/allowed_signers", "cat ~/.ssh/id_ed25519.pub"]) {
    assert.equal((await g(c)).decision, "allow", c);
  }
  for (const c of ["cat ~/.ssh/config", "cat ~/.ssh/id_rsa", "cat ~/.ssh/id_ed25519", "cat ~/.ssh/known_hosts/../id_rsa",
    "cat ~/.ssh/known_hosts ~/.ssh/id_rsa", "cat ~/.ssh/known_hosts*", "cat ~/.ssh/known_hosts_x", "cat ~/.ssh/*"]) {
    const r = await g(c);
    assert.equal(r.decision, "block", c);
    assert.equal(r.rule, "R1-secret-exposure", c);
  }
});

// ── evals/diff-guard.mjs: the block/ask -> allow gate ─────────────────────────────────────────────────────────────────
const rows = [{ id: "a", expected: "block", input: { command: "x" } }, { id: "b", expected: "ask", input: { command: "y" } }, { id: "c", expected: "allow", input: { command: "z" } }];
const dec = (o) => new Map(Object.entries(o));
const J = "a justification that is long enough to count as one";
test("diff-guard: block -> allow and ask -> allow fail unless the exact row and transition are allowlisted with a justification", () => {
  const base = dec({ a: "block", b: "ask", c: "allow" });
  const head = dec({ a: "allow", b: "allow", c: "allow" });
  const bare = compareDecisions(rows, base, head, []);
  assert.deepEqual(bare.failures.map((f) => f.id), ["a", "b"]);
  const some = compareDecisions(rows, base, head, [{ id: "a", from: "block", to: "allow", justification: J }]);
  assert.deepEqual(some.failures.map((f) => f.id), ["b"]);
  assert.deepEqual(some.allowed.map((f) => f.id), ["a"]);
  // wrong transition, wrong id, or a missing/short justification do not allowlist
  assert.equal(compareDecisions(rows, base, head, [{ id: "a", from: "ask", to: "allow", justification: J }]).failures.length, 2);
  assert.equal(compareDecisions(rows, base, head, [{ id: "zz", from: "block", to: "allow", justification: J }]).failures.length, 2);
  const noWhy = compareDecisions(rows, base, head, [{ id: "a", from: "block", to: "allow", justification: "ok" }]);
  assert.equal(noWhy.failures.length, 2);
  assert.equal(noWhy.badAllow.length, 1);
});
test("diff-guard: stricter or equal decisions pass, and are still reported", () => {
  const r = compareDecisions(rows, dec({ a: "block", b: "ask", c: "allow" }), dec({ a: "block", b: "block", c: "ask" }), []);
  assert.equal(r.failures.length, 0);
  assert.deepEqual(r.changes.map((c) => [c.id, c.kind]), [["b", "tightened"], ["c", "tightened"]]);
  const s = compareDecisions(rows, dec({ a: "block", b: "ask", c: "allow" }), dec({ a: "ask", b: "ask", c: "allow" }), []);
  assert.deepEqual(s.changes.map((c) => c.kind), ["softened"]);
  assert.equal(s.failures.length, 0);
});
test("diff-guard: an allowlist entry that no longer occurs is reported as stale", () => {
  const same = dec({ a: "block", b: "ask", c: "allow" });
  assert.equal(compareDecisions(rows, same, same, [{ id: "a", from: "block", to: "allow", justification: J }]).stale.length, 1);
});
test("diff-guard: every row is decided under the hook context too", () => {
  const ctxRows = withContexts([{ id: "r", input: { command: "ls" } }, { id: "s", input: { command: "ls", cwd: "/x" } }]);
  assert.deepEqual(ctxRows.map((r) => r.id), ["r", "r@proj", "s", "s@proj"]);
  assert.equal(ctxRows[1].input.cwd, PROJ);
  assert.equal(ctxRows[3].input.cwd, "/x"); // a row's own cwd wins
});

// Review of 999e0f4 (P3): the gate must not pass vacuously.
test("diff-guard: a decision that is not allow/ask/block (on either side, or missing) fails, it is not 'tightened'", () => {
  const r1 = compareDecisions(rows, dec({ a: "block", b: "ask", c: "allow" }), dec({ a: "weird", b: "ask", c: "allow" }), []);
  assert.deepEqual(r1.failures.map((f) => [f.id, f.kind]), [["a", "invalid"]]);
  const r2 = compareDecisions(rows, dec({ a: "block", b: "ask", c: "allow" }), dec({ b: "ask", c: "allow" }), []); // a missing from head
  assert.deepEqual(r2.failures.map((f) => f.id), ["a"]);
  const r3 = compareDecisions(rows, dec({ b: "ask", c: "allow" }), dec({ a: "allow", b: "ask", c: "allow" }), []); // a missing from base
  assert.deepEqual(r3.failures.map((f) => f.id), ["a"]);
  const same = dec({ a: undefined, b: "ask", c: "allow" }); // equal but invalid on both sides is still invalid
  assert.equal(compareDecisions(rows, same, same, []).failures.length, 1);
  // an allowlist entry cannot excuse an invalid decision
  assert.equal(compareDecisions(rows, dec({ a: "block", b: "ask", c: "allow" }), dec({ a: "weird", b: "ask", c: "allow" }), [{ id: "a", from: "block", to: "weird", justification: J }]).failures.length, 1);
});
test("diff-guard: an allowlist entry with `ids` covers each id and its @proj twin", () => {
  assert.deepEqual(expandAllow([{ ids: ["a", "b"], from: "block", to: "allow", justification: J }]).map((e) => e.id), ["a", "a@proj", "b", "b@proj"]);
  const r = compareDecisions([{ id: "a@proj", input: {} }], dec({ "a@proj": "block" }), dec({ "a@proj": "allow" }), [{ ids: ["a"], from: "block", to: "allow", justification: J }]);
  assert.equal(r.failures.length, 0);
});
const DIFF = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "evals", "diff-guard.mjs");
const runDiff = (...args) => spawnSync(process.execPath, [DIFF, ...args], { encoding: "utf8" });
const inGitCheckout = spawnSync("git", ["-C", dirname(DIFF), "rev-parse", "--verify", "--quiet", "HEAD^{commit}"]).status === 0;
test("diff-guard (CLI): an empty corpus, an unloadable base and an unreadable corpus exit 2, never 0", { skip: !inGitCheckout && "needs a git checkout (the base revision is read with git)" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "dg-"));
  const empty = join(dir, "empty.jsonl");
  writeFileSync(empty, "\n");
  const e = runDiff("--base", "HEAD", "--corpus", empty);
  assert.equal(e.status, 2, e.stdout + e.stderr);
  assert.match(e.stderr, /no rows/);
  assert.equal(runDiff("--base", "no-such-revision-zzz").status, 2);
  assert.equal(runDiff("--base", "HEAD", "--corpus", join(dir, "missing.jsonl")).status, 2);
  const noKit = runDiff("--base", "4b825dc642cb6eb9a060e54bf8d69288fbee4904"); // git's empty tree: no guard.mjs there
  assert.equal(noKit.status, 2, noKit.stdout + noKit.stderr);
  // a one-row corpus decided identically by base and head passes
  const one = join(dir, "one.jsonl");
  writeFileSync(one, JSON.stringify({ id: "x1", expected: "allow", input: { command: "ls" } }) + "\n");
  assert.equal(runDiff("--base", "HEAD", "--corpus", one).status, 0);
});

test("diff-guard wrappers: every row is also decided inside each wrapper, including the output-routing ones the round-31 review found missing", () => {
  const names = WRAPPERS.map((w) => w.name);
  for (const must of ["grp", "bashc", "eval", "if", "gpx", "pamp", "bcpx", "evpx", "ifpx", "coproc", "pxargs", "procsub", "subst"]) assert.ok(names.includes(must), `wrapper ${must}`);
  const wrapped = withWrappers([{ id: "g1", expected: "block", input: { command: "find ~/.ssh -type f" } }, { id: "g2", expected: "allow", input: { file_path: "x" } }]);
  assert.equal(wrapped.length, WRAPPERS.length); // the file_path row has no command to wrap
  const by = Object.fromEntries(wrapped.map((r) => [r.id, r.input.command]));
  assert.equal(by["g1~gpx"], "{ find ~/.ssh -type f; } |xargs cat");
  assert.equal(by["g1~pamp"], "find ~/.ssh -type f |& xargs cat");
  assert.equal(by["g1~bcpx"], "bash -c 'find ~/.ssh -type f' |xargs cat");
  assert.ok(wrapped.every((r) => r.input.cwd === "/home/u/proj" && r.input.home === "/home/u"));
});
test("diff-guard wrappers: a row's allowlist entry covers its structural wrappers only, unless it says wrapped: all", () => {
  const J2 = "a justification that is long enough to count as one";
  const wr = [{ id: "a~grp", expected: "allow", input: {} }, { id: "a~gpx", expected: "allow", input: {} }];
  const base = dec({ "a~grp": "block", "a~gpx": "block" });
  const head = dec({ "a~grp": "allow", "a~gpx": "allow" });
  const plain = compareDecisions(wr, base, head, [{ id: "a", from: "block", to: "allow", justification: J2 }]);
  assert.deepEqual(plain.failures.map((f) => f.id), ["a~gpx"]); // the onward wrapper is not covered
  const all = compareDecisions(wr, base, head, [{ id: "a", from: "block", to: "allow", justification: J2, wrapped: "all" }]);
  assert.deepEqual(all.failures, []);
  const named = compareDecisions(wr, base, head, [{ id: "a", from: "block", to: "allow", justification: J2 }, { id: "a~gpx", from: "block", to: "allow", justification: J2 }]);
  assert.deepEqual(named.failures, []);
  assert.deepEqual(expandAllow([{ id: "a", from: "block", to: "allow", justification: J2 }], ["grp"], ["grp", "gpx"]).filter((e) => e.derived).map((e) => e.id), ["a~grp"]);
});

test("diff-guard wrapper-closure: a block stays block and an ask never drops to allow in any wrapper, independent of main; exemptions need a reason and go stale", () => {
  const corpus = [{ id: "a", expected: "block", input: { command: "cat .env" } }, { id: "b", expected: "ask", input: { command: "x" } }, { id: "c", expected: "allow", input: { command: "ls" } }, { id: "d", expected: "block", input: { file_path: "p" } }];
  const all = (plain, over = {}) => { const m = new Map([[`${plain.id}@proj`, plain.d]]); for (const w of WRAPPERS) m.set(`${plain.id}~${w.name}`, over[w.name] ?? plain.d); return m; };
  const dec = new Map([...all({ id: "a", d: "block" }, { sub: "allow", bt: "ask" }), ...all({ id: "b", d: "ask" }, { grp: "allow" }), ...all({ id: "c", d: "allow" }, { sub: "allow" })]);
  const r = closureViolations(corpus, dec, []);
  assert.deepEqual(r.violations.map((v) => `${v.id}~${v.wrapper} ${v.plain}->${v.got}`).sort(), ["a~bt block->ask", "a~sub block->allow", "b~grp ask->allow"]);
  const J = "a justification that is long enough to count as one";
  const ex = closureViolations(corpus, dec, [{ ids: ["a"], wrappers: ["sub", "bt"], justification: J, issue: "#1" }, { id: "b", wrappers: "*", justification: J, issue: "#2" }, { id: "zz", wrappers: "*", justification: J, issue: "#3" }]);
  assert.deepEqual(ex.violations, []);
  assert.deepEqual(ex.stale.map((e) => e.id), ["zz"]);
  const bad = closureViolations(corpus, dec, [{ id: "a", wrappers: "*", justification: "x", issue: "#1" }, { id: "b", justification: J, issue: "#1" }]);
  assert.equal(bad.badExempt.length, 2);
  assert.equal(bad.violations.length, 3, "a bad exemption exempts nothing");
  // a plain allow, and a row with no command, are never closure rows
  assert.ok(!r.violations.some((v) => v.id === "c" || v.id === "d"));
});

test("diff-guard wrapper-closure: every exemption names an issue (#N), wildcards included; a stale one fails", () => {
  const corpus = [{ id: "a", expected: "block", input: { command: "cat .env" } }];
  const dec = new Map([["a@proj", "block"], ...WRAPPERS.map((w) => [`a~${w.name}`, w.name === "sub" ? "allow" : "block"])]);
  const J = "a justification that is long enough to count as one";
  for (const issue of [undefined, "", "188", "#", "#abc", "n/a", "https://x/1", "#12 #13"]) {
    const r = closureViolations(corpus, dec, [{ id: "a", wrappers: ["sub"], justification: J, ...(issue === undefined ? {} : { issue }) }]);
    assert.equal(r.badExempt.length, 1, `issue ${JSON.stringify(issue)} is not accepted`);
    assert.equal(r.violations.length, 1, "a bad exemption exempts nothing");
  }
  const wild = closureViolations(corpus, dec, [{ id: "a", wrappers: "*", justification: J }]);
  assert.equal(wild.badExempt.length, 1, "a wildcard without an issue is rejected");
  const ok = closureViolations(corpus, dec, [{ id: "a", wrappers: ["sub"], justification: J, issue: "#188" }]);
  assert.deepEqual([ok.violations.length, ok.badExempt.length, ok.stale.length], [0, 0, 0]);
  assert.ok(ISSUE_REF_RE.test("#188") && !ISSUE_REF_RE.test("188"));
  assert.deepEqual(exemptionIssues([{ issue: "#188" }, { ids: ["x"], issue: "#54" }, { issue: "nope" }, { issue: "#188" }]), [188, 54]);
});
test("diff-guard (CLI): a stale or issue-less closure exemption FAILS the run, it is not a note", { skip: !inGitCheckout && "needs a git checkout (the base revision is read with git)" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "dg-"));
  const one = join(dir, "one.jsonl");
  writeFileSync(one, JSON.stringify({ id: "x1", expected: "block", input: { command: "cat .env" } }) + "\n");
  const J = "a justification that is long enough to count as one";
  const allow = (closure) => { const f = join(dir, `allow-${Math.random().toString(36).slice(2)}.json`); writeFileSync(f, JSON.stringify({ bases: { main: [], HEAD: [] }, closure })); return f; };
  assert.equal(runDiff("--base", "HEAD", "--wrappers", "--corpus", one, "--allowlist", allow([])).status, 0, "no exemptions, nothing violates");
  const stale = runDiff("--base", "HEAD", "--wrappers", "--corpus", one, "--allowlist", allow([{ ids: ["x1"], wrappers: ["sub"], justification: J, issue: "#188" }]));
  assert.equal(stale.status, 1, stale.stdout + stale.stderr);
  assert.match(stale.stdout, /STALE closure exemption x1/);
  const noIssue = runDiff("--base", "HEAD", "--wrappers", "--corpus", one, "--allowlist", allow([{ ids: ["x1"], wrappers: "*", justification: J }]));
  assert.equal(noIssue.status, 1, noIssue.stdout + noIssue.stderr);
  assert.match(noIssue.stdout, /BAD closure exemption/);
});
