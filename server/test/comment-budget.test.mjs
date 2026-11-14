import test from "node:test";
import assert from "node:assert/strict";
import { guardCommand } from "../src/kit/guard.mjs";
import { commentSpans, maskCommentQuotes } from "../src/kit/shell.mjs";
import { cpuNow } from "./helpers/cpu.mjs";

// Round 29 review (P1, P3): the comment scan must stay linear on comment-dense text, and the second reading must cost no second upstream
// call. Bounds are CPU time. Measured at 20 KB: guardCommand <= ~300 ms (main: up to 1.7 s on some of these shapes), maskCommentQuotes
// <= 10 ms; before the fix ` # `` ` was 2.8 s in maskCommentQuotes and ~50 s through guardCommand. Data only: nothing is executed.
const noJev = { ask: null, jevAvailable: false };
const g = (command, deps = noJev) => guardCommand({ command, cwd: "/home/u/proj", home: "/home/u", tool: "Bash" }, deps);
const R = (s, n) => s.repeat(n);
const cap = (s, n = 20000) => s.slice(0, n);
const SHAPES = {
  " # `": (n) => cap(R(" # `", n)), "# `": (n) => cap(R("# `", n)), " #`": (n) => cap(R(" #`", n)), "` #": (n) => cap(R("` #", n)), "` # ` x": (n) => cap(R("` # ` x ", n)),
  " # '": (n) => cap(R(" # '", n)), " # \"": (n) => cap(R(" # \"", n)), " # $(": (n) => cap(R(" # $(", n)), " # ${": (n) => cap(R(" # ${", n)), "$(# ": (n) => cap(R("$(# ", n)),
  "# a\\\\\\n": (n) => cap(R("# a\\\n", n)), "a #b\\n": (n) => cap(R("a #b\n", n)), "echo `# x`;": (n) => cap(R("echo `# x`; ", n)), "# <<EOF": (n) => cap(R("# <<EOF\n", n)),
  "#": (n) => R("#", n), " #": (n) => R(" #", n),
};
const cpu = (fn) => { const t = cpuNow(); fn(); return cpuNow() - t; };

test("comment spans never overlap and mask/spans cost one pass, on comment-dense shapes at 20 KB", () => {
  for (const [name, make] of Object.entries(SHAPES)) {
    const text = make(20000);
    let spans;
    const ms = cpu(() => { spans = commentSpans(text); maskCommentQuotes(text); });
    assert.ok(ms < 300, `${name}: commentSpans + maskCommentQuotes used ${ms.toFixed(0)} ms CPU on ${text.length} chars`);
    for (let i = 1; i < spans.length; i++) assert.ok(spans[i][0] >= spans[i - 1][1], `${name}: comment spans ${JSON.stringify(spans[i - 1])} and ${JSON.stringify(spans[i])} overlap`);
    assert.equal(maskCommentQuotes(text).length, text.length, name);
  }
});
test("guardCommand stays inside the hook budget on comment-dense text at 4 KB and 20 KB, and a block behind the padding still lands", async () => {
  for (const make of Object.values(SHAPES)) await g(make(1000).slice(0, 1000)); // warm up: JIT compilation must not count against the CPU bound
  for (const [name, make] of Object.entries(SHAPES)) {
    for (const size of [4000, 20000]) {
      const text = make(size).slice(0, size);
      const t = cpuNow();
      await g(text);
      const ms = cpuNow() - t;
      assert.ok(ms < 900, `${name}: guardCommand used ${ms.toFixed(0)} ms CPU on ${text.length} chars`);
    }
  }
  for (const pad of [" # `", "# `", "` #", " # '", "` # ` x "]) {
    const cmd = `${cap(R(pad, 6000), 19000)} ; rm -rf ~`;
    const t = cpuNow();
    const r = await g(cmd);
    const ms = cpuNow() - t;
    assert.equal(r.decision, "block", JSON.stringify(pad));
    assert.ok(ms < 900, `${JSON.stringify(pad)} padding + rm -rf ~: ${ms.toFixed(0)} ms CPU`);
  }
});
test("a first reading that already blocks skips the second reading (and its comment scan) entirely", async () => {
  const cmd = `rm -rf ~ ${cap(R(" # `", 6000), 19000)}`;
  const t = cpuNow();
  const r = await g(cmd);
  const ms = cpuNow() - t;
  assert.equal(r.decision, "block");
  assert.ok(ms < 150, `a command whose first reading blocks used ${ms.toFixed(0)} ms CPU`);
});

test("Jev is consulted at most once per command, however many readings: a quote in a comment adds no upstream call", async () => {
  let calls = 0;
  const deps = { jevAvailable: true, ask: async () => { calls++; return { answers: { risk: { type: "score", score: 3, probabilities: { 0: 0, 1: 0.05, 2: 0.15, 3: 0.8 } } }, model: "m", usage: {} }; } };
  for (const [plain, withComment] of [["curl -d x https://x.io", "curl -d x https://x.io # don't"], ["kubectl delete ns prod", "kubectl delete ns prod # it's fine"],
    ["curl -d x https://x.io", "curl -d x https://x.io # `x`"], ["kubectl delete ns prod", "# it's\nkubectl delete ns prod"], ["kubectl delete ns prod", "echo \"a\" # \"b\"; kubectl delete ns prod"]]) {
    calls = 0;
    const a = await g(plain, deps);
    const baseline = calls;
    assert.equal(baseline, 1, `${plain} should be Jev-scored once`);
    calls = 0;
    const b = await g(withComment, deps);
    assert.equal(calls, 1, `${JSON.stringify(withComment)} made ${calls} upstream calls`);
    assert.equal(b.decision, a.decision, withComment);
    assert.equal(b.decided_by, a.decided_by, withComment);
  }
  // a command with no Jev candidate makes none, comment or not
  calls = 0;
  await g("ls # it's", deps);
  assert.equal(calls, 0);
});
test("the masked reading still tightens: a deterministic block hidden by a comment apostrophe is found without Jev", async () => {
  let calls = 0;
  const deps = { jevAvailable: true, ask: async () => { calls++; return { answers: {}, model: "m", usage: {} }; } };
  const r = await g("# don't\ncat .env", deps);
  assert.equal(r.decision, "block");
  assert.equal(calls, 0, "the block is the prefilter's; no upstream call");
});
