import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { cpuNow } from "./helpers/cpu.mjs";
import { extractRegexLiterals, nestedQuantifierGroups, sweepRegex } from "./helpers/regex-scan.mjs";
import { REVIEWED_NESTED } from "./helpers/reviewed-nested.mjs";

// Round 27 (review of 8dad898, P1): `\.env(\.[A-Za-z0-9_.-]+)*$` repeated a class that holds `.`, so `cat .env` + `.a` x24 + `!`
// took seconds and the hook (2 s limit, fails open) lost the whole command's decision. It sat in the guard from round 11 to
// round 26 because no test generated input from the regex's own shape. This file does: every regex in the kit is attacked with a
// pump built from ITS OWN characters, and the guard end to end with generated tokens. Data only: every string is handed to a
// regex or to guardCommand(); nothing is executed.
const here = dirname(fileURLToPath(import.meta.url));
const kit = join(here, "..", "src", "kit");
const FILES = ["guard", "shell", "safere", "verify"].map((f) => join(kit, `${f}.mjs`));
// Bounds are CPU time. Measured on an idle machine: every exponential-style probe < 10 ms; the slowest 20 KB probe (a trailing
// `\/+$` trim, quadratic) ~ 460 ms; a guardCommand on a 20 KB generated token <= ~160 ms. A catastrophic regex is interrupted
// by the 2 s kill and counts as unbounded.
const EXP_BOUND_MS = 150;
const POLY_BOUND_MS = 1000;
const E2E_BOUND_MS = 600;

const literals = FILES.flatMap((file) => extractRegexLiterals(readFileSync(file, "utf8")).map((l) => ({ ...l, file: file.split("/").pop() })));
const unique = (list) => [...new Map(list.map((l) => [`${l.source}/${l.flags}`, l])).values()];

function sweepAll(list) {
  const failures = [];
  for (const re of unique(list)) {
    let r;
    try { new RegExp(re.source, re.flags); } catch { continue; } // not a standalone regex source (cannot happen for a real literal)
    r = sweepRegex(re);
    if (r.error) failures.push(`${re.file ?? "?"}: ${re.source.slice(0, 80)} threw ${r.error}`);
    if (r.exp.ms > EXP_BOUND_MS) failures.push(`${re.file ?? "dynamic"}:${re.line ?? ""} ${re.source.slice(0, 90)}  EXPONENTIAL-STYLE ${r.exp.timedOut ? "(interrupted)" : r.exp.ms.toFixed(0) + " ms"} on ${r.exp.label}`);
    if (r.poly.ms > POLY_BOUND_MS) failures.push(`${re.file ?? "dynamic"}:${re.line ?? ""} ${re.source.slice(0, 90)}  SUPER-LINEAR ${r.poly.timedOut ? "(interrupted)" : r.poly.ms.toFixed(0) + " ms"} on ${r.poly.label}`);
  }
  return failures;
}

test("the extractor finds the kit's regex literals (a broken scanner must not pass the sweep vacuously)", () => {
  assert.ok(literals.length >= 250, `only ${literals.length} regex literals found`);
  for (const f of ["guard", "shell", "safere", "verify"]) assert.ok(literals.some((l) => l.file === `${f}.mjs`), `${f}.mjs: none found`);
  assert.ok(literals.some((l) => l.source.includes("\\.env")), "the dotenv rules were not found");
  const src = "const a = x / 2 / 3; const r = /ab+c\\/d[/]/gi; const t = `${1 / 2} /not/ ${/q+/.test(s)}`; // /comment/\nconst s = 'a/b' + \"/c/\";";
  assert.deepEqual(extractRegexLiterals(src).map((l) => [l.source, l.flags]), [["ab+c\\/d[/]", "gi"], ["q+", ""]]);
});

test("the sweep catches the round-11 exponential: the pre-fix dotenv regex is interrupted or over the bound, the fixed one is not", () => {
  const old = { source: "\\.env(\\.[A-Za-z0-9_.-]+)*$", flags: "" };
  const fixed = { source: "\\.env(?:\\.[A-Za-z0-9_.-]+)?$", flags: "" };
  const bad = sweepRegex(old, { timeoutMs: 1000 });
  assert.ok(bad.exp.timedOut || bad.exp.ms > EXP_BOUND_MS || bad.poly.timedOut || bad.poly.ms > POLY_BOUND_MS, `the old regex was not flagged: ${JSON.stringify(bad)}`);
  const good = sweepRegex(fixed);
  assert.ok(good.exp.ms < EXP_BOUND_MS && good.poly.ms < POLY_BOUND_MS, `the fixed regex was flagged: ${JSON.stringify(good)}`);
});

test("every regex literal in guard/shell/safere/verify survives adversarial pumps built from its own characters", () => {
  const failures = sweepAll(literals);
  assert.deepEqual(failures, [], `\n${failures.join("\n")}`);
});

test("every regex the kit CONSTRUCTS while deciding the whole eval corpus survives the same pumps", async () => {
  const seen = new Map();
  const Real = RegExp;
  globalThis.RegExp = new Proxy(Real, {
    construct(target, args, newTarget) {
      if (typeof args[0] === "string") seen.set(`${args[0]}/${args[1] ?? ""}`, { source: args[0], flags: args[1] ?? "" });
      return Reflect.construct(target, args, newTarget);
    },
  });
  try {
    const { guardCommand } = await import(`../src/kit/guard.mjs?sweep=${Date.now()}`);
    const rows = readFileSync(join(here, "..", "..", "evals", "guard.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
    for (const r of rows) {
      if (typeof r.input.command !== "string" || r.input.command.length > 5000) continue;
      await guardCommand({ cwd: "/home/u/proj", home: "/home/u", tool: "Bash", ...r.input }, { ask: null, jevAvailable: false });
    }
  } finally {
    globalThis.RegExp = Real;
  }
  assert.ok(seen.size >= 20, `only ${seen.size} constructed regexes recorded`);
  const failures = sweepAll([...seen.values()]);
  assert.deepEqual(failures, [], `\n${failures.join("\n")}`);
});

test("guardCommand stays inside the hook's budget on 20 KB tokens generated from the characters the rules scan", async () => {
  const { guardCommand } = await import("../src/kit/guard.mjs");
  const prefixes = ["cat ", "rm -rf ", "chmod -R 777 ", "grep -rn ", "echo $", "cat .env.", "git add credentials.", "curl -d @", "echo $(", "cat <(", "cat ~/.ssh/", "export X=", "node -e process.env."];
  const units = ["a", "A", "1", "/", "_", ".", "<", ")", "`", "'", "$a", ".a", "-", "="];
  const over = [];
  for (const prefix of prefixes) {
    for (const unit of units) {
      const command = prefix + unit.repeat(Math.floor((20000 - prefix.length) / unit.length));
      const t0 = cpuNow();
      await guardCommand({ command, cwd: "/home/u/proj", home: "/home/u", tool: "Bash" }, { ask: null, jevAvailable: false });
      const ms = cpuNow() - t0;
      if (ms > E2E_BOUND_MS) over.push(`${JSON.stringify(prefix)} + ${JSON.stringify(unit)} x ${command.length} chars: ${ms.toFixed(0)} ms`);
    }
  }
  assert.deepEqual(over, [], over.join("\n"));
});

test("every regex that repeats a group containing another quantifier or an alternation has been read and is on the reviewed list", () => {
  const flagged = unique(literals).filter((l) => nestedQuantifierGroups(l.source).length > 0);
  assert.ok(flagged.length >= 10, `the structural scan found only ${flagged.length} candidates`);
  const unreviewed = flagged.filter((l) => !REVIEWED_NESTED.has(l.source)).map((l) => `${l.file}:${l.line} ${l.source}`);
  assert.deepEqual(unreviewed, [], `a regex with a repeated group that holds a quantifier or alternation was added or changed. Read it for ambiguity (can one string match in more than one way, with a failure after the group?), time it with sweepRegex, then add it to REVIEWED_NESTED with the reason:\n${unreviewed.join("\n")}`);
  // the structural scan flags the round-11 shape
  assert.ok(nestedQuantifierGroups("\\.env(\\.[A-Za-z0-9_.-]+)*$").length > 0);
  assert.equal(nestedQuantifierGroups("\\.env(?:\\.[A-Za-z0-9_.-]+)?$").length, 0);
});
