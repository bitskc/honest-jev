// Test helpers: synthetic, content-free corpora and manifests written to a temp directory.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const FIXTURES = join(fileURLToPath(new URL(".", import.meta.url)), "fixtures");
export const tmp = (p = "jev-eval-test-") => mkdtempSync(join(tmpdir(), p));
export const writeJsonl = (path, rows) => writeFileSync(path, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
export const writeJson = (path, v) => writeFileSync(path, JSON.stringify(v, null, 2));

// Answer-vector rows in a frozen-corpus shape: numeric `i`, class `truth`, precomputed `split`.
export function gateRows({ reads = 40, writes = 30, split = (i, truth) => (i % 5 === 0 ? "holdout" : "train"), label = "human", extra = [] } = {}) {
  const rows = [];
  let i = 1;
  for (let k = 0; k < reads; k++, i++) rows.push({ i, truth: "READ", split: split(i, "READ"), label_source: label, input: { facts: { open_ask: false }, answers: { wants_answer: 0.96, wants_change: 0.01 + (k % 30) * 0.012 }, write_mass: 0.01 } });
  for (let k = 0; k < writes; k++, i++) rows.push({ i, truth: k % 2 ? "BOTH" : "WRITE", split: split(i, "WRITE"), label_source: label, input: { facts: { open_ask: false }, answers: { wants_answer: 0.96, wants_change: 0.3 + (k % 20) * 0.03 }, write_mass: 0.01 } });
  for (const e of extra) rows.push({ i: i++, label_source: label, ...e });
  return rows;
}

export function gateSuite(over = {}) {
  return {
    version: 1, id: "gate-like", target: { kind: "module", path: "./fixtures/decide.mjs", export: "decide" }, corpus: "corpus.jsonl",
    row_id: "/i", expected: "/truth", decision: "/decision", split: { holdout_pct: 20, field: "/split" },
    harm: {
      cost: { READ: { routed: 0, open_ask: 1, vetoed: 1, not_read: 1, uncertain: 1 }, WRITE: { routed: 10, open_ask: 0, vetoed: 0, not_read: 0, uncertain: 0 }, BOTH: { routed: 10, open_ask: 0, vetoed: 0, not_read: 0, uncertain: 0 }, CORRECTION: { routed: 10, open_ask: 0, vetoed: 0, not_read: 0, uncertain: 0 } },
      hard_zero: [["WRITE", "routed"], ["BOTH", "routed"], ["CORRECTION", "routed"]],
    },
    sweep: [{ name: "change_max", values: [0.15, 0.2, 0.25, 0.3, 0.35], stricter: "low" }, { name: "answer_min", values: [0.7, 0.85], stricter: "high" }],
    min_evidence: { train_per_class: 5, holdout_per_class: 3 }, ...over,
  };
}

/** Write suite + corpus (+ the fixture module is referenced in place). Returns {dir, suitePath}. */
export function writeGate(rows, suiteOver = {}, dir = tmp()) {
  writeJsonl(join(dir, "corpus.jsonl"), rows);
  const suite = gateSuite(suiteOver);
  suite.target.path = join(FIXTURES, "decide.mjs");
  writeJson(join(dir, "suite.json"), suite);
  return { dir, suitePath: join(dir, "suite.json") };
}
