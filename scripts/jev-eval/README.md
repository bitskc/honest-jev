# jev-eval

Measure a decision gate on **your own labelled corpus**: how often it is right, what its mistakes cost, which threshold to use, and what changed since last time. Zero dependencies (Node 22+). A `module` target imports and runs code named in the suite, so only run suites you wrote or reviewed. It never spawns a process and never evaluates corpus text; rows are data passed to the target.

```sh
node scripts/jev-eval/run.mjs score     scripts/jev-eval/suites/guard.json --kit .          # accuracy, harm, hard-zero cells
node scripts/jev-eval/run.mjs calibrate my-suite.json                                       # sweep on train, one holdout judgement
node scripts/jev-eval/run.mjs compare --baseline old.json --current new.json                # item-level changes
node scripts/jev-eval/run.mjs score my-suite.json --dry-run                                 # how many rows would call Jev; sends nothing
```

Built-in suites (`suites/guard.json`, `verify_done.json`, `dispatch.json`) read `evals/*.jsonl` (which lives with the guard's accuracy corpus) and score the kit's own tools in process. `--corpus f` overrides the corpus path and `--kit <checkout>` runs the corpus against another checkout's server code (for example a PR branch).

## Offline, and what "not evaluated" means

With no Jev credentials in the environment (`AI_GATEWAY_API_KEY`, `TYPESAFE_API_KEY` or `JEV_UPSTREAM_API_KEY`) the built-in targets still run every row that the deterministic rules decide. A row that needed a model answer comes back `jev.status: unavailable` and is marked **NOT EVALUATED**: it is excluded from every figure, counted by reason, and called out before any accuracy number. It is neither right nor wrong. With credentials, a live run stops at `--max-calls` (default 2000) upstream calls instead of spending without limit; use `--dry-run` first to see the count. Answers are cached per `(state, questions, model)` (optionally on disk with `--cache f`, mode 0600, no text) so a threshold sweep calls the model once per row, not once per value.

## Suite manifest

```json
{
  "version": 1, "id": "routing-gate",
  "target": { "kind": "module", "path": "./decide.mjs", "export": "decide" },
  "corpus": "corpus.jsonl", "row_id": "/i", "expected": "/truth", "input": "/input", "decision": "/decision",
  "not_evaluated": [{ "pointer": "/jev/status", "in": ["unavailable"], "reason": "jev_unavailable" }],
  "harm": {
    "cost": { "READ": { "routed": 0, "not_read": 1 }, "WRITE": { "routed": 10 } },
    "default_error_cost": 1,
    "hard_zero": [["WRITE", "routed"], ["BOTH", "routed"], ["CORRECTION", "routed"]]
  },
  "split": { "holdout_pct": 20, "key": "/split_key", "salt": "", "field": null },
  "sweep": [{ "name": "change_max", "values": [0.15, 0.2, 0.3], "stricter": "low" }, { "name": "answer_min", "values": [0.7, 0.85], "stricter": "high" }],
  "min_evidence": { "train_per_class": 30, "holdout_per_class": 20 },
  "label_source_default": "derived", "label_overrides": { "g420": "derived" }
}
```

Unknown keys anywhere are errors. Targets: `builtin` (`kit_guard_command`, `kit_verify_done`, `kit_size_dispatch`), `module` (an exported `(input, params) => output` next to the suite), `mcp` (a tool on a deployed Worker; `JEV_MCP_URL` and `JEV_MCP_TOKEN` from the environment, never argv; `https` only, plain `http` for loopback). `sweep[].apply` is `input` (merged into the tool input, e.g. `ask_at`) or `params` (second argument of a module); a multi-entry sweep is a full grid.

Corpus rows are JSONL: `{id, expected, input, label_source?, tags?}`; pointers in the manifest remap them, so a deployment's own frozen corpus shape (`i`, `truth`, a precomputed `split` or a thread key) works unchanged. Committed corpora must hold no customer or workplace text (answer vectors and ids only); a deployment's private corpus lives in its own repo.

## Correctness is the harm matrix

`cost(truth, decision)` is the listed cell; otherwise 0 when equal; otherwise `default_error_cost`. A row is **acceptable** when its cost is 0, so truth `READ` with decision `routed` can be free while truth `WRITE` with `routed` is a **hard-zero** cell: any occurrence fails the run (exit 3) and its row ids are listed. With zero occurrences the report prints the one-sided exact 95% upper bound on the true rate among rows of that truth class (`1 - 0.05^(1/n)`: about 7.2% at n=40) and says zero observed is not zero risk. Proportions print `k/n` with a two-sided 95% Wilson interval; the method is named beside each figure.

## Label provenance

Each row is `human` (a person judged it), `outcome` (an observed downstream result) or `derived` (copied from the system's own behaviour, or model-made). A row with no `label_source` is `derived`; `label_source_default` and `label_overrides` let a suite state otherwise on purpose (issue #125: tuning on labels that follow current behaviour tunes the system to itself). `score` accepts everything and prints the provenance counts (plus a banner if every label is derived). A `calibrate --dry-run` prints how many target calls the sweep would make (an `mcp` target re-calls the Worker for every swept value; the builtin target caches answers) and runs nothing. `calibrate` uses only `human` and `outcome` rows and prints how many it excluded.

## Calibration

1. Sweep every combination on the **train** split, using only evaluable `human`/`outcome` rows.
2. Keep values with zero hard-zero violations; pick the lowest expected harm; ties go to the stricter setting per entry (`stricter: low` prefers the lower value, `high` the higher), earlier entries first.
3. Judge that single value on **holdout** once.

`status`: `recommended`, `insufficient_evidence` (per-class minimums, derived-only corpus, nothing evaluable), `no_feasible_value`, `holdout_violation` (nothing is recommended), `refused_failed_holdout`. Minimums are checked before any holdout row runs. The holdout split is the first four bytes of `sha256(salt:key)` mod 100 (a thread-level split when `key` is `channel:thread`, so rows of one thread land together); a precomputed `split` field wins if the suite names one.

**Holdout discipline.** A holdout is identified by suite id plus split definition (pct, key, field, salt), not by its rows, so appending rows does not make a fresh holdout. Every judgement is appended to `$XDG_STATE_HOME/jev/eval/<suite id>.holdout.jsonl` (override `--state`) with its count. After a `holdout_violation` the same holdout is **not** judged again (exit 5) until `split.salt` is changed, or you pass `--force-holdout "<reason of at least 8 characters>"`, which runs it and logs the reason. The recommendation file records `holdout_evaluations`. The log is local advisory state: two simultaneous runs can both pass its check, and a different machine has a different log. A recommendation is advice only: nothing is ever written to a config, policy or spec file; change a threshold through a reviewed commit.

## Drift

`compare` lists the items whose decision changed, by id, plus items whose evaluation coverage changed (for example evaluated offline-vs-online). It draws no verdict from a count: one flipped item is several points at these sizes. It refuses a model change, a suite or corpus change, or different suites unless `--allow-model-change` / `--allow-corpus-change` is passed, and it says so in the output when you did. A flip into a hard-zero cell exits 3.

## Exit codes

`0` ok or recommended - `2` usage or suite error - `3` hard-zero violation (score) or flip into a hard-zero cell (compare) - `4` not recommended (insufficient evidence, no feasible value, holdout violation) - `5` refused: failed holdout already judged - `6` compare refused.

## Results files

`score` writes `jev-eval-results/<suite id>-<UTC stamp>.json` (git-ignored): suite and corpus hashes, target kind and git commit (read from `.git`, nothing is spawned), models seen, label provenance, metrics, and per-row `{id, truth, decision, evaluated, reason, split, label_source}`. No corpus text and no credentials. Token and cost figures are lower bounds (retried attempts are invisible) and count fresh upstream calls only.

Tests: `bash tests/test-jev-eval.sh [--mutation]`. Offline smoke: `bash tests/smoke-jev-eval.sh`.
