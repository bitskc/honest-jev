// Plain-text rendering for jev-eval. Every proportion shows k/n and its interval with the method named; every
// not-evaluated row is called out before any accuracy figure so a partial run cannot read as a complete one.
const pc = (x) => (x === null || x === undefined ? "n/a" : `${(x * 100).toFixed(1)}%`);
const prop = (p) => (p.n === 0 ? "n/a (n=0)" : `${p.k}/${p.n} = ${pc(p.p)} [${pc(p.low)}, ${pc(p.high)}] (Wilson 95%, two-sided)`);
const mapStr = (m) => (Object.keys(m).length ? Object.entries(m).map(([k, v]) => `${k}=${v}`).join(", ") : "none");

export function renderScore(r) {
  const m = r.metrics, L = [];
  L.push(`jev-eval score: suite ${r.suite_id}  (suite ${r.suite_hash.slice(0, 10)}, corpus ${r.corpus_hash.slice(0, 10)})`);
  L.push(`target: ${r.target.kind}${r.target.tool ? ` ${r.target.tool}` : ""}${r.target.git ? ` @ ${r.target.git.slice(0, 10)}` : ""} - ${r.target.note}`);
  L.push(`rows: ${m.n_rows}   label sources: ${mapStr(r.label_provenance)}${r.label_provenance.derived ? "   (derived labels are scored but never used for calibration)" : ""}`);
  const allDerived = r.label_provenance.derived === m.n_rows;
  if (allDerived) L.push("ALL LABELS ARE DERIVED: the figures below measure agreement with the corpus, not independent correctness.");
  if (m.not_evaluated.n) {
    L.push("", `NOT EVALUATED: ${m.not_evaluated.n} of ${m.n_rows} rows (${mapStr(m.not_evaluated.reasons)})`);
    L.push("  These rows are excluded from every figure below. They are not wrong and not right; they were not judged.");
    if (m.not_evaluated.reasons.jev_unavailable) L.push("  jev_unavailable: the row needed a model answer and no upstream credentials were present (offline). Re-run with AI_GATEWAY_API_KEY / TYPESAFE_API_KEY / JEV_UPSTREAM_API_KEY to judge them.");
  }
  L.push("", `EVALUATED: ${m.n_evaluated} rows`);
  L.push(`  acceptable under the harm matrix: ${prop(m.accuracy)}`);
  L.push(`  expected harm: ${m.expected_harm}${m.mean_harm === null ? "" : ` (mean ${m.mean_harm.toFixed(4)} per row)`}`);
  for (const [cls, s] of Object.entries(m.per_class)) L.push(`  truth ${cls}: ${prop(s.acceptable)}`);
  if (r.harm.hard_zero.length) {
    L.push("", "HARD-ZERO CELLS");
    for (const c of m.hard_zero) {
      if (c.violations) L.push(`  ${c.truth} -> ${c.decision}: ${c.violations} VIOLATION(S) of ${c.exposed} exposed rows: ${c.ids.slice(0, 20).join(", ")}${c.ids.length > 20 ? " ..." : ""}`);
      else L.push(`  ${c.truth} -> ${c.decision}: 0 of ${c.exposed} exposed rows; the true rate is below ${pc(c.upper95_if_zero.value)} (exact 95%, one-sided). Zero observed is not zero risk.`);
    }
  }
  const truths = Object.keys(m.confusion).sort();
  if (truths.length) {
    L.push("", "CONFUSION (rows = truth, columns = decision; evaluated rows only)");
    const decisions = [...new Set(truths.flatMap((t) => Object.keys(m.confusion[t])))].sort();
    L.push(`  ${"".padEnd(14)}${decisions.map((d) => d.padStart(12)).join("")}`);
    for (const t of truths) L.push(`  ${t.padEnd(14)}${decisions.map((d) => String(m.confusion[t][d] ?? 0).padStart(12)).join("")}`);
  }
  const tags = Object.entries(m.by_tag);
  if (tags.length) { L.push("", "BY TAG"); for (const [t, p] of tags) L.push(`  ${t}: ${prop(p)}`); }
  const u = m.usage;
  L.push("", `USAGE: ${u.input_tokens} input / ${u.output_tokens} output tokens from fresh upstream calls${u.cost === null ? "" : `, cost ${u.cost}`}; ${u.cached_rows} row(s) served from the answer cache (tokens not recounted). Lower bound: retried attempts are not visible.`);
  if (m.models.length) L.push(`models: ${m.models.join(", ")}`);
  return L.join("\n");
}

export function renderCalibration(c) {
  const L = [];
  L.push(`jev-eval calibrate: suite ${c.suite_id}  holdout ${c.holdout_id}`);
  L.push(`STATUS: ${c.status}${c.forced ? "  (FORCED re-run of a failed holdout; logged)" : ""}`);
  L.push(`  ${c.reason}`);
  L.push(`  label eligibility: derived rows excluded = ${c.excluded_derived}`);
  if (c.not_evaluated) L.push(`  not evaluated: train ${c.not_evaluated.train ? `${c.not_evaluated.train.n} (${mapStr(c.not_evaluated.train.reasons)})` : "n/a"}${c.not_evaluated.holdout ? `, holdout ${c.not_evaluated.holdout.n} (${mapStr(c.not_evaluated.holdout.reasons)})` : ""}`);
  if (c.n_per_class.train) L.push(`  evaluable per class: train ${mapStr(c.n_per_class.train)}${c.n_per_class.holdout ? `; holdout ${mapStr(c.n_per_class.holdout)}` : ""}   minimums: train ${c.min_evidence.train_per_class}, holdout ${c.min_evidence.holdout_per_class}`);
  if (c.grid.length) {
    L.push("  sweep on TRAIN (expected harm, hard-zero violations):");
    for (const g of c.grid.slice(0, 40)) L.push(`    ${JSON.stringify(g.params)}  harm=${g.expected_harm}  violations=${g.hard_zero_violations}`);
    if (c.grid.length > 40) L.push(`    ... ${c.grid.length - 40} more in the JSON`);
  }
  if (c.candidate) L.push(`  candidate: ${JSON.stringify(c.candidate)}   recommended: ${c.recommended ? JSON.stringify(c.recommended) : "none"}`);
  if (c.holdout) L.push(`  HOLDOUT (single evaluation): ${prop(c.holdout.accuracy)}; hard-zero violations ${c.holdout.hard_zero_violations}`);
  L.push(`  holdout evaluations recorded for this holdout: ${c.holdout_evaluations}`);
  L.push("  A recommendation is advice. Nothing was written to any config, policy or spec file; change a threshold through a reviewed commit.");
  return L.join("\n");
}

export function renderCompare(c) {
  const L = [`jev-eval compare: ${c.flipped} of ${c.compared} items flipped${c.hard_zero_flips ? `, ${c.hard_zero_flips} into a hard-zero cell` : ""} (item-level; no drift verdict is drawn from a count)`];
  if (c.allowed.model_change) L.push("  NOTE: compared across a model change (--allow-model-change)");
  if (c.allowed.corpus_change) L.push("  NOTE: compared across a suite or corpus change (--allow-corpus-change)");
  for (const f of c.flips) L.push(`  ${f.id} [${f.truth}]: ${f.from} -> ${f.to}${f.hard_zero ? "  HARD-ZERO" : ""}`);
  if (c.coverage_changes.length) { L.push(`  evaluation coverage changed for ${c.coverage_changes.length} item(s):`); for (const x of c.coverage_changes.slice(0, 30)) L.push(`    ${x.id}: ${x.from} -> ${x.to}`); }
  if (c.added || c.removed) L.push(`  corpus delta: ${c.added} added, ${c.removed} removed`);
  return L.join("\n");
}
