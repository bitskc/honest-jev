// Item-level drift comparison between two jev-eval results files. It reports WHICH items changed, never a percentage
// alarm: at the sizes these corpora have, one flipped item is several points, and a threshold on that is noise. Refuses
// to compare across a model change, a suite change or a corpus change unless told to, and says so when it was told.
import { isHardZero } from "./score.mjs";

export class CompareError extends Error {}

export function compareResults(baseline, current, { allowModelChange = false, allowCorpusChange = false, harm = null } = {}) {
  const problems = [];
  const bm = (baseline.models ?? []).join(","), cm = (current.models ?? []).join(",");
  if (bm !== cm && !allowModelChange) problems.push(`model changed: baseline [${bm || "none"}] vs current [${cm || "none"}] (pass --allow-model-change to compare anyway)`);
  if (baseline.suite_id !== current.suite_id) problems.push(`different suites: ${baseline.suite_id} vs ${current.suite_id}`);
  if ((baseline.suite_hash !== current.suite_hash || baseline.corpus_hash !== current.corpus_hash) && !allowCorpusChange) problems.push("suite or corpus changed since the baseline (pass --allow-corpus-change to compare anyway)");
  if (problems.length) throw new CompareError(problems.join("; "));

  const base = new Map(baseline.rows.map((r) => [r.id, r]));
  const cur = new Map(current.rows.map((r) => [r.id, r]));
  const flips = [], coverage = [];
  let common = 0;
  for (const [id, c] of cur) {
    const b = base.get(id);
    if (!b) continue;
    if (b.evaluated && c.evaluated) {
      common++;
      if (b.decision !== c.decision) flips.push({ id, truth: c.truth, from: b.decision, to: c.decision, hard_zero: harm ? isHardZero(harm, c.truth, c.decision) : null });
    } else if (b.evaluated !== c.evaluated) coverage.push({ id, from: b.evaluated ? "evaluated" : `not evaluated (${b.reason})`, to: c.evaluated ? "evaluated" : `not evaluated (${c.reason})` });
  }
  return {
    allowed: { model_change: allowModelChange && bm !== cm, corpus_change: allowCorpusChange && (baseline.suite_hash !== current.suite_hash || baseline.corpus_hash !== current.corpus_hash) },
    compared: common, flipped: flips.length, flips, coverage_changes: coverage,
    added: [...cur.keys()].filter((i) => !base.has(i)).length, removed: [...base.keys()].filter((i) => !cur.has(i)).length,
    hard_zero_flips: flips.filter((f) => f.hard_zero).length,
  };
}
