#!/usr/bin/env python3
"""Mutation check for jev-eval (scripts/jev-eval). Copies scripts/ and server/src/ to a scratch directory, applies one
deliberate defect (one or more coordinated edits) at a time, and requires the test suite to FAIL. A surviving mutation
means no test can catch that defect. The real tree is never modified. Data only: nothing here executes a corpus string.

    python3 tests/mutation_check_jev_eval.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CMD = ["node", "--test", "scripts/jev-eval/test/"]
L = "scripts/jev-eval/lib/"

# (name, [(file, old, new), ...]); `old` must occur exactly once in `file`.
MUTATIONS = [
    ("stats: Wilson uses z=1.64", [(L + "stats.mjs", "const Z95 = 1.959963984540054;", "const Z95 = 1.64;")]),
    ("stats: zero-count bound is 0.05^n", [(L + "stats.mjs", "1 - Math.pow(0.05, 1 / n)", "1 - Math.pow(0.05, n)")]),
    ("split: bucket mod 101", [(L + "split.mjs", ".readUInt32BE(0) % 100;", ".readUInt32BE(0) % 101;")]),
    ("split: salt ignored", [(L + "split.mjs", "const text = salt ? `${salt}:${key}` : String(key);", "const text = String(key);")]),
    ("split: precomputed field ignored", [(L + "split.mjs", "  if (s.field) {", "  if (false) {")]),
    ("split: key pointer ignored (always row id)", [(L + "split.mjs", "const key = pointerGet(row, s.key);", "const key = id;")]),
    ("score: unlisted off-diagonal pair is free", [(L + "score.mjs", "return truth === decision ? 0 : harm.default_error_cost;", "return 0;")]),
    ("score: hard-zero violations never recorded", [(L + "score.mjs", "    if (isHardZero(suite.harm, r.truth, r.decision)) (violations[`${r.truth}>${r.decision}`] ??= []).push(r.id);", "")]),
    ("score: hard-zero cell matches on truth only", [(L + "score.mjs", "export const isHardZero = (harm, truth, decision) => harm.hard_zero.some(([t, d]) => t === truth && d === decision);", "export const isHardZero = (harm, truth, decision) => harm.hard_zero.some(([t]) => t === truth);")]),
    ("score: not-evaluated rows scored anyway", [(L + "score.mjs", "const evald = results.filter((r) => r.evaluated);", "const evald = results.filter((r) => r.decision !== undefined);")]),
    ("score: zero-count bound dropped", [(L + "score.mjs", "upper95_if_zero: ids.length === 0 ? { value: zeroUpper95(n), method: \"exact-95-one-sided\", n } : null", "upper95_if_zero: null")]),
    ("score: not_evaluated 'in' rules ignored", [(L + "score.mjs", "r.hasEquals ? v === r.equals : Array.isArray(r.in) && r.in.includes(v)", "r.hasEquals ? v === r.equals : false")]),
    ("score: a throwing target is scored as evaluated", [(L + "score.mjs", "decision: null, evaluated: false, reason: \"call_error\"", "decision: null, evaluated: true, reason: \"call_error\"")]),
    ("score: expected harm not summed", [(L + "score.mjs", "    harm += c;\n", "")]),
    ("calibrate: derived labels become eligible", [(L + "calibrate.mjs", 'const ELIGIBLE = new Set(["human", "outcome"]);', 'const ELIGIBLE = new Set(["human", "outcome", "derived"]);')]),
    ("calibrate: tie-break prefers the looser value", [(L + "calibrate.mjs", '    if (e.stricter === "high") sorted.reverse();', '    if (e.stricter !== "high") sorted.reverse();')]),
    ("calibrate: infeasible values allowed", [(L + "calibrate.mjs", "scored.filter((c) => c.summary.hard_zero_violations === 0)", "scored.filter((c) => c.summary.hard_zero_violations >= 0)")]),
    ("calibrate: failed holdout can be re-judged freely", [(L + "calibrate.mjs", "if (failedBefore.length && !force) {", "if (false) {")]),
    ("calibrate: forced re-run not logged with its reason", [(L + "calibrate.mjs", "force_reason: rec.forced ? String(force).slice(0, 200) : null });\n  }\n  return rec;", "force_reason: null });\n  }\n  return rec;")]),
    ("calibrate: holdout evaluation not logged", [(L + "calibrate.mjs", "  if (statePath) {\n    appendHoldoutLog(statePath, { ts: now().toISOString(), holdout_id: hid, suite_id: suite.id, evaluated: true,", "  if (false) {\n    appendHoldoutLog(statePath, { ts: now().toISOString(), holdout_id: hid, suite_id: suite.id, evaluated: true,")]),
    ("calibrate: holdout identity ignores the salt", [(L + "calibrate.mjs", "key: suite.split.key, field: suite.split.field, salt: suite.split.salt })", "key: suite.split.key, field: suite.split.field })")]),
    ("calibrate: train minimums not enforced", [(L + "calibrate.mjs", "if (evalTrain.length === 0 || trainShort.length) {", "if (evalTrain.length === 0) {")]),
    ("calibrate: holdout label minimums checked only after running the holdout", [(L + "calibrate.mjs", "if (holdout.length === 0 || labelShort.length) {", "if (holdout.length === 0) {")]),
    ("calibrate: a violated holdout still recommends", [(L + "calibrate.mjs", 'rec.recommended = rec.status === "recommended" ? best.combo : null;', "rec.recommended = best.combo;")]),
    ("calibrate: holdout violation not detected", [(L + "calibrate.mjs", 'rec.status = hs.hard_zero_violations === 0 ? "recommended" : "holdout_violation";', 'rec.status = "recommended";')]),
    ("compare: model change allowed silently", [(L + "compare.mjs", "if (bm !== cm && !allowModelChange)", "if (false)")]),
    ("compare: corpus change allowed silently", [(L + "compare.mjs", "if ((baseline.suite_hash !== current.suite_hash || baseline.corpus_hash !== current.corpus_hash) && !allowCorpusChange)", "if (false)")]),
    ("compare: flips counted across evaluated and not-evaluated", [(L + "compare.mjs", "if (b.evaluated && c.evaluated) {", "if (true) {")]),
    ("compare: hard-zero flips not flagged", [(L + "compare.mjs", "hard_zero: harm ? isHardZero(harm, c.truth, c.decision) : null", "hard_zero: null")]),
    ("cli: hard-zero violation exits 0", [("scripts/jev-eval/run.mjs", "return metrics.hard_zero_violations > 0 ? 3 : 0;", "return 0;")]),
    ("cli: force reason length unchecked", [("scripts/jev-eval/run.mjs", "force.trim().length < 8", "force.trim().length < 0")]),
    ("cli: calibrate --dry-run ignored (runs the sweep)", [("scripts/jev-eval/run.mjs", '  if (o["dry-run"]) {\n    const eligible', '  if (false) {\n    const eligible')]),
    ("cli: results rows carry corpus text", [("scripts/jev-eval/run.mjs", "split: r.split, label_source: r.label_source })),", "split: r.split, label_source: r.label_source, text: JSON.stringify(corpus.rows.find((x) => x.id === r.id).input) })),")]),
    ("cli: refused holdout exits 4", [("scripts/jev-eval/run.mjs", 'if (rec.status === "refused_failed_holdout") return 5;', 'if (rec.status === "refused_failed_holdout") return 4;')]),
    ("target: plain http to any host allowed", [(L + "target.mjs", 'if (u.protocol !== "https:" && !loopback)', "if (false)")]),
    ("target: sweep values not applied to the tool input", [(L + "target.mjs", "(e.apply === \"input\" ? inputExtras : moduleParams)[e.name] = params[e.name];", "moduleParams[e.name] = params[e.name];")]),
    ("target: answer cache disabled", [(L + "target.mjs", "if (cache.has(k)) {", "if (false) {")]),
    ("target: builtin abort never raised after the tool swallowed the cap error", [(L + "target.mjs", "      if (blown) throw new BudgetExceeded(maxCalls);\n", "")]),
    ("target: concurrent rows overshoot the cap (no in-flight reservation)", [(L + "target.mjs", "if (fresh + inFlight >= maxCalls) { blown = true;", "if (fresh >= maxCalls) { blown = true;")]),
    ("target: mcp call cap not enforced", [(L + "target.mjs", "if (id >= maxCalls) throw new BudgetExceeded(maxCalls);", "")]),
    ("score: budget abort swallowed as a per-row call_error", [(L + "score.mjs", '      if (e?.name === "BudgetExceeded") throw e;\n', "")]),
    ("cli: --max-calls not validated", [("scripts/jev-eval/run.mjs", "if (!Number.isInteger(maxCalls) || maxCalls < 1)", "if (false)")]),
    ("suite: unknown top-level keys tolerated", [(L + "suite.mjs", 'for (const k of Object.keys(raw)) if (!TOP_KEYS.has(k)) fail(`suite: unknown key "${k}"`);', "")]),
    ("suite: missing label_source treated as human", [(L + "suite.mjs", 'const lsd = raw.label_source_default ?? "derived";', 'const lsd = raw.label_source_default ?? "human";')]),
    ("suite: label override loses to the row's own label", [(L + "suite.mjs", "suite.label_overrides[id] ?? declared ?? suite.label_source_default", "declared ?? suite.label_overrides[id] ?? suite.label_source_default")]),
]


def main():
    tmp = tempfile.mkdtemp(prefix="jev-eval-mutation-")
    survived, killed = [], 0
    try:
        for name, edits in MUTATIONS:
            work = os.path.join(tmp, "w")
            shutil.rmtree(work, ignore_errors=True)
            os.makedirs(work)
            for item in ["scripts", "server/src"]:
                src, dst = os.path.join(ROOT, item), os.path.join(work, item)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copytree(src, dst, ignore=shutil.ignore_patterns("node_modules", "__pycache__"))
            bad = False
            for rel, old, new in edits:
                path = os.path.join(work, rel)
                with open(path) as f:
                    text = f.read()
                if text.count(old) != 1:
                    print("BAD MUTATION (pattern count %d): %s :: %s" % (text.count(old), name, old[:70]))
                    bad = True
                    break
                with open(path, "w") as f:
                    f.write(text.replace(old, new))
            if bad:
                survived.append(name)
                continue
            p = subprocess.run(CMD, cwd=work, capture_output=True, text=True, timeout=300)
            if p.returncode != 0:
                killed += 1
                print("KILLED   %s" % name)
            else:
                survived.append(name)
                print("SURVIVED %s" % name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d mutations, %d killed, %d survived" % (len(MUTATIONS), killed, len(survived)))
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
