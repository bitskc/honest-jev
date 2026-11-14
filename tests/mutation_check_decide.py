#!/usr/bin/env python3
"""Mutation check for kit_decide (server/src/decide, server/src/ledger/record.mjs). Copies the server sources, tests, the
examples and install.sh to a scratch directory, applies one deliberate defect at a time and requires the decide tests to
FAIL. A surviving mutation means no test can catch that defect. The real tree is never modified. Data only: nothing
here executes a string from a spec or a test.

    python3 tests/mutation_check_decide.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CMD = ["node", "--test", "--test-timeout=30000", "test/decide-core.test.mjs", "test/decide-tool.test.mjs"]
D = "server/src/decide/"
R = "server/src/ledger/record.mjs"

# (name, [(file, old, new), ...]); `old` must occur exactly once in `file`.
MUTATIONS = [
    # evaluator
    ("eval: gte is strict", [(D + "evaluate.mjs", 'case "gte": return x >= t;', 'case "gte": return x > t;')]),
    ("eval: gt is inclusive", [(D + "evaluate.mjs", 'case "gt": return x > t;', 'case "gt": return x >= t;')]),
    ("eval: lte is strict", [(D + "evaluate.mjs", 'case "lte": return x <= t;', 'case "lte": return x < t;')]),
    ("eval: lt is inclusive", [(D + "evaluate.mjs", "default: return x < t; // lt", "default: return x <= t; // lt")]),
    ("eval: all/any decisive value swapped", [(D + "evaluate.mjs", "if (r.v === (isAll ? F : T)) seenDecisive = true;", "if (r.v === (isAll ? T : F)) seenDecisive = true;")]),
    ("eval: unknown dominates invalid", [(D + "evaluate.mjs", "if (inv) return { v: I, needs: [], bad };", "if (inv && !unk) return { v: I, needs: [], bad };")]),
    ("eval: not does not flip", [(D + "evaluate.mjs", "return r.v === T ? { v: F, needs: [], bad: [] } : r.v === F ? { v: T, needs: [], bad: [] } : r;", "return r;")]),
    ("eval: absent fact is true", [(D + "evaluate.mjs", "else if (!has) ok = false;", "else if (!has) ok = true;")]),
    ("eval: fact eq is loose", [(D + "evaluate.mjs", "ok = x === c.eq;", "ok = x == c.eq;")]),
    ("eval: exists ignored", [(D + "evaluate.mjs", "ok = has === c.exists;", "ok = true;")]),
    ("eval: numeric fact accepts strings", [(D + "evaluate.mjs", "ok = typeof x === \"number\" && Number.isFinite(x) && cmp(op, x, c[op]);", "ok = cmp(op, x, c[op]);")]),
    ("eval: non-finite knob accepted", [(D + "evaluate.mjs", "&& Number.isFinite(knobs[c.knob])) return knobs[c.knob];", ") return knobs[c.knob];")]),
    ("eval: min_confidence is strict", [(D + "evaluate.mjs", "ok = a.confidence >= (", "ok = a.confidence > (")]),
    ("eval: unknown rule is skipped (first-match broken)", [(D + "evaluate.mjs", "if (r.v === U) return { resolved: false, needs: r.needs, steps: ctx.steps };", "if (r.v === U) continue;")]),
    ("eval: invalid rule is skipped", [(D + "evaluate.mjs", "if (r.v === I) return { resolved: false, invalid: r.bad, steps: ctx.steps };", "if (r.v === I) continue;")]),
    ("eval: label-test missing_as inverted", [(D + "evaluate.mjs", "return { v: c.missing_as ? T : F, needs: [], bad: [] };", "return { v: c.missing_as ? F : T, needs: [], bad: [] };")]),
    ("eval: noul missing_as ignored", [(D + "evaluate.mjs", 'if (own(c, "noul")) { const op = opOf(c); return { v: cmp(op, c.missing_as, threshold', 'if (own(c, "noul")) { const op = opOf(c); return { v: cmp(op, 1 - c.missing_as, threshold')]),
    ("eval: prob_of missing_as ignored", [(D + "evaluate.mjs", 'if (own(c, "prob_of")) { const op = opOf(c); return { v: cmp(op, c.missing_as, threshold', 'if (own(c, "prob_of")) { const op = opOf(c); return { v: cmp(op, 1 - c.missing_as, threshold')]),
    ("eval: prob_of takes the max, not the sum", [(D + "evaluate.mjs", "s += a.probabilities[l] ?? 0;", "s = Math.max(s, a.probabilities[l] ?? 0);")]),
    ("eval: steps not counted", [(D + "evaluate.mjs", "  ctx.steps++;\n", "")]),
    ("answer: noul above 1 accepted", [(D + "evaluate.mjs", "raw.noul >= 0 && raw.noul <= 1", "raw.noul >= 0")]),
    ("answer: unknown choice label accepted", [(D + "evaluate.mjs", "!labels.includes(raw.choice) || ", "")]),
    ("answer: probability above 1 accepted", [(D + "evaluate.mjs", "v < 0 || v > 1", "v < 0")]),
    ("answer: confidence defaults to 1", [(D + "evaluate.mjs", ": probabilities[raw.choice];", ": 1;")]),
    # validator
    ("validate: unknown keys tolerated", [(D + "validate.mjs", "if (!allowed.includes(k)) errs.push(", "if (false) errs.push(")]),
    ("validate: failing may grant", [(D + "validate.mjs", "grants.includes(ou.decision) && ou.decision !== raw.baseline", "false")]),
    ("validate: failing may never be the baseline when granted", [(D + "validate.mjs", "grants.includes(ou.decision) && ou.decision !== raw.baseline", "grants.includes(ou.decision)")]),
    ("validate: restrictive may overlap grants", [(D + "validate.mjs", "if (restrictive.some((w) => grants.includes(w)))", "if (false)")]),
    ("validate: restrictive may contain the baseline", [(D + "validate.mjs", "if (restrictive.includes(raw.baseline))", "if (false)")]),
    ("validate: unused questions tolerated", [(D + "validate.mjs", "for (const q of qids) if (!used.has(q)) errs.push(", "for (const q of qids) if (false && !used.has(q)) errs.push(")]),
    ("validate: depth cap off by one", [(D + "validate.mjs", "if (depth > LIMITS.depth)", "if (depth > LIMITS.depth + 1)")]),
    ("validate: rule cap off by one", [(D + "validate.mjs", "rules.length > LIMITS.rules)", "rules.length > LIMITS.rules + 1)")]),
    ("validate: node cap loosened", [(D + "validate.mjs", "> LIMITS.nodes_per_rule)", "> LIMITS.nodes_per_rule * 4)")]),
    ("validate: question cap loosened", [(D + "validate.mjs", "qids.length > LIMITS.questions)", "qids.length > LIMITS.questions + 4)")]),
    ("validate: fact cap loosened", [(D + "validate.mjs", "if (keys.length > LIMITS.facts)", "if (keys.length > LIMITS.facts + 5)")]),
    ("validate: baseline not required", [(D + "validate.mjs", "if (!inVocab(raw.baseline))", "if (false)")]),
    ("validate: on_unavailable not required", [(D + "validate.mjs", "if (!isObj(ou)) errs.push(", "if (false) errs.push(")]),
    ("validate: fail mode inverted", [(D + "validate.mjs", 'raw.on_unavailable.decision === raw.baseline ? "open" : "closed"', 'raw.on_unavailable.decision === raw.baseline ? "closed" : "open"')]),
    ("validate: hash depends on key order", [(D + "validate.mjs", "Object.keys(v).sort().map((k) => `${JSON.stringify(k)}", "Object.keys(v).map((k) => `${JSON.stringify(k)}")]),
    ("validate: vocabulary words unchecked", [(D + "validate.mjs", 'typeof w !== "string" || !WORD.test(w))) errs.push(`spec.vocabulary', 'typeof w !== "string")) errs.push(`spec.vocabulary')]),
    ("validate: rule id shape unchecked", [(D + "validate.mjs", 'if (typeof r.id !== "string" || !RULE.test(r.id)) errs.push', 'if (typeof r.id !== "string") errs.push')]),
    ("validate: fact key shape unchecked", [(D + "validate.mjs", "if (!FACT.test(k)) errs.push(`facts: key", "if (false) errs.push(`facts: key")]),
    # core
    ("core: fail mode inverted", [(D + "core.mjs", 'spec.on_unavailable.decision === spec.baseline ? "open" : "closed"', 'spec.on_unavailable.decision !== spec.baseline ? "open" : "closed"')]),
    ("core: decided_by swapped on failure", [(D + "core.mjs", 'decided_by: mode === "open" ? "fail_open" : "fail_closed"', 'decided_by: mode === "open" ? "fail_closed" : "fail_open"')]),
    ("core: failure reason ignores the spec's text", [(D + "core.mjs", "reason: spec.on_unavailable.reason ?? DEFAULT_FAIL_REASON_TEXT", "reason: DEFAULT_FAIL_REASON_TEXT")]),
    ("core: omitted answers tolerated offline", [(D + "core.mjs", "if (omitted.length) return", "if (false) return")]),
    # tool
    ("tool: state strings not redacted", [(D + "tool.mjs", 'if (typeof v === "string") return redact(v);\n    if (typeof v === "boolean" || v === null) return v;', 'if (typeof v === "string") return v;\n    if (typeof v === "boolean" || v === null) return v;')]),
    ("tool: state key shape unchecked", [(D + "tool.mjs", "if (!STATE_KEY.test(k)) {", "if (false) {")]),
    ("tool: state size not checked on the input", [(D + "tool.mjs", "    if (serializedSize(state) > LIMITS.state_chars) return tooBig;\n", "")]),
    ("tool: state size not checked on what is sent", [(D + "tool.mjs", "  if (serializedSize(out) > LIMITS.state_chars) return tooBig;\n", "")]),
    ("tool: question text not redacted", [(D + "tool.mjs", "redactStrings(spec.questions)", "spec.questions")]),
    ("tool: error list not capped", [(D + "validate.mjs", "(errs.length > max ?", "(errs.length > max + 1000 ?")]),
    ("validate: over-cap facts still produce per-key errors", [(D + "validate.mjs", "if (keys.length > LIMITS.facts) return {", "if (false) return {")]),
    ("tool: facts sent to the model", [(D + "tool.mjs", "askWithin(upstream, st.state, redactStrings(spec.questions)", "askWithin(upstream, { ...st.state, ...f.facts }, redactStrings(spec.questions)")]),
    ("tool: fact-only prefilter skipped", [(D + "tool.mjs", "if (pre.resolved) {", "if (false) {")]),
    ("tool: budget is not a hard deadline", [(D + "tool.mjs", "askUpstream(upstream, state, questions, { fetchImpl, timeoutMs: budget, signal: ac.signal }), deadline]);", "askUpstream(upstream, state, questions, { fetchImpl, timeoutMs: budget, signal: ac.signal })]);")]),
    ("tool: timeouts reported as upstream errors", [(D + "tool.mjs", "/timed out|timeout|abort/i", "/nomatch/i")]),
    ("tool: malformed replies reported as upstream errors", [(D + "tool.mjs", "/malformed answers envelope|unparseable response|omitted the answer/i", "/nomatch/i")]),
    ("tool: invalid answer reported with the wrong reason", [(D + "tool.mjs", 'out = failureFor(spec, "invalid_response"); jevStatus = "invalid_response";', 'out = failureFor(spec, "upstream_error"); jevStatus = "invalid_response";')]),
    ("tool: caller bug returns a normal result", [(D + "tool.mjs", "asText(r.payload, r.error === true)", "asText(r.payload, false)")]),
    ("tool: budget cap ignored", [(D + "tool.mjs", "Math.min(MAX_BUDGET_MS, Math.max(100,", "Math.min(MAX_BUDGET_MS * 100, Math.max(100,")]),
    # record.mjs (the one record module shared with the fixed kit tools)
    ("record: a fail reason dropped from the closed list", [(R, '"timeout", "invalid_response", "oversize",', '"timeout", "invalid_response",')]),
    ("record: prefilter not a decided_by value", [(R, '["prefilter", "jev", "fail_open"', '["jev", "fail_open"')]),
    ("record: configured cost mislabelled", [(R, 'cost_source: "configured" };', 'cost_source: "upstream" };')]),
    ("record: correlation id shape open", [(R, "const CORRELATION = /^[A-Za-z0-9_-]{1,64}$/;", "const CORRELATION = /^.{1,200}$/;")]),
    ("record: host shape open", [(R, "const HOST = /^[a-z0-9][a-z0-9._-]{0,31}$/;", "const HOST = /^.{1,200}$/;")]),
    ("record: model shape open", [(R, "const MODEL = /^[A-Za-z0-9][A-Za-z0-9._:\\/-]{0,63}$/;", "const MODEL = /^.*$/;")]),
    ("record: keys reordered", [(R, "    tiers: chosen || recommended ? { chosen, recommended } : null,\n    host: pick(HOST, f.host),", "    host: pick(HOST, f.host),\n    tiers: chosen || recommended ? { chosen, recommended } : null,")]),
    ("record: deriveRecord ignores kit_decide's decision", [(R, 'const ownsDecision = tool === "kit_guard_command" || tool === "kit_decide";', 'const ownsDecision = tool === "kit_guard_command";')]),
    ("record: explicit fail_reason ignored (fail_closed loses its code)", [(R, "FAIL_REASONS.includes(p.fail_reason) ? p.fail_reason : decided_by", "false ? p.fail_reason : decided_by")]),
    ("record: log line key renamed", [(R, '{ kind: "jev.decision", ...record }', '{ event: "jev.decision", ...record }')]),
    ("record: opt-out is case-sensitive", [(R, 'String(env.JEV_DECISION_LOG ?? "").trim().toLowerCase() === "off"', 'env.JEV_DECISION_LOG === "off"')]),
    # eval target and wiring
    ("eval-target: knob params dropped", [(D + "eval-target.mjs", "knobs: params", "knobs: {}")]),
    ("eval-target: example name unchecked", [(D + "eval-target.mjs", '|| !/^[a-z0-9][a-z0-9-]{0,47}$/.test(input.example)', "")]),
    ("wiring: kit_decide not registered", [("server/src/index.mjs", "  registerDecideTool(server, () => currentEnv);\n", "")]),
    ("wiring: doctor expects the old tool count", [("install.sh", "EXPECTED_TOOLS=16", "EXPECTED_TOOLS=15")]),
]


def main():
    tmp = tempfile.mkdtemp(prefix="decide-mutation-")
    survived, killed = [], 0
    try:
        for name, edits in MUTATIONS:
            work = os.path.join(tmp, "w")
            shutil.rmtree(work, ignore_errors=True)
            os.makedirs(os.path.join(work, "server"))
            for item in ["server/src", "server/test", "server/package.json", "examples", "install.sh"]:
                src, dst = os.path.join(ROOT, item), os.path.join(work, item)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("node_modules", "__pycache__"))
                else:
                    shutil.copy(src, dst)
            nm = os.path.join(ROOT, "server", "node_modules")
            if os.path.isdir(nm):
                os.symlink(nm, os.path.join(work, "server", "node_modules"))
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
            try:
                p = subprocess.run(CMD, cwd=os.path.join(work, "server"), capture_output=True, text=True, timeout=240)
                failed = p.returncode != 0
            except subprocess.TimeoutExpired:
                failed = True  # a hang is a failure the suite noticed
            if failed:
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
