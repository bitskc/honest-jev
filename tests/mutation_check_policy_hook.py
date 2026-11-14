#!/usr/bin/env python3
"""Mutation check for the policy hook adapter (openspec add-policy-hook-adapter): the trigger grammar and matcher, the plan
helper, the Python hook's policy path, the omp hook's policy path, and the ledger's policy_version pass-through.

Copies the needed tree to a scratch directory, applies ONE deliberate defect at a time (an exact-once text replacement), runs
the tests that cover that file, and requires them to FAIL. A survivor means a weak test, an equivalent mutant or dead code; a
`BAD MUTATION` means a pattern went stale. The first three entries are no-mutation baselines, one per test command: each suite
must pass there, or every "kill" would be meaningless. The real tree is never modified. Data only: nothing here executes a
string from a test.

    python3 tests/mutation_check_policy_hook.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COPY = ["server/src", "server/test", "server/package.json", "scripts", "hooks", "tests", "examples", "install.sh"]

SERVER = (["node", "--test", "--test-timeout=120000", "test/policy-trigger.test.mjs", "test/policy-hook-plan.test.mjs", "test/policy.test.mjs", "test/policy-cli.test.mjs"], "server")
PY = (["python3", "-W", "ignore", "-m", "unittest", "tests/test_policy_hook.py"], ".")
LEDGER_PY = (["python3", "-W", "ignore", "-m", "unittest", "tests/test_ledger_hook.py", "tests/test_policy_hook.py"], ".")
BUN = (["bun", "test", "tests/policy-hook-omp.test.ts"], ".")

TRG = "server/src/policy/trigger.mjs"
SCH = "server/src/policy/schema.mjs"
MRG = "server/src/policy/merge.mjs"
HLP = "scripts/jev-policy-hook.mjs"
PYH = "hooks/jev_guard_hook.py"
PYL = "hooks/jev_ledger.py"
OMP = "hooks/omp/jev-guard.ts"

MUTATIONS = [
    ("baseline: server suites", [], SERVER),
    ("baseline: python hook suite", [], PY),
    ("baseline: omp hook suite", [], BUN),
    # ── grammar ──
    ("trigger: command words may hold spaces and pattern syntax", [(TRG, "const WORD = /^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/;", "const WORD = /^.{1,40}$/;")], SERVER),
    ("trigger: five command words allowed", [(TRG, "command_words: 4,", "command_words: 5,")], SERVER),
    ("trigger: another tool allowed", [(TRG, 'export const TRIGGER_TOOLS = Object.freeze(["Bash"]);', 'export const TRIGGER_TOOLS = Object.freeze(["Bash", "Read"]);')], SERVER),
    ("trigger: an effect may allow", [(TRG, 'export const EFFECTS = Object.freeze(["ask", "deny"]);', 'export const EFFECTS = Object.freeze(["ask", "deny", "allow"]);')], SERVER),
    ("trigger: a shell source exists", [(TRG, 'export const FACT_SOURCES = Object.freeze(["repo_root", "branch", "gh_pr_target", "gh_pr_review_marker"]);', 'export const FACT_SOURCES = Object.freeze(["repo_root", "branch", "gh_pr_target", "gh_pr_review_marker", "shell"]);')], SERVER),
    ("trigger: marker may be any text", [(TRG, "const MARKER = /^[A-Za-z0-9 ._:/@#-]{1,80}$/;", "const MARKER = /^.{1,80}$/;")], SERVER),
    ("trigger: provider timeout cap raised", [(TRG, "timeout_max_ms: 1500", "timeout_max_ms: 60000")], SERVER),
    ("trigger: provider timeout floor dropped", [(TRG, "timeout_min_ms: 100", "timeout_min_ms: 0")], SERVER),
    ("trigger: a fact no rule reads is accepted", [(TRG, "if (spec && !used.has(name) && !feeders.has(name)) errs.push(", "if (false) errs.push(")], SERVER),
    ("trigger: a provider's input fact must be read by a rule", [(TRG, "if (spec && !used.has(name) && !feeders.has(name)) errs.push(", "if (spec && !used.has(name)) errs.push(")], SERVER),
    ("trigger: target_from may name any fact", [(TRG, 'if (!isObj(ref) || ref.source !== "gh_pr_target") errs.push(', 'if (!isObj(ref)) errs.push(')], SERVER),
    ("trigger: a review provider needs no target", [(TRG, 'if (!isObj(ref) || ref.source !== "gh_pr_target") errs.push(', 'if (typeof src.target_from === "string" && (!isObj(ref) || ref.source !== "gh_pr_target")) errs.push(')], SERVER),
    ("trigger: gh_pr_target offered to any command", [(TRG, 'if (src.source === "gh_pr_target" && !isGhPrMerge) errs.push(', 'if (false) errs.push(')], SERVER),
    ("trigger: effect words need not be in the vocabulary", [(TRG, "if (spec && !spec.vocabulary.includes(word)) errs.push(", "if (false) errs.push(")], SERVER),
    ("trigger: unknown source keys tolerated", [(TRG, "for (const k of Object.keys(src)) if (!SOURCE_KEYS[src.source].includes(k)) errs.push(", "for (const k of []) if (false) errs.push(")], SERVER),
    ("trigger: unknown trigger keys tolerated", [(TRG, "for (const k of Object.keys(t)) if (!TRIGGER_KEYS.includes(k)) errs.push(", "for (const k of []) if (false) errs.push(")], SERVER),
    ("trigger: an unmapped restrictive word allows", [(TRG, 'trigger.effect[w] ?? (spec.grants.includes(w) ? "allow" : "ask")', 'trigger.effect[w] ?? "allow"')], SERVER),
    ("trigger: an ungranted word allows", [(TRG, 'spec.grants.includes(w) ? "allow" : "ask"', '"allow"')], SERVER),
    ("trigger: deny ranks below ask", [(TRG, "export const RANK = Object.freeze({ allow: 0, ask: 1, deny: 2 });", "export const RANK = Object.freeze({ allow: 0, ask: 2, deny: 1 });")], SERVER),
    # ── matching ──
    ("match: the program word is not compared", [(TRG, "if (p !== prog) continue;", "if (false) continue;")], SERVER),
    ("match: subcommand words must be adjacent", [(TRG, "const next = args.indexOf(w, at + 1);", "const next = args[at + 1] === w ? at + 1 : -1;")], SERVER),
    ("match: subcommand words in any order", [(TRG, "const next = args.indexOf(w, at + 1);", "const next = args.indexOf(w);")], SERVER),
    ("match: bash -c bodies are not unwrapped", [(TRG, "const unwrapped = safe(() => unwrapScripts(top, UNWRAP_DEPTH), []);", "const unwrapped = [];")], SERVER),
    ("match: substitutions are not walked", [(TRG, "    return [...segs, ...spans.flatMap((sp) => withSubstitutions(text.slice(sp.bodyStart, sp.bodyEnd), depth + 1))];", "    return segs;")], SERVER),
    ("match: literal folding dropped", [(TRG, "const folded = safe(() => foldLiterals(command), command);", "const folded = command;")], SERVER),
    ("match: wrapper peeling dropped", [(TRG, "const [p, args] = safe(() => resolveCommand(seg), [null, []]);", "const [p, args] = safe(() => { const w = seg.trim().split(/\\s+/); return [w[0], w.slice(1)]; }, [null, []]);")], SERVER),
    ("match: no whitespace fallback for over-long commands", [(TRG, "if (command.length <= TRIGGER_LIMITS.command_chars) {", "if (true) {")], SERVER),
    ("match: a parser failure does not fall back", [(TRG, "const safe = (fn, fallback) => { try { return fn(); } catch { return fallback; } };", "const safe = (fn, fallback) => fn();")], SERVER),
    ("target: PR numbers of any length", [(TRG, "const PR_NUMBER = /^[0-9]{1,9}$/;", "const PR_NUMBER = /^[0-9]{1,30}$/;")], SERVER),
    ("target: --subject does not take a value", [(TRG, 'const GH_MERGE_VALUE_LONG = new Set(["author-email", "body", "body-file", "match-head-commit", "repo", "subject"]);', 'const GH_MERGE_VALUE_LONG = new Set(["author-email", "body", "body-file", "match-head-commit", "repo"]);')], SERVER),
    ("target: --match-head-commit does not take a value", [(TRG, '"body-file", "match-head-commit", "repo", "subject"]);', '"body-file", "repo", "subject"]);')], SERVER),
    ("target: --body-file does not take a value", [(TRG, '"body", "body-file", "match-head-commit"', '"body", "match-head-commit"')], SERVER),
    ("target: -b does not take a value", [(TRG, 'const GH_MERGE_VALUE_SHORT = new Set(["A", "F", "R", "b", "t"]);', 'const GH_MERGE_VALUE_SHORT = new Set(["A", "F", "R", "t"]);')], SERVER),
    ("target: -t does not take a value", [(TRG, 'const GH_MERGE_VALUE_SHORT = new Set(["A", "F", "R", "b", "t"]);', 'const GH_MERGE_VALUE_SHORT = new Set(["A", "F", "R", "b"]);')], SERVER),
    ("target: -R is not a repo flag", [(TRG, 'const GH_MERGE_VALUE_SHORT = new Set(["A", "F", "R", "b", "t"]);', 'const GH_MERGE_VALUE_SHORT = new Set(["A", "F", "b", "t"]);')], SERVER),
    ("target: a boolean flag may carry any =value", [(TRG, 'if (eq >= 0 && !["true", "false"].includes(a.slice(eq + 1))) return AMBIGUOUS;', "")], SERVER),
    ("target: unknown long flags are tolerated", [(TRG, "      } else return AMBIGUOUS;\n      continue;", "      }\n      continue;")], SERVER),
    ("target: unknown short flags are tolerated", [(TRG, "if (!GH_MERGE_VALUE_SHORT.has(c)) return AMBIGUOUS;", "if (!GH_MERGE_VALUE_SHORT.has(c)) continue;")], SERVER),
    ("target: two positionals are accepted", [(TRG, "if (positional.length > 1) return AMBIGUOUS;", "")], SERVER),
    ("target: any repo shape is passed through", [(TRG, "const REPO_SHAPE = /^(?:[A-Za-z0-9][A-Za-z0-9.-]{0,252}\\/)?[A-Za-z0-9][A-Za-z0-9._-]{0,99}\\/[A-Za-z0-9._-]{1,100}$/;", "const REPO_SHAPE = /^.+$/;")], SERVER),
    ("target: any URL shape is passed through", [(TRG, "const PR_URL_SHAPE = /^https:\\/\\/[A-Za-z0-9][A-Za-z0-9.-]{0,252}\\/[A-Za-z0-9][A-Za-z0-9._-]{0,99}\\/[A-Za-z0-9._-]{1,100}\\/pull\\/[0-9]{1,9}$/;", "const PR_URL_SHAPE = /^https?:\\/\\/.+$/;")], SERVER),
    ("target: a URL together with --repo is accepted", [(TRG, "if (PR_URL_SHAPE.test(p) && !repoSeen)", "if (PR_URL_SHAPE.test(p))")], SERVER),
    ("target: --repo without a PR is accepted", [(TRG, "return repoSeen ? AMBIGUOUS : { kind: \"none\" };", "return { kind: \"none\" };")], SERVER),
    ("target: two --repo flags are accepted", [(TRG, 'if (name === "repo") { if (repoSeen) return AMBIGUOUS; repoSeen = true; repo = take(v); }', 'if (name === "repo") { repoSeen = true; repo = take(v); }')], SERVER),
    ("target: a branch name is taken as the PR", [(TRG, "return AMBIGUOUS; // a branch name,", 'return { kind: "none" }; // a branch name,')], SERVER),
    ("target: the repo flag value is not shape-checked", [(TRG, "if (repoSeen && !(typeof repo === \"string\" && REPO_SHAPE.test(repo))) return AMBIGUOUS;", "")], SERVER),
    ('hazard: cd is not a hazard', [(TRG, '  /(?:^|[^A-Za-z0-9_])(?:cd|pushd|popd|chdir)(?![A-Za-z0-9_])/,', "  /(?!)/,")], SERVER),
    ('hazard: GH_ names are not a hazard', [(TRG, '  /GH_|GITHUB_ENTERPRISE|GIT_DIR|GIT_WORK_TREE|GIT_CONFIG|--git-dir/,', "  /(?!)/,")], SERVER),
    ('hazard: -C / --chdir is not a hazard', [(TRG, '  /(?:^|\\s)(?:-C|--chdir|--cwd)(?![A-Za-z0-9_-])/,', "  /(?!)/,")], SERVER),
    ('hazard: git remote / git config is not a hazard', [(TRG, '  /(?:^|[^A-Za-z0-9_])git(?![A-Za-z0-9_-])[^;&|\\n]*(?:^|[^A-Za-z0-9_])(?:remote|config)(?![A-Za-z0-9_])/,', "  /(?!)/,")], SERVER),
    ('hazard: gh repo set-default is not a hazard', [(TRG, '  /(?:^|[^A-Za-z0-9_-])set-default(?![A-Za-z0-9_-])/,', "  /(?!)/,")], SERVER),
    ('hazard: export / eval / source is not a hazard', [(TRG, '  /(?:^|[^A-Za-z0-9_-])(?:export|declare|typeset|readonly|eval|source)(?![A-Za-z0-9_-])/,', "  /(?!)/,")], SERVER),
    ('hazard: a dot-sourced file is not a hazard', [(TRG, '  /(?:^|[;&|(\\n]\\s*)\\.\\s+\\S/,', "  /(?!)/,")], SERVER),
    ('hazard: xargs / parallel / find -exec is not a hazard', [(TRG, '  /(?:^|[^A-Za-z0-9_-])(?:xargs|parallel)(?![A-Za-z0-9_-])|(?:^|\\s)-exec(?:dir)?(?![A-Za-z0-9_-])/,', "  /(?!)/,")], SERVER),
    ("hazard: an env name built from an expansion is not a hazard", [(TRG, "  /(?:^|[^A-Za-z0-9_-])env(?![A-Za-z0-9_-])[^;&|\\n]*[$`]|(?:^|[\\s;&|(])[A-Za-z_0-9]*[$`][^\\s=]*=/, // an environment name or value built from an expansion", "  /(?!)/,")], SERVER),
    ("hazard: split quotes are not joined before the scan", [(TRG, "const texts = [command, command.replace(/['\"\\\\]/g, \"\")];", "const texts = [command];")], SERVER),
    ("match: a depth limit does not fall back", [(TRG, "    if (!walked.truncated) return { ...none, segment_count: walked.segments.length };", "    return { ...none, segment_count: walked.segments.length };")], SERVER),
    ("match: the substitution depth is tiny", [(TRG, "const SUBST_DEPTH = 6;", "const SUBST_DEPTH = 2;")], SERVER),
    ("match: truncation is never reported", [(TRG, "if (depth >= SUBST_DEPTH) { if (spans.length) st.truncated = true; return segs; }", "if (depth >= SUBST_DEPTH) return segs;")], SERVER),
    ("match: unwrap truncation is never reported", [(TRG, "if (safe(() => unwrapScripts(top, UNWRAP_DEPTH + 1), []).length > unwrapped.length) st.truncated = true;", "")], SERVER),
    ("match: the fallback ignores substitution punctuation", [(TRG, 'const toks = command.replace(/[$()`;&|<>{}"\'\\\\]/g, " ").split(/\\s+/).filter(Boolean);', "const toks = command.split(/\\s+/).filter(Boolean);")], SERVER),
    ("match: a fallback match is not marked as such", [(TRG, "return hits.length ? { matched: true, hits, segment_count: 0, fallback: true } : none;", "return hits.length ? { matched: true, hits, segment_count: 0, fallback: false } : none;")], SERVER),
    # ── schema and merge ──
    ("schema: a bad trigger does not invalidate the document", [(SCH, "if (!t.ok) { errs.push(...t.errors); return; }", "if (false) { errs.push(...t.errors); return; }")], SERVER),
    ("schema: the validated trigger is dropped", [(SCH, "...(trig ? { trigger: trig } : {})", "")], SERVER),
    ("merge: the user layer's trigger is dropped", [(MRG, "lifted: [], trigger: d.trigger ?? null", "lifted: [], trigger: null")], SERVER),
    ("merge: a lower layer's trigger is not reported", [(MRG, "        lift(have, d, layer.origin, notes);\n        if (d.trigger) notes.push(`${layer.origin} layer, class", "        lift(have, d, layer.origin, notes);\n        if (false) notes.push(`${layer.origin} layer, class")], SERVER),
    ("merge: a lower-layer-only class's trigger is not reported", [(MRG, "          if (d.trigger) notes.push(`${layer.origin} layer, class", "          if (false) notes.push(`${layer.origin} layer, class")], SERVER),
    # ── plan helper ──
    ("plan: triggers are read from every layer", [(HLP, 'const userOnly = loadLayers(p, "user");', 'const userOnly = loadLayers(p, "all");')], SERVER),
    ("plan: a broken user layer is not reported", [(HLP, "if (userOnly.problems.length) return { ok: false, problem: \"user_layer_invalid\" };", "")], SERVER),
    ("plan: a second matching class is not counted", [(HLP, "extra: matches.length - 1,", "extra: 0,")], SERVER),
    ("plan: a skipped provider is reported as a failure", [(HLP, 'if (kind === "skipped") continue;', "")], SERVER),
    ("plan: provider failures are swallowed", [(HLP, "providerFailure = providerFailure ?? { name:", "providerFailure = null; void { name:")], SERVER),
    ("plan: a provider failure maps to the wrong code", [(HLP, 'const CODE = { missing: "client_config", timeout: "client_timeout",', 'const CODE = { missing: "client_network", timeout: "client_network",')], SERVER),
    ("plan: the failure effect is allow", [(HLP, "on_unavailable: { decision: od, effect: effects[od], mode: failMode(spec) },", 'on_unavailable: { decision: od, effect: "allow", mode: failMode(spec) },')], SERVER),
    ("plan: facts no rule reads are forwarded", [(HLP, "if (v !== undefined && read.has(k)) facts[k] = v;", "if (v !== undefined) facts[k] = v;")], SERVER),
    ("plan: the state text is not capped", [(HLP, "const STATE_TEXT_CHARS = 4000;", "const STATE_TEXT_CHARS = 400000;")], SERVER),
    ("plan: gh is not told the PR number", [(HLP, 'if (target.kind === "number") return ["pr", "view", String(target.n),', 'if (target.kind === "number") return ["pr", "view",')], SERVER),
    ("plan: gh is not told the repository", [(HLP, '...(target.repo ? ["--repo", target.repo] : []), ...tail];', "...tail];")], SERVER),
    ("plan: a URL target is dropped", [(HLP, 'if (target.kind === "url") return ["pr", "view", target.url, ...tail];', 'if (target.kind === "url") return ["pr", "view", ...tail];')], SERVER),
    ("plan: an ambiguous target is guessed as the current branch", [(HLP, "  return null;\n}", '  return ["pr", "view", ...tail];\n}')], SERVER),
    ("plan: an ambiguous target reports the wrong failure", [(HLP, 'if (argLists.some((a) => !a)) throw { kind: "input" };', 'if (argLists.some((a) => !a)) throw { kind: "error" };')], SERVER),
    ("targets: a whitespace-scan or depth-limited match is trusted to name a PR", [(TRG, "if (!m || !m.matched || m.fallback || targetHazard(command) ||", "if (!m || !m.matched || targetHazard(command) ||")], SERVER),
    ("targets: hazards in the command are ignored", [(TRG, "if (!m || !m.matched || m.fallback || targetHazard(command) ||", "if (!m || !m.matched || m.fallback ||")], SERVER),
    ("targets: a merge that names no PR is trusted wherever it stands", [(TRG, 'return t.kind === "none" && !sole ? AMBIGUOUS : t;', "return t;")], SERVER),
    ("targets: sole means one merge, however much else runs", [(TRG, "const sole = m.hits.length === 1 && m.segment_count === 1;", "const sole = m.hits.length === 1;")], SERVER),
    ("targets: any number of merges is read", [(TRG, " || m.hits.length > MAX_MERGE_TARGETS) return [AMBIGUOUS];", ") return [AMBIGUOUS];")], SERVER),
    ("targets: the merge cap is large", [(TRG, "export const MAX_MERGE_TARGETS = 3;", "export const MAX_MERGE_TARGETS = 30;")], SERVER),
    ("targets: only the first merge is returned", [(TRG, "  return m.hits.map((h) => {", "  return m.hits.slice(0, 1).map((h) => {")], SERVER),
    ("match: only the first matching segment is reported", [(TRG, "      if (idx) hits.push(without(args, idx));", "      if (idx && !hits.length) hits.push(without(args, idx));")], SERVER),
    ("match: the segment count is always one", [(TRG, "return { matched: true, hits, segment_count: walked.segments.length, fallback: walked.truncated };", "return { matched: true, hits, segment_count: 1, fallback: walked.truncated };")], SERVER),
    ("match: a depth limit with hits found is not a fallback", [(TRG, "return { matched: true, hits, segment_count: walked.segments.length, fallback: walked.truncated };", "return { matched: true, hits, segment_count: walked.segments.length, fallback: false };")], SERVER),
    ("match: a fallback hit runs to the end of the command", [(TRG, "toks.slice(at + 1, next < 0 ? undefined : next);", "toks.slice(at + 1);")], SERVER),
    ("plan: one unreadable merge is dropped instead of failing the answer", [(HLP, "  if (argLists.some((a) => !a)) throw { kind: \"input\" };", "  if (!argLists.length) throw { kind: \"input\" };\n  for (let i = argLists.length - 1; i >= 0; i--) if (!argLists[i]) argLists.splice(i, 1);")], SERVER),
    ("plan: the answer is reviewed when any merge is", [(HLP, "return answers.every(Boolean);", "return answers.some(Boolean);")], SERVER),
    ("plan: only the first merge is asked about", [(HLP, "const argLists = targets.map(viewArgs);", "const argLists = targets.slice(0, 1).map(viewArgs);")], SERVER),
    ("plan: the merge matched by the helper is only the first segment's", [(HLP, "    if (m.matched) matches.push({ d, m });", "    if (m.matched) matches.push({ d, m: { ...m, hits: m.hits.slice(0, 1) } });")], SERVER),
    ("plan: the marker is matched case-insensitively", [(HLP, "bodies.some((b) => b.includes(src.marker))", "bodies.some((b) => b.toLowerCase().includes(src.marker.toLowerCase()))")], SERVER),
    ("plan: the provider timeout is ignored", [(HLP, "timeoutMs: src.timeout_ms ?? TRIGGER_LIMITS.timeout_default_ms", "timeoutMs: 600000")], SERVER),
    ("plan: processes are started through a shell", [(HLP, "windowsHide: true, encoding: \"utf8\" }, (err, stdout) => {", "windowsHide: true, encoding: \"utf8\", shell: true }, (err, stdout) => {")], SERVER),
    ("plan: the repo_root fact falls back to the cwd", [(HLP, 'for (const [name] of byKind("repo_root")) values[name] = gitRoot;', 'for (const [name] of byKind("repo_root")) values[name] = repoRoot;')], SERVER),
    ("plan: a relative cwd is accepted", [(HLP, 'typeof input.cwd !== "string" || !input.cwd.startsWith("/")', 'typeof input.cwd !== "string"')], SERVER),
    ("plan: another tool is accepted", [(HLP, 'input.tool !== "Bash" || typeof input.command', 'typeof input.command')], SERVER),
    ("plan: the parsed JSON is not shape-checked", [(HLP, "!Array.isArray(doc.comments) || !Array.isArray(doc.reviews)", "false")], SERVER),
    # ── python hook ──
    ("py hook: the policy decision is ignored", [(PYH, "final = g.effect if RANK[g.effect] >= RANK[p.effect] else p.effect", "final = g.effect")], PY),
    ("py hook: the weaker decision wins", [(PYH, "final = g.effect if RANK[g.effect] >= RANK[p.effect] else p.effect", "final = g.effect if RANK[g.effect] <= RANK[p.effect] else p.effect")], PY),
    ("py hook: the policy ledger row is not written", [(PYH, "    g.write()\n    p.write()\n", "    g.write()\n")], PY),
    ("py hook: the guard ledger row is not written", [(PYH, "    g.write()\n    p.write()\n", "    p.write()\n")], PY),
    ("py hook: the policy path runs without a trigger", [(PYH, "if policy_input is not None and policy_has_trigger():", "if policy_input is not None:")], PY),
    ("py hook: the opt-in gate follows symlinks and reads any size", [(PYH, "if not stat_is_regular(st) or st.st_size > POLICY_LAYER_MAX:", "if False:")], PY),
    ("py hook: a provider failure is ignored", [(PYH, 'if plan.get("provider_failure"):', "if False:")], PY),
    ("py hook: a second matching class is not asked about", [(PYH, 'if plan.get("extra"):', "if False:")], PY),
    ("py hook: shadow mode enforces the policy", [(PYH, 'if shadow and effect != "allow":', "if False:")], PY),
    ("py hook: a server rejection is treated as an outage", [(PYH, '        except (ServerRejected, RedirectRefused) as e:\n            return done("ask"', '        except ZeroDivisionError as e:\n            return done("ask"')], PY),
    ("py hook: an outage always asks", [(PYH, 'eff = un.get("effect") if un.get("effect") in RANK else "ask"', 'eff = "ask"')], PY),
    ("py hook: an outage always allows", [(PYH, 'eff = un.get("effect") if un.get("effect") in RANK else "ask"', 'eff = "allow"')], PY),
    ("py hook: the Worker is not told its budget", [(PYH, 'call["budget_ms"] = max(300, int(remaining * 1000) - 300)', "pass")], PY),
    ("py hook: the policy deadline is unclamped", [(PYH, "return min(4.0, max(1.0, v)) if v == v else 3.0", "return v if v == v else 3.0")], PY),
    ("py hook: the runtime is node only", [(PYH, 'return shutil.which("node") or shutil.which("bun")', 'return shutil.which("node")')], PY),
    ("py hook: no notice when the helper cannot run", [(PYH, '''            return Outcome("allow", row=dict(decision="allow", decided_by="fail_open", fail_reason=code, enforced=True), tool="kit_decide",\n                           notice=POLICY_NOTICE if MODE != "shadow" and policy_gate_may_be_closed() else None)''', '''            return Outcome("allow", row=dict(decision="allow", decided_by="fail_open", fail_reason=code, enforced=True), tool="kit_decide")''')], PY),
    ("py hook: the notice is shown in shadow mode", [(PYH, 'fail_reason="client_timeout", enforced=True), tool="kit_decide",\n            notice=POLICY_NOTICE if MODE != "shadow" and policy_gate_may_be_closed() else None)', 'fail_reason="client_timeout", enforced=True), tool="kit_decide",\n            notice=POLICY_NOTICE if policy_gate_may_be_closed() else None)')], PY),
    ("py hook: a fail-closed class is never detected", [(PYH, "                    closed = True\n        return closed", "                    closed = False\n        return closed")], PY),
    ("py hook: an unreadable layer counts as open", [(PYH, "    except Exception:\n        return True\n\n\ndef policy_runtime", "    except Exception:\n        return False\n\n\ndef policy_runtime")], PY),
    ("py hook: a layer with non-list decisions counts as open", [(PYH, "        if not isinstance(decisions, list):\n            return True", "        if not isinstance(decisions, list):\n            return False")], PY),
    ("py hook: an open class counts as closed", [(PYH, 'or un.get("decision") != d.get("baseline"):', "or False:")], PY),
    ("py hook: the notice is not sent to the user", [(PYH, '        out["systemMessage"] = notice\n', "")], PY),
    ("py hook: the notice is dropped when the guard asks", [(PYH, "    notice = p.notice or g.notice", "    notice = (p.notice or g.notice) if final == \"allow\" else None")], PY),
    ("py hook: no helper means no ledger row", [(PYH, 'return Outcome("allow", row=dict(decision="allow", decided_by="fail_open", fail_reason=code, enforced=True), tool="kit_decide",\n                           notice=POLICY_NOTICE if MODE != "shadow" and policy_gate_may_be_closed() else None)', 'return Outcome("allow")')], PY),
    ("py hook: the policy row is written as the guard's tool", [(PYH, '            return Outcome(effect, reason, reply=reply, row=row, tool="kit_decide")', "            return Outcome(effect, reason, reply=reply, row=row)")], PY),
    ("py hook: the helper is run through a shell", [(PYH, "r = subprocess.run([node, helper, \"plan\"], input=json.dumps(event_input).encode(), capture_output=True, timeout=budget)", "r = subprocess.run(\"%s %s plan\" % (node, helper), shell=True, input=json.dumps(event_input).encode(), capture_output=True, timeout=budget)")], PY),
    ("py hook: the plan's policy_version is not used", [(PYH, "decision=word, policy_version=pv)", "decision=word)")], PY),
    ("py hook: the reason omits the policy", [(PYH, "        if p.effect == final and p.reason:\n            parts.append(p.reason)\n", "")], PY),
    # ── ledger writers ──
    ("py ledger: policy_version may be any text", [(PYL, '_POLICY_VERSION = re.compile(r"^[0-9a-f]{12}$")', '_POLICY_VERSION = re.compile(r"^.{1,64}$")')], LEDGER_PY),
    ("py ledger: the record's policy_version wins over the plan's", [(PYL, "policy_version if policy_version is not None else r.get(\"policy_version\")", "r.get(\"policy_version\") if r.get(\"policy_version\") is not None else policy_version")], PY),
    # ── omp hook ──
    ("omp hook: policy_version may be any text", [(OMP, "const POLICY_V = /^[0-9a-f]{12}$/;", "const POLICY_V = /^.{1,64}$/;")], BUN),
    ("omp hook: a non-triggering command still fails open", [(OMP, "if (plan.triggered !== true) return null;", "if (false) return null;")], BUN),
    ("omp hook: a provider failure is ignored", [(OMP, 'if (plan.provider_failure && typeof plan.provider_failure === "object") {', "if (false) {")], BUN),
    ("omp hook: a second matching class is not asked about", [(OMP, 'if (typeof plan.extra === "number" && plan.extra > 0) {', "if (false) {")], BUN),
    ("omp hook: a server rejection is treated as an outage", [(OMP, 'if (res.kind === "rejected") {', "if (false) {")], BUN),
    ("omp hook: shadow mode enforces the policy", [(OMP, 'const pe: Effect = shadow() || !pol ? "allow" : pol.effect;', 'const pe: Effect = !pol ? "allow" : pol.effect;')], BUN),
    ("omp hook: the guard's stricter decision is lost", [(OMP, "if (pRank === 0 || gRank > pRank) return", "if (pRank === 0) return")], BUN),
    ("omp hook: the policy's stricter decision is lost", [(OMP, "if (pRank > gRank) return pe ===", "if (false) return pe ===")], BUN),
    ("omp hook: the opt-in gate matches any layer text", [(OMP, "return text !== null && text.includes('\"trigger\"');", "return text !== null;")], BUN),
    ("omp hook: the opt-in gate follows symlinks", [(OMP, "constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK", "constants.O_RDONLY | constants.O_NONBLOCK")], BUN),
    ("omp hook: the policy deadline is unclamped", [(OMP, "return Math.min(4, Math.max(1, Number.isFinite(s) ? s : 3)) * 1000;", "return (Number.isFinite(s) ? s : 3) * 1000;")], BUN),
    ("omp hook: the helper runs in a shell", [(OMP, 'const child = execFile(runtime, [helper, "plan"], { timeout: timeoutMs,', 'const child = execFile(runtime, [helper, "plan"], { shell: true, timeout: timeoutMs,')], BUN),
    ("omp hook: the plan's policy_version is not used", [(OMP, "policyVersion: pv ?? undefined })", "policyVersion: undefined })")], BUN),
    ("omp hook: the runtime is node from PATH only", [(OMP, "  return onPath(\"bun\");\n}", "  return null;\n}")], BUN),
    ("omp hook: this process is never reused when it is node", [(OMP, 'if (/^node(js)?(\\.exe)?$/.test(base)) return execPath;', "")], BUN),
    ("omp hook: bun is not reused when node is absent", [(OMP, 'if (/^bun(\\.exe)?$/.test(base)) return execPath;', "")], BUN),
    ("omp hook: node on PATH is not tried", [(OMP, 'const node = onPath("node");\n  if (node) return node;', "")], BUN),
    ("omp hook: no notice when the helper cannot run", [(OMP, 'return !shadow() && policyGateMayBeClosed(process.env, cwd) ? { effect: "allow", reason: "", rowId: null, notice: POLICY_NOTICE } : null;\n    };', "return null;\n    };")], BUN),
    ("omp hook: the notice is shown in shadow mode", [(OMP, 'return !shadow() && policyGateMayBeClosed(process.env, cwd) ? { effect: "allow", reason: "", rowId: null, notice: POLICY_NOTICE } : null;\n    };', 'return policyGateMayBeClosed(process.env, cwd) ? { effect: "allow", reason: "", rowId: null, notice: POLICY_NOTICE } : null;\n    };')], BUN),
    ("omp hook: the notice is never delivered", [(OMP, "if (pol?.notice) { // for the user", "if (false) { // for the user")], BUN),
    ("omp hook: a layer with non-list decisions counts as open", [(OMP, "if (!Array.isArray(doc.decisions)) return true;", "if (!Array.isArray(doc.decisions)) return false;")], BUN),
    ("omp hook: an unreadable layer counts as open", [(OMP, "  } catch { return true; }\n}", "  } catch { return false; }\n}")], BUN),
    ("omp hook: a fail-closed class is never detected", [(OMP, "un.decision !== d.baseline) closed = true;", "un.decision !== d.baseline) closed = false;")], BUN),
    ("omp hook: an outage always allows", [(OMP, "const effect = asEffect(od.effect);\n      return { effect, reason: `${tag()}: ${why}`", 'const effect: Effect = "allow";\n      return { effect, reason: `${tag()}: ${why}`')], BUN),
]


def main():
    tmp = tempfile.mkdtemp(prefix="jev-mutation-")
    survived, killed, bad_mutations = [], 0, []
    try:
        for name, edits, (cmd, sub) in MUTATIONS:
            work = os.path.join(tmp, "w")
            shutil.rmtree(work, ignore_errors=True)
            os.makedirs(os.path.join(work, "server"))
            for item in COPY:
                src, dst = os.path.join(ROOT, item), os.path.join(work, item)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("node_modules", "__pycache__"))
                else:
                    shutil.copy2(src, dst)
            nm = os.path.join(ROOT, "server", "node_modules")
            if os.path.isdir(nm):
                os.symlink(os.path.realpath(nm), os.path.join(work, "server", "node_modules"))
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
                bad_mutations.append(name)
                continue
            try:
                p = subprocess.run(cmd, cwd=os.path.join(work, sub), capture_output=True, text=True, timeout=600)
                failed = p.returncode != 0
            except subprocess.TimeoutExpired:
                p, failed = None, True
            if not edits:
                if failed:
                    print("BASELINE RED: %s fails with no mutation applied, so every 'kill' would be meaningless\n%s" % (name, ((p.stdout + p.stderr)[-1500:] if p else "timed out")))
                    return 2
                print("baseline green: %s" % name)
                continue
            if failed:
                killed += 1
                print("KILLED   %s" % name)
            else:
                survived.append(name)
                print("SURVIVED %s" % name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n = sum(1 for m in MUTATIONS if m[1])
    print("\n%d mutations, %d killed, %d survived, %d BAD MUTATION" % (n, killed, len(survived), len(bad_mutations)))
    return 1 if survived or bad_mutations else 0


if __name__ == "__main__":
    sys.exit(main())
