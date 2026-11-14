#!/usr/bin/env python3
"""Mutation check for policy layers (server/src/policy, the class path of kit_decide, scripts/jev-policy.mjs). Copies
the server sources and tests, scripts, examples and install.sh to a scratch directory, applies one deliberate defect at a
time and requires the policy and decide tests to FAIL. A surviving mutation means no test can catch that defect, and a
`BAD MUTATION (pattern count N)` means a pattern went stale. The real tree is never modified. Data only: nothing here
executes a string from a policy or a test.

    python3 tests/mutation_check_policy.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CMD = ["node", "--test", "--test-timeout=60000", "test/policy.test.mjs", "test/policy-cli.test.mjs", "test/decide-tool.test.mjs", "test/decide-core.test.mjs"]
P = "server/src/policy/"
T = "server/src/decide/tool.mjs"
CLI = "scripts/jev-policy.mjs"

# (name, [(file, old, new), ...]); `old` must occur exactly once in `file`.
MUTATIONS = [
    ("baseline: no mutation, the suite must pass", []),
    # merge: tighten-only
    ("merge: a lower layer may add any decision (restrictive check off)", [(P + "merge.mjs", "if (!eff.restrictive.includes(rule.decision)) return", "if (false) return")]),
    ("merge: a lower layer may ask a new question", [(P + "merge.mjs", "if (q) return `it asks question", "if (false) return `it asks question")]),
    ("merge: a lower layer may read a new fact", [(P + "merge.mjs", "if (f) return `it reads fact", "if (false) return `it reads fact")]),
    ("merge: a spec with no restrictive set accepts rules", [(P + "merge.mjs", "if (eff.restrictive.length === 0) {", "if (false) {")]),
    ("merge: a lifted rule may reuse an existing rule id", [(P + "merge.mjs", 'if (have.has(rule.id)) return "its id', 'if (false) return "its id')]),
    ("merge: lifted rules appended instead of prepended", [(P + "merge.mjs", "rules: [...taken, ...eff.rules] });\n  if (!merged.ok)", "rules: [...eff.rules, ...taken] });\n  if (!merged.ok)")]),
    ("merge: layers are not ordered user first", [(P + "merge.mjs", "  parsed.sort((a, b) => ORIGINS.indexOf(a.origin) - ORIGINS.indexOf(b.origin));\n", "")]),
    ("merge: a lower layer replaces a user class", [(P + "merge.mjs", "lift(have, d, layer.origin, notes);", "classes.set(d.spec.id, { spec: d.spec, examples: d.examples, facts: d.facts_used, origins: [layer.origin], lifted: [] });")]),
    ("merge: duplicate origins accepted", [(P + "merge.mjs", "if (seen.has(origin)) {", "if (false) {")]),
    ("merge: unknown origins accepted", [(P + "merge.mjs", "if (!ORIGINS.includes(origin)) {", "if (false) {")]),
    ("merge: over-cap layers accepted", [(P + "merge.mjs", "if (total > POLICY_LIMITS.total_bytes)", "if (false)")]),
    ("merge: identical copied rules reported as dropped", [(P + "merge.mjs", "if (twin && canonicalJson(twin) === canonicalJson(rule)) continue;\n", "")]),
    ("merge: ignored fields are not reported", [(P + "merge.mjs", "if (rest.length) notes.push(", "if (false) notes.push(")]),
    ("version: policy_version no longer the effective spec's hash", [(P + "merge.mjs", "export const policyVersion = (entry) => hash12(entry.spec);", "export const policyVersion = (entry) => hash12({ id: entry.spec.id });")]),
    # schema
    ("schema: unknown top-level keys tolerated", [(P + "schema.mjs", 'if (!["v", "decisions"].includes(k))', "if (false)")]),
    ("schema: version not checked", [(P + "schema.mjs", "if (doc.v !== 1)", "if (false)")]),
    ("schema: a failing example does not reject the layer", [(P + "schema.mjs", "if (!c.ok) { errs.push(...c.errors); return; }", "if (false) { errs.push(...c.errors); return; }")]),
    ("schema: duplicate class ids allowed", [(P + "schema.mjs", "if (ids.has(v.spec.id))", "if (false)")]),
    ("schema: oversized layer text accepted", [(P + "schema.mjs", "if (byteLength(text) > POLICY_LIMITS.total_bytes)", "if (false)")]),
    ("schema: layer size counted in characters", [(P + "schema.mjs", "if (byteLength(text) > POLICY_LIMITS.total_bytes)", "if (text.length > POLICY_LIMITS.total_bytes)")]),
    # examples
    ("examples: a rule needs no example", [(P + "examples.mjs", "if (!passing.some((r) => r.got.rule_id === rule.id))", "if (false)")]),
    ("examples: the default may be 'reached' by the failure path", [(P + "examples.mjs", '(r.got.decided_by === "prefilter" || r.got.decided_by === "jev")', "true")]),
    ("examples: a failing example is tolerated", [(P + "examples.mjs", "if (!r.ok) errors.push(", "if (false) errors.push(")]),
    ("examples: decided_by never compared", [(P + "examples.mjs", "(want.decided_by === undefined || got.decided_by === want.decided_by)", "true")]),
    ("examples: identical-condition lint off", [(P + "examples.mjs", "if (seen.has(key)) errors.push(", "if (false) errors.push(")]),
    ("examples: answers for unknown questions allowed", [(P + "examples.mjs", "if (!Object.hasOwn(spec.questions, q))", "if (false)")]),
    ("examples: example facts unchecked", [(P + "examples.mjs", "if (!f.ok) errs.push(...f.errors.map", "if (false) errs.push(...f.errors.map")]),
    ("examples: missing examples tolerated", [(P + "examples.mjs", "if (!Array.isArray(examples) || examples.length === 0) return", "if (!Array.isArray(examples)) return")]),
    # validate (shared)
    ("validate: description key emitted when absent (rebuilt specs fail)", [("server/src/decide/validate.mjs", '...(own(raw, "description") ? { description: raw.description } : {})', "description: raw.description")]),
    # tool: class resolution
    ("tool: class and spec together accepted", [(T, "if (hasSpec === hasClass)", "if (!hasSpec && !hasClass)")]),
    ("tool: layers with an inline spec accepted", [(T, "if (hasSpec && input.policy_layers !== undefined)", "if (false)")]),
    ("tool: class id shape unchecked", [(T, "if (!isClassId(input.class))", "if (false)")]),
    ("tool: over-cap layers accepted", [(T, "if (merged.error) return bad(", "if (false) return bad(")]),
    ("tool: policy_version not recorded", [(T, "correlation_id: input.correlation_id, policy_version: policyVersion,", "correlation_id: input.correlation_id,")]),
    ("tool: merge notes not reported", [(T, "notes: [...mergeNotes, ...notes],", "notes,")]),
    ("tool: tightened_by not reported", [(T, "tightened_by: policy.lifted", "tightened_by: []")]),
    ("tool: unknown class is not an error result", [(T, 'return { error: true, payload: { tool: "kit_decide", error: "unknown_class"', 'return { payload: { tool: "kit_decide", error: "unknown_class"')]),
    ("record: policy_version shape open", [("server/src/ledger/record.mjs", "const POLICY_VERSION = /^[0-9a-f]{12}$/;", "const POLICY_VERSION = /^.*$/;")]),
    # CLI
    ("cli: user layer written without --yes", [(CLI, 'if (origin === "user" && !o.yes) {', "if (false) {")]),
    ("cli: replace without a version bump", [(CLI, "if (!(Number.isInteger(spec.version) && spec.version > decisions[at].version))", "if (false)")]),
    ("cli: replace without --replace", [(CLI, "if (!o.replace) {", "if (false) {")]),
    ("cli: an invalid existing layer is overwritten", [(CLI, "if (!parsed.ok) { out.err(`the existing", "if (false) { out.err(`the existing")]),
    ("cli: symlinked layer files are read", [(CLI, '  if (st.isSymbolicLink()) return { exists: true, error: "is a symlink: refusing to read it" };\n', "")]),
    ("cli: oversized layer files are read", [(CLI, "if (st.size > POLICY_LIMITS.total_bytes) return", "if (false) return")]),
    ("cli: args forwards layers that failed validation", [(CLI, '${v.errors.join("; ")}`); if (origin === "user") userBroken = true; continue; }', '${v.errors.join("; ")}`); if (origin === "user") userBroken = true; }')]),
    ("cli: add overwrites in place instead of atomically", [(CLI, "fd = openSync(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, mode);", "fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC, mode);")]),
    ("cli: init writes the user layer world-readable", [(CLI, "writeAtomic(path, stringify({ v: 1, decisions: [] }), origin === \"user\" ? 0o600 : 0o644, origin === \"user\" ? 0o700 : 0o755);", "writeAtomic(path, stringify({ v: 1, decisions: [] }), 0o644, 0o755);")]),
    ("cli: args ignores the call cap", [(CLI, "if (total > POLICY_LIMITS.total_bytes) {", "if (false) {")]),
    ("cli: add ignores the call cap", [(CLI, "if (pre.error) { out.err(`NOT WRITTEN:", "if (false) { out.err(`NOT WRITTEN:")]),
    ("cli: an unknown class passes args", [(CLI, "if (!m.classes.has(pos[0])) {", "if (false) {")]),
    ("cli: the repo layer may be the user layer's file", [(CLI, 'if (resolveReal(p.repo) === resolveReal(p.user)) return "the repo layer path resolves to the user layer file";', 'if (false) return "x";')]),
    ("cli: a symlinked directory under the repo root is followed", [(CLI, "try { if (lstatSync(cur).isSymbolicLink()) return `a directory in the repo layer path (${seg}) is a symlink`; } catch { break; }", "try { if (false) return 'x'; } catch { break; }")]),
    ("cli: an existing file's mode is reset on replace", [(CLI, "writeAtomic(target, text, cur.mode ?? (origin === \"user\" ? 0o600 : 0o644), origin === \"user\" ? 0o700 : 0o755);", "writeAtomic(target, text, origin === \"user\" ? 0o600 : 0o644, origin === \"user\" ? 0o700 : 0o755);")]),
    ("cli: the umask narrows the preserved mode", [(CLI, "    fchmodSync(fd, mode); // openSync's mode is narrowed by the umask; the file keeps exactly the mode it had\n", "")]),
    ("cli: args builds a call with a broken user file", [(CLI, 'if (userBroken) { out.err("the user layer is invalid or unreadable: refusing to build a call.', 'if (false) { out.err("the user layer is invalid or unreadable: refusing to build a call.')]),
    ("cli: test runs with a broken user file", [(CLI, 'if (userBroken) { out.err("the user layer is invalid or unreadable: not testing', 'if (false) { out.err("the user layer is invalid or unreadable: not testing')]),
    ("cli: list exits 0 with a broken user file", [(CLI, "user_layer_broken: userBroken })); return userBroken ? 1 : 0; }", "user_layer_broken: userBroken })); return 0; }")]),
    ("cli: a user file that fails to read is not 'broken'", [(CLI, '${r.error}`); if (origin === "user") userBroken = true; continue; }', '${r.error}`); continue; }')]),
    ("cli: an invalid user file is not 'broken'", [(CLI, '${v.errors.join("; ")}`); if (origin === "user") userBroken = true; continue; }', '${v.errors.join("; ")}`); continue; }')]),
    ("cli: args totals layers in characters, not bytes", [(CLI, "layers.reduce((n, l) => n + byteLength(l.text), 0)", "layers.reduce((n, l) => n + l.text.length, 0)")]),
    ("cli: example names printed unbounded", [(CLI, 'out.log(`${r.ok ? "pass" : "FAIL"}  ${sanitize(r.name, 60)}', 'out.log(`${r.ok ? "pass" : "FAIL"}  ${r.name}')]),
    ("cli: layer errors printed unsanitised (check)", [(P + "schema.mjs", "if (errs.length) return { ok: false, errors: capErrors(errs).map((e) => sanitize(e)) };", "if (errs.length) return { ok: false, errors: capErrors(errs) };"), (P + "schema.mjs", "return errs.length ? { ok: false, errors: capErrors(errs).map((e) => sanitize(e)) } :", "return errs.length ? { ok: false, errors: capErrors(errs) } :")]),
    ("merge: a class only a lower layer defines is resolved", [(P + "merge.mjs", 'if (layer.origin === "user") {\n          classes.set(', "if (true) {\n          classes.set(")]),
    ("merge: the skipped-user-layer note is dropped", [(P + "merge.mjs", '${userSkipped ? " (the user layer was skipped)" : ""}', '${""}')]),
    ("merge: a lifted rule keeps the layer's reason text", [(P + "merge.mjs", "reason: `Added by a lower layer (rule ${rule.id}).`", "reason: rule.reason")]),
    ("merge: the layer total is counted in characters", [(P + "merge.mjs", 'byteLength(l.text) : 0), 0);', "l.text.length : 0), 0);")]),
    ("version: examples are part of policy_version again", [(P + "merge.mjs", "export const policyVersion = (entry) => hash12(entry.spec);", "export const policyVersion = (entry) => hash12({ spec: entry.spec, examples: entry.examples });")]),
    ("sanitize: odd quoted text kept", [(P + "schema.mjs", "(m, t) => (/^[A-Za-z0-9._:-]{1,48}$/.test(t) ? m : '\"<text>\"')", "(m, t) => m")]),
    ("sanitize: long runs kept", [(P + "schema.mjs", '.replace(/[A-Za-z0-9_.-]{49,}/g, "<long>")\n', "\n")]),
    ("sanitize: non-ASCII kept", [(P + "schema.mjs", '.replace(/[^\\x20-\\x7e]/g, "?")\n', "\n")]),
    ("sanitize: no length bound", [(P + "schema.mjs", ".slice(0, max);", ";")]),
]


def main():
    tmp = tempfile.mkdtemp(prefix="policy-mutation-")
    survived, killed = [], 0
    try:
        for name, edits in MUTATIONS:
            work = os.path.join(tmp, "w")
            shutil.rmtree(work, ignore_errors=True)
            os.makedirs(os.path.join(work, "server"))
            for item in ["server/src", "server/test", "server/package.json", "scripts", "examples", "install.sh"]:
                src, dst = os.path.join(ROOT, item), os.path.join(work, item)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("node_modules", "__pycache__"))
                else:
                    shutil.copy(src, dst)
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
                survived.append(name)
                continue
            try:
                p = subprocess.run(CMD, cwd=os.path.join(work, "server"), capture_output=True, text=True, timeout=300)
                failed = p.returncode != 0
            except subprocess.TimeoutExpired:
                p, failed = None, True  # a hang is a failure the suite noticed
            if not edits:
                if failed:
                    print("BASELINE RED: the suite fails with no mutation applied, so every 'kill' would be meaningless\n" + ((p.stdout + p.stderr)[-1500:] if p else "timed out"))
                    return 2
                print("baseline green")
                continue
            if failed:
                killed += 1
                print("KILLED   %s" % name)
            else:
                survived.append(name)
                print("SURVIVED %s" % name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d mutations, %d killed, %d survived" % (len(MUTATIONS) - 1, killed, len(survived)))
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())
