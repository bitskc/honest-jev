#!/usr/bin/env python3
"""Mutation check for the local-first guard tests.

Copies the relevant tree to a scratch directory, applies one deliberate defect (one or more coordinated edits) at a time,
and requires the matching test suite to FAIL. The first mutation of each hook disables the local step altogether: the new
tests must notice that nothing is settled locally any more. A mutation that survives means the test it targets cannot catch
that defect. The real tree is never modified. Data only: nothing here executes a guarded command string.

    python3 tests/mutation_check_local_first.py            # all mutations
    python3 tests/mutation_check_local_first.py -v         # also print the failing test output of each killed mutation's first failure
    python3 tests/mutation_check_local_first.py disabled   # only the mutations whose name contains "disabled"
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# the unit under mutation is the whole tree: every suite below runs unchanged against the copy

PYT = [sys.executable, "-W", "ignore", "-m", "unittest", "tests/test_local_first.py"]
RUNT = ["node", "--test", "hooks/jev-guard-local.test.mjs"]
OMPT = ["bun", "test", "tests/local-first-omp.test.ts"]
SCRIPTS = ["bash", "tests/test-scripts.sh"]

PYH = "hooks/jev_guard_hook.py"
PYL = "hooks/jev_ledger.py"
RUN = "hooks/jev-guard-local.mjs"
TS = "hooks/omp/jev-guard.ts"
INST = "install.sh"

# (name, [(file, old, new), ...], command). `old` must occur exactly once.
MUTATIONS = [
    # ── python hook ──
    ("hook-py: local step disabled", [(PYH, "    if not local_enabled():\n        return None\n    runtime = policy_runtime()", "    if True:\n        return None\n    runtime = policy_runtime()")], PYT),
    ("hook-py: JEV_GUARD_LOCAL=off ignored", [(PYH, 'return os.environ.get("JEV_GUARD_LOCAL", "").strip().lower() != "off"', "return True")], PYT),
    ("hook-py: an unclear command is treated as settled", [(PYH, 'return local is not None and (local.get("unclear") is True or local.get("decided_by") == "fail_open")', "return False")], PYT),
    ("hook-py: the runner's unclear flag is ignored (decided_by only)", [(PYH, 'local.get("unclear") is True or local.get("decided_by") == "fail_open"', 'local.get("decided_by") == "fail_open"')], PYT),
    ("hook-py: a notice on every call", [(PYH, 'return bool(_ledger is not None and _ledger.mark_once("notice-" + sid))', "return True")], PYT),
    ("hook-py: the notice is not keyed by session", [(PYH, 'return bool(_ledger is not None and _ledger.mark_once("notice-" + sid))', 'return bool(_ledger is not None and _ledger.mark_once("notice-x"))')], PYT),
    ("hook-py: the notice is shown without a local unclear verdict", [(PYH, 'notice = LOCAL_NOTICE if unclear and e.code == "client_config" and first_unclear_in_session() else None', 'notice = LOCAL_NOTICE if e.code == "client_config" and first_unclear_in_session() else None')], PYT),
    ("hook-py: the flagged rule is dropped from the fail_open row", [(PYH, 'hint = {"rule": local.get("rule")} if unclear and isinstance(local.get("rule"), str) else None', "hint = None")], PYT),
    ("hook-py: a rule_error row loses its closed fail_reason", [(PYH, '        row["fail_reason"] = "rule_error"  # a server reply carries this in its record; a local reply has none', "        pass")], PYT),
    ("hook-py: the runner's time budget is not enforced", [(PYH, "capture_output=True, timeout=local_timeout())", "capture_output=True, timeout=None)")], PYT),
    ("hook-py: the network stack is imported eagerly", [(PYH, "import threading\nimport time\n", "import threading\nimport time\nimport urllib.request\n")], PYT),
    ("hook-py: a settled reply still calls the server", [(PYH, "        return reply_outcome(local)\n", "        pass\n")], PYT),
    ("hook-py: a local ask is downgraded to allow when the server is unavailable (no server)", [(PYH, "        note(\"fail-open: %s\" % e.why)\n        if stands is not None:\n            return reply_outcome(stands)\n", "        note(\"fail-open: %s\" % e.why)\n")], PYT),
    ("hook-py: a local ask is downgraded to allow when the server is unavailable (network failure)", [(PYH, "str(e)[:120]))\n        if stands is not None:\n            return reply_outcome(stands)\n", "str(e)[:120]))\n")], PYT),
    ("hook-py: a pure-unclear allow is turned into a stand", [(PYH, 'stands = local if unclear and local.get("decision") in ("ask", "block") else None', "stands = local if unclear else None")], PYT),
    ("ledger-py: the notice marker is not exclusive", [(PYL, "os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)", "os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)")], PYT),
    ("ledger-py: old markers are never pruned", [(PYL, "                if now - os.lstat(p).st_mtime > MARKER_MAX_AGE:", "                if False:")], PYT),
    # ── node runner ──
    ("runner: the unclear flag ignores a model question that only the masked reading raised", [(RUN, 'reply.unclear = consulted > 0 && reply.decision !== "block";', 'reply.unclear = reply.decided_by === "fail_open";')], RUNT),
    ("runner: a block with a model question is called unclear", [(RUN, 'reply.unclear = consulted > 0 && reply.decision !== "block";', "reply.unclear = consulted > 0;")], RUNT),
    ("runner: the release beside the hook is not looked at first", [(RUN, '    resolve(here, "..", "server", "src", "kit", "guard.mjs"),\n', "")], RUNT),
    ("runner: a relative JEV_GUARD_RULES is accepted", [(RUN, "if (custom) return isAbsolute(custom) ? [custom] : [];", "if (custom) return [resolve(custom)];")], RUNT),
    ("runner: judgeStdin drops the rule's suggestion (the in-process corpus run)", [(RUN, "  reply.unclear = consulted > 0 && reply.decision !== \"block\";\n  return reply;", "  reply.unclear = consulted > 0 && reply.decision !== \"block\";\n  return { ...reply, suggestion: null };")], RUNT),
    ("runner: the one-shot entry drops the rule id (only the real spawns see it)", [(RUN, "  process.stdout.write(`${JSON.stringify(reply)}\\n`);\n  return 0;\n}\n\n// Run only", "  process.stdout.write(`${JSON.stringify({ ...reply, rule: null })}\\n`);\n  return 0;\n}\n\n// Run only")], RUNT),
    # ── omp hook ──
    ("hook-omp: local step disabled", [(TS, '    if ((process.env.JEV_GUARD_LOCAL ?? "").trim().toLowerCase() === "off") return null;', "    return null;")], OMPT),
    ("hook-omp: JEV_GUARD_LOCAL=off ignored", [(TS, '    if ((process.env.JEV_GUARD_LOCAL ?? "").trim().toLowerCase() === "off") return null;', "")], OMPT),
    ("hook-omp: the masked-reading model question is not unclear", [(TS, 'unclear: by === "fail_open" || (consulted > 0 && reply.decision !== "block") };', 'unclear: by === "fail_open" };')], OMPT),
    ("hook-omp: an unclear command is treated as settled", [(TS, "const settled = local !== null && !local.unclear && (", "const settled = local !== null && (")], OMPT),
    ("hook-omp: a notice on every call", [(TS, 'if (local?.unclear && g.code === "client_config" && !noticed) {', 'if (local?.unclear && g.code === "client_config") {')], OMPT),
    ("hook-omp: a new session is never told again", [(TS, 'pi.on("session_start", async () => { noticed = false; });', 'pi.on("session_start", async () => {});')], OMPT),
    ("hook-omp: the flagged rule is dropped from the fail_open row", [(TS, 'failReason: g.code, rule: flagged });', "failReason: g.code });")], OMPT),
    ("hook-omp: a rule_error row loses its closed fail_reason", [(TS, 'wouldHave: would, failReason: ruleError });', "wouldHave: would });")], OMPT),
    ("hook-omp: rules found only through the override", [(TS, 'for (const dir of ["honest-jev", "jev-agent-skills"]) {', "for (const dir of []) {")], OMPT),
    ("hook-omp: a local ask is downgraded to allow when the server is unavailable", [(TS, 'const g: McpResult<GuardReply> = answered.kind === "unavailable" && local?.unclear && local.reply.decision !== "allow" ? { kind: "reply", reply: local.reply as GuardReply } : answered;', "const g: McpResult<GuardReply> = answered;")], OMPT),
    ("hook-omp: a pure-unclear allow is turned into a stand (no notice, no fail_open row)", [(TS, 'answered.kind === "unavailable" && local?.unclear && local.reply.decision !== "allow" ?', 'answered.kind === "unavailable" && local?.unclear ?')], OMPT),
    # ── install.sh doctor ──
    ("doctor: the local-rules-only note is never printed", [(INST, 'echo "note guard runs on local rules only; unclear commands are allowed without a model check"', "true")], SCRIPTS),
    ("doctor: the local rules line is never checked", [(INST, '  elif rp=$("$rt" "$runner" --check 2>/dev/null); then ok "guard rules load locally ($rp)"', '  elif true; then ok "guard rules load locally ($runner)"')], SCRIPTS),
]


def fresh_copy(work):
    """The whole tree (never .git or node_modules) in a scratch directory; the stub Worker finds zod through a symlink."""
    shutil.rmtree(work, ignore_errors=True)
    shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns(".git", "node_modules"))
    os.symlink(os.path.join(ROOT, "server", "node_modules"), os.path.join(work, "server", "node_modules"))


def main():
    verbose = "-v" in sys.argv
    pats = [a for a in sys.argv[1:] if a != "-v"]
    todo = [m for m in MUTATIONS if not pats or any(p in m[0] for p in pats)]
    tmp = tempfile.mkdtemp(prefix="jev-mut-localfirst-", dir=os.path.expanduser("~"))
    killed, survived, bad_mutations = 0, [], []
    try:
        # Control: every suite must PASS on the unmutated copy, or a "killed" mutation proves nothing (a suite that cannot run fails everything).
        for cmd in sorted({tuple(m[2]) for m in todo}):
            fresh_copy(os.path.join(tmp, "w"))
            p = subprocess.run(list(cmd), cwd=os.path.join(tmp, "w"), capture_output=True, text=True, timeout=600)
            print("CONTROL  %-4s %s" % ("ok" if p.returncode == 0 else "FAIL", " ".join(cmd[-2:])))
            if p.returncode != 0:
                print((p.stdout + p.stderr)[-1500:])
                return 2
        for name, edits, cmd in todo:
            work = os.path.join(tmp, "w")
            fresh_copy(work)
            bad = False
            for rel, old, new in edits:
                path = os.path.join(work, rel)
                with open(path) as f:
                    text = f.read()
                if text.count(old) != 1:
                    print("BAD MUTATION (pattern count %d): %s :: %s" % (text.count(old), name, old[:60]))
                    bad = True
                    break
                with open(path, "w") as f:
                    f.write(text.replace(old, new))
            if bad:
                bad_mutations.append(name)
                continue
            p = subprocess.run(cmd, cwd=work, capture_output=True, text=True, timeout=600)
            if p.returncode != 0:
                killed += 1
                print("KILLED   %s" % name)
                if verbose:
                    out = (p.stdout + p.stderr).splitlines()
                    hits = [l for l in out if l.startswith(("FAIL:", "ERROR:", "(fail)", "not ok", "✖", "FAIL "))]
                    for l in hits[:3] or out[-3:]:
                        print("           | %s" % l[:170])
            else:
                survived.append(name)
                print("SURVIVED %s" % name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d mutations, %d killed, %d survived, %d BAD MUTATION" % (len(todo), killed, len(survived), len(bad_mutations)))
    return 1 if survived or bad_mutations else 0


if __name__ == "__main__":
    sys.exit(main())
