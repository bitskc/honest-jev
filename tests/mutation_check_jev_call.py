#!/usr/bin/env python3
"""Mutation check for jev-call's kit_decide ledger row (tests/test_jev_call_ledger.py, the report note, the writer's
kit_decide synthesis).

Copies the relevant tree to a scratch directory, applies one deliberate defect at a time, and requires the matching suite
to FAIL. The unmutated tree must pass first (baseline guard). A survivor means a weak test, an equivalent mutant or dead
code. The real tree is never modified. Data only: nothing here executes a guarded command string.

    python3 tests/mutation_check_jev_call.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# install.sh and what it copies (config, skills, update.sh) are here for the installed-layout end-to-end test
COPY = ["server/src", "hooks", "scripts", "tests", "config", "skills", "install.sh", "update.sh"]

CALL = [sys.executable, "-W", "ignore", "-m", "unittest", "tests/test_jev_call_ledger.py"]
REPORT = ["node", "--test", "tests/ledger-report.test.mjs"]
LEDGER = [sys.executable, "-W", "ignore", "-m", "unittest", "tests/test_jev_call_ledger.py", "tests/test_ledger_hook.py"]

JC = "scripts/jev-call.sh"
PYL = "hooks/jev_ledger.py"
REP = "scripts/jev-report.mjs"

# (name, [(file, old, new), ...], command). `old` must occur exactly once.
MUTATIONS = [
    ("jev-call: every tool is recorded", [(JC, 'if os.environ.get("JEV_TOOL") == "kit_decide" and not r.get("isError"):', 'if not r.get("isError"):')], CALL),
    ("jev-call: nothing is ever recorded", [(JC, 'if os.environ.get("JEV_TOOL") == "kit_decide" and not r.get("isError"):', 'if False:')], CALL),
    ("jev-call: an error result is recorded", [(JC, 'if os.environ.get("JEV_TOOL") == "kit_decide" and not r.get("isError"):', 'if os.environ.get("JEV_TOOL") == "kit_decide":')], CALL),
    ("jev-call: a payload without a decision word is recorded", [(JC, ' and isinstance(p.get("decision"), str):', ':')], CALL),
    ("jev-call: another tool's payload is recorded as kit_decide", [(JC, 'if isinstance(p, dict) and p.get("tool") == "kit_decide" and', 'if isinstance(p, dict) and')], CALL),
    ("jev-call: the row is written before the output", [(JC, "print(t)\nsys.stdout.flush()\n", "")], CALL),
    ("jev-call: a writer failure changes the exit code", [(JC, "    except Exception:\n        pass\n", "    except Exception:\n        sys.exit(3)\n")], CALL),
    ("jev-call: a missing writer is silent", [(JC, 'print("jev-call: this kit_decide call was not recorded in the local ledger (hooks/jev_ledger.py not found; run ./install.sh)", file=sys.stderr)', "pass")], CALL),
    ("jev-call: the writer is not looked for beside the script", [(JC, '"${here:+$here/../hooks/jev_ledger.py}" ', "")], CALL),
    ("jev-call: the writer is not looked for under the install dir", [(JC, ' "${HOME:+$HOME/.local/share/honest-jev/hooks/jev_ledger.py}"; do', "; do")], CALL),
    ("jev-call: the host label is not validated", [(JC, 'host = led._pick(led._HOST, rec.get("host")) or "jev-call"', 'host = rec.get("host") or "jev-call"')], CALL),
    ("jev-call: the caller's host label is ignored", [(JC, 'host = led._pick(led._HOST, rec.get("host")) or "jev-call"', 'host = "jev-call"')], CALL),
    ("jev-call: no client label when the caller sent none", [(JC, 'host = led._pick(led._HOST, rec.get("host")) or "jev-call"', 'host = led._pick(led._HOST, rec.get("host"))')], CALL),
    ("jev-call: latency is never recorded", [(JC, "latency_ms=None if t0 is None else (t1 - t0) * 1000", "latency_ms=None")], CALL),
    ("jev-call: latency in seconds", [(JC, "(t1 - t0) * 1000", "(t1 - t0)")], CALL),
    ("jev-call: start time taken after the call", [(JC, 't0="${EPOCHREALTIME:-}"\n', 't0=""\n')], CALL),
    ("jev-call: the reply is passed without its record", [(JC, 'led.record("kit_decide", host, p, ', 'led.record("kit_decide", host, {k: v for k, v in p.items() if k != "record"}, ')], CALL),
    ("jev-call: a relative ledger path is honoured", [(PYL, "return p if os.path.isabs(p) else None", "return p")], CALL),
    # the writer's kit_decide synthesis (a reply whose record was dropped)
    ("writer: kit_decide decision read from `action`", [(PYL, '"decision": r.get("decision") if tool in ("kit_guard_command", "kit_decide") else r.get("action"),', '"decision": r.get("decision") if tool == "kit_guard_command" else r.get("action"),')], CALL),
    ("writer: kit_decide rule read from `rule`", [(PYL, '"rule": r.get("rule_id") if tool == "kit_decide" else r.get("rule"),', '"rule": r.get("rule"),')], CALL),
    ("writer: kit_decide fail_reason replaced by the generic code", [(PYL, '"fail_reason": r.get("fail_reason") if tool == "kit_decide" else (code if decided_by == "fail_open" else None),', '"fail_reason": code if decided_by == "fail_open" else None,')], CALL),
    ("writer: kit_decide policy version not carried", [(PYL, '"policy_version": policy.get("version") if tool == "kit_decide" else None,', '"policy_version": None,')], CALL),
    ("writer: kit_decide verdict taken from the reply", [(PYL, '"verdict": None if tool in ("kit_guard_command", "kit_decide") else r.get("verdict"),', '"verdict": r.get("verdict"),')], CALL),
    ("writer: policy_version not allow-listed", [(PYL, '"policy_version": _pick(_POLICY_VERSION, policy_version if policy_version is not None else r.get("policy_version")),', '"policy_version": policy_version if policy_version is not None else r.get("policy_version"),')], CALL),
    ("writer: policy_version taken from the server record is dropped", [(PYL, 'policy_version if policy_version is not None else r.get("policy_version")),', 'policy_version),')], CALL),
    ("writer: fail_reason not restricted to the closed list", [(PYL, "fr = fr if fr in FAIL_REASONS else None", "fr = fr")], CALL),
    # the report's coverage note
    ("report: the kit_decide note still claims there is no writer", [(REP, 'the local ledger gets a row only when the call goes through `jev-call` (or a hook that triggers it)', 'the local ledger never gets a row')], REPORT),
]


def copy_tree(work):
    for item in COPY:
        src, dst = os.path.join(ROOT, item), os.path.join(work, item)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns("node_modules", "__pycache__")) if os.path.isdir(src) else shutil.copy2(src, dst)
    os.makedirs(os.path.join(work, "server"), exist_ok=True)


def main():
    tmp = tempfile.mkdtemp(prefix="jev-call-mutation-")
    survived, killed, bad_mutations = [], 0, []
    try:
        base = os.path.join(tmp, "base")
        copy_tree(base)
        for label, cmd in (("jev-call ledger", CALL), ("report", REPORT)):
            p = subprocess.run(cmd, cwd=base, capture_output=True, text=True, timeout=300)
            if p.returncode != 0:
                print("BASELINE RED (%s):\n%s" % (label, (p.stdout + p.stderr)[-1500:]))
                return 2
            print("baseline green: %s" % label)
        for name, edits, cmd in MUTATIONS:
            work = os.path.join(tmp, "w")
            shutil.rmtree(work, ignore_errors=True)
            copy_tree(work)
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
            p = subprocess.run(cmd, cwd=work, capture_output=True, text=True, timeout=300)
            if p.returncode != 0:
                killed += 1
                print("KILLED   %s" % name)
            else:
                survived.append(name)
                print("SURVIVED %s" % name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("\n%d mutations, %d killed, %d survived, %d BAD MUTATION" % (len(MUTATIONS), killed, len(survived), len(bad_mutations)))
    return 1 if survived or bad_mutations else 0


if __name__ == "__main__":
    sys.exit(main())
