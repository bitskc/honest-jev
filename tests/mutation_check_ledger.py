#!/usr/bin/env python3
"""Mutation check for the decision-ledger tests (openspec add-decision-ledger).

Copies the relevant tree to a scratch directory, applies one deliberate defect (one or more coordinated edits) at a
time, and requires the matching test suite to FAIL. A mutation that survives means the test it targets cannot catch
that defect. The real tree is never modified. Data only: nothing here executes a guarded command string.

    python3 tests/mutation_check_ledger.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COPY = ["server/src", "server/test", "server/package.json", "hooks", "scripts", "tests", "config"]

SERVER = ["bash", "-c", "cd server && node --test test/ledger.test.mjs"]
HOOKPY = [sys.executable, "-m", "unittest", "tests/test_ledger_hook.py"]
REPORT = ["node", "--test", "tests/ledger-report.test.mjs"]
OMP = ["bun", "test", "tests/ledger-omp.test.ts"]

REC = "server/src/ledger/record.mjs"
PYL = "hooks/jev_ledger.py"
PYH = "hooks/jev_guard_hook.py"
TS = "hooks/omp/jev-guard.ts"
REP = "scripts/jev-report.mjs"
OUT = "scripts/jev-outcome.mjs"

# (name, [(file, old, new), ...], command). `old` must occur exactly once.
MUTATIONS = [
    # ── server record ──
    ("record: fail_reason copies upstream detail text", [(REC, '  if (/no jev credentials/i.test(detail)) return "no_upstream";', '  return detail;\n  if (/no jev credentials/i.test(detail)) return "no_upstream";')], SERVER),
    ("record: leaks the tool's reason text into the record", [(REC, "    would_have: null,\n  };", "    would_have: null,\n    reason: p.reason,\n  };")], SERVER),
    ("record: leaks caller host label unvalidated", [(REC, "    host: pick(HOST, f.host),", "    host: f.host ?? null,")], SERVER),
    ("record: correlation_id skips redact and shape check", [(REC, "  return pick(CORRELATION, redact(v));", "  return v.slice(0, 64);")], SERVER),
    ("record: correlation_id truncated to fit instead of rejected", [(REC, "  return pick(CORRELATION, redact(v));", "  return pick(CORRELATION, redact(v).slice(0, 64));")], SERVER),
    ("record: dispatch tier name reaches the record without a shape check", [(REC, "const chosen = pick(TIER, f.tiers && f.tiers.chosen);", "const chosen = (f.tiers && f.tiers.chosen) ?? null;")], SERVER),
    ("record: verify fail_open mapped to prefilter", [(REC, 'const derived = failed ? "fail_open" : used ? "jev" : "prefilter";', 'const derived = used ? "jev" : "prefilter";')], SERVER),
    ("record: decided_by passthrough accepts any string", [(REC, "DECIDED_BY.includes(p.decided_by);", 'typeof p.decided_by === "string";')], SERVER),
    ("record: guard invalid answer mis-coded as upstream_error", [(REC, '  if (/returned an invalid/i.test(detail)) return "invalid_response"; // guard reports an invalid answer as status "unavailable"', "")], SERVER),
    ("record: timeout mis-coded as upstream_error", [(REC, '  if (/timed out|timeout|abort/i.test(detail)) return "timeout";', "")], SERVER),
    ("record: record no longer the last key", [(REC, "  return { ...payload, record };", "  return { record, ...payload };")], SERVER),
    ("record: FAIL_REASONS gains a code", [(REC, '"client_config", "client_input", "client_timeout",', '"client_config", "client_input", "mystery_code", "client_timeout",')], SERVER),
    ("record: log opt-out ignored", [(REC, '  if (String(env.JEV_DECISION_LOG ?? "").trim().toLowerCase() === "off") return false;\n', "")], SERVER),
    # ── python hook ledger ──
    ("hook-py: ledger opened without O_APPEND", [(PYL, "os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK", "os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK")], HOOKPY),
    ("hook-py: line written in two writes instead of one", [(PYL, "        return os.write(fd, line) == len(line)", "        os.write(fd, line[:-1])\n        time.sleep(0.0001)\n        return os.write(fd, line[-1:]) == 1")], HOOKPY),
    ("hook-py: ledger follows a symlink (NOFOLLOW, regular-file guard and directory guard removed)", [
        (PYL, "os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK", "os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NONBLOCK"),
        (PYL, "if not stat.S_ISREG(os.lstat(path).st_mode):", "if False:"),
        (PYL, "return stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid()", "return True"),
    ], HOOKPY),
    ("hook-py: rotation overwrites a single .1 generation", [
        (PYL, 'target = "%s.%s%06dZ-%d" % (path, time.strftime("%Y%m%dT%H%M%S", time.gmtime(now)), int((now % 1) * 1e6), os.getpid())', 'target = path + ".1"'),
        (PYL, "if not os.path.lexists(target):", "if True:"),
    ], HOOKPY),
    ("hook-py: pruning keeps the wrong number of generations", [(PYL, "rotated_files(path)[:-KEEP_ROTATED]", "rotated_files(path)[:-100]")], HOOKPY),
    ("hook-py: Worker id used as the row id", [(PYL, '"decision_id": str(uuid.uuid4()),', '"decision_id": rid if isinstance(rid, str) and _UUID.match(rid) else str(uuid.uuid4()),')], HOOKPY),
    ("hook-py: fail_reason_for returns exception text", [(PYL, '    """Map an exception to a closed code. The exception\'s text is never read."""\n    try:', '    """Map an exception to a closed code. The exception\'s text is never read."""\n    return str(exc)\n    try:')], HOOKPY),
    ("hook-py: parse errors mis-coded as network", [(PYL, 'return "client_parse"', 'return "client_network"')], HOOKPY),
    ("hook-py: build_row passes decision through unvalidated", [(PYL, '        "decision": _pick(_WORD, decision if decision is not None else r.get("decision")),', '        "decision": decision if decision is not None else r.get("decision"),')], HOOKPY),
    ("hook-py: build_row passes rule through unvalidated", [(PYL, '        "rule": _pick(_RULE, r.get("rule")),', '        "rule": r.get("rule"),')], HOOKPY),
    ("hook-py: build_row passes host through unvalidated", [(PYL, '        "host": _pick(_HOST, host),', '        "host": host,')], HOOKPY),
    ("hook-py: ledger write errors escape every catch-all and reach the hook", [
        (PYL, "    except Exception:\n        return False\n    finally:\n        if fd is not None:", "    except FileNotFoundError:\n        return False\n    finally:\n        if fd is not None:"),
        (PYL, "**kw))\n    except Exception:\n        return False", "**kw))\n    except ZeroDivisionError:\n        return False"),
        (PYH, "except (_LedgerStalled, Exception):\n        pass", "except (_LedgerStalled, ZeroDivisionError):\n        pass"),
    ], HOOKPY),
    ("hook-py: led() no longer catches ordinary ledger exceptions", [(PYH, "except (_LedgerStalled, Exception):\n        pass", "except _LedgerStalled:\n        pass")], HOOKPY),
    ("hook-py: shadow mode forgets enforced=false", [(PYH, '"enforced": would is None,', '"enforced": True,')], HOOKPY),
    ("hook-py: fail_open stores exception text as the reason", [(PYH, 'row=dict(decision="allow", decided_by="fail_open", fail_reason=_ledger.fail_reason_for(e) if _ledger else "client_network", enforced=True))', 'row=dict(decision="allow", decided_by="fail_open", fail_reason=str(e)[:120], enforced=True))')], HOOKPY),
    ("hook-py: stdin-not-json row not recorded", [(PYH, 'fail_open("stdin was not JSON", "client_input")', 'fail_open("stdin was not JSON")')], HOOKPY),
    ("hook-py: dispatch shadow hook starts enforcing", [("hooks/jev_dispatch_shadow.py", "    g.led(reply, decision=action, enforced=False,", "    print('{\"hookSpecificOutput\":{\"permissionDecision\":\"deny\"}}')\n    g.led(reply, decision=action, enforced=False,")], HOOKPY),
    # ── report / outcome ──
    ("report: estimate printed without outcome reports", [(REP, "  if (dispatchOutcomes.length === 0) {", "  if (false) {")], REPORT),
    ("report: prefilter share includes rows where nothing was judged", [(REP, "const judgedRows = decisions.filter(judged);", "const judgedRows = decisions;")], REPORT),
    ("report: repeated advice for one spawn counted twice", [(REP, "      if (cid && seen.has(cid)) { deduped++; continue; }   // advice repeated for one spawn counts once", "")], REPORT),
    ("report: no_ui counted in the approved rate", [(REP, 'const answered = askOutcomes.filter(({ o }) => o.label !== "no_ui");', "const answered = askOutcomes;")], REPORT),
    ("report: non-integer subagent_tokens accepted", [(REP, "Number.isInteger(o.subagent_tokens) && o.subagent_tokens >= 0", 'typeof o.subagent_tokens === "number"')], REPORT),
    ("report: coverage note hidden", [(REP, "note: (perTool[t] ?? 0) === 0 ? why : null", "note: null")], REPORT),
    ("report: rotated generations ignored", [(REP, "  return [...rotated, ...(existsSync(base) ? [base] : [])];", "  return [...(existsSync(base) ? [base] : [])];")], REPORT),
    ("report: costs merged across sources", [(REP, 'const src = j.cost_source ?? "unknown";', 'const src = "total";')], REPORT),
    ("report: lower-bound statement for fail-open dropped", [(REP, '  L.push("    LOWER BOUND: a missing interpreter, a host-level hook timeout and a crashed hook leave no row");', "")], REPORT),
    ("outcome: unknown decision id accepted", [(OUT, "  if (!hasDecision(path, id))", "  if (false)")], REPORT),
    ("outcome: self_reported source mislabelled", [(OUT, 'source: "self_reported" };', 'source: "host_observed" };')], REPORT),
    ("outcome: follows a symlinked ledger", [(OUT, "constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);", "constants.O_NONBLOCK, 0o600);")], REPORT),
    # ── omp hook ──
    ("omp: DECIDED_BY drifts from the other implementations", [(TS, 'export const DECIDED_BY = ["prefilter", "jev", "fail_open", "fail_closed", "policy"] as const;', 'export const DECIDED_BY = ["prefilter", "jev", "fail_open", "fail_closed"] as const;')], OMP),
    ("omp: ledger opened without O_APPEND", [(TS, "constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT", "constants.O_WRONLY | constants.O_CREAT")], OMP),
    ("omp: hostile record decision passed through", [(TS, "    decision: pick(WORD, o.decision ?? r.decision),", "    decision: (o.decision ?? r.decision) as string,")], OMP),
    ("omp: host-observed approval not recorded", [(TS, 'for (const id of ids) setImmediate(() => recordOutcome(id, ok ? "approved" : "denied"));', "void ids;")], OMP),
    ("omp: no_ui outcome not recorded", [(TS, 'for (const id of ids) setImmediate(() => recordOutcome(id, "no_ui"));', "void ids;")], OMP),
    ("omp: ledger follows symlinks", [
        (TS, "constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK;", "constants.O_CREAT | constants.O_NONBLOCK;"),
        (TS, 'if (!lstatSync(path).isFile()) throw new Error("ledger path is not a regular file");', ""),
        (TS, "return st.isDirectory() && (euid() === -1 || st.uid === euid());", "return true;"),
    ], OMP),
]


def main():
    tmp = tempfile.mkdtemp(prefix="jev-mutation-")
    survived, killed, bad_mutations = [], 0, []
    try:
        for name, edits, cmd in MUTATIONS:
            work = os.path.join(tmp, "w")
            shutil.rmtree(work, ignore_errors=True)
            os.makedirs(work)
            for item in COPY:
                src, dst = os.path.join(ROOT, item), os.path.join(work, item)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                if os.path.isdir(src):
                    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("node_modules", "__pycache__"))
                else:
                    shutil.copy2(src, dst)
            os.symlink(os.path.join(ROOT, "server", "node_modules"), os.path.join(work, "server", "node_modules"))
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
