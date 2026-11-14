"""jev-call writes the local decision ledger row for a kit_decide call (the gap the report used to list).

A stub `curl` on PATH answers with a canned MCP response, so nothing touches a network. The ledger path is always an
explicit JEV_LEDGER in a scratch directory. Hostile marker strings ride in every free-text field the server can send;
none may reach the ledger. Data only: nothing here runs a command string under test.

    python3 -m unittest tests/test_jev_call_ledger.py -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
JEV_CALL = os.path.join(ROOT, "scripts", "jev-call.sh")
sys.path.insert(0, os.path.join(ROOT, "hooks"))
import jev_ledger  # noqa: E402

MARK = "ZXQ-HOSTILE-MARKER"
TMP = tempfile.mkdtemp(prefix="jev-call-ledger-")
STUB_BIN = os.path.join(TMP, "bin")
BASH5 = subprocess.run(["bash", "-c", 'echo "${BASH_VERSINFO[0]}"'], capture_output=True, text=True).stdout.strip() >= "5"

# Realistic record: built by the Worker's own assembleRecord with the arguments kit_decide passes it.
_NODE = (
    'import {assembleRecord} from "%s/server/src/ledger/record.mjs";'
    "const r = assembleRecord(JSON.parse(process.argv[1])); console.log(JSON.stringify(r));"
) % ROOT


def server_record(**f):
    base = dict(tool="kit_decide", decision="ask", verdict=None, decided_by="jev", rule="needs-review", fail_reason=None, latency_ms=412,
                jev_used=True, jev_status="ok", model="typesafe-ai/jev", usage={"input_tokens": 100, "output_tokens": 20, "cost": 0.0003},
                prices=None, host="my-agent", correlation_id="corr-1", policy_version="0123456789ab")
    base.update(f)
    out = subprocess.run(["node", "--input-type=module", "-e", _NODE, json.dumps(base)], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def decide_payload(record="default", **over):
    p = {
        "tool": "kit_decide", "decision": "ask", "rule_id": "needs-review", "reason": "%s reason" % MARK, "decided_by": "jev",
        "fail_mode_applied": None, "fail_reason": None,
        "spec": {"id": "pr-merge-gate", "version": 1, "hash": "a" * 64, "fail_mode": "closed"},
        "policy": {"class": "pr-merge-gate", "version": "0123456789ab", "origins": ["user"], "tightened_by": []},
        "answers": {"reviewed": {"value": True, "evidence": "%s evidence" % MARK}}, "steps": [{"rule": "x", "note": MARK}],
        "jev": {"used": True, "status": "ok", "model": "typesafe-ai/jev", "usage": {"input_tokens": 100, "output_tokens": 20, "cost": 0.0003}},
        "notes": ["%s note" % MARK],
        "record": server_record() if record == "default" else record,
    }
    p.update(over)
    return p


def mcp_ok(payload, sse=False):
    msg = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": json.dumps(payload)}]}})
    return ("data: " + msg) if sse else msg


class Env(object):
    def __init__(self, response, rc=0, tool_error=False):
        self.dir = tempfile.mkdtemp(dir=TMP)
        self.home = os.path.join(self.dir, "home")
        os.makedirs(self.home)
        self.ledger = os.path.join(self.dir, "state", "ledger.jsonl")
        self.resp = os.path.join(self.dir, "resp")
        with open(self.resp, "w") as f:
            f.write(response)
        self.env = {"PATH": STUB_BIN + os.pathsep + os.environ["PATH"], "HOME": self.home, "JEV_MCP_TOKEN": "t", "JEV_MCP_URL": "https://x/mcp",
                    "JEV_LEDGER": self.ledger, "STUB_RESP": self.resp, "STUB_RC": str(rc)}

    def run(self, tool="kit_decide", args="{}", script=JEV_CALL):
        p = subprocess.run(["bash", script, tool, args], capture_output=True, text=True, env=self.env, cwd=self.dir, timeout=60)
        return p

    def rows(self):
        if not os.path.exists(self.ledger):
            return []
        with open(self.ledger) as f:
            return [json.loads(x) for x in f if x.strip()]

    def raw(self):
        return open(self.ledger).read() if os.path.exists(self.ledger) else ""


def setUpModule():
    os.makedirs(STUB_BIN)
    stub = os.path.join(STUB_BIN, "curl")
    with open(stub, "w") as f:
        f.write('#!/usr/bin/env bash\ncat >/dev/null\nsleep "${STUB_SLEEP:-0}"\n[ "${STUB_RC:-0}" = 0 ] || exit "$STUB_RC"\ncat "$STUB_RESP"\n')
    os.chmod(stub, 0o755)


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


class JevCallLedger(unittest.TestCase):
    def test_a_decision_is_appended_with_the_hook_writers_allow_list(self):
        e = Env(mcp_ok(decide_payload()))
        p = e.run()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["decision"], "ask")
        (row,) = e.rows()
        self.assertEqual(set(row), set(jev_ledger.build_row({}, tool="x", host="x")), "the key set is the schema the hooks write")
        self.assertEqual((row["tool"], row["decision"], row["decided_by"], row["rule"]), ("kit_decide", "ask", "jev", "needs-review"))
        self.assertEqual((row["host"], row["source"], row["policy_version"], row["correlation_id"]), ("my-agent", "server", "0123456789ab", "corr-1"))
        self.assertEqual(row["jev"]["model"], "typesafe-ai/jev")
        self.assertEqual((row["jev"]["input_tokens"], row["jev"]["output_tokens"], row["jev"]["cost_source"]), (100, 20, "upstream"))
        self.assertRegex(row["decision_id"], r"^[0-9a-f-]{36}$")
        self.assertRegex(row["server_decision_id"], r"^[0-9a-f-]{36}$")
        self.assertNotEqual(row["decision_id"], row["server_decision_id"], "the client mints the row id; the Worker's id is kept apart")

    def test_server_sent_events_framing_is_recorded_too(self):
        e = Env(mcp_ok(decide_payload(), sse=True))
        self.assertEqual(e.run().returncode, 0)
        self.assertEqual(len(e.rows()), 1)

    def test_no_text_from_the_response_reaches_the_ledger(self):
        hostile = server_record()
        hostile.update({"rule": MARK + " x", "host": MARK, "correlation_id": MARK + " spaced", "decision": MARK, "fail_reason": MARK, "decided_by": MARK,
                        "verdict": MARK + "!", "tiers": {"chosen": MARK + " x", "recommended": MARK + "/"}, "policy_version": MARK, "ts": MARK,
                        "decision_id": MARK, "extra": MARK})
        hostile["jev"] = dict(hostile["jev"], model=MARK + " model", status=MARK, detail=MARK)
        e = Env(mcp_ok(decide_payload(record=hostile)))
        self.assertEqual(e.run().returncode, 0)
        self.assertNotIn(MARK, e.raw())
        (row,) = e.rows()
        self.assertEqual(set(row), set(jev_ledger.build_row({}, tool="x", host="x")))
        self.assertEqual((row["rule"], row["policy_version"], row["correlation_id"], row["fail_reason"]), (None, None, None, None))
        self.assertEqual(row["host"], "jev-call", "a host label that does not fit the shape is rejected, not kept; the client label stands in")

    def test_without_a_record_the_row_is_rebuilt_from_the_reply(self):
        e = Env(mcp_ok(decide_payload(record=None, verdict="pass")))
        self.assertEqual(e.run().returncode, 0)
        (row,) = e.rows()
        self.assertIsNone(row["verdict"], "kit_decide has no verdict; a stray reply field must not become one")
        self.assertEqual((row["tool"], row["decision"], row["decided_by"], row["rule"], row["policy_version"], row["host"]),
                         ("kit_decide", "ask", "jev", "needs-review", "0123456789ab", "jev-call"))
        self.assertEqual(row["source"], "client")
        self.assertNotIn(MARK, e.raw())

    def test_a_failure_path_decision_keeps_its_closed_reason(self):
        for rec, label in ((None, "rebuilt"), ("default", "server record")):
            payload = decide_payload(record=server_record(decided_by="fail_closed", fail_reason="timeout", decision="deny", rule=None, jev_used=False, jev_status="unavailable")
                                     if rec == "default" else None,
                                     decision="deny", rule_id=None, decided_by="fail_closed", fail_reason="timeout", fail_mode_applied="deny",
                                     jev={"used": False, "status": "unavailable", "model": None, "usage": None})
            e = Env(mcp_ok(payload))
            self.assertEqual(e.run().returncode, 0, label)
            (row,) = e.rows()
            self.assertEqual((row["decision"], row["decided_by"], row["fail_reason"], row["rule"]), ("deny", "fail_closed", "timeout", None), label)

    def test_a_reason_text_in_fail_reason_is_rejected(self):
        e = Env(mcp_ok(decide_payload(record=None, decided_by="fail_open", fail_reason="%s secret path /etc/shadow" % MARK)))
        self.assertEqual(e.run().returncode, 0)
        (row,) = e.rows()
        self.assertEqual((row["decided_by"], row["fail_reason"]), ("fail_open", "upstream_error"), "the code is replaced by the writer's default, never kept")
        self.assertNotIn(MARK, e.raw())

    def test_the_output_and_exit_code_do_not_depend_on_the_ledger(self):
        resp = mcp_ok(decide_payload())
        on = Env(resp).run()
        off = Env(resp)
        off.env["JEV_LEDGER"] = "off"
        p_off = off.run()
        self.assertEqual((on.returncode, on.stdout), (p_off.returncode, p_off.stdout))
        self.assertEqual(off.rows(), [])
        self.assertFalse(os.path.exists(off.ledger))

    def test_a_relative_ledger_path_is_refused_and_the_call_is_unaffected(self):
        e = Env(mcp_ok(decide_payload()))
        e.env["JEV_LEDGER"] = "rel/ledger.jsonl"
        p = e.run()
        self.assertEqual(p.returncode, 0)
        self.assertEqual(json.loads(p.stdout)["decision"], "ask")
        self.assertFalse(os.path.exists(os.path.join(e.dir, "rel")), "a relative path must not land in the working directory")

    def test_an_unwritable_ledger_does_not_change_the_call(self):
        e = Env(mcp_ok(decide_payload()))
        os.makedirs(e.ledger)  # a directory where the file should be
        p = e.run()
        self.assertEqual(p.returncode, 0)
        self.assertEqual(json.loads(p.stdout)["decision"], "ask")

    def test_a_symlinked_ledger_is_not_followed(self):
        e = Env(mcp_ok(decide_payload()))
        target = os.path.join(e.dir, "elsewhere")
        open(target, "w").close()
        os.makedirs(os.path.dirname(e.ledger))
        os.symlink(target, e.ledger)
        self.assertEqual(e.run().returncode, 0)
        self.assertEqual(os.path.getsize(target), 0)

    def test_nothing_is_written_when_no_decision_was_made(self):
        cases = {
            "tool error result": (json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": [{"type": "text", "text": json.dumps({"tool": "kit_decide", "error": "bad_spec", "note": "No decision was made."})}]}}), 0, 1),
            "isError with a decision-looking payload": (json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": [{"type": "text", "text": json.dumps(decide_payload())}]}}), 0, 1),
            "json-rpc error": (json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "x"}}), 0, 1),
            "unparsable response": ("<html>502</html>", 0, 1),
            "transport failure": ("", 7, 1),
            "payload of another tool": (mcp_ok({"tool": "kit_guard_command", "decision": "block", "reason": "r"}), 0, 0),
            "no decision word": (mcp_ok({"tool": "kit_decide", "note": "x"}), 0, 0),
            "text that is not JSON": (json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "plain"}]}}), 0, 0),
        }
        for label, (resp, curl_rc, want_rc) in cases.items():
            e = Env(resp, rc=curl_rc)
            p = e.run()
            self.assertEqual(p.returncode, want_rc, "%s: %s" % (label, p.stderr))
            self.assertEqual(e.rows(), [], label)

    def test_other_tools_are_not_recorded_by_jev_call(self):
        for tool in ("kit_guard_command", "kit_size_dispatch", "kit_verify_done", "jev_classify"):
            e = Env(mcp_ok(decide_payload()))  # even a reply that looks like a decision: the tool name decides
            self.assertEqual(e.run(tool=tool).returncode, 0)
            self.assertEqual(e.rows(), [], tool)

    def test_missing_writer_says_so_on_stderr_and_still_answers(self):
        e = Env(mcp_ok(decide_payload()))
        lone = os.path.join(e.dir, "lone", "jev-call")
        os.makedirs(os.path.dirname(lone))
        shutil.copy(JEV_CALL, lone)
        p = e.run(script=lone)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(json.loads(p.stdout)["decision"], "ask")
        self.assertIn("not recorded in the local ledger", p.stderr)
        self.assertNotIn(MARK, p.stderr)
        self.assertEqual(e.rows(), [])
        # a different tool says nothing about the ledger
        self.assertNotIn("ledger", e.run(tool="jev_classify", script=lone).stderr)

    def test_installed_layout_finds_the_writer_under_the_share_dir(self):
        e = Env(mcp_ok(decide_payload()))
        share = os.path.join(e.home, ".local", "share", "honest-jev", "hooks")
        os.makedirs(share)
        shutil.copy(os.path.join(ROOT, "hooks", "jev_ledger.py"), share)
        binp = os.path.join(e.home, ".local", "bin", "jev-call")
        os.makedirs(os.path.dirname(binp))
        shutil.copy(JEV_CALL, binp)
        p = e.run(script=binp)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(e.rows()), 1)

    def test_after_install_sh_the_installed_jev_call_records(self):
        e = Env(mcp_ok(decide_payload()))
        inst = subprocess.run(["bash", os.path.join(ROOT, "install.sh"), "--claude"], capture_output=True, text=True, env=dict(e.env, HOME=e.home), cwd=ROOT, timeout=120)
        self.assertEqual(inst.returncode, 0, inst.stdout + inst.stderr)
        installed = os.path.join(e.home, ".local", "bin", "jev-call")
        self.assertTrue(os.path.isfile(installed))
        p = e.run(script=installed)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(e.rows()), 1)

    def test_a_writer_that_fails_to_load_does_not_change_the_call(self):
        e = Env(mcp_ok(decide_payload()))
        share = os.path.join(e.home, ".local", "share", "honest-jev", "hooks")
        os.makedirs(share)
        with open(os.path.join(share, "jev_ledger.py"), "w") as f:
            f.write("raise RuntimeError('%s')\n" % MARK)
        lone = os.path.join(e.dir, "lone", "jev-call")
        os.makedirs(os.path.dirname(lone))
        shutil.copy(JEV_CALL, lone)
        p = e.run(script=lone)
        self.assertEqual(p.returncode, 0)
        self.assertEqual(json.loads(p.stdout)["decision"], "ask")
        self.assertNotIn(MARK, p.stderr, "an exception from the writer is never echoed")

    @unittest.skipUnless(BASH5, "EPOCHREALTIME needs bash 5")
    def test_latency_is_the_client_observed_call_time(self):
        e = Env(mcp_ok(decide_payload(record=None)))
        e.env["STUB_SLEEP"] = "0.3"
        self.assertEqual(e.run().returncode, 0)
        (row,) = e.rows()
        self.assertIsInstance(row["latency_ms"], int)
        self.assertTrue(280 <= row["latency_ms"] < 10000, row["latency_ms"])

    def test_repeated_calls_append_one_row_each(self):
        e = Env(mcp_ok(decide_payload()))
        for _ in range(3):
            self.assertEqual(e.run().returncode, 0)
        rows = e.rows()
        self.assertEqual(len(rows), 3)
        self.assertEqual(len({r["decision_id"] for r in rows}), 3)

    def test_the_report_counts_the_rows(self):
        e = Env(mcp_ok(decide_payload()))
        e.run()
        e.run()
        out = subprocess.run(["node", os.path.join(ROOT, "scripts", "jev-report.mjs"), "--json", e.ledger], capture_output=True, text=True, check=True)
        rep = json.loads(out.stdout)
        self.assertEqual(rep["observed"]["by_tool"]["kit_decide"], 2)
        self.assertEqual(rep["coverage"]["kit_decide"], {"rows": 2, "note": None})


if __name__ == "__main__":
    unittest.main()
