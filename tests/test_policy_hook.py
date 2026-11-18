"""Policy hook adapter tests for the Claude (Python) hook (openspec add-policy-hook-adapter). Data only.

Runs the REAL hook (hooks/jev-guard-hook.sh) against tests/stub-worker.mjs (real kit tool and kit_decide handlers over local
HTTPS with a fake upstream) and a stub `gh` on PATH, in a temp HOME and a temp git repo. Command strings are text sent to a
parser; nothing here executes one (the hostile cases assert exactly that). Needs: python3, node, openssl, git.

    python3 -m unittest tests/test_policy_hook.py -v
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
HOOK = os.path.join(ROOT, "hooks", "jev-guard-hook.sh")
HELPER = os.path.join(ROOT, "scripts", "jev-policy-hook.mjs")
STUB = os.path.join(ROOT, "tests", "stub-worker.mjs")
EXAMPLE = os.path.join(ROOT, "examples", "policies", "pr-merge-gate.json")
TMP = CERT = KEY = None
STUBS = []


def setUpModule():
    global TMP, CERT, KEY
    TMP = tempfile.mkdtemp(prefix="jev-policy-hook-test-")
    CERT, KEY = os.path.join(TMP, "c.pem"), os.path.join(TMP, "k.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", KEY, "-out", CERT, "-days", "2",
                    "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"], check=True, capture_output=True)
    os.makedirs(os.path.join(TMP, "bin"))
    gh = os.path.join(TMP, "bin", "gh")
    with open(gh, "w") as f:
        f.write('#!/bin/sh\necho "$@" >> "$STUB_GH_LOG"\ncase "$STUB_GH" in\n'
                ' reviewed) echo \'{"comments":[{"body":"gstack-review: pass"}],"reviews":[]}\';;\n'
                ' reviewed_in_review) echo \'{"comments":[],"reviews":[{"body":"gstack-review: pass"}]}\';;\n'
                ' unreviewed) echo \'{"comments":[{"body":"lgtm"}],"reviews":[{"body":""}]}\';;\n'
                ' by_pr) case " $STUB_GH_PRS " in *" $3 "*) echo \'{"comments":[{"body":"gstack-review: pass"}],"reviews":[]}\';; *) echo \'{"comments":[{"body":"lgtm"}],"reviews":[]}\';; esac;;\n'
                ' fail) echo boom >&2; exit 1;;\n garbage) echo "not json";;\n wrongshape) echo \'{"comments":"x"}\';;\n hang) sleep 8;;\nesac\n')
    os.chmod(gh, os.stat(gh).st_mode | stat.S_IXUSR)


def tearDownModule():
    for p in STUBS:
        p.terminate()
        p.wait()
        p.stdout.close()
    shutil.rmtree(TMP, ignore_errors=True)


def start_stub(mode="ok", merges="0.97", log=None):
    cmd = ["node", STUB, "--cert", CERT, "--key", KEY, "--mode", mode, "--jev"] + (["--log", log] if log else [])
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, env={**os.environ, "STUB_MERGES_PR": merges})
    STUBS.append(p)
    return int(p.stdout.readline().strip())


def class_doc(trigger=True, open_class=False, cid="pr-merge-gate", command=("gh", "pr", "merge")):
    with open(EXAMPLE) as f:
        spec = json.load(f)
    spec["id"] = cid
    if not trigger:
        spec.pop("trigger")
    else:
        spec["trigger"]["command"] = list(command)
        if list(command[:3]) != ["gh", "pr", "merge"]:
            spec["trigger"]["facts"] = {}  # the PR target source reads gh pr merge's argument list only
    if open_class:
        spec["on_unavailable"] = {"decision": "proceed", "reason": "Fail open: proceed."}
        spec["examples"] = [e for e in spec["examples"] if e["name"] != "no answer from the model fails closed to asking"] + [
            {"name": "no answer from the model fails open", "facts": {"gstack_reviewed": False}, "answers": {}, "expect": {"decision": "proceed", "rule_id": None, "decided_by": "fail_open"}}]
    return spec


class Env:
    def __init__(self, classes=None, **extra):
        self.home = tempfile.mkdtemp(dir=TMP)
        self.repo = os.path.join(self.home, "repo")
        os.makedirs(self.repo)
        for c in (["git", "init", "-q", "."], ["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "i"]):
            subprocess.run(c, cwd=self.repo, check=True, capture_output=True)
        self.layer = os.path.join(self.home, "policy.json")
        self.gh_log = os.path.join(self.home, "gh.log")
        if classes is not None:
            with open(self.layer, "w") as f:
                json.dump({"v": 1, "decisions": classes}, f)
        self.ledger = os.path.join(self.home, "ledger.jsonl")
        self.env = {"PATH": os.path.join(TMP, "bin") + os.pathsep + os.environ["PATH"], "HOME": self.home, "SSL_CERT_FILE": CERT,
                    "JEV_MCP_TOKEN": "stub-token", "JEV_POLICY_USER": self.layer, "JEV_POLICY_HOOK": HELPER, "JEV_LEDGER": self.ledger,
                    "STUB_GH_LOG": self.gh_log, "JEV_GUARD_LOCAL": "off", **extra}  # the policy path rides on the server path here; tests/test_local_first.py covers both together

    def run(self, command, tool="Bash", **over):
        ev = json.dumps({"tool_name": tool, "tool_input": {"command": command}, "cwd": self.repo, "hook_event_name": "PreToolUse"})
        env = {k: v for k, v in {**self.env, **over}.items() if v is not None}
        t0 = time.time()
        p = subprocess.run(["bash", HOOK], input=ev, capture_output=True, text=True, env=env, timeout=30, cwd=self.repo)
        return p, time.time() - t0

    def rows(self):
        if not os.path.exists(self.ledger):
            return []
        with open(self.ledger) as f:
            return [json.loads(l) for l in f if l.strip()]

    def text(self):
        if not os.path.exists(self.ledger):
            return ""
        with open(self.ledger) as f:
            return f.read()

    def gh_calls(self):
        if not os.path.exists(self.gh_log):
            return []
        with open(self.gh_log) as f:
            return [l.strip() for l in f]


def url(port):
    return "https://127.0.0.1:%d/mcp" % port


def decision_of(p):
    if not p.stdout.strip():
        return "none"
    return json.loads(p.stdout).get("hookSpecificOutput", {}).get("permissionDecision", "none")


def notice_of(p):
    return json.loads(p.stdout).get("systemMessage") if p.stdout.strip() else None


def reason_of(p):
    return json.loads(p.stdout).get("hookSpecificOutput", {}).get("permissionDecisionReason", "") if p.stdout.strip() else ""


def policy_rows(e):
    return [r for r in e.rows() if r["tool"] == "kit_decide"]


class LedgerPolicyVersion(unittest.TestCase):
    def test_only_twelve_lowercase_hex_passes(self):
        sys.path.insert(0, os.path.join(ROOT, "hooks"))
        import jev_ledger
        for v, want in (("0123456789ab", "0123456789ab"), ("0123456789AB", None), ("0123456789a", None), ("0123456789abc", None), ("ZXQ-HOSTILE-MARKER", None), (12345, None), (None, None)):
            self.assertEqual(jev_ledger.build_row({"policy_version": v}, tool="kit_decide", host="x")["policy_version"], want, repr(v))
            self.assertEqual(jev_ledger.build_row({}, tool="kit_decide", host="x", policy_version=v)["policy_version"], want, repr(v))
        self.assertEqual(jev_ledger.build_row({"policy_version": "aaaaaaaaaaaa"}, tool="kit_decide", host="x", policy_version="bbbbbbbbbbbb")["policy_version"], "bbbbbbbbbbbb", "an explicit value wins over the record's")


class HookUnits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib.util
        spec = importlib.util.spec_from_file_location("jev_guard_hook_under_test", os.path.join(ROOT, "hooks", "jev_guard_hook.py"))
        cls.hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.hook)

    def test_policy_timeout_default_and_clamp(self):
        for raw, want in ((None, 3.0), ("", 3.0), ("abc", 3.0), ("nan", 3.0), ("0", 1.0), ("0.2", 1.0), ("2.5", 2.5), ("4", 4.0), ("99", 4.0), ("-3", 1.0)):
            old = os.environ.pop("JEV_POLICY_TIMEOUT", None)
            if raw is not None:
                os.environ["JEV_POLICY_TIMEOUT"] = raw
            try:
                self.assertEqual(self.hook.policy_timeout(), want, repr(raw))
            finally:
                os.environ.pop("JEV_POLICY_TIMEOUT", None)
                if old is not None:
                    os.environ["JEV_POLICY_TIMEOUT"] = old

    def test_opt_in_gate_reads_only_a_small_regular_file_that_mentions_a_trigger(self):
        d = tempfile.mkdtemp(dir=TMP)
        good = os.path.join(d, "good.json")
        with open(good, "w") as f:
            f.write('{"v":1,"decisions":[{"trigger":{}}]}')
        none = os.path.join(d, "none.json")
        with open(none, "w") as f:
            f.write('{"v":1,"decisions":[]}')
        big = os.path.join(d, "big.json")
        with open(big, "w") as f:
            f.write('{"trigger":1,"pad":"%s"}' % ("x" * 20000))
        link = os.path.join(d, "link.json")
        os.symlink(good, link)
        fifo = os.path.join(d, "fifo.json")
        os.mkfifo(fifo)
        for path, want in ((good, True), (none, False), (big, False), (link, False), (fifo, False), (os.path.join(d, "missing.json"), False)):
            os.environ["JEV_POLICY_USER"] = path
            try:
                self.assertEqual(self.hook.policy_has_trigger(), want, os.path.basename(path))
            finally:
                os.environ.pop("JEV_POLICY_USER", None)


class PolicyHook(unittest.TestCase):
    NOTICE = ("Jev policy: a policy gate was not evaluated for this command (the helper is unavailable, the policy file is unusable, or it ran "
              "out of time). The reason is in the decision ledger.")

    def test_unreviewed_merge_asks_and_the_call_carries_class_facts_and_layers(self):
        log = os.path.join(TMP, "w1.log")
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub(log=log)), STUB_GH="unreviewed")
        p, _ = e.run("gh pr merge 12 --squash")
        self.assertEqual(decision_of(p), "ask", p.stderr)
        self.assertIn("Jev policy [pr-merge-gate/R1-unreviewed-merge]", reason_of(p))
        with open(log) as f:
            calls = [json.loads(l) for l in f]
        self.assertEqual(len(calls), 1, "exactly one kit_decide call")
        self.assertEqual((calls[0]["class"], calls[0]["facts"], calls[0]["layers"]), ("pr-merge-gate", {"gstack_reviewed": False}, ["user"]))
        self.assertTrue(300 <= calls[0]["budget_ms"] <= 3000, "the Worker is told how long it has: %r" % calls[0]["budget_ms"])
        self.assertEqual(e.gh_calls(), ["pr view 12 --json comments,reviews"])
        pr = policy_rows(e)
        self.assertEqual(len(pr), 1)
        self.assertEqual((pr[0]["decision"], pr[0]["rule"], pr[0]["decided_by"], pr[0]["enforced"], pr[0]["source"]), ("ask_user", "R1-unreviewed-merge", "jev", True, "server"))
        self.assertRegex(pr[0]["policy_version"], r"^[0-9a-f]{12}$")
        self.assertEqual(len([r for r in e.rows() if r["tool"] == "kit_guard_command"]), 1, "the guard still wrote its own row")

    def test_with_the_local_rules_on_the_policy_path_still_runs_beside_them(self):
        # local-first guard: the guard half of this command is settled by the local rules (no kit_guard_command call, a client-sourced
        # prefilter row); the policy half is untouched: one kit_decide call, the class's ask, its own server row
        log = os.path.join(TMP, "w1-local.log")
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub(log=log)), STUB_GH="unreviewed", JEV_GUARD_LOCAL=None)
        p, _ = e.run("gh pr merge 12 --squash")
        self.assertEqual(decision_of(p), "ask", p.stderr)
        self.assertIn("Jev policy [pr-merge-gate/R1-unreviewed-merge]", reason_of(p))
        with open(log) as f:
            self.assertEqual(len([json.loads(l) for l in f]), 1, "exactly one kit_decide call, and no guard call to log")
        guard = [r for r in e.rows() if r["tool"] == "kit_guard_command"]
        self.assertEqual([(r["decided_by"], r["source"], r["server_decision_id"]) for r in guard], [("prefilter", "client", None)])
        pr = policy_rows(e)
        self.assertEqual([(r["decision"], r["rule"], r["source"]) for r in pr], [("ask_user", "R1-unreviewed-merge", "server")])

    def test_reviewed_merge_passes_silently_in_a_comment_or_a_review(self):
        for state in ("reviewed", "reviewed_in_review"):
            e = Env([class_doc()], JEV_MCP_URL=url(start_stub()), STUB_GH=state)
            p, _ = e.run("gh pr merge 12")
            self.assertEqual((decision_of(p), p.stdout.strip()), ("none", ""), state)
            r = policy_rows(e)
            self.assertEqual([(x["decision"], x["rule"]) for x in r], [("proceed", "R3-reviewed-merge")], state)

    def test_no_pr_number_asks_gh_for_the_current_branch(self):
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub()), STUB_GH="reviewed")
        p, _ = e.run("gh pr merge --auto")
        self.assertEqual(decision_of(p), "none")
        self.assertEqual(e.gh_calls(), ["pr view --json comments,reviews"])

    def test_other_commands_do_not_fire(self):
        log = os.path.join(TMP, "w3.log")
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub(log=log)), STUB_GH="unreviewed")
        for cmd in ("gh pr view 12", "git merge main", "echo gh pr merge", 'git commit -m "gh pr merge"', "ls"):
            p, _ = e.run(cmd)
            self.assertEqual(decision_of(p), "none", cmd)
        self.assertEqual(e.gh_calls(), [])
        self.assertFalse(os.path.exists(log), "kit_decide never called")
        self.assertEqual([r for r in e.rows() if r["tool"] == "kit_decide"], [])

    def test_wrapped_merge_still_fires(self):
        for cmd in ("env X=1 gh pr merge 12", "GH_TOKEN=x gh pr merge 12", "time gh pr merge 12", 'bash -c "gh pr merge 12"', "cd /tmp && gh pr merge 12", "gh -R owner/repo pr merge 12"):
            e = Env([class_doc()], JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed")
            p, _ = e.run(cmd)
            self.assertEqual(decision_of(p), "ask", cmd)

    def test_stricter_wins_guard_deny_over_policy_allow(self):
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub()), STUB_GH="reviewed")
        p, _ = e.run("cat .env && gh pr merge 12")
        self.assertEqual(decision_of(p), "deny", p.stderr)
        self.assertIn("Jev guard", reason_of(p))
        self.assertEqual([x["decision"] for x in policy_rows(e)], ["proceed"])

    def test_the_model_saying_not_a_merge_proceeds(self):
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub(merges="0.02")), STUB_GH="unreviewed")
        p, _ = e.run("gh pr merge 12")
        self.assertEqual(decision_of(p), "none")
        self.assertEqual(policy_rows(e)[0]["rule"], "R2-not-a-merge")

    def test_provider_failure_applies_the_class_failure_rule_without_a_model_call(self):
        for state, code in (("fail", "client_network"), ("garbage", "client_parse"), ("wrongshape", "client_parse"), ("hang", "client_timeout")):
            log = os.path.join(TMP, "w-%s.log" % state)
            e = Env([class_doc()], JEV_MCP_URL=url(start_stub(log=log)), STUB_GH=state)
            p, dt = e.run("gh pr merge 12")
            self.assertEqual(decision_of(p), "ask", state)
            self.assertFalse(os.path.exists(log), "%s: no kit_decide call" % state)
            r = policy_rows(e)
            self.assertEqual([(x["decided_by"], x["fail_reason"], x["decision"]) for x in r], [("fail_closed", code, "ask_user")], state)
            self.assertLess(dt, 4.5, "%s: inside the hook budget" % state)

    def test_provider_failure_of_an_open_class_allows(self):
        e = Env([class_doc(open_class=True)], JEV_MCP_URL=url(start_stub()), STUB_GH="fail")
        p, _ = e.run("gh pr merge 12")
        self.assertEqual(decision_of(p), "none")
        self.assertEqual([(x["decided_by"], x["decision"]) for x in policy_rows(e)], [("fail_open", "proceed")])

    def test_worker_outage_follows_the_class(self):
        closed = Env([class_doc()], JEV_MCP_URL=url(start_stub("5xx")), STUB_GH="reviewed")
        p, _ = closed.run("gh pr merge 12")
        self.assertEqual(decision_of(p), "ask", "closed class asks when the Worker is down even though the PR is reviewed")
        self.assertEqual([(x["decided_by"], x["fail_reason"]) for x in policy_rows(closed)], [("fail_closed", "client_http_5xx")])
        opened = Env([class_doc(open_class=True)], JEV_MCP_URL=url(start_stub("5xx")), STUB_GH="unreviewed")
        p, _ = opened.run("gh pr merge 12")
        self.assertEqual(decision_of(p), "none", "an open class allows")

    def test_worker_rejection_asks_even_for_an_open_class(self):
        e = Env([class_doc(open_class=True)], JEV_MCP_URL=url(start_stub("4xx")), STUB_GH="reviewed")
        p, _ = e.run("gh pr merge 12")
        self.assertEqual(decision_of(p), "ask")
        self.assertEqual([(x["decided_by"], x["fail_reason"]) for x in policy_rows(e)], [("fail_closed", "client_rejected")])

    def test_helper_missing_fails_open_and_leaves_a_row(self):
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed", JEV_POLICY_HOOK=os.path.join(TMP, "no-such-helper.mjs"))
        p, _ = e.run("gh pr merge 12")
        self.assertEqual(decision_of(p), "none")
        self.assertEqual(notice_of(p), self.NOTICE, "a fail-closed class that silently allows tells the user")
        r = policy_rows(e)
        self.assertEqual([(x["decision"], x["decided_by"], x["fail_reason"], x["enforced"]) for x in r], [("allow", "fail_open", "client_config", True)])

    def test_a_helper_path_with_spaces_works_because_nothing_goes_through_a_shell(self):
        base = os.path.join(tempfile.mkdtemp(dir=TMP), "My Tools (v2)")
        os.makedirs(os.path.join(base, "scripts"))
        for n in ("jev-policy-hook.mjs", "jev-policy.mjs"):
            shutil.copy(os.path.join(ROOT, "scripts", n), os.path.join(base, "scripts", n))
        os.symlink(os.path.join(ROOT, "server"), os.path.join(base, "server"))
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed", JEV_POLICY_HOOK=os.path.join(base, "scripts", "jev-policy-hook.mjs"))
        p, _ = e.run("gh pr merge 12")
        self.assertEqual(decision_of(p), "ask", p.stderr)
        self.assertIn("Jev policy [pr-merge-gate/R1-unreviewed-merge]", reason_of(p))

    def test_no_trigger_in_the_user_layer_means_no_helper_process(self):
        marker = os.path.join(TMP, "helper-ran")
        script = os.path.join(TMP, "marker-helper.mjs")
        with open(script, "w") as f:
            f.write('import { writeFileSync } from "node:fs"; writeFileSync(%s, "ran"); console.log(JSON.stringify({ok:true,triggered:false}));\n' % json.dumps(marker))
        for classes in (None, [class_doc(trigger=False)]):
            e = Env(classes, JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed", JEV_POLICY_HOOK=script)
            p, _ = e.run("gh pr merge 12")
            self.assertEqual(decision_of(p), "none")
            self.assertFalse(os.path.exists(marker), "the helper never started")
        self.assertEqual(e.gh_calls(), [])

    def test_shadow_mode_never_asks_and_records_would_have(self):
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed", JEV_GUARD_MODE="shadow")
        p, _ = e.run("gh pr merge 12")
        self.assertEqual((decision_of(p), p.stdout.strip()), ("none", ""))
        self.assertIn("policy would ask", p.stderr)
        r = policy_rows(e)
        self.assertEqual([(x["decision"], x["enforced"], x["would_have"]) for x in r], [("ask_user", False, "ask")])

    def test_two_matching_classes_ask(self):
        e = Env([class_doc(), class_doc(cid="any-gh", command=("gh",))], JEV_MCP_URL=url(start_stub()), STUB_GH="reviewed")
        p, _ = e.run("gh pr merge 12")
        self.assertEqual(decision_of(p), "ask")
        self.assertIn("more than one policy gate", reason_of(p))

    def test_deny_effect_maps_to_a_hard_block(self):
        d = class_doc()
        d["trigger"]["effect"] = {"ask_user": "deny"}
        e = Env([d], JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed")
        p, _ = e.run("gh pr merge 12")
        self.assertEqual(decision_of(p), "deny")

    def test_a_repo_layer_cannot_add_a_trigger(self):
        e = Env([class_doc(trigger=False)], JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed")
        os.makedirs(os.path.join(e.repo, ".jev"))
        with open(os.path.join(e.repo, ".jev", "policy.json"), "w") as f:
            json.dump({"v": 1, "decisions": [class_doc()]}, f)
        p, _ = e.run("gh pr merge 12")
        self.assertEqual(decision_of(p), "none")
        self.assertEqual(e.gh_calls(), [])

    def test_hostile_commands_are_data_only(self):
        for i, cmd in enumerate(("gh pr merge 12; touch %s", "gh pr merge $(touch %s)", "gh pr merge 12 `touch %s`", "gh pr merge 12 && touch %s")):
            target = os.path.join(TMP, "pwned-%d" % i)
            e = Env([class_doc()], JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed")
            e.run(cmd % target)
            self.assertFalse(os.path.exists(target), cmd)
            # a clean "gh pr merge 12" followed by another command names PR 12; a substitution in an operand makes the target ambiguous
            self.assertEqual(e.gh_calls(), ["pr view 12 --json comments,reviews"] if cmd.startswith(("gh pr merge 12;", "gh pr merge 12 &&")) else [])
            for c in e.gh_calls():
                self.assertNotIn("touch", c)
                self.assertNotIn(target, c)

    def test_hostile_worker_cannot_put_text_in_the_policy_row(self):
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub("hostile")), STUB_GH="unreviewed")
        e.run("gh pr merge 12 --body top-secret-text")
        rows = policy_rows(e)
        self.assertTrue(rows)
        for r in rows:
            self.assertRegex(r["policy_version"], r"^[0-9a-f]{12}$", "the plan's own version, never the hostile reply's text")
        self.assertNotIn("ZXQ-HOSTILE-MARKER", e.text())
        self.assertNotIn("top-secret-text", e.text())

    def test_the_ledger_has_no_command_text_or_fact_values(self):
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed")
        e.run("gh pr merge 12 --body NEEDLE-IN-BODY")
        self.assertNotIn("NEEDLE-IN-BODY", e.text())
        self.assertNotIn("gstack-review: pass", e.text())
        self.assertNotIn(e.repo, e.text())


class PolicyHookTargets(unittest.TestCase):
    """Which PR the review provider asks about, end to end through the real hook (a stub gh records its argv)."""

    def gh_for(self, command, state="unreviewed"):
        log = os.path.join(TMP, "wl-%d.log" % abs(hash(command)))
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub(log=log)), STUB_GH=state)
        p, _ = e.run(command)
        return e, p, e.gh_calls(), os.path.exists(log)

    def test_a_flag_value_that_looks_like_a_number_is_never_the_pr(self):
        for cmd, want in (("gh pr merge --subject 12 99", "pr view 99 --json comments,reviews"), ("gh pr merge -b 12 99", "pr view 99 --json comments,reviews"),
                          ("gh pr merge --body 12 99", "pr view 99 --json comments,reviews"), ("gh pr merge --match-head-commit 123 99", "pr view 99 --json comments,reviews"),
                          ("gh pr merge 99 --repo other/repo", "pr view 99 --repo other/repo --json comments,reviews"),
                          ("gh pr merge https://github.com/o/r/pull/99", "pr view https://github.com/o/r/pull/99 --json comments,reviews")):
            _, p, calls, _ = self.gh_for(cmd)
            self.assertEqual(calls, [want], cmd)
            self.assertEqual(decision_of(p), "ask", cmd)

    def test_an_ambiguous_target_asks_without_asking_gh_or_the_model(self):
        for cmd in ("gh pr merge feature-x", "gh pr merge #99", "gh pr merge 1234567890", "gh pr merge 12 99", "cd ../other && gh pr merge 99",
                    "GH_REPO=other/repo gh pr merge 99", "gh pr merge --repo $(id)/x 5"):
            e, p, calls, called = self.gh_for(cmd, state="reviewed")  # reviewed: an ask here can only come from the failure rule
            self.assertEqual(calls, [], cmd)
            self.assertFalse(called, "%s: no kit_decide call" % cmd)
            self.assertEqual(decision_of(p), "ask", cmd)
            self.assertEqual([(x["decided_by"], x["fail_reason"]) for x in policy_rows(e)], [("fail_closed", "client_input")], cmd)

    def test_a_reviewed_other_pr_does_not_clear_the_merge(self):
        # the stub reports every PR it is asked about as reviewed; the command names a PR through a shape gh cannot be asked about safely
        _, p, calls, _ = self.gh_for("gh pr merge feature-x", state="reviewed")
        self.assertEqual(decision_of(p), "ask")
        self.assertEqual(calls, [])


class PolicyHookEveryMerge(unittest.TestCase):
    """Every merge in the command is read, and a merge that is not the whole command cannot borrow the current branch's review.
    The stub gh answers 'reviewed' for PR 1 and for the current branch (`pr view --json`), 'not reviewed' for everything else."""

    def run_cmd(self, command, prs="1 --json"):
        log = os.path.join(TMP, "em-%d.log" % abs(hash(command)))
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub(log=log)), STUB_GH="by_pr", STUB_GH_PRS=prs)
        p, _ = e.run(command)
        return e, p, e.gh_calls(), os.path.exists(log)

    def test_a_second_merge_is_read_too(self):
        for cmd in ("gh pr merge 1 && gh pr merge 2", "gh pr merge 1; gh pr merge 2 --squash", "gh pr merge 2 && gh pr merge 1"):
            _, p, calls, _ = self.run_cmd(cmd)
            self.assertEqual(sorted(calls), ["pr view 1 --json comments,reviews", "pr view 2 --json comments,reviews"], cmd)
            self.assertEqual(decision_of(p), "ask", "%s: PR 2 is not reviewed, so the merge asks (it passed silently before)" % cmd)
        _, p, calls, _ = self.run_cmd("gh pr merge 1 && gh pr merge 2", prs="1 2")
        self.assertEqual((decision_of(p), p.stdout.strip(), len(calls)), ("none", "", 2), "all reviewed: allowed")
        e, p, calls, called = self.run_cmd("gh pr merge 1 && gh pr merge", prs="1 --json")
        self.assertEqual((decision_of(p), calls, called), ("ask", [], False), "a bare merge beside another: ambiguous, nothing asked")

    def test_a_merge_with_no_pr_is_trusted_only_when_it_is_the_whole_command(self):
        for cmd in ("gh pr checkout 2 && gh pr merge --squash", "git checkout other && gh pr merge", "echo 2 | xargs gh pr merge", "xargs -a prs.txt gh pr merge",
                    "git remote set-url origin https://example.com/o/other.git && gh pr merge 1", "gh repo set-default o/other && gh pr merge 1",
                    "git config remote.origin.url https://example.com/o/other.git && gh pr merge 1", "env GH_RE''PO=o/r gh pr merge 1", "X=GH_; export ${X}REPO=o/r; gh pr merge 1"):
            e, p, calls, called = self.run_cmd(cmd)
            self.assertEqual((decision_of(p), calls, called), ("ask", [], False), cmd)
            self.assertEqual([(x["decided_by"], x["fail_reason"]) for x in policy_rows(e)], [("fail_closed", "client_input")], cmd)
        _, p, calls, _ = self.run_cmd("gh pr merge --auto")
        self.assertEqual((decision_of(p), calls), ("none", ["pr view --json comments,reviews"]), "a lone bare merge still reads the current branch")
        _, p, calls, _ = self.run_cmd("gh pr checkout 2 && gh pr merge 1")
        self.assertEqual((decision_of(p), calls), ("none", ["pr view 1 --json comments,reviews"]), "an explicit number survives a checkout before it")


class PolicyNotice(unittest.TestCase):
    """A fail-closed class that fails open because the machinery is down tells the USER, once, in fixed words."""
    NOTICE = PolicyHook.NOTICE

    def test_closed_class_helper_missing_unusable_layer_and_timeout_all_notify(self):
        hang = os.path.join(TMP, "hang-helper.mjs")
        with open(hang, "w") as f:
            f.write("setTimeout(() => {}, 20000);\n")
        for label, over, classes in (("helper missing", dict(JEV_POLICY_HOOK=os.path.join(TMP, "none.mjs")), [class_doc()]),
                                     ("helper too slow", dict(JEV_POLICY_HOOK=hang, JEV_POLICY_TIMEOUT="1"), [class_doc()]),
                                     ("layer unusable", {}, "typo")):
            e = Env([class_doc()] if classes == "typo" else classes, JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed", **over)
            if classes == "typo":
                with open(e.layer, "w") as f:
                    json.dump({"v": 1, "decisions": "trigger"}, f)  # still mentions a trigger, but no longer valid
            if label == "layer unusable":
                with open(e.layer.replace("policy.json", "broken-json.json"), "w") as f:
                    f.write('{"v":1,"decisions":[{"trigger": ')  # truncated: not even JSON
                e.env["JEV_POLICY_USER"] = e.layer.replace("policy.json", "broken-json.json")
                p, _ = e.run("gh pr merge 12")
                self.assertEqual((decision_of(p), notice_of(p)), ("none", self.NOTICE), "a layer that is not JSON still tells the user")
                e.env["JEV_POLICY_USER"] = e.layer
            p, _ = e.run("gh pr merge 12")
            self.assertEqual(decision_of(p), "none", label)
            self.assertEqual(notice_of(p), self.NOTICE, label)
            self.assertNotIn("gh pr merge", p.stdout + p.stderr, "%s: the notice carries no command text" % label)
            self.assertNotIn(e.home, p.stdout, "%s: no path in the notice" % label)
            rows = [x["decided_by"] for x in policy_rows(e)]
            self.assertTrue(rows and set(rows) == {"fail_open"}, label)

    def test_an_open_class_does_not_notify(self):
        e = Env([class_doc(open_class=True)], JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed", JEV_POLICY_HOOK=os.path.join(TMP, "none.mjs"))
        p, _ = e.run("gh pr merge 12")
        self.assertEqual(p.stdout.strip(), "", "every triggered class fails open: silence is what the user declared")
        self.assertEqual([x["fail_reason"] for x in policy_rows(e)], ["client_config"], "the ledger still records it")

    def test_notice_rides_along_with_a_stricter_decision_and_never_in_shadow(self):
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed", JEV_POLICY_HOOK=os.path.join(TMP, "none.mjs"))
        p, _ = e.run("cat .env && gh pr merge 12")
        self.assertEqual(decision_of(p), "deny")
        self.assertEqual(notice_of(p), self.NOTICE)
        s, _ = e.run("gh pr merge 12", JEV_GUARD_MODE="shadow")
        self.assertEqual(s.stdout.strip(), "", "shadow mode never enforces, so there is nothing to warn about")

    def test_no_notice_when_nothing_failed(self):
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub()), STUB_GH="reviewed")
        p, _ = e.run("gh pr merge 12")
        self.assertEqual(p.stdout.strip(), "")


class ConcludeTimeout(unittest.TestCase):
    """The policy thread that does not finish inside its deadline (defence in depth; the helper and the Worker call have their own
    timeouts, so it should not happen): the hook still answers, fails open, and tells the user only when it enforces."""

    def run_conclude(self, mode, layer):
        import contextlib
        import importlib.util
        import io
        os.environ["JEV_POLICY_USER"] = layer
        try:
            spec = importlib.util.spec_from_file_location("jev_guard_hook_ct_%s" % mode, os.path.join(ROOT, "hooks", "jev_guard_hook.py"))
            hook = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(hook)
            hook.MODE = mode

            class Hung(object):
                outcome = None
                deadline = time.monotonic() - 10

                def join(self, _t):
                    return None
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), self.assertRaises(SystemExit):
                hook.conclude(hook.Outcome("allow"), Hung())
            return out.getvalue(), err.getvalue()
        finally:
            os.environ.pop("JEV_POLICY_USER", None)

    def test_notice_only_when_enforcing_and_a_class_may_fail_closed(self):
        d = tempfile.mkdtemp(dir=TMP)
        closed, opened = os.path.join(d, "closed.json"), os.path.join(d, "open.json")
        for path, doc in ((closed, class_doc()), (opened, class_doc(open_class=True))):
            with open(path, "w") as f:
                json.dump({"v": 1, "decisions": [doc]}, f)
        out, err = self.run_conclude("enforce", closed)
        self.assertEqual(json.loads(out)["systemMessage"], PolicyHook.NOTICE)
        self.assertIn("policy gate was not evaluated", err)
        for mode, layer in (("shadow", closed), ("enforce", opened)):
            out, err = self.run_conclude(mode, layer)
            self.assertEqual((out, err), ("", ""), "%s / %s" % (mode, os.path.basename(layer)))


class RuntimeChoice(unittest.TestCase):
    def test_node_first_then_bun_then_nothing(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("jev_guard_hook_rt", os.path.join(ROOT, "hooks", "jev_guard_hook.py"))
        hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hook)
        real = hook.shutil.which
        try:
            hook.shutil.which = lambda n: {"node": "/n/node", "bun": "/b/bun"}.get(n)
            self.assertEqual(hook.policy_runtime(), "/n/node")
            hook.shutil.which = lambda n: {"bun": "/b/bun"}.get(n)
            self.assertEqual(hook.policy_runtime(), "/b/bun")
            hook.shutil.which = lambda n: None
            self.assertIsNone(hook.policy_runtime())
        finally:
            hook.shutil.which = real

    def test_the_helper_runs_under_bun_when_node_is_absent(self):
        bun = shutil.which("bun")
        if not bun:
            self.skipTest("bun not installed")
        d = tempfile.mkdtemp(dir=TMP)
        os.symlink(bun, os.path.join(d, "bun"))
        for tool in ("python3", "bash", "git", "dirname"):
            os.symlink(shutil.which(tool), os.path.join(d, tool))
        os.symlink(os.path.join(TMP, "bin", "gh"), os.path.join(d, "gh"))
        e = Env([class_doc()], JEV_MCP_URL=url(start_stub()), STUB_GH="unreviewed")
        e.env["PATH"] = d
        p, _ = e.run("gh pr merge 12")
        self.assertEqual(decision_of(p), "ask", p.stderr)
        self.assertIn("Jev policy [pr-merge-gate/R1-unreviewed-merge]", reason_of(p))


if __name__ == "__main__":
    unittest.main()
