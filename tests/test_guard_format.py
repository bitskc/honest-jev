"""The Claude Code guard hook's prompt text, against the fixture the omp hook's test (tests/guard-format-omp.test.ts) reads too:
both hooks must say the same words. Run: python3 -m unittest tests.test_guard_format  (from the repo root), or python3 tests/test_guard_format.py"""
import importlib.util
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(ROOT, "tests", "fixtures", "guard-format.json"), encoding="utf-8") as f:
    FX = json.load(f)
POLICY = "Jev policy [pr-merge-gate/R1-unreviewed-merge]: ask the user first."


def load_hook():
    spec = importlib.util.spec_from_file_location("jev_guard_hook_format", os.path.join(ROOT, "hooks", "jev_guard_hook.py"))
    hook = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(hook)
    return hook


class GuardFormat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hook = load_hook()

    def test_next_lines_are_the_fixtures(self):
        self.assertEqual(self.hook.NEXT_SAFER, FX["next_safer"])
        self.assertEqual(self.hook.NEXT_ASK, FX["next_ask"])

    def test_guard_replies(self):
        h = self.hook
        for c in FX["cases"]:
            with self.subTest(c["name"]):
                m = h.guard_msg(c["reply"])
                self.assertEqual(h.render_msg(m, "ask").split("\n")[0], c["title"])
                self.assertEqual("\n".join(m["body"]), c["message"])
                self.assertEqual(h.render_msg(m, "declined", True), c["declined"])
                self.assertEqual(h.render_msg(m, "needs approval", True), c["needs_approval"])
                self.assertEqual(h.render_msg(m, "block", True), c["block"])
                both = h.join_msgs([m, h.policy_msg(POLICY)])
                self.assertEqual("\n".join(both["body"]), c["both_message"])

    def test_hook_messages(self):
        h = self.hook
        for c in FX["hook_messages"]:
            with self.subTest(c["name"]):
                m = h.hook_msg(c["label"], c["why"])
                self.assertEqual(h.render_msg(m, "ask").split("\n")[0], c["title"])
                self.assertEqual("\n".join(m["body"]), c["message"])
                self.assertEqual(h.render_msg(m, "declined", True), c["declined"])

    def test_policy_reason_is_untouched(self):
        h = self.hook
        p = FX["policy_only"]
        m = h.policy_msg(p["reason"])
        self.assertEqual(h.render_msg(m, "ask").split("\n")[0], p["title"])
        self.assertEqual("\n".join(m["body"]), p["message"])
        self.assertEqual(h.render_msg(m, "declined", True), p["declined"])
        self.assertEqual(h.render_msg(m, "needs approval", True), p["needs_approval"])

    def test_a_prompt_is_at_most_three_lines_before_next_and_the_title_has_no_backticks(self):
        h = self.hook
        for c in FX["cases"]:
            lines = h.render_msg(h.guard_msg(c["reply"]), "block", True).split("\n")
            self.assertLessEqual(len(lines), 4)
            self.assertNotIn("`", lines[0])
            self.assertEqual(len([l for l in lines if l.startswith("Next:")]), 1)

    def test_notices_are_one_short_line(self):
        h = self.hook
        for n in [h.LOCAL_NOTICE, h.LOCAL_DOWN_NOTICE] + list(h.TRUST_NOTICES.values()):
            self.assertTrue(n.startswith("Jev guard · "), n)
            self.assertNotIn("\n", n)
            self.assertLessEqual(len(n), 220)


if __name__ == "__main__":
    unittest.main()
