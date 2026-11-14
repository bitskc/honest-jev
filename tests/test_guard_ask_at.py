"""JEV_GUARD_ASK_AT parsing in hooks/jev_guard_hook.py matches parseAskAt in hooks/omp/jev-guard.ts.

Run: python3 -m unittest tests/test_guard_ask_at.py
Pure function only: no network, no command executed.
"""
import importlib.util
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("jev_guard_hook", os.path.join(ROOT, "hooks", "jev_guard_hook.py"))
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


class ParseAskAt(unittest.TestCase):
    def test_in_range_numbers_pass_through(self):
        self.assertEqual(hook.parse_ask_at("0.4"), 0.4)
        self.assertEqual(hook.parse_ask_at("1"), 1.0)
        self.assertEqual(hook.parse_ask_at(" 0.65 "), 0.65)

    def test_range_boundaries_are_inclusive(self):
        self.assertEqual(hook.parse_ask_at("0"), 0.0)
        self.assertEqual(hook.parse_ask_at("1.0"), 1.0)
        self.assertEqual(hook.parse_ask_at(".5"), 0.5)
        self.assertEqual(hook.parse_ask_at("5e-1"), 0.5)

    def test_unset_or_blank_falls_back_to_default(self):
        self.assertIsNone(hook.parse_ask_at(None))
        self.assertIsNone(hook.parse_ask_at(""))
        self.assertIsNone(hook.parse_ask_at("   "))

    def test_out_of_range_falls_back_to_default(self):
        for raw in ("-0.1", "1.5", "2", "-1", "1.0001", "1e3"):
            with self.subTest(raw=raw):
                self.assertIsNone(hook.parse_ask_at(raw))

    def test_nan_and_infinity_fall_back_to_default(self):
        for raw in ("nan", "NaN", "inf", "-inf", "Infinity", "-Infinity", "1e400"):
            with self.subTest(raw=raw):
                self.assertIsNone(hook.parse_ask_at(raw))

    def test_unparsable_falls_back_to_default(self):
        # Python float() takes 0_5, 1_0 and 1_0.5; omp Number() takes 0x1, 0b1, 0o7. All must fall back, the same way in both hooks.
        for raw in ("nope", "0.5abc", "0_5", "0x1", "0b1", "1,0", "--1", "0x10", "0o7", "0B1", "0O7", "0X10", "1_0", "1_0.5"):
            with self.subTest(raw=raw):
                self.assertIsNone(hook.parse_ask_at(raw))


if __name__ == "__main__":
    unittest.main()
