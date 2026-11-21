"""Tests of report.py's rows-written check: python3 -I -m unittest discover -s bench"""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import report  # noqa: E402


def labels(pairs):
    return {k: {"d1_rows_written_native": n, "d1_rows_written": d} for k, (n, d) in pairs.items()}


class RowsWrittenCheck(unittest.TestCase):
    def test_equal_counts_pass(self):
        chk = report.rows_written_check(labels({"setup": (7, 7), "stage:big:post": (19, 19)}))
        self.assertTrue(chk["ok"])
        self.assertEqual(chk["rows_off"], 0)
        self.assertEqual(chk["labels_differing"], {})

    def test_one_sampled_row_is_noise(self):
        chk = report.rows_written_check(labels({"stage:big:verify": (12, 11), "stage:mix:verify": (5, 5)}))
        self.assertTrue(chk["ok"])
        self.assertEqual(chk["rows_off"], 1)
        self.assertIn("within the noise", report.check_line(chk))

    def test_differences_add_up_across_labels(self):
        # +1 and -1 on two labels cancel in the totals but are 2 rows off.
        chk = report.rows_written_check(labels({"a": (3, 2), "b": (2, 3)}))
        self.assertFalse(chk["ok"])
        self.assertEqual(chk["rows_off"], 2)
        self.assertEqual(chk["native"], chk["d1"])

    def test_counters_off_in_the_replay_fails(self):
        # OPT-14's run: the replay without the counters, 20 of 36 labels lower.
        chk = report.rows_written_check(labels({"stage:big:post": (1914, 1814), "setup": (6, 6)}))
        self.assertFalse(chk["ok"])
        self.assertIn("FAILED", report.check_line(chk))


if __name__ == "__main__":
    unittest.main()
