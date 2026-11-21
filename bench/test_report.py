"""Tests of report.py's rows-written check: python3 -I -m unittest discover -s bench -p 'test_*.py'

testdata/run is a full local run of main (counts.json, and d1.json without
its statement lists) in which the native meter and D1 agree on every label.
"""
import contextlib
import io
import json
import shutil
import sys
import tempfile
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

    def test_one_row_is_within_the_tolerance(self):
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

    def test_replay_with_the_counters_off_fails(self):
        # The replay without the usage counters: lower on most labels.
        chk = report.rows_written_check(labels({"stage:big:post": (1914, 1814), "setup": (6, 6)}))
        self.assertFalse(chk["ok"])
        self.assertIn("FAILED", report.check_line(chk))

    def test_nothing_to_compare_fails(self):
        for case in ({}, labels({"setup": (0, 0)})):
            chk = report.rows_written_check(case)
            self.assertFalse(chk["ok"])
            self.assertIn("nothing to compare", report.check_line(chk))


class ReportRun(unittest.TestCase):
    """report.py on a run directory: the report is written, then the run
    fails when the check fails."""

    def fixture(self, name="run"):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        run = tmp / name
        shutil.copytree(HERE / "testdata" / "run", run)
        return run

    def run_report(self, shift, empty=False, run=None):
        run = run or self.fixture()
        d1 = json.loads((run / "d1.json").read_text())
        for label, n in shift.items():
            d1["by_label"][label]["d1_rows_written_replay"] -= n
        if empty:
            d1["by_label"] = {}
        (run / "d1.json").write_text(json.dumps(d1))
        code = 0
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                report.main([str(run), "--name", "fixture"])
            except SystemExit as e:
                code = e.code
        results = json.loads((run / "results.json").read_text())
        return code, results, (run / "results.md").read_text()

    def test_agreeing_run_passes(self):
        code, results, md = self.run_report({})
        self.assertIn(code, (0, None))
        self.assertTrue(results["rows_written_check"]["ok"])
        self.assertIn("equals D1's count on all 36 labels", md)

    def test_one_row_apart_passes(self):
        code, results, _ = self.run_report({"stage:tiny:verify": 1})
        self.assertIn(code, (0, None))
        self.assertEqual(results["rows_written_check"]["rows_off"], 1)

    def test_two_rows_apart_fails_after_writing_the_report(self):
        code, results, md = self.run_report({"stage:tiny:verify": 1, "op:put_tiny": 1})
        self.assertEqual(code, 1)
        self.assertFalse(results["rows_written_check"]["ok"])
        self.assertIn("FAILED, rows-written check", md)

    def test_empty_replay_fails_after_writing_the_report(self):
        code, results, md = self.run_report({}, empty=True)
        self.assertEqual(code, 1)
        self.assertFalse(results["rows_written_check"]["ok"])
        self.assertEqual(results["rows_written_check"]["d1"], 0)
        self.assertIn("FAILED, rows-written check", md)

    def test_compare_flags_a_failed_check(self):
        good = self.fixture("good")
        bad = self.fixture("bad")
        self.assertIn(self.run_report({}, run=good)[0], (0, None))
        self.assertEqual(self.run_report({"stage:tiny:verify": 1, "op:put_tiny": 1}, run=bad)[0], 1)
        out = good.parent / "compare.md"
        report.main(["--compare", str(good), str(bad), "--out", str(out)])
        text = out.read_text()
        self.assertIn("the rows-written check of fixture FAILED (2 rows apart, allowed 1)", text)
        self.assertEqual(text.count("rows-written check of"), 1)


if __name__ == "__main__":
    unittest.main()
