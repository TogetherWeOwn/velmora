#!/usr/bin/env python3
"""Tests for bundle_size.py. Run: python3 -I tools/test_bundle_size.py"""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("bundle_size", os.path.join(_HERE, "bundle_size.py"))
bs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bs)

# What wrangler 4.161.0 printed for a real dry run (2,905,738 B wasm +
# 62,623 B shim.js = 2,968,361 B), with its colour codes.
LOG = "\x1b[2m...\x1b[0m\nTotal Upload: 2898.79 KiB / gzip: 1221.25 KiB\nYour Worker has access to\n"


def outdir(tmp, files):
    for name, n in files.items():
        with open(os.path.join(tmp, name), "wb") as f:
            f.write(b"\0" * n)
    return tmp


class Config(unittest.TestCase):
    def test_drops_only_the_top_level_build_table(self):
        src = 'name = "w"\nmain = "build/worker/shim.mjs"\n\n[build]\ncommand = "bash bundle.sh"\n\n[limits]\ncpu_ms = 1\n[env.dev.build]\ncommand = "x"\n'
        got = bs.strip_build_table(src)
        self.assertNotIn("bundle.sh", got)
        self.assertIn("[limits]\ncpu_ms = 1", got)
        self.assertIn('main = "build/worker/shim.mjs"', got)
        self.assertIn("[env.dev.build]", got)

    def test_shipped_wrangler_toml_has_one_build_table(self):
        with open(os.path.join(_HERE, "..", "wrangler.toml")) as f:
            got = bs.strip_build_table(f.read())
        self.assertNotIn("[build]", [line.strip() for line in got.split("\n")])
        self.assertNotIn('command = "cargo install -q --locked worker-build', got)
        # entry.mjs wraps the Rust Worker (its named entrypoints, #186).
        self.assertIn('main = "entry.mjs"', got)


class Measure(unittest.TestCase):
    def test_real_dry_run_numbers(self):
        with tempfile.TemporaryDirectory() as tmp:
            outdir(tmp, {"abc-index_bg.wasm": 2_905_738, "shim.js": 62_623, "shim.js.map": 77_470, "README.md": 111})
            rec, errors = bs.measure(tmp, LOG)
        self.assertEqual(errors, [])
        self.assertEqual(rec["upload_bytes"], 2_968_361)
        self.assertEqual(rec["wasm_bytes"], 2_905_738)
        self.assertEqual(rec["gzip_bytes"], round(1221.25 * 1024))
        self.assertEqual(sorted(rec["files"]), ["abc-index_bg.wasm", "shim.js"])

    def test_at_the_limit_passes_one_byte_over_fails(self):
        for n, ok in ((bs.LIMIT_BYTES, True), (bs.LIMIT_BYTES + 1, False)):
            log = f"Total Upload: {n / 1024:.2f} KiB / gzip: 1.00 KiB\n"
            with tempfile.TemporaryDirectory() as tmp:
                # Sparse: the size counts, not the content.
                with open(os.path.join(tmp, "x.wasm"), "wb") as f:
                    f.truncate(n)
                _, errors = bs.measure(tmp, log)
            self.assertEqual(errors == [], ok, (n, errors))

    def test_large_bundle_below_the_limit_never_blocks(self):
        n = 40 * 1024 * 1024
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "x.wasm"), "wb") as f:
                f.truncate(n)
            _, errors = bs.measure(tmp, f"Total Upload: {n / 1024:.2f} KiB / gzip: 9.00 KiB\n")
        self.assertEqual(errors, [])

    def test_missing_total_line_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            outdir(tmp, {"shim.js": 10})
            _, errors = bs.measure(tmp, "no such line\n")
        self.assertEqual(len(errors), 1)
        self.assertIn("Total Upload", errors[0])

    def test_total_that_disagrees_with_the_outdir_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            outdir(tmp, {"shim.js": 62_623})
            _, errors = bs.measure(tmp, LOG)
        self.assertEqual(len(errors), 1)
        self.assertIn("changed", errors[0])

    def test_empty_outdir_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, errors = bs.measure(tmp, "Total Upload: 0.00 KiB / gzip: 0.00 KiB\n")
        self.assertTrue(any("no module" in e for e in errors))


def rec(n, sha=""):
    return {"upload_bytes": n, "wasm_bytes": n - 60_000, "gzip_bytes": n // 2, "sha": sha}


class Report(unittest.TestCase):
    def test_no_base(self):
        md, warnings = bs.report(rec(3_000_000))
        self.assertIn("3,000,000 bytes", md)
        self.assertIn("No measurement from main", md)
        self.assertEqual(warnings, [])

    def test_small_growth_and_shrink_do_not_warn(self):
        for d in (0, 29_000, -500_000):
            md, warnings = bs.report(rec(3_000_000 + d), rec(3_000_000, "a" * 40))
            self.assertEqual(warnings, [], d)
            self.assertIn(f"{d:+,} bytes", md)
            self.assertIn("aaaaaaaaaaaa", md)

    def test_growth_over_one_percent_warns(self):
        # 1 % of 1,000,000 is 10,000: under 50,000 bytes, still warns.
        _, warnings = bs.report(rec(1_010_001), rec(1_000_000))
        self.assertEqual(len(warnings), 1)
        _, warnings = bs.report(rec(1_010_000), rec(1_000_000))
        self.assertEqual(warnings, [])

    def test_growth_over_50000_bytes_warns_with_the_cost(self):
        # 50,001 of 10 MB is 0.5 %: under 1 %, warns on bytes.
        _, warnings = bs.report(rec(10_050_001), rec(10_000_000))
        self.assertEqual(len(warnings), 1)
        self.assertIn("10.5 ms per MB", warnings[0])
        self.assertIn("about 0.5 ms here", warnings[0])
        _, warnings = bs.report(rec(10_050_000), rec(10_000_000))
        self.assertEqual(warnings, [])

    def test_limit_is_64_mib(self):
        self.assertEqual(bs.LIMIT_BYTES, 67_108_864)

    def test_base_from_another_commit_is_named(self):
        md, warnings = bs.report(rec(3_100_000), rec(3_000_000, "a" * 40), "b" * 40)
        self.assertIn("not this PR's base bbbbbbbbbbbb", md)
        self.assertTrue(warnings[0].startswith("main's measurement is from aaaaaaaaaaaa"))
        md, warnings = bs.report(rec(3_100_000), rec(3_000_000, "a" * 40), "a" * 40)
        self.assertNotIn("not this PR's base", md)
        self.assertTrue(warnings[0].startswith("Worker upload grew"))

    def test_cost_in_the_line(self):
        md, _ = bs.report(rec(4_000_000), rec(3_000_000))
        self.assertIn("about +10.5 ms per request on a new isolate", md)


class Cli(unittest.TestCase):
    def run_cli(self, *args, env=None):
        full = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
        full.update(env or {})
        return subprocess.run(
            [sys.executable, "-I", os.path.join(_HERE, "bundle_size.py"), *args],
            capture_output=True, text=True, env=full,
        )

    def test_measure_then_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            os.mkdir(out)
            outdir(out, {"abc-index_bg.wasm": 2_905_738, "shim.js": 62_623})
            log = os.path.join(tmp, "log")
            with open(log, "w") as f:
                f.write(LOG)
            cur = os.path.join(tmp, "size.json")
            r = self.run_cli("measure", out, log, cur)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            base = os.path.join(tmp, "base.json")
            with open(base, "w") as f:
                json.dump(rec(2_900_000, "b" * 40), f)
            summary = os.path.join(tmp, "summary.md")
            r = self.run_cli("report", cur, base, env={"GITHUB_STEP_SUMMARY": summary})
            self.assertEqual(r.returncode, 0)
            self.assertIn("+68,361 bytes", r.stdout)
            self.assertIn("::warning title=Worker size grew::", r.stdout)
            with open(summary) as f:
                md = f.read()
            self.assertIn("+68,361 bytes", md)
            self.assertNotIn("::warning", md)
            # A missing or empty base file is reported, never an error.
            empty = os.path.join(tmp, "empty.json")
            open(empty, "w").close()
            for b in (os.path.join(tmp, "nope.json"), empty):
                r = self.run_cli("report", cur, b, "c" * 40)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn("No measurement from main", r.stdout)

    def test_measure_over_limit_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            os.mkdir(out)
            n = bs.LIMIT_BYTES + 4096
            with open(os.path.join(out, "x.wasm"), "wb") as f:
                f.truncate(n)
            log = os.path.join(tmp, "log")
            with open(log, "w") as f:
                f.write(f"Total Upload: {n / 1024:.2f} KiB / gzip: 1.00 KiB\n")
            r = self.run_cli("measure", out, log, os.path.join(tmp, "s.json"))
            self.assertEqual(r.returncode, 1)
            self.assertIn("::error::", r.stdout)
            self.assertIn("64 MiB", r.stdout)


if __name__ == "__main__":
    unittest.main()
