#!/usr/bin/env python3
"""Run the workflow's deploy switch, bundle floor, and rollback scripts locally."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_deploy_config import CI_YML, ShellStep, read

PYTHON_CALL = "python3 -I - <<'PY'"
SHA = "a" * 40
VERSION = "10000000-0000-4000-8000-000000000000"
PREVIOUS = "20000000-0000-4000-8000-000000000000"
DEPLOYED = "30000000-0000-4000-8000-000000000000"


def extract(step, keys):
    return ShellStep(read(CI_YML), step, keys)


def run(args, script, cwd, **env):
    return subprocess.run(
        args, input=script, cwd=cwd, env={"PATH": os.environ.get("PATH", os.defpath), **env},
        text=True, capture_output=True, timeout=30, check=False,
    )


class DeploySwitchesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.step = extract("- name: Check the deploy switches", ["if", "id", "env", "run"])

    def check(self, level=b"0\n", **env):
        with tempfile.TemporaryDirectory() as tmp:
            floor = Path(tmp, "floor-level")
            if level is not None:
                floor.write_bytes(level)
            output = Path(tmp, "output")
            result = run(
                [sys.executable, "-I", "-"], self.step.python_script(PYTHON_CALL), tmp,
                GITHUB_SHA=SHA, FLOOR_LEVEL_FILE=str(floor), GITHUB_OUTPUT=str(output), **env,
            )
            return result, output.read_text() if output.exists() else None

    def refused(self, message, **options):
        result, output = self.check(**options)
        self.assertEqual(result.returncode, 1)
        self.assertIn(message, result.stdout + result.stderr)
        self.assertIsNone(output)

    def test_freeze_unset_empty_or_equal(self):
        for options, message in (
            ({}, "off"),
            ({"VELMORA_DEPLOY_FREEZE": ""}, "off"),
            ({"VELMORA_DEPLOY_FREEZE": SHA}, "on, this commit is the one allowed"),
        ):
            result, output = self.check(**options)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"deploy freeze: {message}\n", result.stdout)
            self.assertEqual(output, "migrations=on\nfloor_version=\n")

    def test_freeze_checked_first(self):
        other = "b" * 40
        self.refused(f"::error::deploy frozen: only commit {other} may deploy; this run is {SHA}",
                     level=None, VELMORA_DEPLOY_FREEZE=other)
        for freeze in ("A" * 40, "a" * 39, SHA + "\n"):
            self.refused("VELMORA_DEPLOY_FREEZE must be unset or a full 40-hex commit id",
                         level=None, VELMORA_DEPLOY_FREEZE=freeze)

    def test_floor_invalid(self):
        for level in (None, b"", b" 1", b"1\n\n", b"1\r\n", b"-1", b"nan"):
            self.refused("the bundle has no valid floor level", level=level)
        for minimum in (" 1", "-1", "1\n", "1.5", "²"):
            self.refused("VELMORA_FLOOR_MIN must be unset or a whole number",
                         VELMORA_FLOOR_MIN=minimum)

    def test_floor_comparison(self):
        for level in (b"02", b"10\n"):
            result, output = self.check(level=level, VELMORA_FLOOR_MIN="002")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"floor level of this bundle: {int(level)}; required minimum: 2", result.stdout)
            self.assertEqual(output, "migrations=on\nfloor_version=\n")
        self.refused("bundle floor level 1 is below VELMORA_FLOOR_MIN 2; refusing to deploy",
                     level=b"1\n", VELMORA_FLOOR_MIN="2")

    def test_floor_version_and_migrations_outputs(self):
        for setting, expected in (("", "on"), ("on", "on"), ("off", "off")):
            result, output = self.check(VELMORA_CATALOGUE_MIGRATIONS=setting, VELMORA_FLOOR_VERSION=VERSION)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"rollback floor version: {VERSION}\n", result.stdout)
            self.assertIn(f"catalogue migrations: {expected}\n", result.stdout)
            self.assertEqual(output, f"migrations={expected}\nfloor_version={VERSION}\n")
        self.refused("VELMORA_FLOOR_VERSION must be unset or a lowercase version id (UUID)",
                     VELMORA_FLOOR_VERSION="bad")
        self.refused("VELMORA_CATALOGUE_MIGRATIONS must be unset, on or off",
                     VELMORA_CATALOGUE_MIGRATIONS="OFF")


class BuildFloorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.step = extract("- name: Write the floor level beside the bundle", ["if", "working-directory", "run"])

    def check(self, source):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "build").mkdir()
            (root / "src/lib.rs").write_text(source)
            output = root / "build/floor-level"
            result = run([sys.executable, "-I", "-"], self.step.python_script(PYTHON_CALL), tmp)
            return result, output.read_bytes() if output.exists() else None

    def test_shipped_constant(self):
        result, output = self.check(read(Path(__file__).resolve().parents[1] / "src/lib.rs"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "floor level: 0\n")
        self.assertEqual(output, b"0\n")

    def test_missing_or_duplicate_constant(self):
        for source in ("", "pub const FLOOR_LEVEL: u32 = 0;\npub const FLOOR_LEVEL: u32 = 1;\n"):
            result, output = self.check(source)
            self.assertEqual(result.returncode, 1)
            self.assertIn("expected exactly one FLOOR_LEVEL constant in src/lib.rs", result.stderr)
            self.assertIsNone(output)


class RollbackTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.step = extract("- id: rollback", ["name", "if", "working-directory", "env", "run"])
        if cls.step.lines[1].strip() != "name: Roll back to the recorded version":
            raise AssertionError("unexpected rollback step name")

    def check(self, floor=VERSION, target_date="2026-01-03T00:00:00Z", **options):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stub = root / "node_modules/.bin/wrangler"
            stub.parent.mkdir(parents=True)
            stub.write_text("""#!/usr/bin/env python3
import json, os, sys

with open("calls", "a") as calls:
    calls.write(" ".join(sys.argv[1:]) + "\\n")
match sys.argv[1:]:
    case ["deployments", "status", "--json", "-c", "wrangler.deploy.toml"]:
        print(json.dumps({"versions": [{"version_id": os.environ["DEPLOYED"], "percentage": 100}]}))
    case ["versions", "view", version, "--json", "-c", "wrangler.deploy.toml"]:
        if version == os.environ.get("VIEW_FAILURE"):
            sys.exit(1)
        date = os.environ["TARGET_DATE"] if version == os.environ["PREV_VERSION"] else "2026-01-02T00:00:00Z"
        print(json.dumps({"metadata": {"created_on": date}, "annotations": {}}))
    case ["rollback", version, "-c", "wrangler.deploy.toml", "--message", _, "-y"]:
        assert version == os.environ["PREV_VERSION"]
        if os.environ.get("ROLLBACK_FAILURE"):
            sys.exit("✘ [ERROR] Rollback not allowed [code: 100402]")
        print("Successfully rolled back")
    case _:
        raise AssertionError(sys.argv)
""")
            stub.chmod(0o755)
            deploy_output = root / "wrangler.ndjson"
            deploy_output.write_text(json.dumps({"type": "deploy", "version_id": DEPLOYED}) + "\n")
            output = root / "output"
            summary = root / "summary"
            result = run(
                ["bash"], "\n".join(self.step.shell) + "\n", tmp,
                RUNNER_TEMP=tmp, FLOOR_VERSION=floor, PREV_VERSION=PREVIOUS, DEPLOYED=DEPLOYED,
                WRANGLER_OUTPUT_FILE_PATH=str(deploy_output), GITHUB_OUTPUT=str(output),
                GITHUB_STEP_SUMMARY=str(summary), TARGET_DATE=target_date, **options,
            )
            return result, output.read_text(), (root / "calls").read_text(), summary.exists()

    def test_floor_unset_or_same_as_target(self):
        for floor in ("", PREVIOUS):
            result, output, calls, summary = self.check(floor=floor)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("versions view", calls)
            self.assertIn(f"rollback {PREVIOUS}", calls)
            self.assertEqual(output, "rollback=done\n")
            self.assertTrue(summary)

    def test_target_older_than_floor(self):
        self.assert_floor_refused(target_date="2026-01-02T00:30:00+01:00")

    def test_failed_or_invalid_version_view(self):
        for version in (PREVIOUS, VERSION):
            self.assert_floor_refused(VIEW_FAILURE=version)
        self.assert_floor_refused(target_date="invalid")

    def assert_floor_refused(self, **options):
        result, output, calls, summary = self.check(**options)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("::error::rollback refused:", result.stdout)
        self.assertNotIn(f"rollback {PREVIOUS}", calls)
        self.assertEqual(output, "rollback=refused-floor\n")
        self.assertFalse(summary)

    def test_cloudflare_refusal(self):
        result, output, calls, summary = self.check(ROLLBACK_FAILURE="yes")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("[code: 100402]", result.stdout)
        self.assertIn("rollback refused by Cloudflare", result.stdout)
        self.assertIn(f"rollback {PREVIOUS}", calls)
        self.assertEqual(output, "rollback=refused\n")
        self.assertFalse(summary)

    def test_success_at_or_above_floor(self):
        for timestamp in ("2026-01-02T00:00:00Z", "2026-01-02T00:00:00.001Z"):
            result, output, calls, summary = self.check(target_date=timestamp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(f"versions view {VERSION}", calls)
            self.assertIn("Successfully rolled back", result.stdout)
            self.assertEqual(output, "rollback=done\n")
            self.assertTrue(summary)


if __name__ == "__main__":
    unittest.main()
