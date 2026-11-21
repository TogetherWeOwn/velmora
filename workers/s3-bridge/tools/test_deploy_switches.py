#!/usr/bin/env python3
"""Run the workflow's deploy switch, bundle floor, and rollback scripts locally."""

import json
import os
from pathlib import Path
import re
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


FRESH_IF = "steps.fresh.outputs.fresh == 'true'"


def deploy_job(ci):
    return ci.split("\n  deploy:\n", 1)[1].split("\n  deploy-alert:\n", 1)[0]


class WorkflowWiringTest(unittest.TestCase):
    def test_switches(self):
        step = extract("- name: Check the deploy switches", ["if", "id", "env", "run"])
        self.assertEqual(step.lines[step.where["if"]].strip(), f"if: {FRESH_IF}")
        self.assertEqual(step.lines[step.where["id"]].strip(), "id: switches")
        self.assertEqual(
            [line.strip() for line in step.lines[step.where["env"] + 1:step.where["run"]]],
            [f"{name}: ${{{{ vars.{name} }}}}" for name in (
                "VELMORA_DEPLOY_FREEZE", "VELMORA_FLOOR_MIN", "VELMORA_FLOOR_VERSION",
                "VELMORA_CATALOGUE_MIGRATIONS",
            )] + ["FLOOR_LEVEL_FILE: workers/s3-bridge/build/floor-level"],
        )

    def test_migrations(self):
        ci = read(CI_YML)
        for name, condition in (
            ("Apply D1 migrations (remote)", "steps.switches.outputs.migrations == 'on'"),
            ("Check that no catalogue migration is pending", "steps.switches.outputs.migrations == 'off'"),
            ("Apply directory migrations (remote)", "vars.VELMORA_DIRECTORY_D1_ID != ''"),
        ):
            with self.subTest(step=name):
                self.assertEqual(ci.count(f"      - name: {name}\n"), 1)
                self.assertIn(f"      - name: {name}\n        if: {FRESH_IF} && {condition}\n", ci)

    def test_rollback_and_alert(self):
        ci = read(CI_YML)
        deploy = deploy_job(ci)
        self.assertIn("\n    outputs:\n      rollback: ${{ steps.rollback.outputs.rollback }}\n", deploy)
        step = extract("- id: rollback", ["name", "if", "working-directory", "env", "run"])
        self.assertIn("\n      - id: rollback\n", deploy)
        self.assertIn("          FLOOR_VERSION: ${{ steps.switches.outputs.floor_version }}",
                      step.lines[step.where["env"] + 1:step.where["run"]])
        alert = ci.split("\n  deploy-alert:\n", 1)[1]
        self.assertIn("\n    needs: [ci-ok, deploy-build, deploy]\n", alert)
        self.assertIn(
            "\n    if: ${{ always() && github.event_name == 'push' && github.ref == 'refs/heads/main' && "
            "(needs.ci-ok.result == 'failure' || needs.deploy-build.result == 'failure' || "
            "needs.deploy.result == 'failure' || needs.deploy.result == 'cancelled') }}\n",
            alert,
        )
        step = extract("- name: Report the failed deploy", ["env", "run"])
        env = step.lines[step.where["env"] + 1:step.where["run"]]
        self.assertIn("          ROLLBACK: ${{ needs.deploy.outputs.rollback }}", env)
        self.assertIn("          CI_RESULT: ${{ needs.ci-ok.result }}", env)


class FreshTest(unittest.TestCase):
    def test_tip_and_freeze(self):
        step = ShellStep(deploy_job(read(CI_YML)), "- id: fresh", ["name", "env", "run"])
        self.assertEqual(step.lines[step.where["env"] + 1:step.where["run"]], [
            "          VELMORA_DEPLOY_FREEZE: ${{ vars.VELMORA_DEPLOY_FREEZE }}",
        ])
        newer = "b" * 40
        for tip, freeze, code, output, message in (
            (SHA, "", 0, "fresh=true\n", "is the tip of main"),
            (newer, "", 0, "fresh=false\n", "the newer run deploys"),
            (newer, SHA, 0, "fresh=true\n",
             f"deploy: {SHA} is the frozen commit; it deploys although main is at {newer}"),
            (newer, newer, 1, "", f"::error::main moved from {SHA} to {newer}"),
        ):
            with self.subTest(tip=tip, freeze=freeze), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                stub = root / "git"
                stub.write_text("#!/bin/bash\nprintf '%s\\trefs/heads/main\\n' \"$TIP\"\n")
                stub.chmod(0o755)
                out = root / "output"
                out.touch()
                summary = root / "summary"
                result = run(
                    ["bash"], "\n".join(step.shell), tmp,
                    PATH=f"{tmp}:{os.environ.get('PATH', os.defpath)}", TIP=tip, GITHUB_SHA=SHA,
                    GITHUB_REPOSITORY="test/repo", VELMORA_DEPLOY_FREEZE=freeze,
                    GITHUB_OUTPUT=str(out), GITHUB_STEP_SUMMARY=str(summary),
                )
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(out.read_text(), output)
                self.assertIn(message, result.stdout)
                self.assertEqual(summary.exists(), output == "fresh=false\n")


class PendingMigrationsTest(unittest.TestCase):
    def test_wrangler_list_results(self):
        step = extract("- name: Check that no catalogue migration is pending",
                       ["if", "working-directory", "env", "run"])
        for status, log, code, message in (
            (0, "0004_pending.sql", 1,
             "::error::a catalogue migration is pending while VELMORA_CATALOGUE_MIGRATIONS is off; refusing to deploy"),
            (0, "No migrations to apply!", 0, ""),
            (1, "Wrangler API error", 1, "::error::could not list catalogue migrations; refusing to deploy"),
        ):
            with self.subTest(log=log), tempfile.TemporaryDirectory() as tmp:
                stub = Path(tmp, "node_modules/.bin/wrangler")
                stub.parent.mkdir(parents=True)
                stub.write_text(
                    '#!/bin/bash\n'
                    '[[ "$*" == "d1 migrations list velmora-catalog --remote -c wrangler.deploy.toml" ]] || exit 99\n'
                    'echo "$LOG" >&2\nexit "$STATUS"\n'
                )
                stub.chmod(0o755)
                result = run(["bash"], "\n".join(step.shell), tmp,
                             RUNNER_TEMP=tmp, LOG=log, STATUS=str(status))
                self.assertEqual(result.returncode, code, result.stderr)
                expected = ["catalogue migrations skipped (VELMORA_CATALOGUE_MIGRATIONS=off)", log]
                if message:
                    expected.append(message)
                self.assertEqual(result.stdout.splitlines(), expected)


class DeployAlertTest(unittest.TestCase):
    def check(self, *, ci="success", rollback=""):
        step = extract("- name: Report the failed deploy", ["env", "run"])
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp, "curl")
            stub.write_text(
                '#!/bin/bash\n'
                'while [[ "$1" != --data && "$#" -gt 0 ]]; do shift; done\n'
                '[[ "$1" == --data ]] || exit 1\n'
                'cat >/dev/null\nprintf "%s" "$2" > body.json\n'
            )
            stub.chmod(0o755)
            result = run(
                ["bash"], "\n".join(step.shell), tmp, PATH=f"{tmp}:{os.environ.get('PATH', os.defpath)}",
                ALERTS_INGEST_URL="https://example.invalid", ALERTS_INGEST_TOKEN="test",
                GITHUB_SHA=SHA, CI_RESULT=ci, BUILD_RESULT="skipped" if ci == "failure" else "success",
                DEPLOY_RESULT="skipped" if ci == "failure" else "failure", ROLLBACK=rollback,
                RUN_URL="https://example.invalid/run",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("deploy alert sent", result.stdout)
            return json.loads(Path(tmp, "body.json").read_text())

    def test_failed_checks(self):
        body = self.check(ci="failure")
        self.assertEqual(body["key"], "deploy-failed")
        self.assertIn("The checks failed on main, so nothing was deployed.", body["detail"])

    def test_rollback_refusals(self):
        for rollback in ("refused", "refused-floor", "refused-floor-unknown", "manual-check"):
            with self.subTest(rollback=rollback):
                body = self.check(rollback=rollback)
                self.assertEqual(body["key"], "deploy-rollback-refused")
                if rollback == "manual-check":
                    self.assertEqual(body["title"], "Production deploy failed; rollback needs a manual check")
                else:
                    self.assertIn(f"The rollback was refused ({rollback})", body["detail"])


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
        source = read(Path(__file__).resolve().parents[1] / "src/lib.rs")
        pattern = r"^pub const FLOOR_LEVEL: u32 = ([0-9]+);$"
        matches = list(re.finditer(pattern, source, re.MULTILINE))
        self.assertEqual(len(matches), 1)
        at = matches[0].start()
        comment_depth = 0
        in_line_comment = False
        for token in re.findall(r"/\*|\*/|//|\n", source[:at]):
            if token == "\n":
                in_line_comment = False
            elif not in_line_comment:
                if token == "/*":
                    comment_depth += 1
                elif token == "*/" and comment_depth:
                    comment_depth -= 1
                elif token == "//" and not comment_depth:
                    in_line_comment = True
        self.assertEqual(comment_depth, 0, "FLOOR_LEVEL must be outside block comments")
        self.assertFalse(in_line_comment)
        self.assertFalse(source[:at].splitlines()[-1].lstrip().startswith("#[cfg"))
        result, output = self.check(source)
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
from pathlib import Path

call = " ".join(sys.argv[1:])
log = Path("calls")
previous_calls = log.read_text().splitlines() if log.exists() else []
with log.open("a") as calls:
    calls.write(call + "\\n")
match sys.argv[1:]:
    case ["deployments", "status", "--json", "-c", "wrangler.deploy.toml"]:
        print(json.dumps({"versions": [{"version_id": os.environ.get("ACTIVE", os.environ["DEPLOYED"]), "percentage": 100}]}))
    case ["versions", "view", version, "--json", "-c", "wrangler.deploy.toml"]:
        if version == os.environ.get("VIEW_FAILURE") and previous_calls.count(call) < int(os.environ.get("FAIL_ATTEMPTS", "3")):
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
            if not options.pop("missing_output", False):
                deploy_output.write_text(json.dumps({"type": "deploy", "version_id": DEPLOYED}) + "\n")
            sleep = root / "sleep"
            sleep.write_text('#!/bin/bash\nprintf "sleep %s\\n" "$1" >> calls\n')
            sleep.chmod(0o755)
            output = root / "output"
            summary = root / "summary"
            result = run(
                ["bash"], "\n".join(self.step.shell) + "\n", tmp,
                PATH=f"{tmp}:{os.environ.get('PATH', os.defpath)}",
                RUNNER_TEMP=tmp, FLOOR_VERSION=floor, PREV_VERSION=PREVIOUS, DEPLOYED=DEPLOYED,
                GITHUB_SHA=SHA, GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1",
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
        self.assert_floor_refused("refused-floor", "is older than the rollback floor version",
                                  target_date="2026-01-02T00:30:00+01:00")

    def test_failed_version_view_retries(self):
        for version in (PREVIOUS, VERSION):
            with self.subTest(version=version):
                calls = self.assert_floor_refused("refused-floor-unknown", "could not be read",
                                                  VIEW_FAILURE=version)
                view = f"versions view {version} --json -c wrangler.deploy.toml"
                self.assertEqual(calls.splitlines()[-5:], [view, "sleep 5", view, "sleep 5", view])

    def test_version_view_recovers_on_third_attempt(self):
        result, output, calls, _ = self.check(VIEW_FAILURE=VERSION, FAIL_ATTEMPTS="2")
        self.assertEqual(result.returncode, 0, result.stderr)
        view = f"versions view {VERSION} --json -c wrangler.deploy.toml"
        self.assertEqual(calls.splitlines()[2:7], [view, "sleep 5", view, "sleep 5", view])
        self.assertEqual(output, "rollback=done\n")

    def test_invalid_version_timestamp(self):
        self.assert_floor_refused("refused-floor-unknown", "could not be read", target_date="invalid")

    def assert_floor_refused(self, outcome, message, **options):
        result, output, calls, summary = self.check(**options)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("::error::rollback refused:", result.stdout)
        self.assertIn(message, result.stdout)
        self.assertNotIn(f"rollback {PREVIOUS}", calls)
        self.assertEqual(output, f"rollback={outcome}\n")
        self.assertFalse(summary)
        return calls

    def test_manual_check_when_deployed_version_is_unknown_or_active_version_differs(self):
        for options, message in (
            ({"missing_output": True}, "this run has no deployed version id"),
            ({"ACTIVE": VERSION}, "active version " + VERSION + " is neither"),
        ):
            with self.subTest(message=message):
                result, output, calls, summary = self.check(**options)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(message, result.stdout)
                self.assertEqual(output, "rollback=manual-check\n")
                self.assertNotIn(f"rollback {PREVIOUS}", calls)
                self.assertFalse(summary)

    def test_cloudflare_refusal(self):
        result, output, calls, summary = self.check(ROLLBACK_FAILURE="yes")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("[code: 100402]", result.stdout)
        self.assertIn("::error::wrangler rollback failed (Cloudflare refused it or the call failed; "
                      f"see the output above); production stays on {DEPLOYED}; check manually", result.stdout)
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
