#!/usr/bin/env python3
"""Tests for the production config generator of the deploy job.

The generator is the Python script of the step "Generate the production
wrangler config" in .github/workflows/ci.yml. These tests take the
script from that file as it stands and run it the way the step does
(`python3 -I - wrangler.toml wrangler.deploy.toml`), on the shipped
wrangler.toml and with made-up values. No credential, no network.

Run: python3 -I tools/test_deploy_config.py

With DEPLOY_CONFIG_BASELINE=<path of another ci.yml> the generator of
that file runs beside this one: wherever the record layout is not asked
for, the two must write the same bytes (see BaselineTest).
"""

import itertools
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest

sys.dont_write_bytecode = True

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.normpath(os.path.join(_HERE, "..", "..", ".."))
CI_YML = os.path.join(_ROOT, ".github", "workflows", "ci.yml")
WRANGLER_TOML = os.path.join(_HERE, "..", "wrangler.toml")

STEP = "- name: Generate the production wrangler config"
CALL = "python3 -I - wrangler.toml wrangler.deploy.toml <<'PY'"

# Made-up values of the right shape. Neither is a real host or database.
HOST = "s3.generator-test.example"
DBID = "0f0e0d0c-0b0a-4908-8706-050403020100"
PREFIX = "generator-test/records/"
REQUIRED = {"VELMORA_S3_HOST": HOST, "VELMORA_D1_DATABASE_ID": DBID}

SWITCH = "VELMORA_RECORD_LAYOUT"
TENANT_LINE = 'RECORD_LAYOUT = "tenant"'
REFUSED_VALUE = "VELMORA_RECORD_LAYOUT must be unset, flat or tenant"
REFUSED_SHIPPED = "the prod section of the shipped file sets RECORD_LAYOUT"
REFUSED_READ_BACK = "the generated config does not carry the record layout that was asked for"
REFUSED_TOML = "the generated config is not valid TOML with a prod [vars] table"


def read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def indent_of(line):
    return len(line) - len(line.lstrip())


class Step:
    """The generator step of a ci.yml: its script and what it is given."""

    def __init__(self, ci_text):
        lines = ci_text.split("\n")
        at = [i for i, line in enumerate(lines) if line.strip() == STEP]
        if len(at) != 1:
            raise AssertionError(f"expected one step {STEP!r}, found {len(at)}")
        self.line = at[0]
        level = indent_of(lines[self.line])
        stop = next(
            (i for i in range(self.line + 1, len(lines))
             if lines[i].strip() and indent_of(lines[i]) <= level),
            len(lines),
        )
        self.lines = lines[self.line:stop]
        calls = [i for i, line in enumerate(self.lines) if line.strip() == CALL]
        if len(calls) != 1:
            raise AssertionError(f"expected one line {CALL!r} in the step, found {len(calls)}")
        pad = self.lines[calls[0]][: indent_of(self.lines[calls[0]])]
        body = []
        for line in self.lines[calls[0] + 1:]:
            if line == pad + "PY":
                break
            if line.strip() and not line.startswith(pad):
                raise AssertionError(f"a script line is left of its block: {line!r}")
            body.append(line[len(pad):] if line.strip() else "")
        else:
            raise AssertionError("the script has no end")
        self.script = "\n".join(body) + "\n"
        # `NAME: ${{ vars.NAME }}` lines of the step's env table.
        self.env = {}
        for line in self.lines[: calls[0]]:
            m = re.fullmatch(r"\s*([A-Z0-9_]+): \$\{\{ (.+) \}\}", line)
            if m:
                self.env[m.group(1)] = m.group(2)

    def run(self, toml_text, env):
        """Returns (exit code, stdout, stderr, bytes written or None)."""
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "wrangler.toml"), "w", encoding="utf-8", newline="") as f:
                f.write(toml_text)
            given = {"PATH": os.environ.get("PATH", "")}
            given.update(REQUIRED)
            given.update({k: v for k, v in env.items() if v is not None})
            for name, value in env.items():
                if value is None:
                    given.pop(name, None)
            done = subprocess.run(
                [sys.executable, "-I", "-", "wrangler.toml", "wrangler.deploy.toml"],
                input=self.script.encode("utf-8"),
                cwd=tmp,
                env=given,
                capture_output=True,
                timeout=60,
                check=False,
            )
            out = os.path.join(tmp, "wrangler.deploy.toml")
            written = None
            if os.path.exists(out):
                with open(out, "rb") as f:
                    written = f.read()
            return (
                done.returncode,
                done.stdout.decode("utf-8"),
                done.stderr.decode("utf-8"),
                written,
            )


def prod_end(lines):
    """Index of the first [env.*] table header: the prod section ends there."""
    return next(
        (i for i, line in enumerate(lines) if re.match(r"\s*\[\[?env\.", line)),
        len(lines),
    )


def without_switches(toml_text):
    """What the generator wrote before any switch existed, worked out here
    and not by the generator: the shipped text with the two placeholders
    filled and the prod [build] table dropped. Every other byte stays."""
    lines = toml_text.split("\n")
    end = prod_end(lines)
    fills = {
        'S3_HOST = "velmora-s3.<account>.workers.dev"': f'S3_HOST = "{HOST}"',
        'database_id = "<from wrangler d1 create>"': f'database_id = "{DBID}"',
    }
    out, in_build = [], False
    for i, line in enumerate(lines):
        word = line.strip()
        if i < end and word == "[build]":
            in_build = True
            continue
        if in_build and not word.startswith("["):
            continue
        in_build = False
        if i < end and word in fills:
            line = line[: indent_of(line)] + fills[word]
        out.append(line)
    return "\n".join(out).encode("utf-8")


def add_after(toml_text, anchor, new_line):
    """The shipped text with one line more, after the prod line `anchor`."""
    lines = toml_text.split("\n")
    hits = [i for i in range(prod_end(lines)) if lines[i].strip() == anchor]
    if len(hits) != 1:
        raise AssertionError(f"expected one prod line {anchor!r}, found {len(hits)}")
    return "\n".join(lines[: hits[0] + 1] + [new_line] + lines[hits[0] + 1:])


class GeneratorCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ci = read(CI_YML)
        cls.step = Step(cls.ci)
        cls.shipped = read(WRANGLER_TOML)

    def ok(self, env, toml_text=None):
        code, out, err, written = self.step.run(self.shipped if toml_text is None else toml_text, env)
        self.assertEqual(code, 0, f"{env!r}: {err}")
        self.assertIsNotNone(written, env)
        return out, written

    def refused(self, env, message, toml_text=None):
        code, out, err, written = self.step.run(self.shipped if toml_text is None else toml_text, env)
        self.assertNotEqual(code, 0, env)
        self.assertIn(message, err, env)
        self.assertIsNone(written, f"{env!r}: a refusal must leave no file")
        self.assertNotIn("record layout in force", out, env)
        return err


# The values under which the record layout is not asked for.
NOT_ASKED = (None, "", "flat")
# Every setting of the two older switches: the layout must not depend on them.
OLDER = [
    {"VELMORA_RECOVERY_COPY": copy, "VELMORA_RECOVERY_PREFIX": prefix, "VELMORA_VERIFY_MODE": mode}
    for (copy, prefix), mode in itertools.product(
        ((None, None), ("off", None), ("off", PREFIX), ("on", PREFIX)),
        (None, "body", "light"),
    )
]


class RecordLayoutTest(GeneratorCase):
    def test_the_shipped_file_names_no_layout(self):
        doc = tomllib.loads(self.shipped)
        self.assertNotIn("RECORD_LAYOUT", doc["vars"])
        for name, env in doc.get("env", {}).items():
            self.assertNotIn("RECORD_LAYOUT", env.get("vars", {}), name)

    def test_unset_or_flat_writes_the_file_from_before_the_switch(self):
        before = without_switches(self.shipped)
        for value in NOT_ASKED:
            out, written = self.ok({SWITCH: value})
            self.assertEqual(written, before, repr(value))
            self.assertEqual(out.splitlines()[-1], "record layout in force: flat", repr(value))
            self.assertNotIn(b"\nRECORD_LAYOUT", written, repr(value))
            self.assertNotIn("RECORD_LAYOUT", tomllib.loads(written.decode("utf-8"))["vars"])

    def test_unset_or_flat_adds_nothing_under_any_older_switch(self):
        for older in OLDER:
            _, unset = self.ok({**older, SWITCH: None})
            for value in NOT_ASKED[1:]:
                _, written = self.ok({**older, SWITCH: value})
                self.assertEqual(written, unset, f"{older!r} {value!r}")

    def test_tenant_adds_one_line_to_the_prod_vars(self):
        for older in OLDER:
            _, flat = self.ok({**older, SWITCH: "flat"})
            out, tenant = self.ok({**older, SWITCH: "tenant"})
            self.assertEqual(out.splitlines()[-1], "record layout in force: tenant", older)
            lines = flat.decode("utf-8").split("\n")
            mode = older["VELMORA_VERIFY_MODE"] or "body"
            at = [i for i, line in enumerate(lines) if line == f'VERIFY_MODE = "{mode}"']
            self.assertEqual(len(at), 1, older)
            want = lines[: at[0] + 1] + [TENANT_LINE] + lines[at[0] + 1:]
            self.assertEqual(tenant.decode("utf-8").split("\n"), want, older)
            # The line is in the prod [vars] table and nowhere else, and
            # nothing else of the document moved.
            flat_doc = tomllib.loads(flat.decode("utf-8"))
            tenant_doc = tomllib.loads(tenant.decode("utf-8"))
            self.assertEqual(tenant_doc["vars"].pop("RECORD_LAYOUT"), "tenant", older)
            self.assertEqual(tenant_doc, flat_doc, older)
            self.assertEqual(tenant.count(b"RECORD_LAYOUT ="), 1, older)

    def test_any_other_value_fails_and_writes_nothing(self):
        for value in (
            "Tenant", "TENANT", "Flat", "FLAT", " tenant", "tenant ", "tenant\n", " flat",
            "flat\n", " ", "on", "off", "1", "true", "default", "t_0000000000000000",
            "m/x/", "m/x/t_0000000000000000/", "flat,tenant", "tenant,flat", '"tenant"',
            'tenant"\nMAINTENANCE = "restore', "tenant\nRECORD_LAYOUT = \"flat\"", "ténant",
        ):
            for older in (OLDER[0], OLDER[-1]):
                self.refused({**older, SWITCH: value}, REFUSED_VALUE)

    def test_a_shipped_file_that_sets_the_layout_is_refused_whatever_is_asked(self):
        anchor = 'VERIFY_MODE = "body"'
        for line in (
            'RECORD_LAYOUT = "flat"', TENANT_LINE, '  RECORD_LAYOUT = "tenant"',
            "RECORD_LAYOUT=\"tenant\"", 'RECORD_LAYOUT = ""',
        ):
            doctored = add_after(self.shipped, anchor, line)
            for value in (*NOT_ASKED, "tenant"):
                self.refused({SWITCH: value}, REFUSED_SHIPPED, doctored)

    def test_a_layout_the_line_check_does_not_see_is_caught_on_read_back(self):
        anchor = 'VERIFY_MODE = "body"'
        # A quoted key is the same key to TOML and is not matched as a line.
        for line in ('"RECORD_LAYOUT" = "tenant"', '"RECORD_LAYOUT" = "flat"', "'RECORD_LAYOUT' = \"x\""):
            doctored = add_after(self.shipped, anchor, line)
            for value in NOT_ASKED:
                self.refused({SWITCH: value}, REFUSED_READ_BACK, doctored)
            # With "tenant" the key would be there twice: not valid TOML.
            self.refused({SWITCH: "tenant"}, REFUSED_TOML, doctored)

    def test_the_log_names_the_layout_and_no_value(self):
        for value, name in ((None, "flat"), ("flat", "flat"), ("tenant", "tenant")):
            out, _ = self.ok({**OLDER[-1], SWITCH: value})
            self.assertEqual(out.count("record layout in force: "), 1, value)
            self.assertIn(f"record layout in force: {name}\n", out, value)
            for secret in (HOST, DBID, PREFIX):
                self.assertNotIn(secret, out, value)

    def test_the_step_hands_the_variable_to_the_script_before_the_deploy(self):
        step = self.step
        self.assertEqual(step.env.get(SWITCH), f"vars.{SWITCH}")
        # Every variable the script reads is handed to it, from `vars`
        # under its own name, and nothing is handed that it does not read.
        read_by_script = set(re.findall(r'os\.environ\.get\("([A-Z0-9_]+)"', step.script))
        self.assertEqual(read_by_script, set(step.env))
        for name, source in step.env.items():
            self.assertEqual(source, f"vars.{name}")
        self.assertIn(SWITCH, read_by_script)
        # A refusal ends the job before anything reaches production: the
        # step comes before the migrations and before the deploy.
        lines = self.ci.split("\n")
        place = {}
        for later in ("- name: Apply D1 migrations (remote)", "name: Deploy the Worker"):
            hits = [i for i, line in enumerate(lines) if line.strip() == later]
            self.assertEqual(len(hits), 1, later)
            place[later] = hits[0]
            self.assertLess(step.line, hits[0], later)
        self.assertIn("set -euo pipefail", [line.strip() for line in step.lines])
        # Nothing else in the workflow chooses a layout.
        mentions = [line for line in lines if "RECORD_LAYOUT" in line and not line.strip().startswith("#")]
        outside = [line for line in mentions if line not in step.lines]
        self.assertEqual(outside, [])


class OlderSwitchesTest(GeneratorCase):
    """The switches the step had before: held here so that the record
    layout cannot change them unseen."""

    def test_verify_mode(self):
        _, body = self.ok({"VELMORA_VERIFY_MODE": "body"})
        self.assertEqual(body, without_switches(self.shipped))
        _, light = self.ok({"VELMORA_VERIFY_MODE": "light"})
        self.assertEqual(light, body.replace(b'\nVERIFY_MODE = "body"\n', b'\nVERIFY_MODE = "light"\n'))
        self.assertNotEqual(light, body)
        self.refused({"VELMORA_VERIFY_MODE": "sampled"}, "VELMORA_VERIFY_MODE must be unset, body or light")

    def test_recovery_copy(self):
        _, off = self.ok({"VELMORA_RECOVERY_COPY": "off", "VELMORA_RECOVERY_PREFIX": PREFIX})
        self.assertEqual(off, without_switches(self.shipped))
        _, on = self.ok({"VELMORA_RECOVERY_COPY": "on", "VELMORA_RECOVERY_PREFIX": PREFIX})
        self.assertEqual(
            on,
            off.replace(
                b'\nRECOVERY_COPY = "off"\n',
                f'\nRECOVERY_COPY = "on"\nRECOVERY_PREFIX = "{PREFIX}"\n'.encode("utf-8"),
            ),
        )
        self.assertNotEqual(on, off)
        self.refused({"VELMORA_RECOVERY_COPY": "on"}, "VELMORA_RECOVERY_PREFIX is missing")
        self.refused({"VELMORA_RECOVERY_COPY": "yes"}, "VELMORA_RECOVERY_COPY must be unset, off or on")

    def test_required_values(self):
        self.refused({"VELMORA_S3_HOST": None}, "VELMORA_S3_HOST is missing")
        self.refused({"VELMORA_D1_DATABASE_ID": "not-a-uuid"}, "VELMORA_D1_DATABASE_ID is missing")


@unittest.skipUnless(
    os.environ.get("DEPLOY_CONFIG_BASELINE"),
    "set DEPLOY_CONFIG_BASELINE to the ci.yml of the commit to compare with",
)
class BaselineTest(GeneratorCase):
    """Beside the generator of another ci.yml (the one in production, for
    a change of the generator): with the layout not asked for, the same
    bytes for every setting of the older switches, and the same first
    log line."""

    def test_same_bytes_as_the_baseline_when_the_layout_is_not_asked_for(self):
        baseline = Step(read(os.environ["DEPLOY_CONFIG_BASELINE"]))
        self.assertNotEqual(baseline.script, self.step.script, "the baseline is this very generator")
        compared = 0
        for older in OLDER:
            code, out, err, want = baseline.run(self.shipped, older)
            self.assertEqual(code, 0, f"{older!r}: {err}")
            for value in NOT_ASKED:
                got_out, got = self.ok({**older, SWITCH: value})
                self.assertEqual(got, want, f"{older!r} {value!r}")
                self.assertEqual(got_out.splitlines()[0], out.splitlines()[0], f"{older!r} {value!r}")
                compared += 1
        self.assertEqual(compared, len(OLDER) * len(NOT_ASKED))
        for bad in (
            {"VELMORA_VERIFY_MODE": "sampled"},
            {"VELMORA_RECOVERY_COPY": "on"},
            {"VELMORA_S3_HOST": "Not A Host"},
        ):
            code, _, err, written = baseline.run(self.shipped, bad)
            self.assertNotEqual(code, 0, bad)
            self.assertIsNone(written, bad)
            self.refused(bad, err.strip())


if __name__ == "__main__":
    unittest.main(verbosity=2)
