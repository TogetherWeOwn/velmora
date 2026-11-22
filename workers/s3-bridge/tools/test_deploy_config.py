#!/usr/bin/env python3
"""Tests for the production config generator of the deploy job.

The generator is the Python script of the step "Generate the production
wrangler config" in .github/workflows/ci.yml. These tests take the
script from that file as it stands and run it with the call the step
makes (`python3 -I - wrangler.toml wrangler.deploy.toml`), on the
shipped wrangler.toml and with made-up values. No credential, no
network. The step itself is held to one shape (see Step): its shell is
`set -euo pipefail`, that call and the script, and nothing else, so
that what runs here is all that runs there.

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
STRICT = "set -euo pipefail"
CALL = "python3 -I - wrangler.toml wrangler.deploy.toml <<'PY'"
END = "PY"
# The keys of the step, in this order. No `shell:`, no
# `continue-on-error:`: the default shell stops at the first failure
# and a failed step fails the job.
STEP_KEYS = ["if", "working-directory", "env", "run"]

# Made-up values of the right shape. Neither is a real host or database.
HOST = "s3.generator-test.example"
DBID = "0f0e0d0c-0b0a-4908-8706-050403020100"
PREFIX = "generator-test/records/"
REQUIRED = {"VELMORA_S3_HOST": HOST, "VELMORA_D1_DATABASE_ID": DBID}

SWITCH = "VELMORA_RECORD_LAYOUT"
TENANT_LINE = 'RECORD_LAYOUT = "tenant"'
REFUSED_VALUE = "VELMORA_RECORD_LAYOUT must be unset, flat or tenant"
REFUSED_SHIPPED = "the prod section of the shipped file sets RECORD_LAYOUT"
LOG = "record layout in the generated config: "
REFUSED_READ_BACK = "the generated config does not carry the record layout that was asked for"
REFUSED_TOML = "the generated config is not valid TOML with a prod [vars] table"


def read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def indent_of(line):
    return len(line) - len(line.lstrip())


class ShellStep:
    """Extract a named workflow step and check its top-level keys."""

    def __init__(self, ci_text, step, keys):
        lines = ci_text.split("\n")
        at = [i for i, line in enumerate(lines) if line.strip() == step]
        if len(at) != 1:
            raise AssertionError(f"expected one step {step!r}, found {len(at)}")
        self.line = at[0]
        level = indent_of(lines[self.line])
        self.stop = next(
            (i for i in range(self.line + 1, len(lines))
             if lines[i].strip() and indent_of(lines[i]) <= level),
            len(lines),
        )
        self.lines = lines[self.line:self.stop]
        while self.lines and not self.lines[-1].strip():
            self.lines.pop()
        # The keys of the step are the lines two columns right of its dash.
        key_pad = " " * (level + 2)
        indexed_keys = [
            (i, line[len(key_pad):].split(":", 1)[0])
            for i, line in enumerate(self.lines)
            if i and line.startswith(key_pad) and not line[len(key_pad):].startswith((" ", "#"))
        ]
        self.keys = [name for _, name in indexed_keys]
        if self.keys != keys:
            raise AssertionError(f"the step has the keys {self.keys}, expected {keys}")
        where = self.where = {name: i for i, name in indexed_keys}
        if self.lines[where["run"]] != key_pad + "run: |":
            raise AssertionError("the step's run is not a `|` block")
        # The run block, as the shell gets it: YAML takes the indentation
        # of the first line off every line.
        block = self.lines[where["run"] + 1:]
        if not block or indent_of(block[0]) <= len(key_pad):
            raise AssertionError("the step's run block is empty")
        pad = block[0][: indent_of(block[0])]
        shell = []
        for line in block:
            if line.strip() and not line.startswith(pad):
                raise AssertionError(f"a line of the run block is left of the block: {line!r}")
            shell.append(line[len(pad):] if line.strip() else "")
        self.shell = shell

    def python_script(self, call):
        shell = self.shell
        if shell[:2] != [STRICT, call] or len(shell) < 4:
            raise AssertionError(f"the run block does not start with {STRICT!r} and {call!r}")
        if shell.count(END) != 1 or shell[-1] != END:
            raise AssertionError(f"the run block must end at its only {END!r} line")
        return "\n".join(shell[2:-1]) + "\n"


class Step(ShellStep):
    """The generator step of a ci.yml: its script and what it is given.

    The step must have this shape and no other, or nothing is run:

        - name: Generate the production wrangler config
          if: ...
          working-directory: ...
          env:
            NAME: ${{ vars.NAME }}      (one line for each variable)
          run: |
            set -euo pipefail
            python3 -I - wrangler.toml wrangler.deploy.toml <<'PY'
            (the script)
            PY

    A shell line before, between or after these would run in the deploy
    and not in the tests, so there is none.
    """

    def __init__(self, ci_text):
        super().__init__(ci_text, STEP, STEP_KEYS)
        where = self.where
        key_pad = " " * (indent_of(self.lines[0]) + 2)
        if self.lines[where["env"]] != key_pad + "env:":
            raise AssertionError("the step's env is not a table of its own lines")
        # `NAME: ${{ vars.NAME }}` lines of the step's env table, and no
        # line of another form.
        self.env = {}
        for line in self.lines[where["env"] + 1: where["run"]]:
            m = re.fullmatch(r"\s+([A-Z0-9_]+): \$\{\{ (.+) \}\}", line)
            if not m or m.group(1) in self.env:
                raise AssertionError(f"an env line of the step is not `NAME: ${{{{ ... }}}}`: {line!r}")
            self.env[m.group(1)] = m.group(2)
        self.script = self.python_script(CALL)

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


def with_older(toml_text, older):
    """What the generator wrote for a setting of the two older switches
    before the record layout existed, worked out here: without_switches()
    and the one replacement each of the two switches makes."""
    want = without_switches(toml_text)
    swaps = []
    if older.get("VELMORA_VERIFY_MODE") == "light":
        swaps.append((b'\nVERIFY_MODE = "body"\n', b'\nVERIFY_MODE = "light"\n'))
    if older.get("VELMORA_RECOVERY_COPY") == "on":
        prefix = older["VELMORA_RECOVERY_PREFIX"]
        swaps.append((
            b'\nRECOVERY_COPY = "off"\n',
            f'\nRECOVERY_COPY = "on"\nRECOVERY_PREFIX = "{prefix}"\n'.encode("utf-8"),
        ))
    for old, new in swaps:
        if want.count(old) != 1:
            raise AssertionError(f"expected one line {old!r}, found {want.count(old)}")
        want = want.replace(old, new)
    return want


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
        self.assertNotIn("record layout", out, env)
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


class S3HostsTest(GeneratorCase):
    switch = "VELMORA_S3_HOSTS"
    log = "extra S3 hosts in the generated config: "
    first = "s3.customer.example"
    second = "s3.legacy.example"

    def test_unset_or_empty_preserves_the_baseline(self):
        _, baseline = self.ok({})
        for value in (None, ""):
            out, written = self.ok({self.switch: value})
            self.assertEqual(written, baseline)
            self.assertNotIn(b"\nS3_HOSTS", written)
            self.assertNotIn("S3_HOSTS", tomllib.loads(written.decode("utf-8"))["vars"])
            self.assertEqual(out.splitlines()[-1], self.log + "0")
            self.assertNotIn(HOST, out)

    def test_set_adds_one_line_after_the_primary_host_and_logs_only_classes(self):
        shipped_host = 'S3_HOST = "velmora-s3.<account>.workers.dev"'
        indented = self.shipped.replace(shipped_host, "  " + shipped_host, 1)
        _, baseline = self.ok({}, indented)
        for value, summary in (
            (f"{self.first}=customer", "1 (customer)"),
            (f"{self.first}=customer,{self.second}=legacy", "2 (customer,legacy)"),
        ):
            with self.subTest(value=value):
                out, written = self.ok({self.switch: value}, indented)
                line = f'  S3_HOSTS = "{value}"'
                expected = add_after(baseline.decode("utf-8"), f'S3_HOST = "{HOST}"', line)
                self.assertEqual(written, expected.encode("utf-8"))
                self.assertEqual(written.count(b"S3_HOSTS ="), 1)
                self.assertEqual(tomllib.loads(written.decode("utf-8"))["vars"]["S3_HOSTS"], value)
                self.assertEqual(out.splitlines()[-1], self.log + summary)
                for host in (HOST, self.first, self.second):
                    self.assertNotIn(host, out)

    def test_invalid_lists_are_refused_before_writing(self):
        message = (
            "VELMORA_S3_HOSTS must be a comma separated list of <lowercase host>=legacy|customer, "
            "at most 8, without S3_HOST or a repeat"
        )
        for value in (
            "A.example=customer", "a.example:443=customer", " a.example=customer",
            "a.example =customer", "a.example=customer\n", "a.example=Customer",
            "a.example=public", "a.example", "a.example=", "=legacy",
            ",a.example=customer", "a.example=customer,", "a.example=customer,,b.example=legacy",
            "a.example=customer,a.example=legacy", f"{HOST}=customer",
            ",".join(f"s3-{i}.example=legacy" for i in range(9)),
        ):
            with self.subTest(value=value):
                self.refused({self.switch: value}, message)

    def test_a_shipped_prod_host_list_is_refused_whatever_is_asked(self):
        for anchor, line in (
            ('VERIFY_MODE = "body"', 'S3_HOSTS = ""'),
            ('VERIFY_MODE = "body"', '  "S3_HOSTS" = "extra.example=legacy"'),
            ("[build]", 'S3_HOSTS = "extra.example=legacy"'),
            ("[vars]", 'nested = { S3_HOSTS = "extra.example=legacy" }'),
        ):
            doctored = add_after(self.shipped, anchor, line)
            for value in (None, "", f"{self.first}=customer", "invalid"):
                with self.subTest(line=line, value=value):
                    self.refused(
                        {self.switch: value}, "the prod section of the shipped file sets S3_HOSTS",
                        doctored,
                    )


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
            self.assertEqual(out.splitlines()[-2], LOG + "flat", repr(value))
            self.assertNotIn(b"\nRECORD_LAYOUT", written, repr(value))
            self.assertNotIn("RECORD_LAYOUT", tomllib.loads(written.decode("utf-8"))["vars"])

    def test_unset_or_flat_adds_nothing_under_any_older_switch(self):
        seen = set()
        for older in OLDER:
            want = with_older(self.shipped, older)
            seen.add(want)
            for value in NOT_ASKED:
                _, written = self.ok({**older, SWITCH: value})
                self.assertEqual(written, want, f"{older!r} {value!r}")
        # body or light, copy off or on: four files, and no more.
        self.assertEqual(len(seen), 4)

    def test_tenant_adds_one_line_to_the_prod_vars(self):
        for older in OLDER:
            _, flat = self.ok({**older, SWITCH: "flat"})
            out, tenant = self.ok({**older, SWITCH: "tenant"})
            self.assertEqual(out.splitlines()[-2], LOG + "tenant", older)
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
            self.assertEqual(out.count("record layout"), 1, value)
            self.assertIn(f"{LOG}{name}\n", out, value)
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
        # Nothing outside the step chooses a layout.
        outside = [
            line for i, line in enumerate(lines)
            if "RECORD_LAYOUT" in line and not line.strip().startswith("#")
            and not step.line <= i < step.stop
        ]
        self.assertEqual(outside, [])

    def test_the_step_is_the_script_and_nothing_else(self):
        # Step() refuses any other shape; this holds the shape in a test
        # of its own, by name.
        step = self.step
        self.assertEqual(step.keys, STEP_KEYS)
        self.assertEqual(step.shell[:2], [STRICT, CALL])
        self.assertEqual(step.shell[-1], END)
        self.assertEqual("\n".join(step.shell[2:-1]) + "\n", step.script)
        self.assertEqual(step.shell.count(END), 1)
        # Inside the step the layout is named by the env line and by the
        # script, and by no other line.
        named = [line.strip() for line in step.lines if "RECORD_LAYOUT" in line]
        in_script = [line.strip() for line in step.script.split("\n") if "RECORD_LAYOUT" in line]
        self.assertEqual(named, [f"{SWITCH}: ${{{{ vars.{SWITCH} }}}}"] + in_script)

    def test_a_step_of_another_shape_is_not_run(self):
        lines = self.ci.split("\n")
        step = self.step
        call = next(i for i in range(step.line, step.stop) if lines[i].strip() == CALL)
        end = next(i for i in range(call, step.stop) if lines[i].strip() == END)
        run = next(i for i in range(step.line, call) if lines[i].strip() == "run: |")
        pad = lines[call][: indent_of(lines[call])]
        key_pad = lines[run][: indent_of(lines[run])]

        def put(at, *new):
            return "\n".join(lines[:at] + list(new) + lines[at:])

        def drop(at):
            return "\n".join(lines[:at] + lines[at + 1:])

        Step(put(step.stop, ""))  # the file as it stands, one empty line more: accepted
        for name, text in {
            "a shell line before the call": put(call, pad + f"export {SWITCH}=tenant"),
            "a shell line before set": put(call - 1, pad + f"export {SWITCH}=tenant"),
            "a shell line after the script": put(end + 1, pad + "sed -i /RECORD_LAYOUT/d wrangler.deploy.toml"),
            "an echo after the script": put(end + 1, pad + "echo 'RECORD_LAYOUT = \"tenant\"' >> wrangler.deploy.toml"),
            "a command after the script": put(end + 1, pad + "true"),
            "a status that is ignored": "\n".join(lines[:call] + [lines[call] + " || true"] + lines[call + 1:]),
            "another interpreter call": "\n".join(lines[:call] + [lines[call].replace("-I ", "")] + lines[call + 1:]),
            "no strict mode": drop(call - 1),
            "set +e before the call": put(call, pad + "set +e"),
            "a second end line": put(end, pad + END),
            "the script moved right of the call": "\n".join(
                lines[:call] + [pad + "{"] + ["  " + line if line.strip() else line for line in lines[call:end + 1]]
                + [pad + "} || true"] + lines[end + 1:]),
            "continue-on-error": put(run, key_pad + "continue-on-error: true"),
            "another shell": put(run, key_pad + "shell: bash {0}"),
            "a literal in env": put(run, key_pad + f"  {SWITCH}_DEFAULT: tenant"),
            "the variable twice in env": put(run, lines[run - 1]),
            "a key after run": put(end + 1, key_pad + "continue-on-error: true"),
        }.items():
            self.assertNotEqual(text, self.ci, name)
            with self.assertRaises(AssertionError, msg=name):
                Step(text)


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


class DeployConfigSwitchesTest(GeneratorCase):
    directory = "12345678-abcd-4000-8000-000000000000"
    maintenance_line = 'MAINTENANCE = "off"                  # off | restore'

    def test_unset_empty_and_off_preserve_the_shipped_config(self):
        for env in ({}, {
            "VELMORA_MAINTENANCE": "",
            "VELMORA_CATALOGUE_ID": "",
            "VELMORA_JOB_FORMAT": "",
            "VELMORA_DIRECTORY_D1_ID": "",
        }, {"VELMORA_MAINTENANCE": "off"}):
            out, written = self.ok(env)
            self.assertEqual(written, without_switches(self.shipped))
            doc = tomllib.loads(written.decode())
            self.assertEqual(doc["vars"]["MAINTENANCE"], "off")
            self.assertNotIn("CATALOGUE_ID", doc["vars"])
            self.assertNotIn("JOB_FORMAT", doc["vars"])
            self.assertEqual([db["binding"] for db in doc["d1_databases"]], ["CATALOG"])
            for line in (
                "maintenance in the generated config: off",
                "catalogue id in the generated config: main (default)",
                "job format in the generated config: 1 (default)",
                "directory database in the generated config: none",
            ):
                self.assertEqual(out.splitlines().count(line), 1)

    def test_set_switches_preserve_comment_and_add_ordered_vars_and_binding(self):
        catalogue = "a0_-" * 8
        out, written = self.ok({
            "VELMORA_MAINTENANCE": "restore",
            "VELMORA_CATALOGUE_ID": catalogue,
            "VELMORA_JOB_FORMAT": "2",
            "VELMORA_DIRECTORY_D1_ID": self.directory,
        })
        text = written.decode()
        maintenance = self.maintenance_line.replace('"off"', '"restore"')
        self.assertIn(f'{maintenance}\nCATALOGUE_ID = "{catalogue}"\nJOB_FORMAT = "2"\n', text)
        self.assertIn(
            'migrations_dir = "migrations"\n\n[[d1_databases]]\nbinding = "DIRECTORY"\n'
            f'database_name = "velmora-directory"\ndatabase_id = "{self.directory}"\n'
            'migrations_dir = "migrations-directory"\n\n# Production data', text,
        )
        doc = tomllib.loads(text)
        self.assertEqual(doc["vars"]["MAINTENANCE"], "restore")
        self.assertEqual(doc["vars"]["CATALOGUE_ID"], catalogue)
        self.assertEqual(doc["vars"]["JOB_FORMAT"], "2")
        self.assertEqual(doc["d1_databases"].pop(), {
            "binding": "DIRECTORY", "database_name": "velmora-directory",
            "database_id": self.directory, "migrations_dir": "migrations-directory",
        })
        baseline = tomllib.loads(without_switches(self.shipped).decode())
        self.assertEqual(doc["d1_databases"], baseline["d1_databases"])
        self.assertEqual(doc["env"], baseline["env"])
        for line in (
            "maintenance in the generated config: restore",
            f"catalogue id in the generated config: {catalogue}",
            "job format in the generated config: 2",
            "directory database in the generated config: bound",
        ):
            self.assertEqual(out.splitlines().count(line), 1)
        for private in (HOST, DBID, self.directory):
            self.assertNotIn(private, out)

    def test_job_format_one_and_catalogue_can_be_set_independently(self):
        for name, value in (("CATALOGUE_ID", "a"), ("JOB_FORMAT", "1")):
            _, written = self.ok({f"VELMORA_{name}": value})
            expected = add_after(without_switches(self.shipped).decode(), self.maintenance_line,
                                 f'{name} = "{value}"')
            self.assertEqual(written, expected.encode())

    def test_invalid_values(self):
        for variable, values, message in (
            ("MAINTENANCE", ("on", "Restore", "restore\n"), "must be unset, off or restore"),
            ("CATALOGUE_ID", ("a" * 33, "Main", "a.b", "a\n", "é"), "must be unset or 1 to 32 of a-z 0-9 _ -"),
            ("JOB_FORMAT", ("0", "3", " 1", "2\n"), "must be unset, 1 or 2"),
            ("DIRECTORY_D1_ID", ("a", self.directory.upper(), self.directory + "\n"), "must be unset or a lowercase UUID"),
            ("DIRECTORY_D1_ID", (DBID,), "must not be the catalogue database"),
        ):
            for value in values:
                key = f"VELMORA_{variable}"
                with self.subTest(key=key, value=value):
                    self.refused({key: value}, f"{key} {message}")

    def test_shipped_restore_requires_the_production_variable(self):
        self.refused({}, "use VELMORA_MAINTENANCE to change the deployed setting",
                     self.shipped.replace(self.maintenance_line,
                                          self.maintenance_line.replace('"off"', '"restore"'), 1))

    def test_shipped_maintenance_must_be_unique_and_in_vars(self):
        missing = self.shipped.replace(self.maintenance_line + "\n", "", 1)
        for fixture in (missing, add_after(self.shipped, self.maintenance_line, self.maintenance_line)):
            self.refused({}, "expected exactly one prod line MAINTENANCE", fixture)
        self.refused({}, "the prod MAINTENANCE line is not in the [vars] table",
                     add_after(missing, "[build]", self.maintenance_line))
        for key in ('"MAINTENANCE" = "restore"', "nested = { MAINTENANCE = 'restore' }"):
            self.refused({}, "the prod section sets MAINTENANCE a second time",
                         add_after(self.shipped, "[build]", key))

    def test_shipped_optional_vars_and_directory_are_refused(self):
        for key in ("CATALOGUE_ID", "JOB_FORMAT"):
            for line in (f'{key} = "1"', f'nested = {{ "{key}" = "1" }}'):
                self.refused({}, f"the prod section of the shipped file sets {key}",
                             add_after(self.shipped, "[build]", line))
        self.refused({}, "the prod section of the shipped file binds DIRECTORY",
                     self.shipped.replace('binding = "CATALOG"', "binding = 'DIRECTORY'", 1))

    def test_directory_requires_catalogue_anchor_and_readback(self):
        self.refused({"VELMORA_DIRECTORY_D1_ID": self.directory},
                     "expected exactly one prod CATALOG migrations_dir line",
                     self.shipped.replace('migrations_dir = "migrations"\n', "", 1))
        self.refused({}, "the generated config does not carry the expected D1 bindings",
                     self.shipped.replace('binding = "CATALOG"', 'binding = "OTHER"', 1))


class KeyBucketsTest(GeneratorCase):
    """VELMORA_KEYS_A_BUCKET and VELMORA_KEYS_B_BUCKET: the two key
    buckets of the tenant keys, bound together or not at all."""

    a, b = "velmora-keys-a", "velmora-keys-b"
    log = "key buckets in the generated config: "
    cache = 'bucket_name = "velmora-cache-enam"'

    def both(self, a=None, b=None):
        return {"VELMORA_KEYS_A_BUCKET": self.a if a is None else a,
                "VELMORA_KEYS_B_BUCKET": self.b if b is None else b}

    def test_unset_or_empty_preserves_the_baseline(self):
        for env in ({}, {"VELMORA_KEYS_A_BUCKET": "", "VELMORA_KEYS_B_BUCKET": ""}):
            out, written = self.ok(env)
            self.assertEqual(written, without_switches(self.shipped))
            self.assertEqual(out.splitlines().count(self.log + "none"), 1)
            doc = tomllib.loads(written.decode())
            self.assertEqual([b["binding"] for b in doc["r2_buckets"]], ["SAFETY", "CACHE"])

    def test_both_set_bind_both_after_the_cache_bucket(self):
        out, written = self.ok(self.both())
        text = written.decode()
        self.assertIn(
            f'{self.cache}\n\n[[r2_buckets]]\nbinding = "KEYS_A"\nbucket_name = "{self.a}"'
            f'\n\n[[r2_buckets]]\nbinding = "KEYS_B"\nbucket_name = "{self.b}"\n', text)
        doc = tomllib.loads(text)
        baseline = tomllib.loads(without_switches(self.shipped).decode())
        self.assertEqual(doc["r2_buckets"], baseline["r2_buckets"] + [
            {"binding": "KEYS_A", "bucket_name": self.a},
            {"binding": "KEYS_B", "bucket_name": self.b},
        ])
        self.assertEqual(doc["env"], baseline["env"])
        self.assertEqual(doc["vars"], baseline["vars"])
        self.assertEqual(out.splitlines().count(self.log + "bound"), 1)
        for name in (self.a, self.b, HOST, DBID):
            self.assertNotIn(name, out)
        # The text after the new tables is the shipped text.
        expected = without_switches(self.shipped).decode().replace(
            self.cache,
            f'{self.cache}\n\n[[r2_buckets]]\nbinding = "KEYS_A"\nbucket_name = "{self.a}"'
            f'\n\n[[r2_buckets]]\nbinding = "KEYS_B"\nbucket_name = "{self.b}"', 1)
        self.assertEqual(text, expected)

    def test_one_alone_is_refused(self):
        for env in ({"VELMORA_KEYS_A_BUCKET": self.a}, {"VELMORA_KEYS_B_BUCKET": self.b},
                    self.both(b="")):
            with self.subTest(env=env):
                self.refused(env, "VELMORA_KEYS_A_BUCKET and VELMORA_KEYS_B_BUCKET must be set together")

    def test_invalid_names_are_refused(self):
        for bad in ("Velmora-keys", "ab", "-keys", "keys-", "a" * 64, self.a + "\n", "keys_a", "keys.a"):
            for variable, env in (("VELMORA_KEYS_A_BUCKET", self.both(a=bad)),
                                  ("VELMORA_KEYS_B_BUCKET", self.both(b=bad))):
                with self.subTest(variable=variable, value=bad):
                    self.refused(env, f"{variable} must be unset or an R2 bucket name")

    def test_the_same_bucket_twice_is_refused(self):
        self.refused(self.both(b=self.a),
                     "VELMORA_KEYS_A_BUCKET and VELMORA_KEYS_B_BUCKET must not be the same bucket")

    def test_a_bucket_the_file_binds_is_refused(self):
        # Production's buckets, and the dev Worker's (it deletes in them).
        for variable, env in (("VELMORA_KEYS_A_BUCKET", self.both(a="velmora-safety-enam")),
                              ("VELMORA_KEYS_B_BUCKET", self.both(b="velmora-cache-enam")),
                              ("VELMORA_KEYS_A_BUCKET", self.both(a="velmora-cache-dev")),
                              ("VELMORA_KEYS_B_BUCKET", self.both(b="velmora-safety-dev"))):
            with self.subTest(variable=variable, env=env):
                self.refused(env, f"{variable} must not be a bucket the file already binds")

    def test_a_shipped_key_binding_is_refused_whatever_is_asked(self):
        for binding in ("KEYS_A", "KEYS_B"):
            for line in (f'binding = "{binding}"', f"binding = '{binding}'"):
                fixture = add_after(self.shipped, self.cache,
                                    f'\n[[r2_buckets]]\n{line}\nbucket_name = "shipped-keys"')
                for env in ({}, self.both()):
                    with self.subTest(binding=binding, line=line, env=env):
                        self.refused(env, f"the prod section of the shipped file binds {binding}", fixture)

    def test_the_cache_anchor_is_required_when_set(self):
        fixture = self.shipped.replace(self.cache, 'bucket_name = "velmora-cache-other"', 1)
        self.refused(self.both(), "expected exactly one prod CACHE bucket_name line", fixture)
        # Unset, the anchor is not needed.
        self.ok({}, fixture)

    def test_a_shipped_key_binding_of_any_kind_is_refused(self):
        # A service binding: the line pattern catches it.
        services = add_after(self.shipped, self.cache,
                             '\n[[services]]\nbinding = "KEYS_A"\nservice = "other"')
        # A quoted key: only the parsed file shows it.
        quoted = add_after(self.shipped, self.cache,
                           '\n[[r2_buckets]]\n"binding" = "KEYS_B"\nbucket_name = "x-keys"')
        # An inline table of another binding type.
        inline = add_after(self.shipped, "[build]",
                           'kv_namespaces = [{ binding = "KEYS_A", id = "0123" }]')
        for fixture, binding in ((services, "KEYS_A"), (quoted, "KEYS_B"), (inline, "KEYS_A")):
            for env in ({}, self.both()):
                with self.subTest(binding=binding, env=env):
                    self.refused(env, f"the prod section of the shipped file binds {binding}", fixture)

    def test_read_back_refuses_a_key_table_that_is_not_what_was_asked(self):
        # A line after the cache bucket's name lands in the KEYS_B table.
        fixture = add_after(self.shipped, self.cache, 'jurisdiction = "eu"')
        self.refused(self.both(), "the generated config does not carry the expected key bucket bindings",
                     fixture)

    def test_a_shipped_key_binding_with_a_comment_is_refused(self):
        # No spaces around `=`, and a comment after the value.
        fixture = add_after(self.shipped, self.cache,
                            '\n[[r2_buckets]]\nbinding="KEYS_A" # inline\nbucket_name = "x-keys"')
        self.refused({}, "the prod section of the shipped file binds KEYS_A", fixture)


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
