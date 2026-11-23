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

# The segment writer: on when MAX_OBJECT_EXTENTS is above what one
# recovery record holds.
WRITER = "MAX_OBJECT_EXTENTS"
SINGLE_RECORD_EXTENTS = 10000
REFUSED_WRITER = (
    f"the generated config sets MAX_OBJECT_EXTENTS above {SINGLE_RECORD_EXTENTS} "
    "(segmented records) while the record layout is flat"
)
BRIDGE_SRC = os.path.join(_ROOT, "crates", "velmora-bridge", "src")


def read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return f.read()


def indent_of(line):
    return len(line) - len(line.lstrip())


class Step:
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
        lines = ci_text.split("\n")
        at = [i for i, line in enumerate(lines) if line.strip() == STEP]
        if len(at) != 1:
            raise AssertionError(f"expected one step {STEP!r}, found {len(at)}")
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
        keys = [
            (i, line[len(key_pad):].split(":", 1)[0])
            for i, line in enumerate(self.lines)
            if i and line.startswith(key_pad) and not line[len(key_pad):].startswith((" ", "#"))
        ]
        self.keys = [name for _, name in keys]
        if self.keys != STEP_KEYS:
            raise AssertionError(f"the step has the keys {self.keys}, expected {STEP_KEYS}")
        where = dict((name, i) for i, name in keys)
        if self.lines[where["env"]] != key_pad + "env:":
            raise AssertionError("the step's env is not a table of its own lines")
        if self.lines[where["run"]] != key_pad + "run: |":
            raise AssertionError("the step's run is not a `|` block")
        # `NAME: ${{ vars.NAME }}` lines of the step's env table, and no
        # line of another form.
        self.env = {}
        for line in self.lines[where["env"] + 1: where["run"]]:
            m = re.fullmatch(r"\s+([A-Z0-9_]+): \$\{\{ (.+) \}\}", line)
            if not m or m.group(1) in self.env:
                raise AssertionError(f"an env line of the step is not `NAME: ${{{{ ... }}}}`: {line!r}")
            self.env[m.group(1)] = m.group(2)
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
        # `set -euo pipefail`, the call, the script, the end of the
        # script. The shell ends the script at the first line that is
        # `PY`, so that line must be the last one of the block.
        if shell[:2] != [STRICT, CALL] or len(shell) < 4:
            raise AssertionError(f"the run block does not start with {STRICT!r} and {CALL!r}")
        if shell.index(END) != len(shell) - 1:
            raise AssertionError(f"the run block does not end with the script's {END!r} line")
        self.script = "\n".join(shell[2:-1]) + "\n"

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
            "at most 8, without S3_HOST, a repeat or a subdomain of another host"
        )
        for value in (
            "A.example=customer", "a.example:443=customer", " a.example=customer",
            "a.example =customer", "a.example=customer\n", "a.example=Customer",
            "a.example=public", "a.example", "a.example=", "=legacy",
            ",a.example=customer", "a.example=customer,", "a.example=customer,,b.example=legacy",
            "a.example=customer,a.example=legacy", f"{HOST}=customer",
            f"eu.{HOST}=customer", f"{HOST.split('.', 1)[1]}=customer",
            "a.example=legacy,x.a.example=customer",
            "x.a.example=customer,a.example=legacy",
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


class SegmentWriterTest(GeneratorCase):
    """The record layout against the segment writer: a config that lets
    an object have more extents than one record holds is generated only
    with the tenant layout."""

    ANCHOR = 'VERIFY_MODE = "body"'

    def with_extents(self, value_toml):
        return add_after(self.shipped, self.ANCHOR, f"{WRITER} = {value_toml}")

    def test_the_shipped_file_leaves_the_writer_off(self):
        doc = tomllib.loads(self.shipped)
        self.assertNotIn(WRITER, doc["vars"])

    def bridge_const(self, name):
        """The value of `pub const <name>: u32` in the bridge: a number,
        or the value of the one other constant it is set to."""
        found = []
        for file in sorted(os.listdir(BRIDGE_SRC)):
            if file.endswith(".rs"):
                found += re.findall(
                    rf"^pub const {name}: u32 = ([^;]+);$", read(os.path.join(BRIDGE_SRC, file)), re.M)
        self.assertEqual(len(found), 1, name)
        if re.fullmatch(r"[0-9_]+", found[0]):
            return int(found[0].replace("_", ""))
        other = re.fullmatch(r"(?:[a-z_]+::)*([A-Z_]+)", found[0])
        self.assertIsNotNone(other, f"{name} = {found[0]}")
        return self.bridge_const(other.group(1))

    def test_the_number_is_the_one_of_the_bridge(self):
        self.assertEqual(self.bridge_const("SINGLE_RECORD_EXTENTS"), SINGLE_RECORD_EXTENTS)
        self.assertIn(f"single = {SINGLE_RECORD_EXTENTS}\n", self.step.script)

    def test_absent_is_off_in_the_worker_too(self):
        # The generator takes an absent or empty MAX_OBJECT_EXTENTS as
        # the writer off. That is true only while the value the Worker
        # takes then is no more than one record holds. A build that
        # raises it must make the generator take absent as on.
        config = read(os.path.join(BRIDGE_SRC, "config.rs"))
        arm = re.findall(
            r'match optional_u64\(&get, "MAX_OBJECT_EXTENTS"\)\? \{\n\s*None => ([A-Z_]+),\n', config)
        self.assertEqual(len(arm), 1, "the Worker's read of MAX_OBJECT_EXTENTS has another shape")
        self.assertLessEqual(self.bridge_const(arm[0]), SINGLE_RECORD_EXTENTS, arm[0])
        # Unset and empty are one case there, as they are here: the
        # function gives `None` for everything but a value that is not
        # empty after a trim.
        body = re.findall(r"\nfn optional_u64\([^{]*\{\n(.*?)\n\}\n", config, re.S)
        self.assertEqual(len(body), 1)
        arms = [line.strip() for line in body[0].split("\n")]
        self.assertEqual(arms[0], "match get(name) {")
        self.assertEqual(arms[1], "Some(v) if !v.trim().is_empty() => v")
        self.assertEqual(arms[-2:], ["_ => Ok(None),", "}"])

    def test_the_writer_on_is_refused_with_the_flat_layout(self):
        for value in (
            '"10001"', '"131072"', '" 10001 "', '"99999"', '"100000"', '"18446744073709551615"',
            # Not a plain number: the Worker reads some of these as a
            # number, the generator takes every one as on.
            '"+10001"', '"+1"', '"10k"', '"0x2711"', '"1e5"', '"١٠٠٠١"', '"on"', '"-1"',
            # Not a string at all.
            "10001", "20000", "1", "true", '["10001"]',
        ):
            doctored = self.with_extents(value)
            for older in (OLDER[0], OLDER[-1]):
                for layout in NOT_ASKED:
                    self.refused({**older, SWITCH: layout}, REFUSED_WRITER, doctored)

    def one_line_more(self, flat, tenant, what):
        """`tenant` is `flat` with the layout line after the VERIFY_MODE
        line and no other byte changed."""
        lines = flat.decode("utf-8").split("\n")
        at = [i for i, line in enumerate(lines) if line == self.ANCHOR]
        self.assertEqual(len(at), 1, what)
        want = lines[: at[0] + 1] + [TENANT_LINE] + lines[at[0] + 1:]
        self.assertEqual(tenant.decode("utf-8").split("\n"), want, what)

    def test_the_writer_on_is_generated_with_the_tenant_layout(self):
        for value in ('"10001"', '"131072"', '" 10001 "'):
            doctored = self.with_extents(value)
            out, written = self.ok({SWITCH: "tenant"}, doctored)
            doc = tomllib.loads(written.decode("utf-8"))
            self.assertEqual(doc["vars"]["RECORD_LAYOUT"], "tenant", value)
            self.assertEqual(doc["vars"][WRITER], tomllib.loads(f"v = {value}")["v"], value)
            self.assertEqual(out.splitlines()[-2], LOG + "tenant", value)
            # The bytes: what the step wrote for this file before the
            # rule, and the one line.
            self.one_line_more(without_switches(doctored), written, value)

    def test_the_writer_off_is_generated_with_either_layout(self):
        for value in ('"10000"', '"1"', '"0"', '" 10000 "', '"09999"', '""', '"  "'):
            doctored = self.with_extents(value)
            for older in (OLDER[0], OLDER[-1]):
                # The bytes the step wrote for this file before the
                # rule, worked out here.
                want = with_older(doctored, older)
                self.assertIn(f"\n{WRITER} = {value}\n".encode("utf-8"), want, value)
                for layout in NOT_ASKED:
                    _, written = self.ok({**older, SWITCH: layout}, doctored)
                    self.assertEqual(written, want, f"{value} {layout!r} {older!r}")
            _, written = self.ok({SWITCH: "tenant"}, doctored)
            self.one_line_more(without_switches(doctored), written, value)

    def test_a_writer_line_the_eye_does_not_see_is_still_read(self):
        # A quoted key, and a key set in a later line of the prod [vars]
        # table: the check reads the document, not the lines.
        for line in (f'"{WRITER}" = "10001"', f"'{WRITER}' = \"131072\""):
            doctored = add_after(self.shipped, self.ANCHOR, line)
            self.refused({SWITCH: "flat"}, REFUSED_WRITER, doctored)
            self.ok({SWITCH: "tenant"}, doctored)

    def test_another_environment_does_not_count(self):
        # The writer on in [env.dev] only: the prod table decides.
        lines = self.shipped.split("\n")
        at = [i for i, line in enumerate(lines) if line.startswith("vars = {") and i > prod_end(lines) - 1]
        self.assertEqual(len(at), 1)
        lines[at[0]] = lines[at[0]].replace("vars = { ", f'vars = {{ {WRITER} = "131072", ', 1)
        doctored = "\n".join(lines)
        self.assertEqual(tomllib.loads(doctored)["env"]["dev"]["vars"][WRITER], "131072")
        for layout in (*NOT_ASKED, "tenant"):
            self.ok({SWITCH: layout}, doctored)


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
