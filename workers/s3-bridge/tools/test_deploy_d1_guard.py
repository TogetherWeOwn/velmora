#!/usr/bin/env python3
"""Run CI's D1 migration policy step offline with a disposable rendered config."""

from hashlib import sha256
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from textwrap import dedent
import unittest


TOOLS = Path(__file__).resolve().parent
WORKER = TOOLS.parent
WORKFLOW = WORKER.parents[1] / ".github/workflows/ci.yml"
MANIFEST = "d1-frozen-migrations.sha256"


class DeployD1GuardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        step = re.search(r"(?m)^      - id: d1-migrations\n((?:^ {8}.*\n)+)", workflow)
        if step is None:
            raise AssertionError("CI has no D1 migration policy step")
        env, script = step[1].split("        run: |\n", 1)
        cls.script = dedent(script)
        cls.pins = dict(re.findall(r'^          (D1_FROZEN_\w+): "([0-9a-f]+)"$', env, re.M))

    def setUp(self):
        temp = self.enterContext(tempfile.TemporaryDirectory(prefix="velmora-ci-d1-"))
        self.worker = Path(temp)
        self.output = self.worker / "github-output"
        self.migrations = self.worker / "migrations"
        shutil.copytree(WORKER / "migrations", self.migrations)
        (self.worker / "tools").mkdir()
        for name in ("deploy_d1_guard.py", MANIFEST):
            shutil.copyfile(TOOLS / name, self.worker / "tools" / name)

    def policy(self, backend=None, migrations_dir=None, *, extra="", extra_bindings=""):
        config = self.worker / "wrangler.deploy.toml"
        config.write_text(
            f"{extra}[vars]\n"
            + (f"CATALOG_BACKEND = {backend}\n" if backend is not None else "")
            + '[[d1_databases]]\nbinding = "CATALOG"\ndatabase_name = "velmora-catalog"\n'
            + (f'migrations_dir = "{migrations_dir}"\n' if migrations_dir is not None else "")
            + extra_bindings
            + '[env.dev.vars]\nCATALOG_BACKEND = "d1"\n'
            + '[[env.dev.d1_databases]]\nbinding = "CATALOG"\nmigrations_dir = "dev-migrations"\n',
            encoding="utf-8",
        )
        self.output.unlink(missing_ok=True)
        return subprocess.run(
            ["bash", "-c", self.script], cwd=self.worker, capture_output=True, text=True,
            env={"PATH": os.environ["PATH"], "GITHUB_OUTPUT": str(self.output),
                 "CATALOG_BACKEND": "d1", **self.pins},
        )

    def allowed(self, result, apply):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(encoding="utf-8"), f"apply={apply}\n")

    def refused(self, result, error):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(error, result.stderr)
        self.assertFalse(self.output.exists())

    def test_unset_never_defaults_to_writable_d1_in_deploy(self):
        self.refused(self.policy(), "rendered CATALOG_BACKEND must be explicit")

    def test_explicit_d1_leaves_new_migrations_for_wrangler(self):
        (self.migrations / "9999_new.sql").write_text("SELECT 1;\n", encoding="utf-8")
        self.allowed(self.policy('"d1"'), "true")

    def test_frozen_tree_skips_remote_apply_for_pg_and_both_frozen_modes(self):
        for mode in ("pg", "pg-frozen", "d1-frozen"):
            with self.subTest(mode=mode):
                self.allowed(self.policy(f'"{mode}"'), "false")

    def test_new_file_blocks_pg_and_both_frozen_modes(self):
        (self.migrations / "9999_new.sql").write_text("SELECT 1;\n", encoding="utf-8")
        for mode in ("pg", "pg-frozen", "d1-frozen"):
            with self.subTest(mode=mode):
                self.refused(self.policy(f'"{mode}"'), 'added: "9999_new.sql"')

    def test_changed_file_blocks_pg(self):
        with (self.migrations / "0001_init.sql").open("ab") as sql:
            sql.write(b"\n-- changed\n")
        self.refused(self.policy('"pg"'), 'changed: "0001_init.sql"')

    def test_missing_file_blocks_pg(self):
        (self.migrations / "0001_init.sql").unlink()
        self.refused(self.policy('"pg"'), 'removed: "0001_init.sql"')

    def test_check_uses_rendered_binding_directory_instead_of_default(self):
        alternate = self.worker / "custom-migrations"
        shutil.copytree(self.migrations, alternate)
        self.allowed(self.policy('"pg"', alternate.name), "false")
        (alternate / "9999_new.sql").touch()
        self.refused(self.policy('"pg"', alternate.name), 'added: "9999_new.sql"')

    def test_missing_directory_fails_closed(self):
        self.refused(self.policy('"pg"', "missing"), "cannot read D1 migrations directory")

    def test_manifest_tampering_does_not_bless_an_added_migration(self):
        new = self.migrations / "9999_new.sql"
        new.write_bytes(b"SELECT 1;\n")
        with (self.worker / "tools" / MANIFEST).open("a", encoding="ascii") as manifest:
            manifest.write(f"{sha256(new.read_bytes()).hexdigest()}  {new.name}\n")
        self.refused(self.policy('"pg"'), "frozen D1 manifest checksum does not match")

    def test_invalid_backend_fails_closed(self):
        for value in ('""', '"D1"', '"other"', "true"):
            with self.subTest(value=value):
                self.refused(self.policy(value), "invalid CATALOG_BACKEND")

    def test_ambiguous_catalog_binding_fails_closed(self):
        second = '[[d1_databases]]\nbinding = "OTHER"\ndatabase_name = "CATALOG"\n'
        self.refused(self.policy('"d1"', extra_bindings=second), 'expected one unambiguous CATALOG D1 binding')

    def test_frozen_migrations_do_not_follow_symlinks(self):
        migration = self.migrations / '0001_init.sql'
        target = self.worker / 'same-bytes.sql'
        migration.rename(target)
        migration.symlink_to(target)
        self.refused(self.policy('"pg"'), 'changed: "0001_init.sql"')

    def test_cannot_keep_an_out_of_band_backend(self):
        self.refused(self.policy(extra="keep_vars = true\n"), "keep_vars must be disabled")


if __name__ == "__main__":
    unittest.main()
