#!/usr/bin/env python3
"""Exercise the workflow's migration check against committed git trees."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_deploy_switches import PYTHON_CALL, extract, run

CATALOGUE = "workers/s3-bridge/migrations"
DIRECTORY = "workers/s3-bridge/migrations-directory"


class MigrationsCheckTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        step = extract("- name: Check migration files", ["env", "run"])
        cls.script = step.python_script(PYTHON_CALL)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.git("init", "-q")
        self.original = self.write(CATALOGUE, "0003_init.sql", "CREATE TABLE items (id INT);")
        self.base = self.commit()

    def git(self, *args):
        return subprocess.check_output(
            ["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
             "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
            cwd=self.root, text=True,
        ).strip()

    def write(self, folder, name, contents):
        path = self.root / folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-qm", "migration fixture")
        return self.git("rev-parse", "HEAD")

    def check(self, message, *, refused=False, base=None, switch=""):
        result = run(
            [sys.executable, "-I", "-"], self.script, self.root,
            BASE_SHA=self.base if base is None else base, HEAD_SHA=self.commit(),
            VELMORA_CATALOGUE_MIGRATIONS=switch,
        )
        self.assertEqual(result.returncode, int(refused), result.stdout + result.stderr)
        self.assertIn(message, result.stderr if refused else result.stdout)

    def test_append(self):
        self.write(CATALOGUE, "0004_next.sql", "-- DROP TABLE ignored\nALTER TABLE items ADD COLUMN name TEXT;")
        self.check("1 file(s) checked, 0 error(s)")

    def test_modify(self):
        self.original.write_text("SELECT 1;")
        self.assert_append_only()

    def test_delete(self):
        self.original.unlink()
        self.assert_append_only()

    def test_rename(self):
        self.original.rename(self.original.with_name("0004_other.sql"))
        self.assert_append_only()

    def assert_append_only(self):
        self.check("migration 0003_init.sql was changed or removed; migrations are append-only", refused=True)

    def test_bad_number(self):
        for name in ("0002_prior.sql", "0003_same.sql", "0004_NotSnake.sql", "5_next.sql"):
            self.write(CATALOGUE, name, "SELECT 1;")
        self.check("number greater than 3", refused=True)

    def test_destructive_sql(self):
        for number, sql in enumerate((
            "dRoP\nTABLE items;", "DROP COLUMN name;", "ALTER TABLE items DROP name;",
            "ALTER TABLE items RENAME TO other;",
        ), 4):
            self.write(CATALOGUE, f"{number:04}_contract.sql", "-- contract: \n" + sql)
        self.check("contains destructive SQL without a first-line contract reason", refused=True)

    def test_contract_exception(self):
        self.write(CATALOGUE, "0004_contract.sql", "-- contract: retired legacy table\nDROP TABLE items;")
        self.check("1 file(s) checked, 0 error(s)")

    def test_catalogue_switch_off(self):
        self.write(CATALOGUE, "0004_next.sql", "SELECT 1;")
        self.check("no new catalogue migration while VELMORA_CATALOGUE_MIGRATIONS is off",
                   refused=True, switch="off")

    def test_catalogue_switch_off_refuses_non_sql_file(self):
        self.write(CATALOGUE, "README.md", "New file")
        self.check("no new catalogue migration while VELMORA_CATALOGUE_MIGRATIONS is off",
                   refused=True, switch="off")

    def test_directory_is_independent(self):
        self.write(DIRECTORY, "0001_init.sql", "CREATE TABLE directory (id INT);")
        self.check("1 file(s) checked, 0 error(s)", switch="off")

    def test_zero_base_skips(self):
        self.original.unlink()
        self.check("migration check skipped: this event has no base commit", base="0" * 40)

    def test_missing_base_skips(self):
        self.original.unlink()
        self.check("migration check skipped: this event has no base commit", base="")


if __name__ == "__main__":
    unittest.main()
