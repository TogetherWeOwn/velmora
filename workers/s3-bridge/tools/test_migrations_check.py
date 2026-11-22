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

    def check(self, message, *, refused=False, base=None, switch="", event="push"):
        result = run(
            [sys.executable, "-I", "-"], self.script, self.root,
            BASE_SHA=self.base if base is None else base, HEAD_SHA=self.commit(),
            VELMORA_CATALOGUE_MIGRATIONS=switch, GITHUB_EVENT_NAME=event,
        )
        self.assertEqual(result.returncode, int(refused), result.stdout + result.stderr)
        self.assertIn(message, result.stderr if refused else result.stdout)

    def test_append(self):
        self.write(CATALOGUE, "0004_next.sql", "-- additive change\nALTER TABLE items ADD COLUMN name TEXT;")
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

    def assert_destructive(self, sql, name="0004_contract.sql"):
        self.write(CATALOGUE, name, sql)
        self.check(f"migration {name} contains destructive SQL without a first-line contract reason",
                   refused=True)

    def test_drop_table(self):
        self.assert_destructive("dRoP\nTABLE items;")

    def test_drop_column(self):
        self.assert_destructive("DROP COLUMN name;")

    def test_drop_index(self):
        self.assert_destructive("DROP INDEX idx;")

    def test_drop_trigger(self):
        self.assert_destructive("DROP TRIGGER trg;")

    def test_drop_view(self):
        self.assert_destructive("DROP VIEW v;")

    def test_delete_from(self):
        self.assert_destructive("DELETE FROM items;")

    def test_alter_drop(self):
        self.assert_destructive("ALTER TABLE items DROP name;")

    def test_alter_rename(self):
        self.assert_destructive("ALTER TABLE items RENAME TO other;")

    def test_drop_with_block_comment(self):
        self.assert_destructive("DROP/**/TABLE items;")

    def test_drop_with_line_comment(self):
        self.assert_destructive("DROP -- retire items\nTABLE items;")

    def test_drop_after_quoted_dashes(self):
        self.assert_destructive("SELECT '--'; DROP TABLE items;")

    def test_contract_on_second_line(self):
        self.assert_destructive("-- header\n-- contract: retired table\nDROP TABLE items;")

    def test_empty_contract_reason(self):
        self.assert_destructive("-- contract: \nDROP TABLE items;")

    def test_superseded_indexes_without_contract(self):
        self.assert_destructive(self.superseded_indexes(), "0023_drop_superseded_indexes.sql")

    def test_superseded_indexes_with_contract(self):
        self.write(CATALOGUE, "0023_drop_superseded_indexes.sql",
                   "-- contract: retired indexes\n" + self.superseded_indexes())
        self.check("1 file(s) checked, 0 error(s)")

    def test_migrations_next_is_excluded(self):
        self.write("workers/s3-bridge/migrations-next", "0023_drop_superseded_indexes.sql",
                   self.superseded_indexes())
        self.check("0 file(s) checked, 0 error(s)")

    def superseded_indexes(self):
        return (Path(__file__).resolve().parents[1]
                / "migrations-next/0023_drop_superseded_indexes.sql").read_text()

    def test_pr_behind_main_after_migration(self):
        self.write(CATALOGUE, "0004_main.sql", "SELECT 1;")
        main = self.commit()
        self.git("checkout", "-q", "--detach", self.base)
        self.write(".", "docs.md", "Documentation only")
        self.check("0 file(s) checked, 0 error(s)", base=main, event="pull_request")

    def test_merge_group_uses_highest_from_merge_base(self):
        self.write(CATALOGUE, "0005_shared.sql", "SELECT 1;")
        shared = self.commit()
        self.write(CATALOGUE, "0007_main.sql", "SELECT 2;")
        main = self.commit()
        self.git("checkout", "-q", "--detach", shared)
        self.write(CATALOGUE, "0006_queued.sql", "SELECT 3;")
        self.check("1 file(s) checked, 0 error(s)", base=main, event="merge_group")

    def test_push_uses_before_even_when_histories_diverge(self):
        self.write(CATALOGUE, "0004_main.sql", "SELECT 1;")
        before = self.commit()
        self.git("checkout", "-q", "--detach", self.base)
        self.write(".", "docs.md", "Documentation only")
        self.check("migration 0004_main.sql was changed or removed", base=before, refused=True)

    def test_merge_group_detects_number_collision(self):
        self.write(CATALOGUE, "0004_main.sql", "SELECT 1;")
        main = self.commit()
        self.write(CATALOGUE, "0004_queued.sql", "SELECT 2;")
        self.check("number greater than 4", base=main, event="merge_group", refused=True)

    def test_event_sha_wiring(self):
        step = extract("- name: Check migration files", ["env", "run"])
        self.assertEqual([line.strip() for line in step.lines[2:4]], [
            "BASE_SHA: ${{ github.event.pull_request.base.sha || github.event.merge_group.base_sha || github.event.before }}",
            "HEAD_SHA: ${{ github.event.pull_request.head.sha || github.event.merge_group.head_sha || github.sha }}",
        ])

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
