"""pg-migrate.sh against a disposable PostgreSQL database: fresh and import
migrations, the D1 parity gate for the statement-level usage triggers, and
the shared trigger fixture.

Set VELMORA_TEST_PG_MIGRATE=1 and the standard PGHOST, PGPORT, PGUSER and
PGDATABASE for an administrator of a disposable, local, trust-authenticated
cluster (the CI service, or an initdb of your own). Use no cluster that
serves anything else: roles.sql changes the kofra_* roles cluster-wide
(pg_read_all_data for kofra_ro, session defaults for kofra_app), and
dropping a test schema does not undo that. Each test creates and drops its
own schema. Only those four libpq variables (and PGPASSWORD) reach psql.
"""

import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import unittest

BRIDGE = Path(__file__).resolve().parents[1]
MIGRATE = BRIDGE / "ops" / "pg-migrate.sh"
ROLES = ("kofra_migrate", "kofra_app", "kofra_ro")
# Every shipped stage: both modes apply them all.
STAGES = sorted(f.name[:4] for f in (BRIDGE / "pg").glob("[0-9][0-9][0-9][0-9]_*.sql"))


def libpq_env():
    # No PGHOSTADDR, PGSERVICE or other PG* setting can redirect psql.
    env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
    env.update({k: os.environ[k] for k in ("PGHOST", "PGPORT", "PGUSER", "PGDATABASE", "PGPASSWORD")
                if k in os.environ})
    return env


def psql(sql, *, user=None, schema=None, check=True):
    env = libpq_env()
    if user:
        env["PGUSER"] = user
    prefix = f'SET search_path TO "{schema}", pg_temp;\n' if schema else ""
    result = subprocess.run(["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], input=prefix + sql,
                            capture_output=True, text=True, env=env)
    if check and result.returncode != 0:
        raise AssertionError(f"psql failed ({result.returncode}): {result.stderr.strip()}")
    return result


@unittest.skipUnless(os.environ.get("VELMORA_TEST_PG_MIGRATE") == "1",
                     "set VELMORA_TEST_PG_MIGRATE=1 and PG* for a disposable local cluster that serves nothing else")
class PgMigrate(unittest.TestCase):
    def setUp(self):
        host = os.environ.get("PGHOST", "")
        self.assertTrue(host in ("localhost", "127.0.0.1", "::1") or host.startswith("/"),
                        "use a local disposable database")
        for role in ROLES:
            psql(f"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') "
                 f"THEN CREATE ROLE {role} LOGIN; END IF; END $$;")
        self.schema = "mig_" + secrets.token_hex(8)
        psql(f"CREATE SCHEMA {self.schema}")
        self.addCleanup(psql, f"DROP SCHEMA {self.schema} CASCADE")
        roles = subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-v", f"schema={self.schema}",
                                "-f", str(BRIDGE / "pg" / "roles.sql")], capture_output=True, text=True,
                               env=libpq_env())
        self.assertEqual(roles.returncode, 0, roles.stderr)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.env = Path(tmp.name) / "pg.env"
        lock = 7_413_100_000 + secrets.randbelow(1_000_000)
        lines = [f"PGHOST={host}", f"PGDATABASE={os.environ['PGDATABASE']}", "PGUSER=kofra_migrate",
                 f"PGSCHEMA={self.schema}", f"PGLOCKKEY={lock}"]
        if os.environ.get("PGPORT"):
            lines.append(f"PGPORT={os.environ['PGPORT']}")
        self.env.write_text("\n".join(lines) + "\n")
        self.env.chmod(0o600)

    def migrate(self, *args, ok=True):
        result = subprocess.run(["bash", str(MIGRATE), str(self.env), *args], capture_output=True, text=True)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def owner_sql(self, sql):
        return psql(sql, user="kofra_migrate", schema=self.schema)

    def ledger(self):
        out = self.owner_sql("SELECT version FROM schema_migrations ORDER BY version").stdout
        return out.split()

    def test_fresh_schema_verifies_and_passes_the_trigger_fixture(self):
        self.migrate("--to", "0001")
        applied = self.migrate()
        self.assertIn("0003_usage_statement_triggers.sql: applied", applied.stdout)
        self.assertEqual(self.ledger(), STAGES)
        self.assertIn("Schema matches D1", self.migrate("--verify").stdout)
        fixture = self.migrate("--test").stdout
        self.assertIn("Trigger tests passed", fixture)
        self.assertIn("(2 key-order mixed-hour statements)", fixture)

    def test_import_mode_applies_the_statement_triggers_before_activation(self):
        self.migrate("--to", "0001", "--import-mode")
        # What the importer leaves: its marker and the copied usage rows.
        self.owner_sql("CREATE TABLE _velmora_import_incomplete (ready boolean PRIMARY KEY CHECK (ready));"
                       "INSERT INTO usage_global(id) VALUES (1), (2);")
        applied = self.migrate("--import-mode").stdout
        self.assertIn("0002_baseline_post.sql: applied", applied)
        self.assertIn("0003_usage_statement_triggers.sql: applied", applied)
        self.assertEqual(self.ledger(), STAGES)
        self.assertIn("Schema matches D1", self.migrate("--verify").stdout)

    def test_a_concurrent_index_stage_waits_out_a_long_writer(self):
        # A writer transaction older than the build, longer than the
        # migrator's 3 s lock timeout: CREATE INDEX CONCURRENTLY waits for
        # it, and must not fail and leave an INVALID index.
        no_tx = [f.name[:4] for f in sorted((BRIDGE / "pg").glob("[0-9][0-9][0-9][0-9]_*.sql"))
                 if f.read_text().startswith("-- velmora: no-transaction\n")]
        self.assertTrue(no_tx, "a shipped stage builds its indexes concurrently")
        before = STAGES[STAGES.index(no_tx[0]) - 1]
        self.migrate("--to", "0001")
        self.migrate("--to", before)
        holder = subprocess.Popen(["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], stdin=subprocess.PIPE,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=libpq_env())
        holder.stdin.write(f'SET search_path TO "{self.schema}", pg_temp;\n'
                           "BEGIN; LOCK TABLE extents IN ROW EXCLUSIVE MODE; SELECT pg_sleep(6); COMMIT;\n")
        holder.stdin.close()
        self.addCleanup(holder.wait)
        for _ in range(100):
            held = psql(f"SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation "
                        f"JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = '{self.schema}' "
                        f"AND c.relname = 'extents' AND l.mode = 'RowExclusiveLock' AND l.granted").stdout
            if held.strip() == "1":
                break
            time.sleep(0.05)
        else:
            self.fail("the writer never took its lock")
        applied = self.migrate()
        self.assertEqual(holder.wait(), 0, holder.stderr.read())
        self.assertIn(f"{no_tx[0]}_", applied.stdout)
        self.assertEqual(self.ledger(), STAGES)
        self.assertIn("Schema matches D1", self.migrate("--verify").stdout)

    def test_parity_gate_names_a_changed_usage_trigger(self):
        cases = {
            "extents.usage_extents_insert":
                "DROP TRIGGER usage_extents_insert ON extents;"
                "CREATE TRIGGER usage_extents_insert AFTER INSERT ON extents REFERENCING NEW TABLE AS new_rows "
                "FOR EACH ROW EXECUTE FUNCTION trg_usage_extents_insert_stmt();",
            "outbox.usage_outbox_stage":
                "DROP TRIGGER usage_outbox_stage ON outbox;"
                "CREATE TRIGGER usage_outbox_stage AFTER UPDATE ON outbox "
                "FOR EACH STATEMENT EXECUTE FUNCTION trg_usage_outbox_stage_stmt();",
            "outbox.usage_outbox_failure":
                "DROP TRIGGER usage_outbox_failure ON outbox;"
                "CREATE TRIGGER usage_outbox_failure AFTER UPDATE OF last_error ON outbox "
                "FOR EACH ROW EXECUTE FUNCTION trg_usage_outbox_failure_stmt();",
            "extents.generation_extents_on_insert":
                "DROP TRIGGER generation_extents_on_insert ON extents;"
                "CREATE TRIGGER generation_extents_on_insert AFTER INSERT ON extents REFERENCING NEW TABLE AS n "
                "FOR EACH ROW WHEN (NEW.generation_id IS NOT NULL AND NEW.seq IS NOT NULL "
                "AND NEW.plain_offset IS NOT NULL) EXECUTE FUNCTION trg_generation_extents_on_insert();",
        }
        self.migrate("--to", "0001")
        self.migrate()
        for name, tamper in cases.items():
            with self.subTest(name):
                self.owner_sql("BEGIN;" + tamper + "COMMIT;")
                result = self.migrate("--verify", ok=False)
                self.assertIn("triggers missing/changed", result.stderr)
                self.assertIn(name, result.stderr)
                # Undo by replaying the shipped definition in the same way.
                self.owner_sql("BEGIN;" + RESTORE[name] + "COMMIT;")
                self.assertIn("Schema matches D1", self.migrate("--verify").stdout)


RESTORE = {
    "extents.usage_extents_insert":
        "DROP TRIGGER usage_extents_insert ON extents;"
        "CREATE TRIGGER usage_extents_insert AFTER INSERT ON extents REFERENCING NEW TABLE AS new_rows "
        "FOR EACH STATEMENT EXECUTE FUNCTION trg_usage_extents_insert_stmt();",
    "outbox.usage_outbox_stage":
        "DROP TRIGGER usage_outbox_stage ON outbox;"
        "CREATE TRIGGER usage_outbox_stage AFTER UPDATE ON outbox "
        "REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows "
        "FOR EACH STATEMENT EXECUTE FUNCTION trg_usage_outbox_stage_stmt();",
    "outbox.usage_outbox_failure":
        "DROP TRIGGER usage_outbox_failure ON outbox;"
        "CREATE TRIGGER usage_outbox_failure AFTER UPDATE OF last_error ON outbox "
        "FOR EACH STATEMENT EXECUTE FUNCTION trg_usage_outbox_failure_stmt();",
    "extents.generation_extents_on_insert":
        "DROP TRIGGER generation_extents_on_insert ON extents;"
        "CREATE TRIGGER generation_extents_on_insert AFTER INSERT ON extents FOR EACH ROW "
        "WHEN (NEW.generation_id IS NOT NULL AND NEW.seq IS NOT NULL AND NEW.plain_offset IS NOT NULL) "
        "EXECUTE FUNCTION trg_generation_extents_on_insert();",
}


if __name__ == "__main__":
    unittest.main()
