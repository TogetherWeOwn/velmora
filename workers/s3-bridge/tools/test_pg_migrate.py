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

import ast
import contextlib
import os
from pathlib import Path
import re
import secrets
import select
import shlex
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
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


def clone_bridge(tmp, appended=None):
    """Copy what pg-migrate.sh reads, appending SQL to named PG migrations."""
    clone = Path(tmp) / "s3-bridge"
    for part in ("ops", "pg", "migrations", "migrations-local"):
        if (BRIDGE / part).is_dir():
            shutil.copytree(BRIDGE / part, clone / part)
    for name, sql in (appended or {}).items():
        migration = clone / "pg" / name
        migration.write_text(migration.read_text() + sql)
    return clone / "ops" / "pg-migrate.sh"


@contextlib.contextmanager
def delayed_pg():
    """Add 100 ms to every proxied request and response packet."""
    host = os.environ["PGHOST"]
    port = int(os.environ.get("PGPORT", "5432"))

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            if host.startswith("/"):
                upstream = socket.socket(socket.AF_UNIX)
                upstream.connect(str(Path(host) / f".s.PGSQL.{port}"))
            else:
                upstream = socket.create_connection((host, port))
            with upstream:
                try:
                    while True:
                        readable, _, _ = select.select([self.request, upstream], [], [])
                        for source in readable:
                            data = source.recv(65536)
                            if not data:
                                return
                            if source is self.request:
                                time.sleep(0.1)
                                upstream.sendall(data)
                            else:
                                time.sleep(0.1)
                                self.request.sendall(data)
                except (BrokenPipeError, ConnectionResetError):
                    # PostgreSQL may close the connection on a transaction timeout.
                    return

    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler) as proxy:
        thread = threading.Thread(target=proxy.serve_forever)
        thread.start()
        try:
            yield proxy.server_address[1]
        finally:
            proxy.shutdown()
            thread.join()


class MigrationParser(unittest.TestCase):
    def test_lint_preserves_leading_comments_in_server_statement(self):
        source = MIGRATE.read_text()
        python = source.split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        tree = ast.parse(python)
        wanted = []
        names = {'SQL_TOKEN', 'sql_tokens_with_spans', 'sql_tokens', 'lint_migration'}
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id == 'SQL_TOKEN' for target in node.targets):
                wanted.append(node)
            elif isinstance(node, ast.FunctionDef) and node.name in names:
                wanted.append(node)

        def die(message):
            raise AssertionError(message)

        namespace = {'re': re, 'die': die, 'ValueError': ValueError}
        exec(compile(ast.Module(body=wanted, type_ignores=[]), str(MIGRATE), 'exec'), namespace)
        sql = "-- leading line comment\n/* leading block comment */\nCREATE TABLE parser_comments (value TEXT);"
        _, raw = namespace['lint_migration'](sql, False, 'parser_comments.sql')
        self.assertEqual(raw, [sql])
        # A comment after a semicolon belongs to the statement that follows it.
        first = "CREATE TABLE parser_first (value TEXT);"
        second = "\n-- between statements\n/* block */\nCREATE TABLE parser_second (value TEXT);"
        _, raw = namespace['lint_migration'](first + second, False, 'parser_comments.sql')
        self.assertEqual(raw, [first, second])
        for flag in ("SELECT set_config('velmora.migration_apply', 'off', true);",
                     "SET LOCAL velmora . migration_apply = off;", 'SET "velmora".migration_apply = off;'):
            with self.subTest(flag), self.assertRaisesRegex(AssertionError, "belongs to the migration runner"):
                namespace['lint_migration'](flag, False, 'parser_flag.sql')
        # Comments and unrelated names that merely contain the word are fine.
        harmless = "-- velmora.migration_apply\nCREATE INDEX CONCURRENTLY IF NOT EXISTS migration_apply_idx ON t (id);"
        self.assertEqual(namespace['lint_migration'](harmless, True, 'parser_flag.sql')[1], [harmless])
        alias = "SELECT velmora.migration_ apply FROM velmora;"
        self.assertEqual(namespace['lint_migration'](alias, False, 'parser_flag.sql')[1], [alias])
        # The wrapper reads each statement as a literal; this setting must stay on.
        for scs in ("SET LOCAL standard_conforming_strings = off;",
                    "SELECT set_config('standard_conforming_strings', 'off', true);",
                    'SET "standard_conforming_strings" TO off;'):
            with self.subTest(scs), self.assertRaisesRegex(AssertionError, "standard_conforming_strings belongs"):
                namespace['lint_migration'](scs, False, 'parser_scs.sql')

    def test_oversized_online_batch_names_the_argument_limit(self):
        # Linux refuses a single argv string of 128 KiB or more (MAX_ARG_STRLEN).
        # This fails before any connection, so the port need not be listening.
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp, {"0001_baseline_pre.sql": "\nSELECT '" + "x" * 131072 + "';\n"})
            env = Path(tmp) / "pg.env"
            env.write_text("PGHOST=127.0.0.1\nPGPORT=9\nPGDATABASE=velmora_test\nPGUSER=kofra_migrate\n"
                           "PGSCHEMA=mig_size\nPGLOCKKEY=7413100001\n")
            env.chmod(0o600)
            result = subprocess.run(["bash", str(script), str(env)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("0001_baseline_pre.sql: one-message batch is", result.stderr)
        self.assertIn("128 KiB", result.stderr)


class SqliteTwins(unittest.TestCase):
    """Post-cutover stages and their SQLite twins (offline)."""

    def check(self, change):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            change(script.parents[1])
            return subprocess.run(["bash", str(script), "--check-migrations"],
                                  capture_output=True, text=True, timeout=60)

    def test_the_shipped_twins_are_each_declared_once(self):
        result = self.check(lambda bridge: None)
        self.assertEqual(result.returncode, 0, result.stderr)
        twins = len(list((BRIDGE / "migrations-local").glob("[0-9][0-9][0-9][0-9]_*.sql")))
        self.assertIn(f"SQLite twin coverage: {twins} files accounted for", result.stdout)

    def test_a_twin_no_stage_declares_fails(self):
        def add(bridge):
            (bridge / "migrations-local" / "0099_orphan.sql").write_text("CREATE TABLE orphan (id INTEGER);\n")
        result = self.check(add)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SQLite twins without a PostgreSQL stage: 0099_orphan.sql", result.stderr)

    def test_a_changed_twin_fails(self):
        def change(bridge):
            twin = sorted((bridge / "migrations-local").glob("*.sql"))[0]
            twin.write_text(twin.read_text() + "-- changed\n")
        result = self.check(change)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SQLite twin fingerprint changed or is missing", result.stderr)

    def test_a_later_stage_without_a_twin_fails(self):
        def drop(bridge):
            twin = sorted((bridge / "migrations-local").glob("*.sql"))[-1]
            stage = bridge / "pg" / twin.name
            stage.write_text("".join(l for l in stage.read_text().splitlines(True)
                                     if not l.startswith("-- velmora: sqlite-twin ")))
            twin.unlink()
        result = self.check(drop)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PostgreSQL stages after the cutover without a SQLite twin", result.stderr)

    def test_a_twin_has_the_version_of_its_stage(self):
        def renumber(bridge):
            twin = sorted((bridge / "migrations-local").glob("*.sql"))[0]
            stage = bridge / "pg" / twin.name
            moved = bridge / "pg" / f"0099{stage.name[4:]}"
            stage.rename(moved)
        result = self.check(renumber)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("a SQLite twin has the version of its PostgreSQL stage", result.stderr)

    def test_later_stages_neither_reference_nor_uniquely_index_a_historical_table(self):
        stages = sorted((BRIDGE / "pg").glob("[0-9][0-9][0-9][0-9]_*.sql"))
        historical = set()
        for stage in stages:
            if stage.name[:4] <= "0003":
                historical.update(re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?([a-z_0-9]+)", stage.read_text(), re.I))
        self.assertIn("extents", historical)
        for stage in stages:
            if stage.name[:4] <= "0003":
                continue
            text = re.sub(r"--[^\n]*", "", stage.read_text())
            for table in re.findall(r"\bREFERENCES\s+([a-z_0-9]+)", text, re.I):
                self.assertNotIn(table.lower(), historical, f"{stage.name} references {table}")
            for table in re.findall(r"CREATE\s+UNIQUE\s+INDEX\b[^;]*?\bON\s+([a-z_0-9]+)", text, re.I):
                self.assertNotIn(table.lower(), historical, f"{stage.name} uniquely indexes {table}")

    def test_later_stages_use_only_additive_statement_forms(self):
        # After the baseline: new tables, indexes, added columns and literal
        # rows of new tables. No UPDATE, DELETE, or INSERT ... SELECT.
        stages = sorted((BRIDGE / "pg").glob("[0-9][0-9][0-9][0-9]_*.sql"))
        historical = set()
        for stage in stages:
            if stage.name[:4] <= "0003":
                historical.update(t.lower() for t in re.findall(
                    r"CREATE TABLE (?:IF NOT EXISTS )?([a-z_0-9]+)", stage.read_text(), re.I))
        forms = [
            r"CREATE TABLE ([a-z_0-9]+) \(.*",
            r"CREATE (?:UNIQUE )?INDEX (?:CONCURRENTLY )?(?:IF NOT EXISTS )?[a-z_0-9]+ ON [a-z_0-9]+ ?\(.*",
            r"ALTER TABLE [a-z_0-9]+ ADD COLUMN .*",
            r"INSERT INTO ([a-z_0-9]+) ?\([a-z_0-9, ]+\) VALUES \([0-9, ]+\)",
        ]
        for stage in stages:
            if stage.name[:4] <= "0003":
                continue
            text = re.sub(r"--[^\n]*", "", stage.read_text())
            for statement in filter(None, (" ".join(s.split()) for s in text.split(";"))):
                match = next((re.fullmatch(f, statement, re.I | re.S) for f in forms
                              if re.fullmatch(f, statement, re.I | re.S)), None)
                self.assertIsNotNone(match, f"{stage.name}: {statement[:80]}")
                if statement.upper().startswith(("CREATE TABLE", "INSERT")):
                    self.assertNotIn(match.group(1).lower(), historical, f"{stage.name}: {statement[:80]}")

    def test_stages_and_twins_are_plain_ascii(self):
        # Printable ASCII, tab and newline only: no backslash, no NUL,
        # comments included.
        files = sorted((BRIDGE / "pg").glob("[0-9][0-9][0-9][0-9]_*.sql"))
        files += sorted((BRIDGE / "migrations-local").glob("[0-9][0-9][0-9][0-9]_*.sql"))
        for f in files:
            bad = sorted({b for b in f.read_bytes() if not (32 <= b < 127 or b in (9, 10)) or b == 92})
            self.assertEqual(bad, [], f.name)

    def test_no_new_d1_migration_after_the_cutover(self):
        # The frozen D1 takes no schema change: the last D1 file is the one
        # the cutover baseline covers.
        self.assertEqual(max(f.name[:4] for f in (BRIDGE / "migrations").glob("[0-9][0-9][0-9][0-9]_*.sql")),
                         "0027")


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

    def migrate(self, *args, ok=True, script=MIGRATE, env_file=None, env=None):
        result = subprocess.run(["bash", str(script), str(env_file or self.env), *args],
                                capture_output=True, text=True, env=env)
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

    def server_version(self):
        return int(psql("SHOW server_version_num").stdout.strip())

    def migrate_online_with(self, sql, *, ok=True):
        """Apply 0001-0002, grant app access, then run 0003 with SQL appended."""
        self.migrate("--to", "0002")
        self.owner_sql(f'GRANT USAGE ON SCHEMA "{self.schema}" TO kofra_app')
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp, {"0003_usage_statement_triggers.sql": sql})
            return self.migrate(script=script, ok=ok)

    def test_online_migration_survives_network_round_trips(self):
        self.migrate("--to", "0002")
        self.owner_sql(f'GRANT USAGE ON SCHEMA "{self.schema}" TO kofra_app')
        original_host = os.environ["PGHOST"]
        original_port = os.environ.get("PGPORT", "5432")
        with delayed_pg() as proxy_port:
            # Always name the proxy port: with PGPORT unset, psql would reach
            # PostgreSQL directly on 5432 and skip the added latency.
            lines = [f"PGHOST=127.0.0.1" if line.startswith("PGHOST=") else line
                     for line in self.env.read_text().splitlines() if not line.startswith("PGPORT=")]
            lines.append(f"PGPORT={proxy_port}")
            self.env.write_text("\n".join(lines) + "\n")
            result = self.migrate()

        self.assertEqual(os.environ["PGHOST"], original_host)
        self.assertEqual(os.environ.get("PGPORT", "5432"), original_port)
        self.assertIn("0003_usage_statement_triggers.sql: applied", result.stdout)

    def test_online_statement_budget_rejects_slow_statement(self):
        result = self.migrate_online_with("\nCREATE TABLE operator_test (value TEXT CHECK (value || 'x' = 'x'));\n"
                                          "SELECT pg_sleep(4);\n", ok=False)
        # PostgreSQL 17+ also sets transaction_timeout, which fires first
        # (25P04); before 17 only statement_timeout applies (57014).
        self.assertIn("25P04" if self.server_version() >= 170000 else "57014", result.stderr)
        self.assertEqual(self.ledger(), ["0001", "0002"])
        self.assertEqual(self.owner_sql("SELECT to_regclass('operator_test') IS NULL").stdout.strip(), "t")

    def test_online_statement_budget_applies_to_each_statement(self):
        # Two 2 s statements: each fits the 3 s statement budget, but together
        # they exceed PostgreSQL 17+'s 3 s transaction budget.
        sleeps = "\nSELECT pg_sleep(2);\nSELECT pg_sleep(2);\n"
        if self.server_version() >= 170000:
            result = self.migrate_online_with(sleeps, ok=False)
            self.assertIn("25P04", result.stderr)
            self.assertEqual(self.ledger(), ["0001", "0002"])
        else:
            result = self.migrate_online_with(sleeps)
            self.assertIn("0003_usage_statement_triggers.sql: applied", result.stdout)
            self.assertEqual(self.ledger(), STAGES)

    def test_online_migration_text_may_contain_the_wrapper_tags(self):
        result = self.migrate_online_with(
            "\nSELECT '$velmora_0$ $velmora_migration$';\n"
            "CREATE FUNCTION operator_tags() RETURNS text LANGUAGE sql AS $velmora_migration1$ "
            "SELECT 'it''s $velmora_migration$ and $velmora_record$' $velmora_migration1$;\n")
        self.assertIn("0003_usage_statement_triggers.sql: applied", result.stdout)
        self.assertEqual(self.ledger(), STAGES)
        self.assertEqual(self.owner_sql("SELECT operator_tags()").stdout.strip(),
                         "it's $velmora_migration$ and $velmora_record$")

    def test_online_migration_cannot_clear_the_apply_decision(self):
        result = self.migrate_online_with("\nCREATE TABLE operator_reset (value TEXT);\nRESET ALL;\n"
                                          "CREATE TABLE operator_after_reset (value TEXT);\n", ok=False)
        self.assertIn("changed the runner apply decision", result.stderr)
        self.assertEqual(self.ledger(), ["0001", "0002"])
        self.assertEqual(self.owner_sql("SELECT to_regclass('operator_reset') IS NULL").stdout.strip(), "t")

    def test_online_migration_cannot_skip_its_ledger_row(self):
        # The lint cannot see a computed setting name; the ledger check must.
        result = self.migrate_online_with(
            "\nCREATE TABLE review_partial (x int);\n"
            "SELECT set_config('velmora.' || 'migration_' || 'apply', 'off', true);\n"
            "CREATE TABLE review_after (x int);\n", ok=False)
        self.assertIn("changed the runner apply decision", result.stderr)
        self.assertNotIn("0003_usage_statement_triggers.sql: already applied", result.stdout)
        self.assertEqual(self.ledger(), ["0001", "0002"])
        self.assertEqual(self.owner_sql("SELECT to_regclass('review_partial') IS NULL").stdout.strip(), "t")

    def test_already_applied_online_migration_runs_nothing(self):
        self.migrate()
        self.owner_sql(f'GRANT USAGE ON SCHEMA "{self.schema}" TO kofra_app')
        before = self.owner_sql("SELECT applied_at FROM schema_migrations ORDER BY version").stdout
        # A second online run skips every guarded statement, the seeds and the ledger row.
        triggers = "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid " \
                   "WHERE c.relnamespace = current_schema()::regnamespace AND NOT t.tgisinternal"
        count = self.owner_sql(triggers).stdout
        result = self.migrate()
        for stage in ("0001_baseline_pre.sql", "0002_baseline_post.sql", "0003_usage_statement_triggers.sql"):
            self.assertIn(f"{stage}: already applied", result.stdout)
        self.assertEqual(self.owner_sql("SELECT applied_at FROM schema_migrations ORDER BY version").stdout, before)
        self.assertEqual(self.owner_sql(triggers).stdout, count)
        self.assertEqual(self.owner_sql("SELECT count(*) FROM usage_global").stdout.strip(), "2")

    def test_verify_runs_on_psql_older_than_15(self):
        self.migrate()
        with tempfile.TemporaryDirectory() as tmp:
            shim = Path(tmp) / "psql"
            shim.write_text('#!/bin/sh\nif [ "$1" = --version ]; then echo "psql (PostgreSQL) 14.12"; exit 0; fi\n'
                            f'exec {shlex.quote(shutil.which("psql"))} "$@"\n')
            shim.chmod(0o755)
            env = dict(os.environ, PATH=f"{tmp}{os.pathsep}{os.environ['PATH']}")
            self.assertIn("Schema matches D1", self.migrate("--verify", env=env).stdout)
            # Online migration batches still need psql 15 (SHOW_ALL_RESULTS).
            self.assertIn("requires psql 15", self.migrate(env=env, ok=False).stderr)

    def test_fresh_schema_verifies_and_passes_the_trigger_fixture(self):
        self.migrate("--to", "0001")
        applied = self.migrate()
        self.assertIn("0003_usage_statement_triggers.sql: applied", applied.stdout)
        self.assertEqual(self.ledger(), STAGES)
        self.assertIn("Schema matches D1", self.migrate("--verify").stdout)
        fixture = self.migrate("--test").stdout
        self.assertIn("Trigger tests passed", fixture)
        self.assertIn("(2 key-order mixed-hour statements)", fixture)
        activated = self.migrate("--activate").stdout
        self.assertIn("0003_usage_statement_triggers.sql: already applied", activated)
        self.assertIn("App schema USAGE granted", activated)

    def test_verify_refuses_settings_that_log_bind_values(self):
        self.migrate()
        self.assertIn("Schema matches D1", self.migrate("--verify").stdout)
        check = "privilege check failed: app sessions log no bind values"
        db = '"' + os.environ["PGDATABASE"].replace('"', '""') + '"'
        for setting in ["log_statement = 'all'", "log_statement = 'mod'",
                        "log_min_duration_statement = 0", "log_min_duration_sample = 0",
                        "log_transaction_sample_rate = 1", "log_parameter_max_length_on_error = -1",
                        "auto_explain.log_min_duration = 0", "pginsights.raw_queries = on",
                        "pgaudit.log = 'all'"]:
            name = setting.split(" = ")[0]
            for scope in ["", f"IN DATABASE {db} "]:
                with self.subTest(setting=setting, scope=scope):
                    psql(f"ALTER ROLE kofra_app {scope}SET {setting}")
                    try:
                        result = self.migrate("--verify", ok=False)
                        self.assertIn(check, result.stdout + result.stderr)
                    finally:
                        psql(f"ALTER ROLE kofra_app {scope}RESET {name}")
        self.assertIn("Schema matches D1", self.migrate("--verify").stdout)
        # Every role's default, and a server-level extension setting this
        # session sees only as a placeholder.
        def reloaded(name, expected):
            # pg_reload_conf() only signals: wait until a new session sees it.
            for _ in range(100):
                seen = psql(f"SELECT coalesce(current_setting('{name}', true), '')").stdout.strip()
                if seen == expected:
                    return
                time.sleep(0.1)
            self.fail(f"configuration reload not visible: {seen!r}")

        for setup, undo, value in [
                ("ALTER ROLE ALL SET log_statement = 'all'", "ALTER ROLE ALL RESET log_statement", None),
                ("ALTER SYSTEM SET auto_explain.log_min_duration = 0; SELECT pg_reload_conf()",
                 "ALTER SYSTEM RESET auto_explain.log_min_duration; SELECT pg_reload_conf()",
                 ("auto_explain.log_min_duration", "0")),
                ("ALTER SYSTEM SET pgaudit.log = 'all'; SELECT pg_reload_conf()",
                 "ALTER SYSTEM RESET pgaudit.log; SELECT pg_reload_conf()", ("pgaudit.log", "all"))]:
            with self.subTest(setup=setup):
                for statement in setup.split("; "):
                    psql(statement)
                try:
                    if value is not None:
                        reloaded(*value)
                    result = self.migrate("--verify", ok=False)
                    self.assertIn(check, result.stdout + result.stderr)
                finally:
                    for statement in undo.split("; "):
                        psql(statement)
                    if value is not None:
                        reloaded(value[0], "")
        # A removed extension setting leaves an empty placeholder: no longer
        # a refusal.
        self.assertIn("Schema matches D1", self.migrate("--verify").stdout)
        # An explicit pgaudit.log = 'none' logs nothing: accepted.
        psql("ALTER SYSTEM SET pgaudit.log = 'none'")
        psql("SELECT pg_reload_conf()")
        try:
            reloaded("pgaudit.log", "none")
            self.assertIn("Schema matches D1", self.migrate("--verify").stdout)
        finally:
            psql("ALTER SYSTEM RESET pgaudit.log")
            psql("SELECT pg_reload_conf()")
            reloaded("pgaudit.log", "")

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

    def test_a_live_cutover_schema_takes_the_later_stages_online(self):
        # The production upgrade: a schema at the cutover baseline with app
        # access granted takes every later stage as an online migration over
        # a network with round-trip latency, ledger and parity included.
        baseline = "0003"
        later = [v for v in STAGES if v > baseline]
        self.assertTrue(later, "a stage ships after the cutover baseline")
        self.migrate("--to", baseline)
        self.owner_sql(f'GRANT USAGE ON SCHEMA "{self.schema}" TO kofra_app')
        with delayed_pg() as proxy_port:
            lines = [f"PGHOST=127.0.0.1" if line.startswith("PGHOST=") else line
                     for line in self.env.read_text().splitlines() if not line.startswith("PGPORT=")]
            lines.append(f"PGPORT={proxy_port}")
            original = self.env.read_text()
            self.env.write_text("\n".join(lines) + "\n")
            try:
                applied = self.migrate().stdout
            finally:
                self.env.write_text(original)
        names = {f.name[:4]: f.name for f in (BRIDGE / "pg").glob("[0-9][0-9][0-9][0-9]_*.sql")}
        for version in later:
            self.assertIn(f"{names[version]}: applied", applied)
        self.assertIn(f"{names[baseline]}: already applied", applied)
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
