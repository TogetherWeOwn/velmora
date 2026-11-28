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
import json
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
STAGES = ["0001", "0002", "0003"]


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
    """Copy only the cutover baseline so synthetic versions are always free."""
    clone = Path(tmp) / "s3-bridge"
    for part in ("ops", "migrations"):
        shutil.copytree(BRIDGE / part, clone / part)

    def after_cutover(_, names):
        return {name for name in names if re.fullmatch(r"[0-9]{4}_.*\.sql", name) and name[:4] not in STAGES}

    shutil.copytree(BRIDGE / "pg", clone / "pg", ignore=after_cutover)
    for name, sql in (appended or {}).items():
        migration = clone / "pg" / name
        migration.write_text(migration.read_text() + sql)
    return clone / "ops" / "pg-migrate.sh"


def add_migration(script, name, pg, sqlite=None):
    bridge = script.parents[1]
    (bridge / "pg" / name).write_text(pg)
    if sqlite is not None:
        twins = bridge / "migrations-local"
        twins.mkdir(exist_ok=True)
        (twins / name).write_text(sqlite)


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
        names = {'sql_tokens_with_spans', 'sql_tokens', 'lint_migration', 'check_concurrent_arguments'}
        constants = {'SQL_TOKEN', 'PSQL_ARGUMENT_LIMIT', 'PSQL_CONCURRENT_ARGUMENTS_LIMIT'}
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(
                    isinstance(target, ast.Name) and target.id in constants for target in node.targets):
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

    def test_post_cutover_lint_refuses_non_additive_statements(self):
        cases = {
            'DROP TABLE extents': 'DROP',
            'DROP INDEX extents_evictable': 'DROP',
            'ALTER TABLE extents DROP COLUMN plan': 'DROP',
            'ALTER TABLE extents DROP CONSTRAINT example': 'DROP',
            'ALTER TABLE extents RENAME TO moved': 'RENAME',
            'ALTER INDEX extents_evictable RENAME TO moved': 'RENAME',
            'ALTER TABLE extents ALTER COLUMN id TYPE bigint': 'ALTER COLUMN TYPE',
            'ALTER TABLE extents ALTER COLUMN id SET DATA TYPE bigint': 'ALTER COLUMN TYPE',
            'ALTER TABLE extents ALTER COLUMN plan SET NOT NULL': 'SET NOT NULL',
            'ALTER TABLE extents ADD COLUMN bad INTEGER NOT NULL': 'NOT NULL without DEFAULT',
            'ALTER TABLE extents ADD COLUMN bad INTEGER NOT NULL DEFAULT (NULL)': 'NOT NULL without DEFAULT',
            'ALTER TABLE extents ADD COLUMN bad TEXT NOT NULL DEFAULT CAST(NULL AS text)': 'NOT NULL without DEFAULT',
            'ALTER TABLE extents ADD COLUMN bad INTEGER NOT NULL DEFAULT (0 + NULL)': 'NOT NULL without DEFAULT',
            "ALTER TABLE extents ADD COLUMN bad TEXT NOT NULL CHECK (bad <> 'DEFAULT')": 'NOT NULL without DEFAULT',
            'CREATE TABLE derived (extra text) INHERITS (extents)': 'INHERITS',
            'CREATE TABLE derived PARTITION OF extents DEFAULT': 'PARTITION OF',
            'CREATE TABLE derived (LIKE extents INCLUDING DEFAULTS)': 'LIKE targets a historical',
            'CREATE TABLE derived (extent_id text REFERENCES extents(id) ON DELETE CASCADE)':
                'REFERENCES targets a historical',
            'CREATE TABLE derived (extent_id text, FOREIGN KEY (extent_id) REFERENCES extents(id))':
                'REFERENCES targets a historical',
            'CREATE UNIQUE INDEX unique_probe ON extents(created_at)': 'UNIQUE index on a historical',
        }
        for sql, diagnostic in cases.items():
            with self.subTest(sql=sql), tempfile.TemporaryDirectory() as tmp:
                script = clone_bridge(tmp)
                add_migration(script, '0004_bad.sql', f'-- example\n\n{sql};\n', 'SELECT 1;')
                result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'0004_bad.sql:3: {diagnostic}', result.stderr)

    def test_allowlist_refuses_unapproved_syntax_before_connecting(self):
        cases = {
            "INSERT INTO sample(id) VALUES (setval('fixture_sequence', 1))": 'literal',
            "INSERT INTO sample(id) SELECT 1": 'expected VALUES',
            'UPDATE sample SET id = 2': 'unsupported statement',
            'DELETE FROM sample': 'unsupported statement',
            "ALTER TABLE sample ADD COLUMN example text DEFAULT set_config('fixture.key', 'value', false)": 'literal',
            "CREATE TABLE extra (id bigint CHECK (setval('fixture_sequence', 1) > 0))": 'function must be allowlisted',
            'ALTER TABLE outbox ADD NOT NULL lease_owner NOT VALID': 'expected ADD COLUMN',
            'CREATE TABLE U&"test_name" (id bigint)': 'Unicode escapes',
            "CREATE TABLE extra (name text DEFAULT E'plain')": 'escape strings',
            'CREATE TABLE IF NOT EXISTS sample (id bigint, new_col text)': 'already declared',
            'CREATE INDEX repeat_name ON sample(id); CREATE INDEX IF NOT EXISTS repeat_name ON sample(id)': 'already declared',
            'CREATE INDEX bad ON extents(least(id, id))': 'historical index key',
            "CREATE TABLE extra (label text CHECK ((label || label) <> ''))": 'expected )',
        }
        for sql, error in cases.items():
            with self.subTest(sql=sql), tempfile.TemporaryDirectory() as tmp:
                script = clone_bridge(tmp)
                add_migration(script, '0004_sample.sql', 'CREATE TABLE sample (id bigint);', 'CREATE TABLE sample (id INTEGER);')
                add_migration(script, '0005_bad.sql', sql + ';', 'SELECT 1;')
                result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(error, result.stderr)

    def test_historical_index_allows_plain_keys_and_simple_partial_predicates(self):
        cases = (
            ("id) WHERE safety_state = 'released' AND (last_read_at IS NOT NULL OR cipher_size <= 1)", None),
            ("id) WHERE cipher_size + 1 > 3", 'historical index predicate'),
            ("id) WHERE safety_state = 'released'::text", 'historical index predicate'),
            ("cipher_size + 1)", 'historical index keys must be plain columns'),
            # SQL value functions are not columns, unquoted, in a predicate or key.
            ("id) WHERE current_timestamp IS NOT NULL", 'expected an unqualified catalogue identifier'),
            ("id) WHERE CURRENT_USER = 'x'", 'expected an unqualified catalogue identifier'),
            ("localtime)", 'expected an unqualified catalogue identifier'),
        )
        for body, error in cases:
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tmp:
                script = clone_bridge(tmp)
                add_migration(script, '0004_probe.sql', f'CREATE INDEX probe_idx ON extents({body};',
                              'CREATE INDEX probe_idx ON extents(id);')
                result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
                if error is None:
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(error, result.stderr)

    def test_index_refuses_now_in_post_cutover_key_and_predicate(self):
        for body in ('(now())', '(id) WHERE now() IS NOT NULL'):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tmp:
                script = clone_bridge(tmp)
                add_migration(script, '0004_probe.sql', 'CREATE TABLE sample (id bigint); '
                              f'CREATE INDEX probe_idx ON sample{body};',
                              'CREATE TABLE sample (id INTEGER); CREATE INDEX probe_idx ON sample(id);')
                result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('function must be allowlisted', result.stderr)

    def test_allowlist_refuses_literal_insert_into_historical_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            add_migration(script, '0004_bad.sql',
                          "INSERT INTO meta(k, v) VALUES ('fixture_key', 'fixture_value');\n",
                          'SELECT 1;')
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn('0004_bad.sql:1: INSERT may only seed a post-cutover table', result.stderr)

    def test_allowlist_refuses_trailing_clauses(self):
        cases = (
            ('ON CONFLICT', 'INSERT INTO sample(id) VALUES (1) ON CONFLICT DO NOTHING', 'SELECT 1'),
            ('RETURNING', 'INSERT INTO sample(id) VALUES (1) RETURNING id', 'SELECT 1'),
            ('index WITH', 'CREATE INDEX sample_probe ON sample(id) WITH (fillfactor = 70)',
             'CREATE INDEX sample_probe ON sample(id)'),
            ('table WITH', 'CREATE TABLE child (id bigint) WITH (fillfactor = 70)',
             'CREATE TABLE child (id INTEGER)'),
            ('PARTITION BY', 'CREATE TABLE child (id bigint) PARTITION BY RANGE (id)',
             'CREATE TABLE child (id INTEGER)'),
            ('ADD COLUMN constraint', 'ALTER TABLE sample ADD COLUMN tag text UNIQUE',
             'ALTER TABLE sample ADD COLUMN tag TEXT'),
        )
        for clause, pg, twin in cases:
            with self.subTest(clause=clause), tempfile.TemporaryDirectory() as tmp:
                script = clone_bridge(tmp)
                add_migration(script, '0004_sample.sql', 'CREATE TABLE sample (id bigint);',
                              'CREATE TABLE sample (id INTEGER);')
                add_migration(script, '0005_bad.sql', pg + ';', twin + ';')
                result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('0005_bad.sql:1: unsupported trailing clause in an additive migration', result.stderr)

    def test_allowlist_accepts_pure_expressions_and_literal_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            pg = ('CREATE TABLE sample (id bigint PRIMARY KEY, label TEXT DEFAULT lower(\'X\'), '
                  'CHECK (least(id, 99) > 0 AND length(coalesce(label, \'\')) >= 0));\n'
                  'CREATE TABLE child (id bigint REFERENCES sample(id));\n'
                  'CREATE INDEX sample_floor ON sample(greatest(id, 1));\n'
                  "INSERT INTO sample(id, label) VALUES (1, 'literal'), (2, NULL);\n")
            twin = ('CREATE TABLE sample (id INTEGER PRIMARY KEY, label TEXT);\n'
                    'CREATE TABLE child (id INTEGER REFERENCES sample(id));\n'
                    'CREATE INDEX sample_floor ON sample(id);\n')
            add_migration(script, '0004_sample.sql', pg, twin)
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_guard_rejects_stray_twin_and_nonconcurrent_no_transaction_sql(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            add_migration(script, '0004_plain_index.sql', '-- velmora: no-transaction\n'
                          'CREATE INDEX ordinary_idx ON extents(id);', 'CREATE INDEX ordinary_idx ON extents(id);')
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertIn('only CREATE INDEX CONCURRENTLY IF NOT EXISTS is allowed', result.stderr)
            (script.parents[1] / 'pg' / '0004_plain_index.sql').unlink()
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('migrations-local contains a version with no post-cutover PG migration', result.stderr)

    def test_transaction_control_is_refused_in_legacy_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp, {'0003_usage_statement_triggers.sql': '\nCOMMIT;\n'})
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('transaction control belongs to the migration runner', result.stderr)

    def test_number_and_parameter_do_not_consume_following_dollar_quote(self):
        for prefix in ('1', '$11'):
            with self.subTest(prefix=prefix), tempfile.TemporaryDirectory() as tmp:
                script = clone_bridge(tmp, {'0003_usage_statement_triggers.sql':
                    f"\nSELECT {prefix}$a$fixture$a$ :lint_only;\n"})
                result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
                self.assertIn('psql variable substitution is not allowed', result.stderr)

    def test_post_cutover_lint_accepts_additive_migration_with_local_twin(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            name = '0004_kofra_example.sql'
            add_migration(script, name,
                          "CREATE TABLE kofra_example (id bigint PRIMARY KEY, note text DEFAULT 'DROP RENAME');\n"
                          'ALTER TABLE extents\n ADD COLUMN test_flag bigint NOT NULL DEFAULT 0,\n'
                          ' ADD COLUMN test_note text;\n',
                          'CREATE TABLE kofra_example (id INTEGER PRIMARY KEY, note TEXT);\n'
                          'ALTER TABLE extents ADD COLUMN test_flag INTEGER NOT NULL DEFAULT 0;\n'
                          'ALTER TABLE extents ADD COLUMN test_note TEXT;\n')
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            (script.parents[1] / 'migrations-local' / name).unlink()
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(f'{name}: missing SQLite twin in migrations-local', result.stderr)

    def test_post_cutover_lint_checks_multiaction_lines_even_for_concurrent_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            add_migration(script, '0004_bad.sql',
                          '-- velmora: no-transaction\nALTER TABLE extents ADD COLUMN new_col text,\n'
                          ' DROP COLUMN plan;\n', 'SELECT 1;')
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('0004_bad.sql:3: DROP is not additive', result.stderr)

    def test_post_cutover_sqlite_twin_rejects_a_different_object_or_attach(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            name = '0004_kofra_example.sql'
            other_db = Path(tmp) / 'unexpected.db'
            for twin, message in (
                    ('CREATE TABLE other (id INTEGER);', 'does not add the same tables'),
                    (f"ATTACH DATABASE '{other_db}' AS other;", 'SQLite replay failed (SQLITE_AUTH)')):
                with self.subTest(twin=twin):
                    add_migration(script, name, 'CREATE TABLE kofra_example (id bigint);', twin)
                    result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(message, result.stderr)
                    self.assertFalse(other_db.exists())

    def test_post_cutover_lint_rejects_pg_only_baseline_names(self):
        cases = [
            ('ALTER TABLE outbox ADD COLUMN IF NOT EXISTS seq bigint;',
             'ALTER TABLE outbox ADD COLUMN seq INTEGER;', 'outbox.seq is a historical PostgreSQL column'),
            ('-- velmora: no-transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS outbox_seq_key ON outbox(seq);',
             'CREATE INDEX outbox_seq_key ON outbox(extent_id);', 'outbox_seq_key is a historical PostgreSQL name'),
        ]
        for pg, sqlite, expected in cases:
            with self.subTest(pg=pg), tempfile.TemporaryDirectory() as tmp:
                script = clone_bridge(tmp)
                add_migration(script, '0004_collision.sql', pg, sqlite)
                result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_post_cutover_twin_includes_explicit_columns_on_new_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            add_migration(script, '0004_example.sql',
                          'CREATE TABLE kofra_example (id bigint); '
                          'ALTER TABLE kofra_example ADD COLUMN note text;',
                          'CREATE TABLE kofra_example (id INTEGER);')
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('SQLite twin 0004_example.sql does not add the declared columns', result.stderr)

    def test_pg_file_refuses_non_ascii_bytes_and_every_backslash(self):
        cases = (
            ('CREATE\u00a0INDEX CONCURRENTLY IF NOT EXISTS fixture_idx ON extents(id);', 'non-ASCII byte'),
            ('-- \\!\nCREATE INDEX CONCURRENTLY IF NOT EXISTS fixture_idx ON extents(id);', 'backslash'),
            ('\\!\nCREATE INDEX CONCURRENTLY IF NOT EXISTS fixture_idx ON extents(id);', 'backslash'),
            ('-- \x00\nCREATE INDEX CONCURRENTLY IF NOT EXISTS fixture_idx ON extents(id);', 'NUL byte'),
        )
        for sql, diagnostic in cases:
            with self.subTest(diagnostic=diagnostic, comment=sql.startswith('--')), tempfile.TemporaryDirectory() as tmp:
                script = clone_bridge(tmp)
                add_migration(script, '0004_bad.sql', '-- velmora: no-transaction\n' + sql,
                              'CREATE INDEX fixture_idx ON extents(id);')
                result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'0004_bad.sql:2: {diagnostic} in migration SQL', result.stderr)

    def test_pg_file_refuses_control_bytes_inside_line_comments(self):
        # Offline byte-check fixtures only. The DROP token has no operand.
        for control in ('\rDROP', '\v', '\f', '\x1b', '\x7f'):
            with self.subTest(control=control), tempfile.TemporaryDirectory() as tmp:
                script = clone_bridge(tmp)
                add_migration(script, '0004_bad.sql', '-- velmora: no-transaction\n'
                              f'-- fixture control {control}\n'
                              'CREATE INDEX CONCURRENTLY IF NOT EXISTS fixture_idx ON extents(id);',
                              'CREATE INDEX fixture_idx ON extents(id);')
                result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('0004_bad.sql:2: ASCII control byte in migration SQL', result.stderr)

    def test_lint_refuses_psql_variables_but_not_casts_or_quoted_text(self):
        stage = '0003_usage_statement_triggers.sql'
        for token in (':lint_only', ":'lint_only'", ':"lint_only"', ':{?lint_only}'):
            with self.subTest(token=token), tempfile.TemporaryDirectory() as tmp:
                script = clone_bridge(tmp, {stage: f'\nSELECT {token};\n'})
                result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertRegex(result.stderr, rf'{re.escape(stage)}:[1-9][0-9]*: psql variable substitution is not allowed')
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp, {stage: "\n-- :lint_only\nSELECT 1::bigint, ':lint_only';\n"})
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_post_cutover_lint_accepts_array_and_static_literal_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            add_migration(script, '0004_defaults.sql',
                          'ALTER TABLE extents\n'
                          ' ADD COLUMN fixture_array bigint[] DEFAULT ARRAY[1, 2],\n'
                          ' ADD COLUMN fixture_ratio numeric NOT NULL DEFAULT 1e-3,\n'
                          ' ADD COLUMN fixture_label text NOT NULL DEFAULT \'\' COLLATE "C",\n'
                          ' ADD COLUMN fixture_order text NOT NULL COLLATE "C" DEFAULT \'x\';\n',
                          "ALTER TABLE extents ADD COLUMN fixture_array TEXT DEFAULT '[1, 2]';\n"
                          'ALTER TABLE extents ADD COLUMN fixture_ratio REAL NOT NULL DEFAULT 1e-3;\n'
                          "ALTER TABLE extents ADD COLUMN fixture_label TEXT NOT NULL DEFAULT '';\n"
                          "ALTER TABLE extents ADD COLUMN fixture_order TEXT NOT NULL DEFAULT 'x';\n")
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_oversized_concurrent_statement_is_refused_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            add_migration(script, '0004_concurrent.sql', '-- velmora: no-transaction\n'
                          'CREATE INDEX CONCURRENTLY IF NOT EXISTS fixture_idx ON extents(id) '
                          "WHERE id <> '" + 'x' * (128 * 1024) + "';\n",
                          'CREATE INDEX fixture_idx ON extents(id);')
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('0004_concurrent.sql: concurrent statement exceeds the psql -c argument limit', result.stderr)

    def test_concurrent_index_requires_no_transaction_header_offline(self):
        for optional in ('', 'IF NOT EXISTS '):
            with self.subTest(optional=optional), tempfile.TemporaryDirectory() as tmp:
                script = clone_bridge(tmp)
                add_migration(script, '0004_concurrent.sql',
                              f'CREATE INDEX CONCURRENTLY {optional}fixture_idx ON extents(id);',
                              'CREATE INDEX fixture_idx ON extents(id);')
                result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('no-transaction', result.stderr)

    def test_oversized_concurrent_argument_list_is_refused_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            names = [f'fixture_{i}_idx' for i in range(24)]
            pg = '-- velmora: no-transaction\n' + ''.join(
                f'-- {"x" * (96 * 1024)}\nCREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON extents(id);\n'
                for name in names)
            twin = ''.join(f'CREATE INDEX {name} ON extents(id);\n' for name in names)
            add_migration(script, '0004_oversize.sql', pg, twin)
            result = subprocess.run(['bash', str(script), '--check-migrations'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn('aggregate', result.stderr)

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


# A psql shim for deterministic races. hook.json beside it names the hooks:
#   after_snapshot: admin SQL in another session after the read-only index snapshot;
#   inject: SQL in the runner's own session right after the index fence (or,
#           for a concurrent file, after the first message containing inject_after);
#   between: SQL (as between_user) in another session before a concurrent
#            migration's ledger transaction, which then runs in a new session
#            with the per-build records the first session made;
#   hold_w1: hold the W1 advisory key in another session during the first
#            concurrent ledger transaction, which runs in a new session;
#   replace: [old, new] pairs applied to the runner's SQL, each recorded when seen.
# Each hook fires once, and only for the configured version.
HOOK_PSQL = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

here = Path(sys.argv[0]).resolve().parent
config = json.loads((here / 'hook.json').read_text())
real, schema, args = config['psql'], config['schema'], sys.argv[1:]
record = "schema_migrations VALUES ('" + config['version'] + "'"


def note(text):
    with (here / 'hook.log').open('a') as log:
        log.write(text + '\n')


def once(hook):
    if hook not in config or (here / (hook + '.done')).exists():
        return False
    (here / (hook + '.done')).write_text('')
    note('fired ' + hook)
    return True


def side_session(sql, user):
    env = dict(os.environ, PGUSER=user, PGAPPNAME='velmora-test-hook')
    result = subprocess.run([real, '-X', '-qAt', '-v', 'ON_ERROR_STOP=1'], env=env, capture_output=True, text=True,
                            input='SET search_path TO "' + schema + '", pg_temp;\n' + sql)
    if result.returncode:
        note('hook failed: ' + result.stderr)
        sys.exit(97)


def held(key):
    env = dict(os.environ, PGAPPNAME='velmora-test-hook')
    probe = subprocess.run([real, '-X', '-qAt', '-c', f"SELECT pg_try_advisory_xact_lock('{key}'::bigint)"],
                           env=env, capture_output=True, text=True)
    return probe.stdout.strip() == 'f'


def split_head(options, messages):
    # Read back what the runner recorded after each build in this session,
    # so the new session gets those values, not a fresh sample.
    names = [n for m in messages if m.startswith('DO $velmora_built$')
             for n in re.findall(r"'(velmora[.]built_[0-9]+)'", m)]
    show = [f"SELECT 'velmora-hook {n} ' || pg_catalog.current_setting('{n}', true)" for n in names]
    head = psql(options + [x for m in [*messages[:-1], *show] for x in ('-c', m)])
    lines = head.stdout.splitlines()
    head.records = [line.split(' ', 2)[1:] for line in lines if line.startswith('velmora-hook ')]
    head.stdout = ''.join(line + '\n' for line in lines if not line.startswith('velmora-hook '))
    return head


def split_setup(head):
    setup = ('SET search_path TO "' + schema + '", pg_temp; SET standard_conforming_strings = on; '
             'SET client_min_messages = error;')
    if head.records:
        setup += (' DO $hook$ BEGIN ' + ' '.join(f"PERFORM pg_catalog.set_config('{name}', '{value}', false);"
                                              for name, value in head.records) + ' END $hook$;')
    return ['-c', setup]


def psql(argv, stdin=None):
    return subprocess.run([real, *argv], input=stdin, capture_output=True, text=True,
                          stdin=None if stdin is not None else subprocess.DEVNULL)


def finish(*results):
    sys.stdout.write(''.join(r.stdout for r in results))
    sys.stderr.write(''.join(r.stderr for r in results))
    sys.exit(results[-1].returncode)


if args == ['--version']:
    os.execv(real, [real, *args])
first = args.index('-c') if '-c' in args else len(args)
options, messages = args[:first], args[first + 1::2]
stdin = None if messages else sys.stdin.read()
for old, new in config.get('replace', []):
    if any(old in m for m in messages) or (stdin and old in stdin):
        note('seen ' + old)
    messages = [m.replace(old, new) for m in messages]
    stdin = stdin and stdin.replace(old, new)


def after_fence(text):
    # The fence deparses under pg_catalog, then restores the schema path.
    fence = text.find('SET LOCAL search_path TO pg_catalog, pg_temp;\n')
    restore = 'SET LOCAL search_path TO "' + schema + '", pg_temp;\n'
    end = text.find(restore, fence)
    if record not in text or fence < 0 or end < 0 or not once('inject'):
        return text
    end += len(restore)
    return text[:end] + config['inject'] + '\n' + text[end:]


if len(messages) > 1 and record in messages[-1]:
    if once('inject'):
        marker = config.get('inject_after')
        at = 1 if marker is None else next(i for i, m in enumerate(messages) if marker in m) + 1
        messages.insert(at, config['inject'])
    if once('between'):
        head = split_head(options, messages)
        if head.returncode:
            finish(head)
        side_session(config['between'], config.get('between_user', 'kofra_migrate'))
        setup = split_setup(head)
        finish(head, psql(options + setup + ['-c', messages[-1]]))
    if once('hold_w1'):
        head = split_head(options, messages)
        if head.returncode:
            finish(head)
        holder = subprocess.Popen([real, '-X', '-qAt'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                  text=True, env=dict(os.environ, PGAPPNAME='velmora-test-hook'))
        holder.stdin.write(f"SELECT pg_advisory_lock('{config['hold_w1']}'::bigint);\n")
        holder.stdin.flush()
        for _ in range(200):
            if held(config['hold_w1']):
                break
            time.sleep(0.05)
        else:
            note('hook failed: W1 was not held')
            sys.exit(97)
        setup = split_setup(head)
        tail = psql(options + setup + ['-c', messages[-1]])
        holder.stdin.close()
        holder.wait()
        finish(head, tail)
    finish(psql(options + [x for m in messages for x in ('-c', m)]))
if messages:
    finish(psql(options + [x for m in messages for x in ('-c', after_fence(m))]))
result = psql(options, after_fence(stdin))
if result.returncode == 0 and 'READ ONLY' in stdin and 'pg_get_indexdef' in stdin and once('after_snapshot'):
    side_session(config['after_snapshot'], config['admin'])
finish(result)
'''

REUSE_TABLES = ('CREATE TABLE kofra_t (id bigint PRIMARY KEY, a bigint, b bigint);\n'
                'CREATE TABLE kofra_u (id bigint PRIMARY KEY, v bigint);\n')
REUSE_TWIN = ('CREATE TABLE kofra_t (id INTEGER PRIMARY KEY, a INTEGER, b INTEGER);\n'
              'CREATE TABLE kofra_u (id INTEGER PRIMARY KEY, v INTEGER);\n')
# kofra_a already exists when 0005 runs; kofra_b does not.
REUSE_BOTH = ('CREATE INDEX IF NOT EXISTS kofra_a ON kofra_t (id);\n'
              'CREATE INDEX IF NOT EXISTS kofra_b ON kofra_u (v);\n')
REUSE_ONLY = 'CREATE INDEX IF NOT EXISTS kofra_a ON kofra_t (id);\n'
CONCURRENT_MISMATCH = 'existing concurrent index definition does not match the migration'
ORDINARY_MISMATCH = 'existing index definition does not match the migration'
TABLE_BUSY = 'index table busy; retry later'


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
        self.baseline_script = clone_bridge(tmp.name)
        self.env = Path(tmp.name) / "pg.env"
        lock = self.lock = 7_413_100_000 + secrets.randbelow(1_000_000)
        lines = [f"PGHOST={host}", f"PGDATABASE={os.environ['PGDATABASE']}", "PGUSER=kofra_migrate",
                 f"PGSCHEMA={self.schema}", f"PGLOCKKEY={lock}"]
        if os.environ.get("PGPORT"):
            lines.append(f"PGPORT={os.environ['PGPORT']}")
        self.env.write_text("\n".join(lines) + "\n")
        self.env.chmod(0o600)

    def migrate(self, *args, ok=True, script=None, env_file=None, env=None):
        result = subprocess.run(["bash", str(script or self.baseline_script), str(env_file or self.env), *args],
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

    def test_pending_uses_read_only_ledger_in_version_order(self):
        self.migrate("--to", "0002")
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            name = '0004_kofra_example.sql'
            sql = 'CREATE TABLE kofra_example (id INTEGER PRIMARY KEY);'
            add_migration(script, name, sql, sql)
            pending = self.migrate('--pending', ok=False, script=script)
            self.assertEqual(pending.returncode, 3, pending.stderr)
            self.assertEqual(pending.stdout.splitlines(), ['0003_usage_statement_triggers.sql', name])
            self.assertEqual(self.ledger(), ['0001', '0002'])
            self.migrate(script=script)
            self.assertEqual(self.migrate('--pending', script=script).stdout, '')
            self.owner_sql("UPDATE schema_migrations SET sha256 = 'wrong' WHERE version = '0004'")
            bad_history = self.migrate('--pending', ok=False, script=script)
            self.assertNotIn(bad_history.returncode, (0, 3))
            self.assertEqual(bad_history.stdout, '')
            self.assertIn('applied migration history does not match', bad_history.stderr)

    def test_pending_refuses_a_gap_in_applied_migration_history(self):
        self.migrate()
        self.owner_sql("DELETE FROM schema_migrations WHERE version = '0002'")
        pending = self.migrate('--pending', ok=False)
        self.assertNotEqual(pending.returncode, 3)
        self.assertEqual(pending.stdout, '')
        self.assertIn('applied migration history is not an ordered prefix', pending.stderr)

    def test_online_apply_refuses_search_path_drift_before_ledger_insert(self):
        result = self.migrate_online_with('\nSET LOCAL search_path TO pg_catalog;\n', ok=False)
        self.assertIn('migration changed schema or search_path', result.stderr)
        self.assertEqual(self.ledger(), ['0001', '0002'])

    def test_verify_requires_every_shipped_version_applied(self):
        self.migrate('--to', '0002')
        result = self.migrate('--verify', ok=False)
        self.assertIn('not all requested migrations have been applied', result.stderr)

    def test_verify_requires_columns_created_in_post_cutover_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            add_migration(script, '0004_sample.sql', 'CREATE TABLE sample (id bigint, required text);',
                          'CREATE TABLE sample (id INTEGER, required TEXT);')
            self.migrate(script=script)
            self.owner_sql('ALTER TABLE sample DROP COLUMN required')
            result = self.migrate('--verify', script=script, ok=False)
            self.assertIn('column sample.required', result.stderr)

    def test_verify_rejects_inheritance_from_historical_catalogue(self):
        self.migrate()
        self.owner_sql('CREATE TABLE extra_extents () INHERITS (extents);')
        verify = self.migrate('--verify', ok=False)
        self.assertIn('historical catalogue tables cannot have inherited children: extents', verify.stderr)

    def test_concurrent_indexes_are_separate_sql_arguments_in_one_psql_session(self):
        self.migrate()
        self.owner_sql(f'GRANT USAGE ON SCHEMA "{self.schema}" TO kofra_app')
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            name = '0004_concurrent.sql'
            sql = ('CREATE INDEX IF NOT EXISTS fixture_extent_id ON extents(id);\n'
                   'CREATE INDEX IF NOT EXISTS fixture_extent_bucket ON extents(bucket_id);\n')
            add_migration(script, name, '-- velmora: no-transaction\n' +
                          sql.replace('CREATE INDEX', 'CREATE INDEX CONCURRENTLY'), sql)
            shim = Path(tmp) / 'psql'
            observations = Path(tmp) / 'observations.txt'
            shim.write_text(f"""#!/usr/bin/env python3
import os
from pathlib import Path
import sys
commands = [value for flag, value in zip(sys.argv, sys.argv[1:]) if flag == '-c']
counts = [command.count('CREATE INDEX CONCURRENTLY') for command in commands
          if 'CREATE INDEX CONCURRENTLY' in command]
if counts:
    with Path({str(observations)!r}).open('a') as log:
        log.write(str(counts) + '\\n')
os.execv({shutil.which('psql')!r}, [{shutil.which('psql')!r}, *sys.argv[1:]])
""")
            shim.chmod(0o755)
            env = dict(os.environ, PATH=f"{tmp}{os.pathsep}{os.environ['PATH']}")
            self.assertIn(f'{name}: applied', self.migrate(script=script, env=env).stdout)
            self.assertTrue(observations.exists(), 'concurrent SQL did not travel in -c arguments')
            self.assertEqual(observations.read_text().splitlines(), ['[1, 1]'])
            self.assertIn(f'{name}: already applied', self.migrate(script=script, env=env).stdout)
            self.assertEqual(self.ledger(), [*STAGES, '0004'])
            self.assertIn('Post-cutover objects verified', self.migrate('--verify', script=script, env=env).stdout)

    def hold_extents_for(self, seconds):
        """A writer transaction that holds ROW EXCLUSIVE on extents for
        `seconds`, begun now: older than anything the migrator starts."""
        holder = subprocess.Popen(["psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], stdin=subprocess.PIPE,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=libpq_env())
        holder.stdin.write(f'SET search_path TO "{self.schema}", pg_temp;\n'
                           f"BEGIN; LOCK TABLE extents IN ROW EXCLUSIVE MODE; SELECT pg_sleep({seconds}); COMMIT;\n")
        holder.stdin.close()
        self.addCleanup(holder.stderr.close)
        self.addCleanup(holder.wait)
        for _ in range(100):
            held = psql(f"SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation "
                        f"JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = '{self.schema}' "
                        f"AND c.relname = 'extents' AND l.mode = 'RowExclusiveLock' AND l.granted").stdout
            if held.strip() == "1":
                return holder
            time.sleep(0.05)
        self.fail("the writer never took its lock")

    def test_a_concurrent_index_stage_waits_out_a_long_writer(self):
        # An app writer transaction older than the build and longer than the
        # migrator's 3 s lock timeout: CREATE INDEX CONCURRENTLY waits for it,
        # and must not fail and leave an INVALID index.
        self.migrate()
        self.owner_sql(f'GRANT USAGE ON SCHEMA "{self.schema}" TO kofra_app')
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            name = '0004_concurrent.sql'
            sql = 'CREATE INDEX IF NOT EXISTS fixture_extent_bucket ON extents(bucket_id);\n'
            add_migration(script, name, '-- velmora: no-transaction\n' +
                          sql.replace('CREATE INDEX', 'CREATE INDEX CONCURRENTLY'), sql)
            holder = self.hold_extents_for(6)
            applied = self.migrate(script=script).stdout
            self.assertEqual(holder.wait(), 0, holder.stderr.read())
            self.assertIn(f'{name}: applied', applied)
            self.assertEqual(self.ledger(), [*STAGES, '0004'])
            self.assertIn('Post-cutover objects verified', self.migrate('--verify', script=script).stdout)

    def test_a_blocker_held_past_the_build_timeout_ends_in_the_runners_refusal(self):
        # A transaction older than the build and held longer than the build's
        # lock_timeout: the runner's own diagnosed refusal (the invalid index
        # it left), and no ledger row. The clone's timeout is cut to 1 s, so
        # the test does not wait 90 s; production has no such knob.
        self.migrate()
        self.owner_sql(f'GRANT USAGE ON SCHEMA "{self.schema}" TO kofra_app')
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            runner = script.read_text()
            self.assertEqual(runner.count("SET lock_timeout = '90s'"), 1)
            script.write_text(runner.replace("SET lock_timeout = '90s'", "SET lock_timeout = '1s'"))
            name = '0004_concurrent.sql'
            sql = 'CREATE INDEX IF NOT EXISTS fixture_extent_bucket ON extents(bucket_id);\n'
            add_migration(script, name, '-- velmora: no-transaction\n' +
                          sql.replace('CREATE INDEX', 'CREATE INDEX CONCURRENTLY'), sql)
            holder = self.hold_extents_for(5)
            refused = self.migrate(script=script, ok=False)
            self.assertEqual(holder.wait(), 0, holder.stderr.read())
            self.assertIn(f'{name}: catalogue contains an invalid index; repair it before retrying',
                          refused.stderr)
            self.assertEqual(self.ledger(), STAGES, 'no ledger row')

    def test_a_live_cutover_schema_takes_later_stages_online_over_a_delayed_network(self):
        # The production upgrade: a schema at the cutover baseline with app
        # access granted takes a later transactional stage and a later
        # concurrent-index stage online, over a network with round-trip
        # latency, ledger and verification included.
        self.migrate()
        self.owner_sql(f'GRANT USAGE ON SCHEMA "{self.schema}" TO kofra_app')
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            add_migration(script, '0004_fixture_table.sql',
                          'CREATE TABLE fixture_later (id BIGINT PRIMARY KEY, note TEXT COLLATE "C");\n',
                          'CREATE TABLE fixture_later (id INTEGER PRIMARY KEY, note TEXT);\n')
            sql = 'CREATE INDEX IF NOT EXISTS fixture_extent_bucket ON extents(bucket_id);\n'
            add_migration(script, '0005_fixture_index.sql', '-- velmora: no-transaction\n' +
                          sql.replace('CREATE INDEX', 'CREATE INDEX CONCURRENTLY'), sql)
            original = self.env.read_text()
            with delayed_pg() as proxy_port:
                lines = [f"PGHOST=127.0.0.1" if line.startswith("PGHOST=") else line
                         for line in original.splitlines() if not line.startswith("PGPORT=")]
                lines.append(f"PGPORT={proxy_port}")
                self.env.write_text("\n".join(lines) + "\n")
                try:
                    applied = self.migrate(script=script).stdout
                finally:
                    self.env.write_text(original)
            self.assertIn('0004_fixture_table.sql: applied', applied)
            self.assertIn('0005_fixture_index.sql: applied', applied)
            self.assertEqual(self.migrate('--pending', script=script).stdout, '')
            self.assertEqual(self.ledger(), [*STAGES, '0004', '0005'])
            self.assertIn('Post-cutover objects verified', self.migrate('--verify', script=script).stdout)

    def test_failed_concurrent_statement_leaves_migration_pending(self):
        self.migrate()
        self.owner_sql(f'GRANT USAGE ON SCHEMA "{self.schema}" TO kofra_app')
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            name = '0004_concurrent.sql'
            twin = ('CREATE INDEX fixture_extent_id ON extents(id);\n'
                    'CREATE INDEX fixture_extent_bucket ON extents(bucket_id);\n')
            pg = ('-- velmora: no-transaction\n' + twin.replace('CREATE INDEX', 'CREATE INDEX CONCURRENTLY IF NOT EXISTS')
                  .replace('(bucket_id)', '(missing_test_column)'))
            add_migration(script, name, pg, twin)
            result = self.migrate(script=script, ok=False)
            self.assertIn(f'{name}: SQLSTATE 42703', result.stderr)
            self.assertEqual(self.ledger(), STAGES)
            pending = self.migrate('--pending', script=script, ok=False)
            self.assertEqual((pending.returncode, pending.stdout), (3, name + '\n'))

            unchanged = pg.replace('missing_test_column', 'bucket_id')
            changed = unchanged.replace('fixture_extent_id ON extents(id)',
                                        'fixture_extent_id ON extents(bucket_id)')
            add_migration(script, name, changed, twin.replace('fixture_extent_id ON extents(id)',
                                                             'fixture_extent_id ON extents(bucket_id)'))
            mismatch = self.migrate(script=script, ok=False)
            self.assertIn('index definition does not match', mismatch.stderr)
            self.assertEqual(self.ledger(), STAGES)
            self.assertEqual(self.owner_sql("SELECT to_regclass('fixture_extent_bucket') IS NULL").stdout.strip(), 't')
            self.assertIn('(id)', self.owner_sql("SELECT pg_get_indexdef('fixture_extent_id'::regclass)").stdout)

            add_migration(script, name, unchanged, twin)
            self.assertIn(f'{name}: applied', self.migrate(script=script).stdout)
            self.assertIn('Post-cutover objects verified', self.migrate('--verify', script=script).stdout)

    def test_ordinary_index_if_not_exists_checks_the_existing_definition(self):
        self.migrate()
        self.owner_sql('CREATE INDEX fixture_existing ON extents(id);')
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            name = '0004_ordinary.sql'
            wrong = 'CREATE INDEX IF NOT EXISTS fixture_existing ON extents(bucket_id);'
            add_migration(script, name, wrong, wrong)
            mismatch = self.migrate(script=script, ok=False)
            self.assertIn('index definition does not match', mismatch.stderr)
            self.assertEqual(self.ledger(), STAGES)
            same = wrong.replace('(bucket_id)', '(id)')
            add_migration(script, name, same, same)
            self.assertIn(f'{name}: applied', self.migrate(script=script).stdout)
            self.assertEqual(self.ledger(), [*STAGES, '0004'])

    def hooked(self, tmp, **hooks):
        """PATH and log for the HOOK_PSQL shim; hooks fire for version 0005."""
        hook = Path(tmp) / 'hook'
        hook.mkdir()
        (hook / 'hook.json').write_text(json.dumps(dict(
            psql=shutil.which('psql'), schema=self.schema, admin=os.environ['PGUSER'], version='0005', **hooks)))
        (hook / 'psql').write_text(HOOK_PSQL)
        (hook / 'psql').chmod(0o755)
        return dict(os.environ, PATH=f"{hook}{os.pathsep}{os.environ['PATH']}"), hook / 'hook.log'

    def reuse_setup(self, tmp, indexes, *, mode, existing=True):
        """Apply 0001-0004 in mode (online, import or concurrent), create the
        matching kofra_a if existing, and add 0005 with the given index statements."""
        script = clone_bridge(tmp)
        args = ('--import-mode',) if mode == 'import' else ()
        if mode == 'import':
            self.migrate('--to', '0001', '--import-mode', script=script)
            self.owner_sql("CREATE TABLE _velmora_import_incomplete (ready boolean PRIMARY KEY CHECK (ready));"
                           "INSERT INTO usage_global(id) VALUES (1), (2);")
        add_migration(script, '0004_kofra_tables.sql', REUSE_TABLES, REUSE_TWIN)
        self.migrate(*args, script=script)
        if mode != 'import':
            self.owner_sql(f'GRANT USAGE ON SCHEMA "{self.schema}" TO kofra_app')
        if existing:
            self.owner_sql('CREATE INDEX kofra_a ON kofra_t (id);')
        pg = indexes
        if mode == 'concurrent':
            pg = '-- velmora: no-transaction\n' + indexes.replace('CREATE INDEX', 'CREATE INDEX CONCURRENTLY')
        add_migration(script, '0005_kofra_indexes.sql', pg, indexes)
        return script, args

    def index_oid(self, name):
        return self.owner_sql(f"SELECT coalesce(to_regclass('{name}')::oid, 0)").stdout.strip()

    def assert_refused_without_ledger_row(self, result, script, message, *, retried=False):
        self.assertIn(f'0005_kofra_indexes.sql: {message}', result.stderr)
        if retried:
            self.assertIn('0005_kofra_indexes.sql: SQLSTATE VL023, retry 5/5', result.stderr)
        else:
            self.assertNotIn('retry', result.stderr)
        self.assertNotIn('0005', self.ledger())
        pending = self.migrate('--pending', script=script, ok=False)
        self.assertEqual((pending.returncode, pending.stdout), (3, '0005_kofra_indexes.sql\n'), pending.stderr)

    def concurrent_reuse_race(self, tmp, between, *, user='kofra_migrate'):
        script, _ = self.reuse_setup(tmp, REUSE_BOTH, mode='concurrent')
        env, log = self.hooked(tmp, between=between, between_user=user)
        result = self.migrate(script=script, env=env, ok=False)
        self.assertIn('fired between', log.read_text())
        self.assert_refused_without_ledger_row(result, script, CONCURRENT_MISMATCH)
        return script, result

    def test_reused_index_dropped_before_concurrent_ledger_write_is_refused(self):
        # A plain DROP INDEX after the fence: the migration stays pending.
        with tempfile.TemporaryDirectory() as tmp:
            script, _ = self.concurrent_reuse_race(tmp, 'DROP INDEX kofra_a;')
            self.assertEqual(self.index_oid('kofra_a'), '0')
            # The next run builds the missing index and records the migration.
            self.assertIn('0005_kofra_indexes.sql: applied', self.migrate(script=script).stdout)
            self.assertIn('Post-cutover objects verified', self.migrate('--verify', script=script).stdout)

    def test_reused_index_dropped_concurrently_before_ledger_write_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.concurrent_reuse_race(tmp, 'DROP INDEX CONCURRENTLY kofra_a;')
            self.assertEqual(self.index_oid('kofra_a'), '0')

    def test_concurrent_ledger_lock_timeout_retries_with_a_fresh_plan(self):
        # W1 is busy past the 3 s lock_timeout after kofra_b was built. The
        # retry must reuse kofra_b, not refuse it against the stale snapshot.
        with tempfile.TemporaryDirectory() as tmp:
            script, _ = self.reuse_setup(tmp, REUSE_BOTH, mode='concurrent')
            env, log = self.hooked(tmp, hold_w1=str(self.lock))
            result = self.migrate(script=script, env=env)
            self.assertIn('fired hold_w1', log.read_text())
            self.assertIn('0005_kofra_indexes.sql: SQLSTATE 55P03, retry 1/5', result.stderr)
            self.assertIn('0005_kofra_indexes.sql: applied', result.stdout)
            self.assertEqual(self.ledger(), [*STAGES, '0004', '0005'])
            self.assertIn('Post-cutover objects verified', self.migrate('--verify', script=script).stdout)

    def test_reused_index_made_invalid_maps_to_the_concurrent_mismatch(self):
        # The reuse check runs before the catalogue-wide invalid-index check.
        with tempfile.TemporaryDirectory() as tmp:
            _, result = self.concurrent_reuse_race(
                tmp, 'UPDATE pg_catalog.pg_index SET indisvalid = false WHERE indexrelid = '
                f"'\"{self.schema}\".kofra_a'::regclass;", user=os.environ['PGUSER'])
            self.assertNotIn('invalid index', result.stderr)

    def test_reused_index_replaced_before_online_ledger_write_is_refused(self):
        # Same name and definition, new OID.
        with tempfile.TemporaryDirectory() as tmp:
            script, _ = self.reuse_setup(tmp, REUSE_BOTH, mode='online')
            before = self.index_oid('kofra_a')
            env, log = self.hooked(tmp, inject='DROP INDEX kofra_a; CREATE INDEX kofra_a ON kofra_t (id);')
            result = self.migrate(script=script, env=env, ok=False)
            self.assertIn('fired inject', log.read_text())
            self.assert_refused_without_ledger_row(result, script, ORDINARY_MISMATCH)
            self.assertEqual(self.index_oid('kofra_a'), before)
            self.assertEqual(self.index_oid('kofra_b'), '0')

    def test_reused_index_definition_change_before_lock_is_refused(self):
        # Same OID, valid and ready; only the deparsed definition differs.
        with tempfile.TemporaryDirectory() as tmp:
            script, _ = self.reuse_setup(tmp, REUSE_BOTH, mode='online')
            env, log = self.hooked(tmp, inject='ALTER INDEX kofra_a SET (fillfactor = 50);')
            result = self.migrate(script=script, env=env, ok=False)
            self.assertIn('fired inject', log.read_text())
            self.assert_refused_without_ledger_row(result, script, ORDINARY_MISMATCH)
            self.assertNotIn('fillfactor', self.owner_sql("SELECT pg_get_indexdef('kofra_a'::regclass)").stdout)

    def test_reused_index_dropped_before_import_ledger_write_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            script, args = self.reuse_setup(tmp, REUSE_BOTH, mode='import')
            env, log = self.hooked(tmp, inject='DROP INDEX kofra_a;')
            result = self.migrate(*args, script=script, env=env, ok=False)
            self.assertIn('fired inject', log.read_text())
            self.assert_refused_without_ledger_row(result, script, ORDINARY_MISMATCH)
            self.assertNotEqual(self.index_oid('kofra_a'), '0')

    def held_reused_table(self, script, args, env, *, release_on_retry=False):
        """Run the migration while another session holds kofra_t in the mode
        DROP INDEX CONCURRENTLY takes; optionally release it at the first retry."""
        blocker = subprocess.Popen(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1'], stdin=subprocess.PIPE,
                                   stdout=subprocess.DEVNULL, text=True, env=libpq_env())
        try:
            blocker.stdin.write(f'BEGIN;\nLOCK TABLE "{self.schema}".kofra_t IN SHARE UPDATE EXCLUSIVE MODE;\n')
            blocker.stdin.flush()
            held = (f"SELECT count(*) FROM pg_locks WHERE relation = '\"{self.schema}\".kofra_t'::regclass "
                    "AND mode = 'ShareUpdateExclusiveLock' AND granted")
            for _ in range(100):
                if psql(held).stdout.strip() == '1':
                    break
                time.sleep(0.05)
            else:
                self.fail('blocker did not take its lock')
            if not release_on_retry:
                return self.migrate(*args, script=script, env=env, ok=False)
            run = subprocess.Popen(['bash', str(script), str(self.env), *args], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, env=env)
            first = run.stderr.readline()
            self.assertIn('retry 1/5', first)
            blocker.stdin.write('ROLLBACK;\n')
            blocker.stdin.close()
            out, err = run.communicate(timeout=120)
            self.assertEqual(run.returncode, 0, err)
            return subprocess.CompletedProcess(run.args, run.returncode, out, first + err)
        finally:
            if not blocker.stdin.closed:
                blocker.stdin.write('ROLLBACK;\n')
            blocker.stdin.close()
            blocker.wait(timeout=30)

    def reuse_lock_timeout(self, mode, *, replace=()):
        with tempfile.TemporaryDirectory() as tmp:
            script, args = self.reuse_setup(tmp, REUSE_ONLY, mode=mode)
            env, log = self.hooked(tmp, replace=list(replace))
            result = self.held_reused_table(script, args, env)
            for old, _ in replace:
                self.assertIn(f'seen {old}', log.read_text())
            # Busy, not a mismatch: the matching index must not look droppable.
            self.assert_refused_without_ledger_row(result, script, TABLE_BUSY, retried=True)
            self.assertNotIn('does not match', result.stderr)
            self.assertNotEqual(self.index_oid('kofra_a'), '0')
            self.assertIn('0005_kofra_indexes.sql: applied', self.migrate(*args, script=script).stdout)

    # With app access, the real timeouts: the lock wait ends inside the 3 s
    # statement and transaction budgets, so the refusal is the busy table.
    def test_concurrent_reuse_lock_timeout_writes_no_ledger_row(self):
        self.reuse_lock_timeout('concurrent')

    def test_online_reuse_lock_timeout_writes_no_ledger_row(self):
        self.reuse_lock_timeout('online')

    def test_import_reuse_lock_timeout_writes_no_ledger_row(self):
        # Without app access the wait is 30 s, shortened to 1 s for the test.
        self.reuse_lock_timeout('import', replace=[["SET LOCAL lock_timeout = '30s'", "SET LOCAL lock_timeout = '1s'"]])

    def busy_until_retry(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            script, args = self.reuse_setup(tmp, REUSE_ONLY, mode=mode)
            env, _ = self.hooked(tmp)
            result = self.held_reused_table(script, args, env, release_on_retry=True)
            self.assertIn('0005_kofra_indexes.sql: SQLSTATE VL023, retry 1/5', result.stderr)
            self.assertIn('0005_kofra_indexes.sql: applied', result.stdout)
            self.assertEqual(self.ledger()[-1], '0005')

    def test_busy_index_table_is_retried_until_free_concurrent(self):
        self.busy_until_retry('concurrent')

    def test_busy_index_table_is_retried_until_free_online(self):
        self.busy_until_retry('online')

    def built_race(self, inject, *, recovers, side_session=False):
        """Build kofra_a, then kofra_b; inject runs after kofra_a's build, in
        the runner's session or, after both builds, in another session."""
        with tempfile.TemporaryDirectory() as tmp:
            script, _ = self.reuse_setup(tmp, REUSE_BOTH, mode='concurrent', existing=False)
            hooks = dict(between=inject) if side_session else dict(inject=inject, inject_after="velmora.built_0'")
            env, log = self.hooked(tmp, **hooks)
            result = self.migrate(script=script, env=env, ok=False)
            self.assertIn('fired between' if side_session else 'fired inject', log.read_text())
            self.assert_refused_without_ledger_row(result, script, CONCURRENT_MISMATCH)
            self.assertNotEqual(self.index_oid('kofra_b'), '0')
            if recovers:
                # The next run builds what is missing and records the migration.
                self.assertIn('0005_kofra_indexes.sql: applied', self.migrate(script=script).stdout)
                self.assertIn('Post-cutover objects verified', self.migrate('--verify', script=script).stdout)
            else:
                # A different index under the name stays refused until repaired.
                self.assertIn(CONCURRENT_MISMATCH, self.migrate(script=script, ok=False).stderr)

    def test_index_built_by_this_run_dropped_before_ledger_write_is_refused(self):
        self.built_race('DROP INDEX kofra_a;', recovers=True)

    def test_index_built_by_this_run_replaced_before_ledger_write_is_refused(self):
        self.built_race('DROP INDEX kofra_a; CREATE INDEX kofra_a ON kofra_t (a);', recovers=False)

    def test_index_built_by_this_run_replaced_by_another_session_is_refused(self):
        self.built_race('DROP INDEX kofra_a; CREATE INDEX kofra_a ON kofra_t (a);', recovers=False,
                        side_session=True)

    def test_same_name_index_created_after_snapshot_is_refused_at_the_fence(self):
        with tempfile.TemporaryDirectory() as tmp:
            script, _ = self.reuse_setup(tmp, REUSE_BOTH, mode='concurrent')
            env, log = self.hooked(tmp, after_snapshot='CREATE INDEX kofra_b ON kofra_u (v);')
            result = self.migrate(script=script, env=env, ok=False)
            self.assertIn('fired after_snapshot', log.read_text())
            self.assert_refused_without_ledger_row(result, script, CONCURRENT_MISMATCH)

    def test_import_mode_fence_refuses_index_created_after_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            script, args = self.reuse_setup(tmp, REUSE_BOTH, mode='import')
            env, log = self.hooked(tmp, after_snapshot='CREATE INDEX kofra_b ON kofra_u (v);')
            result = self.migrate(*args, script=script, env=env, ok=False)
            self.assertIn('fired after_snapshot', log.read_text())
            self.assert_refused_without_ledger_row(result, script, ORDINARY_MISMATCH)

    def test_absent_index_is_built_without_if_not_exists(self):
        # A different same-name index appearing after the fence fails the
        # build instead of turning it into a silent no-op.
        with tempfile.TemporaryDirectory() as tmp:
            script, _ = self.reuse_setup(tmp, REUSE_BOTH, mode='concurrent')
            env, log = self.hooked(tmp, inject='CREATE INDEX kofra_b ON kofra_u (id);')
            result = self.migrate(script=script, env=env, ok=False)
            self.assertIn('fired inject', log.read_text())
            self.assert_refused_without_ledger_row(result, script, 'SQLSTATE 42P07')

    def test_existing_index_whose_predicate_starts_with_a_group_is_reused(self):
        # pg_get_indexdef wraps the whole predicate in one pair; only that
        # outer pair is removed, so the source grouping still matches.
        with tempfile.TemporaryDirectory() as tmp:
            index = 'CREATE INDEX IF NOT EXISTS kofra_p ON kofra_t (id) WHERE (a = 1) OR (b = 2);\n'
            script, _ = self.reuse_setup(tmp, index, mode='online')
            self.owner_sql(index)
            before = self.index_oid('kofra_p')
            self.assertIn('WHERE ((a = 1) OR (b = 2))',
                          self.owner_sql("SELECT pg_get_indexdef('kofra_p'::regclass)").stdout)
            self.assertIn('0005_kofra_indexes.sql: applied', self.migrate(script=script).stdout)
            self.assertEqual(self.index_oid('kofra_p'), before)

    def test_full_shipped_chain_verifies(self):
        self.migrate(script=MIGRATE)
        self.assertEqual(self.migrate('--pending', script=MIGRATE).stdout, '')
        self.assertIn('Schema matches D1', self.migrate('--verify', script=MIGRATE).stdout)

    def test_verify_checks_pg_only_objects_without_masking_baseline_drift(self):
        self.migrate()
        self.owner_sql(f'GRANT USAGE ON SCHEMA "{self.schema}" TO kofra_app')
        with tempfile.TemporaryDirectory() as tmp:
            script = clone_bridge(tmp)
            name = '0004_kofra_example.sql'
            sql = ('CREATE TABLE kofra_example (id bigint PRIMARY KEY, note text);\n'
                   'CREATE INDEX kofra_example_note ON kofra_example(note);\n'
                   'ALTER TABLE extents ADD COLUMN test_flag bigint NOT NULL DEFAULT 0;\n'
                   'CREATE INDEX test_extents_flag ON extents(test_flag);\n')
            add_migration(script, name, sql, sql)
            self.migrate(script=script)
            self.assertIn('Post-cutover objects verified', self.migrate('--verify', script=script).stdout)
            self.owner_sql('ALTER TABLE extents ADD COLUMN untracked_col bigint;')
            drift = self.migrate('--verify', ok=False, script=script)
            self.assertIn('columns unexpected/changed: extents.untracked_col', drift.stderr)
            self.owner_sql('ALTER TABLE extents DROP COLUMN untracked_col; DROP TABLE kofra_example;')
            missing = self.migrate('--verify', ok=False, script=script)
            self.assertIn('table kofra_example', missing.stderr)
            self.assertIn('index kofra_example.kofra_example_note', missing.stderr)

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
