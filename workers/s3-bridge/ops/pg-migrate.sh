#!/usr/bin/env bash
set -eu
# The connection file is parsed, not sourced. Only libpq's child environment
# receives the credentials; neither shell expansion nor psql argv sees them.
exec python3 -I - "$0" "$@" <<'PY'
import argparse
from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import time

PG = Path(sys.argv[1]).resolve().parent.parent / 'pg'
D1 = PG.parent / 'migrations'
LOCAL = PG.parent / 'migrations-local'
# -I excludes the current directory; import only from the runner's own directory.
sys.path.insert(0, str(PG.parent / 'ops'))
from pg_catalog import CUTOVER_BASELINE, Failure, lint_additive, replay_sqlite_twins, verify_post_cutover

W1 = 7413000001
MIGRATOR = 7413000002
DATA_ENV = {'PGHOST', 'PGPORT', 'PGDATABASE', 'PGUSER', 'PGPASSWORD',
            'PGSSLMODE', 'PGSSLROOTCERT', 'PGCONNECT_TIMEOUT'}
ERRORS = {
    'VL010': 'target schema must be owned by kofra_migrate and closed to PUBLIC',
    'VL011': 'applied migration history does not match the shipped files',
    'VL012': 'pre-copy target must have no app access, import marker, post-copy migration or catalogue rows',
    'VL013': 'post-copy import requires the import marker, no app access and both imported usage rows',
    'VL014': 'fresh migration requires no import marker and both fresh usage rows',
    'VL015': 'catalogue contains an invalid index; repair it before retrying',
    'VL016': 'activation refused while the import marker exists',
    'VL017': 'not all requested migrations have been applied',
    'VL018': 'a migration statement changed the runner apply decision; the migration was rolled back',
    '25P04': 'SQLSTATE 25P04: online migration exceeded the 3 s transaction budget',
    '57014': 'SQLSTATE 57014: an online migration statement exceeded the 3 s statement budget or was canceled',
}
# Declared engine difference (0003): these D1 per-row usage triggers are
# PostgreSQL statement triggers. Each entry is the column list (KEEP_COLUMNS:
# the D1 trigger's own) and the OLD and NEW transition table names. Every
# other trigger must stay per-row and have no transition tables.
KEEP_COLUMNS = object()
STATEMENT_TRIGGERS = {
    'usage_extents_insert': ((), None, 'new_rows'),
    'usage_extents_update': ((), 'old_rows', 'new_rows'),
    'usage_extents_delete': ((), 'old_rows', None),
    'usage_generations_insert': ((), None, 'new_rows'),
    'usage_generations_update': ((), 'old_rows', 'new_rows'),
    'usage_generations_delete': ((), 'old_rows', None),
    'usage_outbox_insert': ((), None, 'new_rows'),
    'usage_outbox_delete': ((), 'old_rows', None),
    # Fires before usage_outbox_stage (name order) for the same statement.
    'usage_outbox_failure': (KEEP_COLUMNS, None, None),
    'usage_outbox_stage': ((), 'old_rows', 'new_rows'),
}
MARKER = "to_regclass(format('%I._velmora_import_incomplete', current_schema()))"
USAGE = "has_schema_privilege('kofra_app', current_schema(), 'USAGE')"
SEEDS = '(SELECT count(*) FROM usage_global WHERE id IN (1, 2)) = 2'
BAD_INDEX = '''EXISTS (SELECT FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
    WHERE c.relnamespace = to_regnamespace(current_schema()) AND NOT (i.indisvalid AND i.indisready))'''
LEDGER = '''CREATE TABLE schema_migrations (
    version TEXT COLLATE "C" PRIMARY KEY,
    sha256 TEXT COLLATE "C" NOT NULL,
    applied_at BIGINT NOT NULL
);
REVOKE ALL ON TABLE schema_migrations FROM kofra_app;'''
RESTART_IDENTITIES = '''
DO $$
DECLARE next_id bigint;
BEGIN
    SELECT greatest(coalesce(max(id), 0) + 1, 1) INTO next_id FROM gc;
    EXECUTE format('ALTER TABLE gc ALTER COLUMN id RESTART WITH %s', next_id);
    SELECT greatest(coalesce(max(id), 0) + 1, 1) INTO next_id FROM usage_recounts;
    EXECUTE format('ALTER TABLE usage_recounts ALTER COLUMN id RESTART WITH %s', next_id);
    SELECT greatest(coalesce(max(seq), 0) + 1, 1) INTO next_id FROM outbox;
    EXECUTE format('ALTER TABLE outbox ALTER COLUMN seq RESTART WITH %s', next_id);
END;
$$;
'''


def die(message):
    raise SystemExit(f'pg-migrate: {message}')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sql_files(root):
    result = {}
    for f in sorted(root.glob('*.sql')):
        if root == PG and f.name in {'roles.sql', 'check_schema.sql', 'test_triggers.sql'}:
            continue
        if not re.fullmatch(r'[0-9]{4}_[a-z0-9_]+\.sql', f.name) or f.name[:4] in result:
            die(f'invalid or duplicate migration filename: {f.name}')
        result[f.name[:4]] = (f.name, f.read_bytes())
    return result


def coverage(files, d1, *, quiet=False):
    covered = set()
    for name, body in files.values():
        for selection, expected in re.findall(
            rb'^-- velmora: d1-baseline ([0-9,-]+) ([0-9a-f]{64})$', body, re.M
        ):
            versions = set()
            for part in selection.decode().split(','):
                lo, hi = (part.split('-') if '-' in part else (part, part))
                if len(lo) != 4 or len(hi) != 4 or lo > hi:
                    die(f'invalid D1 baseline range in {name}')
                versions.update(f'{i:04d}' for i in range(int(lo), int(hi) + 1))
            missing = versions - d1.keys()
            if missing:
                die('D1 baseline files missing: ' + ', '.join(sorted(missing)))
            actual = digest(''.join(f'{d1[v][0]} {digest(d1[v][1])}\n' for v in sorted(versions)).encode())
            if actual != expected.decode():
                die(f'D1 baseline fingerprint changed ({name}); compare the schemas before updating it')
            if covered & versions:
                die('duplicate D1 coverage')
            covered.update(versions)
        for source, expected in re.findall(
            rb'^-- velmora: d1-twin ([0-9]{4}_[a-z0-9_]+\.sql) ([0-9a-f]{64})$', body, re.M
        ):
            version = source[:4].decode()
            if version not in d1 or (d1[version][0], digest(d1[version][1])) != (source.decode(), expected.decode()):
                die(f'D1 twin fingerprint changed or is missing ({name})')
            if version in covered:
                die(f'duplicate D1 coverage: {version}')
            covered.add(version)
    missing = d1.keys() - covered
    if missing:
        die('D1 migrations without a PostgreSQL translation: ' + ', '.join(d1[v][0] for v in sorted(missing)))
    if not covered:
        die('no D1 migration coverage found')
    if not quiet:
        print(f'D1 migration coverage: {len(covered)} files accounted for', flush=True)


def lock_key(raw, setting):
    if not re.fullmatch(r'-?[0-9]{1,19}', raw) or not -(2**63) <= int(raw) < 2**63:
        die(f'{setting} must be a signed bigint (PGLOCKKEY is required for a lane schema)')
    return int(raw)


def connection(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(fd, encoding='utf-8') as f:
            st = os.fstat(f.fileno())
            if not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600 or st.st_uid != os.geteuid():
                die('connection file must be a regular file owned by the caller with mode 0600')
            contents = f.read(65537)
    except (OSError, UnicodeError):
        die('cannot open or decode connection file')
    if len(contents) > 65536 or '\0' in contents:
        die('invalid connection file size or encoding')
    values = {}
    for n, line in enumerate(contents.split('\n'), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or key not in DATA_ENV | {'PGSCHEMA', 'PGLOCKKEY', 'PGMIGRATELOCKKEY', 'PGBRANCHID'} or key in values or '\r' in value:
            die(f'invalid or duplicate connection entry on line {n}')
        values[key] = value
    schema = values.pop('PGSCHEMA', 'public')
    raw_lock = values.pop('PGLOCKKEY', str(W1) if schema == 'public' else '')
    if not re.fullmatch(r'[a-z][a-z0-9_]{0,62}', schema) or schema.startswith('pg_') or schema == 'information_schema':
        die('invalid PGSCHEMA')
    lock = lock_key(raw_lock, 'PGLOCKKEY')
    migration_lock = lock_key(values.pop('PGMIGRATELOCKKEY', str(MIGRATOR if schema == 'public' else lock ^ (1 << 62))),
                              'PGMIGRATELOCKKEY')
    if (schema == 'public' and (lock, migration_lock) != (W1, MIGRATOR)) or (
            schema != 'public' and ({lock, migration_lock} & {W1, MIGRATOR} or lock == migration_lock)):
        die('public must use the fixed W1 and migrator keys; lane keys must be distinct and non-production')
    branch = values.pop('PGBRANCHID', None)
    if branch is not None and not re.fullmatch(r'[a-z0-9]{1,63}', branch):
        die('PGBRANCHID must be a nonempty literal branch id')
    allowed_users = {'kofra_migrate'}
    if branch is not None:
        allowed_users.add(f'kofra_migrate.{branch}')
    if values.get('PGUSER') not in allowed_users or not values.get('PGHOST') or not values.get('PGDATABASE'):
        die('PGHOST, PGDATABASE and PGUSER=kofra_migrate (optionally suffixed with the exact PGBRANCHID) are required')
    host = values['PGHOST']
    if ',' in host or not re.fullmatch(r'[A-Za-z0-9_.-]+', values['PGDATABASE']):
        die('only one host and a literal database name are supported')
    if host not in ('localhost', '127.0.0.1', '::1') and not host.startswith('/'):
        if values.get('PGSSLMODE') != 'verify-full':
            die('remote connections require PGSSLMODE=verify-full')
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG')}
    env.update(PGAPPNAME='velmora-pg-migrate', PGCONNECT_TIMEOUT='5', PGCLIENTENCODING='UTF8', LC_ALL='C')
    env.update(values)
    return env, schema, lock, migration_lock


def check(condition, code):
    return f"DO $$ BEGIN IF ({condition}) THEN RAISE EXCEPTION USING ERRCODE = '{code}'; END IF; END $$;\n"


def pg_literal(text):
    """Quote migration text for a server-side EXECUTE without client parsing."""
    return "'" + text.replace("'", "''") + "'"


# Set exactly once per online batch, under the locks, before any guarded
# statement; current_setting without missing_ok fails closed if it is absent.
APPLY = "current_setting('velmora.migration_apply') = 'on'"
SKIP = "current_setting('velmora.migration_apply') = 'off'"


def guarded(body):
    """A top-level DO running body when APPLY holds. Any value other than on or
    off (RESET ALL clears it) aborts the transaction. Its dollar tag is chosen
    to be absent from the body, so no migration text can end the quote."""
    body = f"BEGIN IF {APPLY} THEN {body} ELSIF NOT {SKIP} THEN RAISE EXCEPTION USING ERRCODE = 'VL018'; END IF; END"
    suffix = 0
    while f'$velmora_{suffix}$' in body:
        suffix += 1
    return f'DO $velmora_{suffix}$ {body} $velmora_{suffix}$;\n'


def execute_migration(source_statements):
    """Send each original statement as its own top-level DO in the batch. PostgreSQL
    13+ restarts statement_timeout for each statement of a simple-query message,
    so each migration statement keeps its own 3 s budget, as over stdin."""
    return ''.join(guarded(f'EXECUTE {pg_literal(statement)};') for statement in source_statements)


SQL_TOKEN = re.compile(r'''\s+|--[^\n]*|/\*|\$(?:[A-Za-z_]\w*)?\$|
    [eE]'(?:\\.|''|[^'\\])*'|'(?:''|[^'])*'|"(?:""|[^"])*"|
    [\w$]+|::|<>|!=|>=|<=|!~|.''', re.X | re.S | re.ASCII)


def sql_tokens_with_spans(sql, *, ascii_only=True):
    """Keep literals and dollar bodies intact; omit comments with source spans."""
    if ascii_only and not sql.isascii():
        raise ValueError('non-ASCII SQL cannot be tokenized')
    i = 0
    while i < len(sql):
        start = i
        token = SQL_TOKEN.match(sql, i).group()
        i += len(token)
        if token.isspace() or token.startswith('--'):
            continue
        if token == '/*':
            depth = 1
            while depth:
                boundary = re.search(r'/\*|\*/', sql[i:])
                if boundary is None:
                    raise ValueError('unterminated block comment')
                i += boundary.end()
                depth += 1 if boundary.group() == '/*' else -1
            continue
        if re.fullmatch(r'\$(?:[A-Za-z_]\w*)?\$', token):
            end = sql.find(token, i)
            if end < 0:
                raise ValueError('unterminated dollar quote')
            end += len(token)
            token += sql[i:end]
            i = end
        elif token in {"'", '"'}:
            raise ValueError('unterminated quoted value')
        elif token == '\\':
            raise ValueError('psql metacommands are not allowed')
        yield token, start, i


def sql_tokens(sql):
    # Read-only schema comparison also consumes historical SQLite metadata.
    # It can contain non-ASCII comments and is never sent to psql.
    for token, _, _ in sql_tokens_with_spans(sql, ascii_only=False):
        yield token


def lint_migration(sql, no_tx, name, *, additive_objects=None):
    statements, source_statements, pending = [], [], []
    segment_start = 0
    try:
        for token, _, end in sql_tokens_with_spans(sql):
            if token == ';':
                if pending:
                    statements.append(pending)
                    source_statements.append(sql[segment_start:end])
                pending = []
                segment_start = end
            else:
                pending.append(token)
    except ValueError as e:
        die(f'{name}: {e}')
    if pending or not statements:
        die(f'{name}: migration must contain terminated SQL statements')
    if additive_objects is not None:
        lint_additive(sql, source_statements, sql_tokens_with_spans, name, additive_objects)
    for statement in statements:
        # Comments are already gone; literals, bodies and (quoted) names remain.
        # Token boundaries stay spaces, so "velmora.migration_ apply" is not a match.
        text = ' '.join(statement).lower().replace('"', '')
        if re.search(r'\bvelmora\s*\.\s*migration_apply\b', text):
            die(f'{name}: velmora.migration_apply belongs to the migration runner')
        # Online statements are read as PL/pgSQL literals, which needs this setting on.
        if re.search(r'\bstandard_conforming_strings\b', text):
            die(f'{name}: standard_conforming_strings belongs to the migration runner')
    for statement in statements:
        head = [token.upper() for token in statement[:7]]
        if head[0] in {'ABORT', 'BEGIN', 'COMMIT', 'END', 'ROLLBACK', 'START'} or head[:2] == ['PREPARE', 'TRANSACTION']:
            die(f'{name}: transaction control belongs to the migration runner')
        if no_tx:
            if head[:2] == ['CREATE', 'UNIQUE']:
                del head[1]
            if head[:6] != ['CREATE', 'INDEX', 'CONCURRENTLY', 'IF', 'NOT', 'EXISTS']:
                die(f'{name}: only CREATE INDEX CONCURRENTLY IF NOT EXISTS is allowed')
    return statements, source_statements


def predicate(text):
    if not text:
        return None
    # Hide quoted tokens before rewriting SQL syntax. A literal string that
    # contains "::text" or "BETWEEN" is data, not a cast or comparison.
    quoted = []
    def hide(token):
        if token.startswith(("'", '"', "E'", "e'")):
            quoted.append(token)
            return f'\x01{len(quoted) - 1}\x02'
        return token
    text = ' '.join(hide(t) for t in sql_tokens(text))
    # pg_get_expr expands IN to ANY and BETWEEN to two comparisons.
    text = re.sub(r'\(\s*(-?\s*\d+)\s*\)\s*::\s*bigint\b', r'\1', text, flags=re.I)
    text = re.sub(r'::\s*(?:text|bigint)\b', '', text, flags=re.I)
    text = re.sub(r'(=\s*ANY|<>\s*ALL)\s*\(\s*ARRAY\s*\[([^\]]+)\]\s*\)',
                  lambda m: ('IN' if m[1].startswith('=') else 'NOT IN') + f' ({m[2]})', text, flags=re.I)
    text = re.sub(r'(\w+(?:\s*\(\s*\w+\s*\))?)\s+BETWEEN\s+(\d+)\s+AND\s+(\d+)',
                  r'(\1 >= \2 AND \1 <= \3)', text, flags=re.I)
    text = re.sub(r'\x01(\d+)\x02', lambda m: quoted[int(m[1])], text)
    tokens = [t if t.startswith(("'", '"', "E'", "e'")) else t.lower() for t in sql_tokens(text)]

    def parse(parts):
        depth = 0
        top = []
        for i, token in enumerate(parts):
            if depth == 0 and token in ('or', 'and'):
                top.append((i, token))
            depth += (token == '(') - (token == ')')
            if not depth and i == len(parts) - 1 and parts[0] == '(' and nested:
                return parse(parts[1:-1])
            if i == 0:
                nested = depth > 0
            elif not depth:
                nested = False
        for op in ('or', 'and'):
            for i, token in reversed(top):
                if token == op:
                    return (op, parse(parts[:i]), parse(parts[i+1:]))
        return tuple(parts)

    return parse(tokens)


def sqlite_checks(ddl):
    tokens = list(sql_tokens(ddl))
    for start, token in enumerate(tokens[:-1]):
        if token.upper() != 'CHECK' or tokens[start + 1] != '(':
            continue
        depth = 1
        end = start + 2
        while depth:
            depth += (tokens[end] == '(') - (tokens[end] == ')')
            end += 1
        yield ' '.join(tokens[start + 2:end - 1])


def trigger_condition(tokens):
    upper = [token.upper() for token in tokens]
    if 'WHEN' not in upper:
        return None
    begin = upper.index('WHEN') + 1
    return predicate(' '.join(tokens[begin:upper.index('EXECUTE', begin)]))


def pg_trigger_bodies(migrations):
    # The D1 replay identifies which triggers should exist; the PG DDL that
    # supplies their translated PL/pgSQL also pins their installed bodies.
    functions, triggers = {}, {}
    for _, _, parsed in migrations.values():
        for statement in parsed[0]:
            head = [token.upper() for token in statement]
            if head[:3] == ['CREATE', 'OR', 'REPLACE']:
                statement = statement[:1] + statement[3:]
                head = head[:1] + head[3:]
            if head[:2] == ['CREATE', 'FUNCTION'] and 'TRIGGER' in head and 'AS' in head:
                src = statement[head.index('AS') + 1]
                tag = re.match(r'\$(?:[A-Za-z_]\w*)?\$', src)
                if tag is None:
                    die('expected a dollar-quoted trigger function body')
                functions[statement[2]] = digest(src[tag.end():-tag.end()].encode())
            if head[:2] == ['CREATE', 'TRIGGER'] and 'EXECUTE' in head:
                triggers[statement[2]] = (statement[head.index('EXECUTE') + 2], trigger_condition(statement))
            if head[:2] == ['DROP', 'TRIGGER']:
                triggers.pop(statement[4 if head[2:4] == ['IF', 'EXISTS'] else 2], None)
    return {t: (f, functions.get(f), cond) for t, (f, cond) in triggers.items()}


def compare(actual, d1, migrations):
    expected = defaultdict(set)
    types = {'INTEGER': 'bigint', 'TEXT': 'text', 'BLOB': 'bytea'}
    db = sqlite3.connect(':memory:')
    for _, body in d1.values():
        db.executescript(body.decode())
    schema = db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE sql IS NOT NULL").fetchall()
    for typ, name, table, sql in schema:
        if name.startswith('sqlite_'):
            continue
        if typ == 'table':
            expected['tables'].add(name)
            cols = db.execute('SELECT * FROM pragma_table_info(?)', (name,)).fetchall()
            for _, col, kind, required, default, pk in cols:
                ident = 'd' if (table, col) in {('gc', 'id'), ('usage_recounts', 'id')} else ''
                expected['columns'].add((table, col, types[kind], bool(required or pk), ident,
                                         'C' if kind == 'TEXT' else None, default))
            for expr in sqlite_checks(sql):
                if table == 'articles':
                    expr = expr.replace("NOT GLOB '*[^0-9a-z]*'", "!~ '[^0-9a-z]'")
                expected['checks'].add((table, predicate(expr), True))
            pkcols = tuple((c[1], False, False) for c in sorted(cols, key=lambda c: c[5]) if c[5])
            if pkcols:
                expected['indexes'].add((table, '<pk>', True, True, True, 'btree', pkcols, None))
            for _, idx, unique, origin, _ in db.execute('SELECT * FROM pragma_index_list(?)', (table,)):
                if origin == 'pk':
                    continue
                keys = [(col, bool(desc), bool(desc)) for _, _, col, desc, _, key in
                        db.execute('SELECT * FROM pragma_index_xinfo(?)', (idx,)) if key]
                if idx == 'outbox_due':
                    keys.append(('seq', False, False))
                if idx == 'gc_due':
                    keys.append(('id', False, False))
                if idx == 'extents_evictable':
                    keys[0] = ('last_read_at', False, True)
                index_sql = db.execute('SELECT sql FROM sqlite_master WHERE name=?', (idx,)).fetchone()[0]
                where = re.split(r'\bWHERE\b', index_sql, maxsplit=1, flags=re.I)[-1] if index_sql else None
                if where == index_sql:
                    where = None
                expected['indexes'].add((table, idx if origin == 'c' else '<unique>', False, bool(unique),
                                         True, 'btree', tuple(keys), predicate(where)))
            fks = defaultdict(list)
            for key, seq, target, src, dst, update, delete, match in db.execute(
                'SELECT * FROM pragma_foreign_key_list(?)', (table,)
            ):
                if (update, delete, match) != ('NO ACTION', 'NO ACTION', 'NONE'):
                    die(f'new D1 foreign-key actions on {table} require an explicit translation')
                fks[key].append((seq, target, src, dst))
            for rows in fks.values():
                rows.sort()
                expected['foreign_keys'].add((table, rows[0][1], tuple(r[2] for r in rows),
                                              tuple(r[3] for r in rows), 'a', 'a', 's', True))
        elif typ == 'trigger':
            timing, event, updates = re.search(
                r'\b(BEFORE|AFTER)\s+(INSERT|UPDATE|DELETE)(?:\s+OF\s+([a-z_0-9,\s]+?))?\s+ON\b', sql, re.I
            ).groups()
            kind = 1 + (2 if timing.upper() == 'BEFORE' else 0) + {'INSERT': 4, 'DELETE': 8, 'UPDATE': 16}[event.upper()]
            columns, transition = tuple(re.findall(r'\w+', updates or '')), (None, None)
            if name in STATEMENT_TRIGGERS:
                declared, *transition = STATEMENT_TRIGGERS[name]
                kind &= ~1
                columns = columns if declared is KEEP_COLUMNS else declared
            expected['triggers'].add((table, name, 'O', kind, columns, *transition))

    unknown = STATEMENT_TRIGGERS.keys() - {r[1] for r in expected['triggers']}
    if unknown:
        die('declared statement triggers are not D1 triggers: ' + ', '.join(sorted(unknown)))
    expected['columns'].add(('outbox', 'seq', 'bigint', True, 'd', None, None))
    expected['indexes'].add(('outbox', 'outbox_seq_key', False, True, True, 'btree', (('seq', False, False),), None))
    actual['tables'] = set(actual['tables'] or ())
    actual['columns'] = {tuple(r[:6]) + (re.sub(r'::(?:text|bigint)$', '', r[6]) if r[6] else None,)
                         for r in (actual['columns'] or ())}
    explicit = {r[1] for r in expected['indexes'] if not r[1].startswith('<')}
    actual['indexes'] = {(t, '<pk>' if pk else '<unique>' if uq and i not in explicit else i,
                          pk, uq, valid, method, tuple(map(tuple, keys)), predicate(where))
                         for t, i, pk, uq, valid, method, keys, where in (actual['indexes'] or ())}
    actual['foreign_keys'] = {tuple(r[:2]) + (tuple(r[2]), tuple(r[3])) + tuple(r[4:])
                              for r in (actual['foreign_keys'] or ())}
    actual_triggers = actual['triggers'] or ()
    actual['triggers'] = {tuple(r[:4]) + (tuple(r[4]),) + tuple(r[9:11]) for r in actual_triggers}
    expected_bodies = pg_trigger_bodies(migrations)
    actual_bodies = {r[1]: (r[5], r[6], trigger_condition(list(sql_tokens(r[7])))) for r in actual_triggers if r[8]}
    actual['checks'] = {(t, predicate(expr), valid) for t, expr, valid in (actual['checks'] or ())}
    bad = []
    for kind, entries in expected.items():
        for label, delta in [('missing/changed', entries - actual[kind]), ('unexpected/changed', actual[kind] - entries)]:
            if delta:
                names = {r if isinstance(r, str) else r[0] if kind == 'checks'
                         else '.'.join(r[:2]) for r in delta}
                bad.append(f'{kind} {label}: {", ".join(sorted(names))}')
    for trigger in sorted(actual_bodies.keys() | expected_bodies.keys()):
        if expected_bodies.get(trigger) != actual_bodies.get(trigger):
            bad.append(f'trigger body or WHEN differs from the shipped PG translation: {trigger}')
    if not actual['tx_guard']:
        bad.append('missing or incorrect tx_guard_ok CHECK')
    if not actual['identities_ready']:
        bad.append('identity sequence positions must be above copied keys and within bigint range')
    bad.extend(f'privilege check failed: {name}' for name, ok in actual['privileges'].items() if ok is not True)
    if bad:
        die('\n'.join(bad))
    print('Schema matches D1: ' + ', '.join(f'{len(rows)} {kind}' for kind, rows in expected.items())
          + '; identity, C collation, tx_guard and grants verified')


def test_triggers(run, begin, history, complete, d1):
    sql = (PG / 'test_triggers.sql').read_text()
    fixture = sql.split('-- BEGIN SHARED FIXTURE\n', 1)[1].split('-- END SHARED FIXTURE\n', 1)[0]
    fixture = fixture.replace("decode('','hex')", "X''")
    db = sqlite3.connect(':memory:')
    for _, body in d1.values():
        db.executescript(body.decode())
    # The PG fixture sets seq explicitly to avoid consuming identities. It is
    # unused by any D1 trigger, so give SQLite a fixture-only column for it.
    db.executescript('ALTER TABLE outbox ADD COLUMN seq INTEGER; '
                     'CREATE TABLE wp2_usage_trace(step TEXT,target TEXT,values_ TEXT);')
    db.executescript(fixture)
    # SQLite applies a multi-row statement's rows in its plan's order, PG
    # in ascending hour order. A marked mixed-hour statement must visit
    # outbox rows in key order, which the fixture makes the hour order.
    ordered = re.findall(r'^-- velmora: sqlite-key-order\n(.*?);$', fixture, re.M | re.S)
    for statement in ordered:
        plan = [row[3] for row in db.execute('EXPLAIN QUERY PLAN ' + statement)]
        if len(plan) != 1 or not re.fullmatch(
                r'SEARCH outbox USING (?:COVERING )?INDEX sqlite_autoindex_outbox_1 \(extent_id=\?\)', plan[0]):
            die(f'fixture statement is not applied in key order by SQLite: {plan}')
    if len(ordered) < 2:
        die('fixture lost its key-order mixed-hour statements')
    expected = {(s, t): v for s, t, v in db.execute('SELECT * FROM wp2_usage_trace')}
    actual = {(s, t): v for s, t, v in json.loads(run(begin + history + complete + sql + '\nROLLBACK;\n',
                                                   report='trigger tests'))}
    if expected != actual:
        mismatches = [f'{s}/{t}: SQLite={expected.get((s,t))}, PG={actual.get((s,t))}'
                      for s, t in sorted(expected.keys() | actual.keys()) if expected.get((s,t)) != actual.get((s,t))]
        die('trigger parity differences (synthetic fixture):\n' + '\n'.join(mismatches))
    print(f'Trigger tests passed: 8 refusals, insert/adopt and {len(expected)} SQLite parity checkpoints '
          f'({len(ordered)} key-order mixed-hour statements); rolled back')


def main():
    p = argparse.ArgumentParser(prog='pg-migrate.sh', usage='%(prog)s ENV-FILE [--to NNNN | --pending | --verify | --test] '
                                     '[--import-mode | --activate], or %(prog)s --check-migrations')
    p.add_argument('env_file', nargs='?')
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--to')
    mode.add_argument('--pending', action='store_true')
    mode.add_argument('--verify', action='store_true')
    mode.add_argument('--test', action='store_true')
    mode.add_argument('--check-migrations', action='store_true')
    activation = p.add_mutually_exclusive_group()
    activation.add_argument('--activate', action='store_true')
    activation.add_argument('--import-mode', action='store_true')
    args = p.parse_args(sys.argv[2:])
    files = sql_files(PG)
    d1 = sql_files(D1)
    migrations, declarations = {}, {}
    post_cutover = {kind: set() for kind in ('tables', 'columns', 'indexes')}
    for version, (name, body) in files.items():
        # Limit all numbered PostgreSQL files before parsing or reading any
        # connection file. SQLite-only inputs never reach psql.
        bad = re.search(rb'[\x00\\\x80-\xff]', body)
        if bad:
            kind = {b'\x00': 'NUL byte', b'\\': 'backslash'}.get(bad[0], 'non-ASCII byte')
            line = body.count(b'\n', 0, bad.start()) + 1
            die(f'{name}:{line}: {kind} in migration SQL')
        sql = body.decode('ascii')
        no_tx = sql.splitlines()[:1] == ['-- velmora: no-transaction']
        if no_tx and version in {'0001', '0002'}:
            die('baseline stages must be transactional')
        if version > CUTOVER_BASELINE:
            before = {kind: entries.copy() for kind, entries in post_cutover.items()}
            parsed = lint_migration(sql, no_tx, name, additive_objects=post_cutover)
            declarations[version] = name, {kind: entries - before[kind] for kind, entries in post_cutover.items()}
        else:
            parsed = lint_migration(sql, no_tx, name)
        migrations[version] = sql, no_tx, parsed
    baseline = {v: files[v] for v in files if v <= CUTOVER_BASELINE}
    coverage(baseline, d1, quiet=args.pending)
    twins = sql_files(LOCAL)
    if declarations or twins:
        replay_sqlite_twins(d1, twins, declarations)
    if args.check_migrations:
        if args.env_file or args.activate or args.import_mode:
            p.error('--check-migrations does not take a connection file or other flags')
        return
    if not args.env_file or ((args.pending or args.verify or args.test) and (args.activate or args.import_mode)):
        p.error('provide a connection file; --pending, --verify and --test do not change migration or activation state')
    target = max(files) if args.to is None else args.to
    if target not in files or (args.activate and target != max(files)):
        p.error('--to must name a shipped version; activation requires the full schema')
    env, schema, lock, migration_lock = connection(args.env_file)
    if not args.pending:
        print(f'Catalogue schema: {schema}; W1 key: {lock}; migrator key: {migration_lock}', flush=True)
    prefix = f'''SET search_path TO "{schema}", pg_temp;
SET standard_conforming_strings = on;
SET client_min_messages = error;
''' + check(f"current_user <> 'kofra_migrate' OR session_user <> current_user OR current_schema() IS DISTINCT FROM '{schema}' OR NOT EXISTS (SELECT FROM pg_namespace n WHERE n.nspname = '{schema}' AND n.nspowner = current_user::regrole AND NOT EXISTS (SELECT FROM aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a WHERE a.grantee = 0))", 'VL010')

    transactional_prefix = f'''SET LOCAL search_path TO "{schema}", pg_temp;
SET LOCAL standard_conforming_strings = on;
SET LOCAL client_min_messages = error;
''' + check(f"current_user <> 'kofra_migrate' OR session_user <> current_user OR current_schema() IS DISTINCT FROM '{schema}' OR NOT EXISTS (SELECT FROM pg_namespace n WHERE n.nspname = '{schema}' AND n.nspowner = current_user::regrole AND NOT EXISTS (SELECT FROM aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a WHERE a.grantee = 0))", 'VL010')

    one_message_checked = False

    def run(sql, *, retry=False, report=None, one_message=False, concurrent=False):
        nonlocal one_message_checked
        messages = (sql,) if one_message else sql if concurrent else ()
        # Linux rejects one argv string of 128 KiB or more (MAX_ARG_STRLEN, with its NUL).
        for message in messages:
            size = len(message.encode())
            if size >= 128 * 1024:
                die(f'{report}: one-message batch is {size} bytes; psql -c takes under 128 KiB, '
                    'so split the migration into smaller files')
        if one_message and not one_message_checked:
            version = subprocess.run(['psql', '--version'], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, check=False)
            match = re.search(r'\b(\d+)(?:\.\d+)?\b', version.stdout)
            if version.returncode != 0 or not match or int(match.group(1)) < 15:
                die('one-message mode requires psql 15 or newer')
            one_message_checked = True
        for attempt in range(6):
            command = ['psql', '-X', '-qAtw', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=sqlstate']
            kwargs = {'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE, 'text': True,
                      'encoding': 'utf-8', 'errors': 'replace', 'env': env, 'check': False}
            if messages:
                for message in messages:
                    command.extend(('-c', message))
                kwargs['stdin'] = subprocess.DEVNULL
            else:
                kwargs['input'] = prefix + sql
            result = subprocess.run(command, **kwargs)
            if result.returncode == 0:
                return result.stdout.strip()
            # Do not forward libpq messages, SQL, or row contents from a live database.
            # The severity word comes from the server's locale even in SQLSTATE mode.
            states = re.findall(r':[^\S\n]+([0-9A-Z]{5})[^\S\n]*$', result.stderr, re.M)
            state = states[-1] if states else None
            if concurrent and state == 'VL020':
                return 'already applied'  # Caller independently confirms the ledger row.
            if state == '55P03' and retry and attempt < 5:
                print(f'{report}: SQLSTATE 55P03, retry {attempt + 1}/5', file=sys.stderr, flush=True)
                time.sleep(0.25 * (2 ** attempt))
                continue
            reason = ERRORS.get(state) or (f'SQLSTATE {state}' if state else 'psql connection or client failure')
            die(f'{report or "database operation"}: {reason}')

    # Cast the complete signed literal, including the sign of BIGINT_MIN.
    begin = f"BEGIN;\nSET LOCAL lock_timeout = '3s';\nSELECT pg_advisory_xact_lock('{lock}'::bigint);\n"
    # Never wait for the migration key with an open snapshot: an in-progress
    # concurrent index build could be waiting for that very snapshot to end.
    migrator_session = ("SET lock_timeout = '3s';\n"
                        f"SELECT pg_try_advisory_lock('{migration_lock}'::bigint) AS migrator_locked \\gset\n"
                        '\\if :migrator_locked\n\\else\n' + check('true', '55P03') + '\\endif\n')
    ledger_create, ledger_revoke = LEDGER.rstrip().split(';\n', 1)
    online_migrator_session = ("SET lock_timeout = '3s';\nDO $velmora_migrator$ BEGIN IF NOT pg_try_advisory_lock('" +
                               f"{migration_lock}'::bigint) THEN RAISE EXCEPTION USING ERRCODE = '55P03'; END IF; END $velmora_migrator$;\n")
    online_limits_sql = ("DO $velmora_limits$ BEGIN IF " + USAGE + " THEN "
                         "EXECUTE 'SET LOCAL statement_timeout = ''3s'''; "
                         "IF current_setting('server_version_num')::int >= 170000 THEN "
                         "EXECUTE 'SET LOCAL transaction_timeout = ''3s'''; END IF; "
                         "END IF; END $velmora_limits$;\n")
    concurrent_tx = begin + ('' if args.import_mode else online_limits_sql)
    ledger_exists = "to_regclass(format('%I.schema_migrations', current_schema())) IS NOT NULL"
    fingerprints = ', '.join(f"('{v}', '{digest(body)}')" for v, (_, body) in files.items())
    history = check(f'''EXISTS (SELECT FROM schema_migrations m WHERE NOT EXISTS (
        SELECT FROM (VALUES {fingerprints}) shipped(version, sha256)
        WHERE shipped.version = m.version AND shipped.sha256 = m.sha256))''', 'VL011')
    complete = check(f'(SELECT count(*) FROM schema_migrations) <> {len(files)}', 'VL017')
    read_history = ('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n' + transactional_prefix
                    + check(f'NOT ({ledger_exists})', 'VL017') + history)
    if args.pending:
        applied = set(run(read_history + "SELECT version FROM schema_migrations;\nCOMMIT;\n",
                          report='pending migrations').splitlines())
        if applied != set(list(files)[:len(applied)]):
            die('pending migrations: applied migration history is not an ordered prefix')
        pending = [name for version, (name, _) in files.items() if version not in applied]
        if pending:
            print('\n'.join(pending))
            return 3
        return

    verify_sql = read_history + complete + (PG / 'check_schema.sql').read_text() + '\nCOMMIT;\n'

    def verify(report):
        manifest = json.loads(run(verify_sql, report=report))
        inherited = set(manifest['inherited_tables'] or ()) - post_cutover['tables']
        if inherited:
            die('historical catalogue tables cannot have inherited children: ' + ', '.join(sorted(inherited)))
        if declarations:
            verify_post_cutover(manifest, post_cutover)
        compare(manifest, d1, {v: migrations[v] for v in baseline})
        if declarations:
            print('Post-cutover objects verified')

    # Verify uses the stdin transport (also works with psql 14).
    if args.verify:
        verify('schema verification')
        return
    if args.test:
        test_triggers(run, begin, history, complete, d1)
        return

    import_pre = check(f"{USAGE} OR {MARKER} IS NOT NULL OR EXISTS (SELECT FROM schema_migrations WHERE version <> '0001')", 'VL012') + '''
DO $$
DECLARE t record; populated boolean;
BEGIN
    FOR t IN SELECT relname FROM pg_class WHERE relnamespace = to_regnamespace(current_schema())
             AND relkind IN ('r', 'p') AND relname <> 'schema_migrations' LOOP
        EXECUTE format('SELECT EXISTS (SELECT FROM %I.%I)', current_schema(), t.relname) INTO populated;
        IF populated THEN RAISE EXCEPTION USING ERRCODE = 'VL012'; END IF;
    END LOOP;
END;
$$;
'''
    for version, (name, body) in files.items():
        if version > target:
            break
        sql, no_tx, parsed = migrations[version]
        _, source_statements = parsed
        record = (f"INSERT INTO schema_migrations VALUES ('{version}', '{digest(body)}', "
                  "(extract(epoch FROM clock_timestamp()) * 1000)::bigint);")
        if no_tx:
            # Each statement gets a SQL-only -c in one psql session. W1 is
            # released during CIC; the session migrator lock stays held.
            applied = f"EXISTS (SELECT FROM schema_migrations WHERE version = '{version}')"
            prepare = (prefix + online_migrator_session + concurrent_tx
                       + check(f'NOT ({ledger_exists})', 'VL017') + history)
            if args.import_mode:
                prepare += check(f'{MARKER} IS NULL OR {USAGE} OR NOT ({SEEDS})', 'VL013')
            else:
                prepare += check(f'{MARKER} IS NOT NULL', 'VL016' if args.activate else 'VL014')
            # ON_ERROR_STOP ends the session without running any queued -c if
            # this version is already applied. Confirm that outcome separately.
            prepare += check(applied, 'VL020') + check(BAD_INDEX, 'VL015') + 'COMMIT;\n'
            finish = concurrent_tx + check(BAD_INDEX, 'VL015') + record + "\nCOMMIT;\nSELECT 'applied';\n"
            output = run([prepare, *source_statements, finish], retry=True, report=name, concurrent=True).splitlines()
            if output == ['already applied']:
                confirmed = run(read_history + f'SELECT {applied};\nCOMMIT;\n', report=name)
                if confirmed != 't':
                    die(f'{name}: ledger does not confirm the concurrent migration was already applied')
            elif not output or output[-1] != 'applied':
                die(f'{name}: no migration status returned')
            print(f'{name}: {output[-1]}', flush=True)
            continue
        if not args.import_mode:
            # psql metacommands cannot be part of a -c simple-query message.
            # Keep the branch and status inside SQL so the wrapper and every
            # migration statement reach the server in one network message.
            batch = online_migrator_session + begin + transactional_prefix + online_limits_sql
            if version == '0001':
                batch += ("DO $velmora_ledger$ BEGIN IF NOT " + ledger_exists + " THEN EXECUTE " +
                          pg_literal(ledger_create) + "; EXECUTE " + pg_literal(ledger_revoke) + "; END IF; END $velmora_ledger$;\n")
            else:
                batch += check(f'NOT ({ledger_exists})', 'VL017')
            batch += history
            batch += check(f'{MARKER} IS NOT NULL', 'VL016' if args.activate else 'VL014')
            # Decide apply or skip once, then guard every statement and the ledger on it.
            batch += (f"DO $velmora_decide$ BEGIN IF EXISTS (SELECT FROM schema_migrations WHERE version = '{version}') THEN "
                      "PERFORM set_config('velmora.migration_apply', 'off', true); ELSE\n")
            if version == '0002':
                batch += (f"    IF ({MARKER} IS NOT NULL OR NOT ({SEEDS})) THEN "
                          "RAISE EXCEPTION USING ERRCODE = 'VL014'; END IF;\n")
            if version == '0001':
                batch += (f"    IF ({USAGE} OR {MARKER} IS NOT NULL) THEN "
                          "RAISE EXCEPTION USING ERRCODE = 'VL012'; END IF;\n")
            batch += "    PERFORM set_config('velmora.migration_apply', 'on', true); END IF; END $velmora_decide$;\n"
            batch += execute_migration(source_statements)
            batch += guarded(('INSERT INTO usage_global(id) VALUES (1), (2); ' if version == '0001' else '') + record)
            # The lint cannot see a computed setting name, so commit only with the ledger row present.
            batch += check(f"NOT EXISTS (SELECT FROM schema_migrations WHERE version = '{version}')", 'VL018')
            batch += (f"SELECT CASE WHEN {APPLY} THEN 'applied' ELSE 'already applied' END;\nCOMMIT;\n")
            output = run(batch, retry=True, report=name, one_message=True).splitlines()
            if not output or output[-1] not in {'applied', 'already applied'}:
                die(f'{name}: no migration status returned')
            print(f'{name}: {output[-1]}', flush=True)
            continue
        # Transactional offline/import stages keep the existing stdin runner.
        # Only the runner's own text can contain psql metacommands.
        batch = migrator_session + begin
        batch += f'SELECT {ledger_exists} AS ledger_exists \\gset\n\\if :ledger_exists\n\\else\n'
        batch += LEDGER + '\n\\endif\n' if version == '0001' else check('true', 'VL017') + '\\endif\n'
        batch += history
        batch += f"SELECT EXISTS (SELECT FROM schema_migrations WHERE version = '{version}') AS applied \\gset\n"
        if version >= '0002':
            batch += check(f'{MARKER} IS NULL OR {USAGE} OR NOT ({SEEDS})', 'VL013')
        batch += '\\if :applied\n'
        if target == '0001':
            batch += import_pre
        batch += '\\echo already applied\n\\else\n'
        if version == '0001':
            batch += check(f'{USAGE} OR {MARKER} IS NOT NULL', 'VL012')
        batch += sql + '\n'
        if version == '0002':
            batch += RESTART_IDENTITIES
        if version == '0001':
            batch += import_pre
        batch += record + '\n\\echo applied\n\\endif\nCOMMIT;\n'
        output = run(batch, retry=True, report=name).splitlines()
        if not output or output[-1] not in {'applied', 'already applied'}:
            die(f'{name}: no migration status returned')
        print(f'{name}: {output[-1]}', flush=True)
    if args.activate:
        verify('pre-activation verification')
        run(online_migrator_session + begin + transactional_prefix + online_limits_sql + history + complete
            + check(f'{MARKER} IS NOT NULL', 'VL016')
            + f'GRANT USAGE ON SCHEMA "{schema}" TO kofra_app;\nCOMMIT;\n', retry=True,
            report='activation', one_message=True)
        print('App schema USAGE granted')


try:
    sys.exit(main())
except Failure as exc:
    die(str(exc))
except (OSError, UnicodeError, json.JSONDecodeError, sqlite3.Error) as exc:
    die(f'cannot read migration files or schema metadata ({type(exc).__name__})')
PY
