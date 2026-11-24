"""Shared catalogue migration contracts. No credentials or catalogue values in diagnostics."""

from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys

OPS = Path(__file__).resolve().parent
SAFE_INT = 2**53 - 1
MARKER = "_velmora_import_incomplete"
RESTORE_COLUMNS = ("id", "state", "since_ms", "started_at", "finished_at",
                   "reached_phase", "reached_after", "reached_extent")
# Parents precede children; see the foreign-key declarations in the D1 baseline.
TABLES = (
    "tx_guard", "buckets", "access_keys", "grants", "generations", "objects", "extents",
    "articles", "verifications", "outbox", "uploads", "upload_parts", "gc", "provider_permits",
    "meta", "provider_health", "scan_cursors", "generation_extents", "key_floors", "restore_state",
    "rollback_stamp", "write_intents", "upload_part_extents", "usage_global", "usage_buckets",
    "usage_hours", "usage_recounts", "verify_raises", "verify_escalations", "recovery_copy_log",
)
UNKEYED = {"tx_guard", "recovery_copy_log"}
PG_TYPES = {"INTEGER": "int8", "TEXT": "text", "BLOB": "bytea"}
JSON_CAP = 1 << 20


class Failure(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Failure(reason)


def ident(name):
    require(re.fullmatch(r"[a-z_][a-z0-9_]*", name), "invalid database identifier")
    return f'"{name}"'


def idents(names):
    return ", ".join(map(ident, names))


def diagnostic_main(action):
    os.umask(0o077)
    try:
        return action() or 0
    except Failure as error:
        print(f"{Path(sys.argv[0]).stem}: {error}", file=sys.stderr)
    except Exception as error:
        # Driver errors may include secrets (e.g. constraint values or conninfo).
        code = getattr(error, "sqlstate", None) or getattr(error, "sqlite_errorname", None)
        suffix = f" [{code}]" if code and re.fullmatch(r"[A-Z0-9_]+", code) else ""
        print(f"{Path(sys.argv[0]).stem}: {type(error).__name__}{suffix}", file=sys.stderr)
    return 1


def json_input(path):
    if str(path) == "-":
        raw = sys.stdin.buffer.read(JSON_CAP + 1)
    else:
        with Path(path).open("rb") as inp:
            raw = inp.read(JSON_CAP + 1)
    require(len(raw) <= JSON_CAP, "JSON input exceeds 1 MiB")

    def unique(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs), "JSON input has duplicate fields")
        return result

    obj = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(obj, dict), "expected a JSON object")
    return obj


def safe_int(value):
    return type(value) is int and -SAFE_INT <= value <= SAFE_INT


def f1_receipt(path):
    receipt = json_input(path)
    require(safe_int(receipt.get("f1_started_at_ms")) and receipt["f1_started_at_ms"] >= 0,
            "invalid F1 start timestamp")
    require(type(receipt.get("f7_started")) is bool, "missing F7 deploy state")
    for key, nullable in (("restore_state_before", True), ("restore_state_armed", False)):
        require(key in receipt, "F1 receipt is missing restore_state")
        row = receipt[key]
        if row is None and nullable:
            continue
        require(isinstance(row, dict) and row.keys() == set(RESTORE_COLUMNS), "invalid F1 restore_state columns")
        require(row["state"] in ("complete", "replaying") and safe_int(row["id"]) and row["id"] == 1,
                "invalid F1 restore_state id or state")
        require(all(safe_int(row[k]) for k in ("since_ms", "started_at")), "invalid F1 restore_state timestamps")
        require(all(row[k] is None or safe_int(row[k]) for k in ("finished_at", "reached_phase", "reached_extent")),
                "invalid F1 restore_state progress")
        text = row["reached_after"]
        require(text is None or (isinstance(text, str) and "\0" not in text), "invalid F1 restore_state cursor")
        if text is not None:
            text.encode("utf-8", "strict")
    before = receipt["restore_state_before"]
    expected = dict.fromkeys(RESTORE_COLUMNS)
    expected.update(id=1, state="replaying", since_ms=-1, started_at=0 if before is None else before["started_at"] + 1)
    require(before is None or before["state"] == "complete" or before["since_ms"] == -1,
            "F1 cannot replace an unfinished replay")
    require(receipt["restore_state_armed"] == expected, "F1 restore_state does not match the expected arm")
    return receipt


def restore_values(record):
    return tuple(record[column] for column in RESTORE_COLUMNS)


@contextmanager
def sqlite_source(path):
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("BEGIN")
        yield db


def source_schema(db):
    objects = dict(db.execute("SELECT name,type FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'"))
    require(MARKER not in objects, "D1 export has an incomplete import marker")
    actual = {name for name, kind in objects.items() if kind == "table"}
    actual -= {"_cf_KV", "_cf_METADATA", "d1_migrations"}
    require(actual == set(TABLES), "D1 export catalogue table set differs from the baseline")
    schema = {}
    for table in TABLES:
        rows = list(db.execute(f"PRAGMA table_xinfo({ident(table)})"))
        require(all(row[2] in PG_TYPES and row[6] == 0 for row in rows), f"{table}: unsupported D1 column definition")
        columns = {row[1]: row[2] for row in rows}
        idents(columns)
        keys = tuple(row[1] for row in sorted(rows, key=lambda row: row[5]) if row[5])
        require(bool(keys) == (table not in UNKEYED), f"{table}: unexpected D1 primary key")
        schema[table] = (columns, keys)
    require(tuple(schema["restore_state"][0]) == RESTORE_COLUMNS, "D1 restore_state schema differs from the baseline")
    return schema


def check_source_arm(db, receipt):
    rows = db.execute(f"SELECT {idents(RESTORE_COLUMNS)} FROM restore_state LIMIT 2").fetchall()
    require(rows == [restore_values(receipt["restore_state_armed"])],
            "exported restore_state does not match the recorded armed row")


def projection(table):
    return " WHERE k <> 'revive'" if table == "scan_cursors" else ""


def source_count(db, table, receipt):
    if table == "restore_state":
        return int(receipt["restore_state_before"] is not None)
    return db.execute(f"SELECT count(*) FROM {ident(table)}{projection(table)}").fetchone()[0]


def pg_settings(path, role):
    allowed = {
        "PGHOST": "host", "PGPORT": "port", "PGDATABASE": "dbname", "PGUSER": "user",
        "PGPASSWORD": "password", "PGSSLMODE": "sslmode", "PGSSLROOTCERT": "sslrootcert",
        "PGCONNECT_TIMEOUT": "connect_timeout", "PGSCHEMA": None, "PGLOCKKEY": None, "PGMIGRATELOCKKEY": None,
    }
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, encoding="utf-8", newline="") as inp:
        mode = os.fstat(inp.fileno())
        require(stat.S_ISREG(mode.st_mode) and mode.st_uid == os.geteuid() and stat.S_IMODE(mode.st_mode) == 0o600,
                "Postgres env file must be owned by the caller with mode 0600")
        raw = inp.read(65_537)
    require(len(raw) <= 65_536 and "\0" not in raw, "invalid Postgres env file size or encoding")
    values = {}
    for line in raw.split("\n"):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        name, sep, value = line.partition("=")
        require(sep and name in allowed and name not in values and "\r" not in value, "invalid Postgres env assignment")
        values[name] = value
    require(values.get("PGHOST") and values.get("PGUSER") == role and
            re.fullmatch(r"[A-Za-z0-9_.-]+", values.get("PGDATABASE", "")),
            f"literal PGHOST, PGDATABASE and PGUSER={role} required")
    schema = values.get("PGSCHEMA", "public")
    require(re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema) and not schema.startswith("pg_")
            and schema != "information_schema", "invalid PGSCHEMA")
    lock = values.get("PGLOCKKEY", "7413000001" if schema == "public" else "")
    require(re.fullmatch(r"-?[0-9]{1,19}", lock) and -(2**63) <= int(lock) < 2**63,
            "invalid or missing Postgres lock key")
    require((schema == "public") == (int(lock) == 7413000001), "public and test schemas must use different lock keys")
    host = values["PGHOST"]
    require("," not in host and (host.startswith("/") or host in ("localhost", "127.0.0.1", "::1")
                                 or values.get("PGSSLMODE") == "verify-full"),
            "one Postgres host required; remote connections require verify-full TLS")
    config = {allowed[k]: value for k, value in values.items() if allowed[k] is not None}
    config.setdefault("port", "5432")
    config.setdefault("connect_timeout", "10")
    return config, schema, int(lock)


@contextmanager
def postgres(path, role="kofra_migrate"):
    import psycopg

    config, schema, lock = pg_settings(path, role)
    # Match pg-migrate: ambient libpq variables (e.g. PGHOSTADDR/PGSERVICE)
    # must not select a different server or add connection credentials.
    ambient = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("PG")}
    try:
        connection = psycopg.connect(**config, autocommit=True, options="-c client_encoding=UTF8")
    finally:
        os.environ.update(ambient)
    with connection as db:
        db.execute(f"SET search_path TO {ident(schema)}")
        require(db.execute("SELECT current_schema(), current_setting('server_encoding')").fetchone() == (schema, "UTF8"),
                "Postgres target schema must exist and use UTF8")
        yield db, schema, lock


def lock_w1(db, key):
    db.execute("SET LOCAL lock_timeout = '3s'")
    db.execute("SELECT pg_advisory_xact_lock(%s::bigint)", (key,))


def marker_exists(db):
    return db.execute("SELECT to_regclass(%s) IS NOT NULL", (MARKER,)).fetchone()[0]


def app_has_usage(db, schema):
    return db.execute("SELECT has_schema_privilege('kofra_app', %s, 'USAGE')", (schema,)).fetchone()[0]


def pg_columns(db, schema, source):
    rows = db.execute("""SELECT c.relname, a.attname, t.typname, co.collname
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid
        JOIN pg_catalog.pg_type t ON t.oid = a.atttypid
        LEFT JOIN pg_catalog.pg_collation co ON co.oid = a.attcollation
        WHERE n.nspname = %s AND c.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped""", (schema,))
    actual = {table: {} for table in TABLES}
    for table, col, dtype, collation in rows:
        if table in actual:
            actual[table][col] = (dtype, collation)
    for table, (columns, _) in source.items():
        expected = {c: (PG_TYPES[d], "C" if d == "TEXT" else None) for c, d in columns.items()}
        if table == "outbox":
            expected["seq"] = ("int8", None)
        require(actual[table] == expected, f"{table}: D1 and Postgres column definitions differ")


def migrate(env, *args):
    result = subprocess.run(["bash", str(OPS / "pg-migrate.sh"), str(env), *args],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            text=True, check=False)
    if result.returncode:
        # pg-migrate emits fixed local diagnostics and SQLSTATE only, but do not
        # forward stderr from bash/startup/other subprocesses verbatim.
        refused = "pre-copy target must have no app access, import marker, post-copy migration or catalogue rows"
        if result.stderr.rstrip().endswith(refused):
            raise Failure("pre-COPY target is non-empty, active, already claimed, or past migration 0001")
        state = re.search(r"\bSQLSTATE ([0-9A-Z]{5})\b", result.stderr)
        detail = f" (SQLSTATE {state[1]})" if state else ""
        raise Failure(f"pg-migrate {' '.join(args)} exited {result.returncode}{detail}; inspect migration separately")
