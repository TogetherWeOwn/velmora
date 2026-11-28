"""Shared catalogue migration contracts. No credentials or catalogue values in diagnostics."""

from contextlib import closing, contextmanager
from hashlib import file_digest, sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import urllib.error
import urllib.request

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
SOURCE_KEYS = {
    "buckets": ("id",), "access_keys": ("access_key_id",), "grants": ("access_key_id", "bucket_id"),
    "generations": ("id",), "objects": ("bucket_id", "key"), "extents": ("id",),
    "articles": ("extent_id", "idx"), "verifications": ("extent_id", "backbone", "verified_at"),
    "outbox": ("extent_id",), "uploads": ("id",), "upload_parts": ("upload_id", "part_number"),
    "gc": ("id",), "provider_permits": ("provider_id", "slot"), "meta": ("k",),
    "provider_health": ("provider_id",), "scan_cursors": ("k",), "generation_extents": ("generation_id", "seq"),
    "key_floors": ("bucket_id", "key"), "restore_state": ("id",), "rollback_stamp": ("id",),
    "write_intents": ("extent_id",), "upload_part_extents": ("upload_id", "part_number", "piece"),
    "usage_global": ("id",), "usage_buckets": ("kind", "bucket_id"), "usage_hours": ("hour",),
    "usage_recounts": ("id",), "verify_raises": ("extent_id", "backbone", "plan_rev"),
    "verify_escalations": ("backbone",),
}
INT_KEY = {"gc", "restore_state", "rollback_stamp", "usage_global", "usage_buckets", "usage_hours", "usage_recounts"}
ROWID_TEXT_PK = {"access_keys", "buckets", "extents", "generations", "outbox", "uploads"}
KEYLESS_COLUMNS = {"tx_guard": ("ok",), "recovery_copy_log": ("at", "kind", "pass", "swept", "problems", "checked", "detail")}
D1_SYSTEM = {"_cf_KV", "_cf_METADATA", "d1_migrations"}
PG_TYPES = {"INTEGER": "int8", "TEXT": "text", "BLOB": "bytea"}
JSON_CAP = 1 << 20
ATTEMPT_ID = re.compile(r"[0-9a-f]{32}\Z")
D1_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
F7_PREFIX = "cutover_f7:"
R1B_PREFIX = "cutover_r1b:"
# Last PG migration shipped at the D1 freeze (2026-11-28, c7b955e9).
CUTOVER_BASELINE = "0003"
# These baseline relation names are not visible in the D1 replay: SQLite
# uses different implicit index names and does not have identity sequences.
HISTORICAL_PG_RELATIONS = {
    f"{table}_pkey" for table in TABLES if table not in UNKEYED | {"tx_guard"}
} | {"buckets_name_key", "articles_message_id_key", "outbox_seq_key", "schema_migrations_pkey",
     "gc_id_seq", "usage_recounts_id_seq", "outbox_seq_seq"}


# Deliberately not a general SQL parser: each supported expansion consumes its
# entire statement. Unknown types, operators and clauses require operator review.
NUMBER = re.compile(r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[Ee][+-]?[0-9]+)?\Z")
TYPES = {"BIGINT", "INT8", "INTEGER", "INT", "INT4", "SMALLINT", "INT2", "TEXT", "VARCHAR", "CHAR",
         "CHARACTER", "BOOLEAN", "BOOL", "BYTEA", "JSON", "JSONB", "UUID", "NUMERIC", "DECIMAL",
         "REAL", "FLOAT4", "FLOAT8", "DOUBLE", "DATE", "TIMESTAMP", "TIMESTAMPTZ", "TIME"}
PURE_CALLS = {"NOW": 0, "LOWER": 1, "LENGTH": 1, "COALESCE": None}
POST_TABLE_CALLS = {"LEAST": None, "GREATEST": None}
INDEX_CALLS = {name: arity for name, arity in PURE_CALLS.items() if name != "NOW"}
HISTORICAL_COMPARISONS = {"=", "<>", "<", ">", "<=", ">="}
BINARY = {"+", "-", "*", "/", "%", "=", "!=", "<>", "<", ">", "<=", ">=", "AND", "OR"}
SQL_VALUES = {"CURRENT_CATALOG", "CURRENT_DATE", "CURRENT_ROLE", "CURRENT_SCHEMA", "CURRENT_TIME",
              "CURRENT_TIMESTAMP", "CURRENT_USER", "LOCALTIME", "LOCALTIMESTAMP", "SESSION_USER",
              "SYSTEM_USER", "USER", "DEFAULT"}


class AdditiveStatement:
    def __init__(self, source, start, spans, name, objects):
        self.source, self.start, self.spans, self.name = source, start, spans, name
        self.words = [token.upper() for token, _, _ in spans]
        self.i = 0
        self.tables, self.columns, self.indexes = (objects[key] for key in ("tables", "columns", "indexes"))

    def peek(self, offset=0):
        i = self.i + offset
        return self.words[i] if i < len(self.words) else ""

    def refuse(self, message, i=None):
        i = min(self.i if i is None else i, len(self.spans) - 1)
        line = self.source.count("\n", 0, self.start + self.spans[i][1]) + 1
        raise Failure(f"{self.name}:{line}: {message}")

    def take(self, *words):
        if self.words[self.i:self.i + len(words)] != list(words):
            return False
        self.i += len(words)
        return True

    def need(self, *words):
        if not self.take(*words):
            self.refuse("expected " + " ".join(words))

    def identifier(self):
        token = self.spans[self.i][0] if self.peek() else ""
        value = token[1:-1] if token.startswith('"') else token.lower()
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", value) or value in {"schema_migrations", MARKER}:
            self.refuse("expected an unqualified catalogue identifier")
        self.i += 1
        return value

    def new_relation(self):
        pos = self.i
        relation = self.identifier()
        if relation in TABLES or relation in HISTORICAL_PG_RELATIONS:
            self.refuse(f"{relation} is a historical PostgreSQL name", pos)
        if relation in self.tables or any(name == relation for _, name in self.indexes):
            self.refuse(f"{relation} is already declared by a post-cutover migration", pos)
        return relation

    def existing_table(self):
        pos = self.i
        table = self.identifier()
        if table not in TABLES and table not in self.tables:
            self.refuse("expected an existing catalogue table", pos)
        return table

    def comma_list(self, item, end):
        item()
        while self.take(","):
            item()
        self.need(end)

    def type_name(self):
        typ = self.peek()
        if typ not in TYPES:
            self.refuse("column and cast types must be allowlisted built-in types")
        self.i += 1
        if typ == "DOUBLE":
            self.need("PRECISION")
        if typ in {"CHARACTER", "CHAR"}:
            self.take("VARYING")
        if self.take("("):
            def modifier():
                if not self.peek().isdigit():
                    self.refuse("expected a numeric type modifier")
                self.i += 1
            self.comma_list(modifier, ")")
        if typ in {"TIME", "TIMESTAMP"} and (self.take("WITH") or self.take("WITHOUT")):
            self.need("TIME", "ZONE")
        while self.take("["):
            self.need("]")

    def collation(self):
        if self.peek() != '"C"':
            self.refuse('only COLLATE "C" is allowed')
        self.i += 1

    def atom(self):
        token = self.peek()
        if token in {"TRUE", "FALSE", "NULL"} or token.startswith("'") or NUMBER.fullmatch(token):
            self.i += 1
            return True, token != "NULL"
        return False, False

    def literal(self):
        if self.take("("):
            nonnull = self.literal()
            self.need(")")
        elif self.take("ARRAY", "["):
            if not self.take("]"):
                self.comma_list(self.literal, "]")
            nonnull = True
        elif self.take("+") or self.take("-"):
            if not NUMBER.fullmatch(self.peek()):
                self.refuse("expected a signed numeric literal")
            self.i += 1
            nonnull = True
        else:
            found, nonnull = self.atom()
            if not found:
                self.refuse("expected a literal value")
        if self.take("COLLATE"):
            self.collation()
        return nonnull

    def expression(self, *, names, calls):
        # Precedence is the server's responsibility. We recognize only terms,
        # simple operators, safe built-in casts and explicitly approved calls.
        def expr():
            return self.expression(names=names, calls=calls)

        while self.peek() in {"+", "-", "NOT"}:
            self.i += 1
        if self.take("("):
            expr()
            self.need(")")
        elif self.take("CAST", "("):
            expr()
            self.need("AS")
            self.type_name()
            self.need(")")
        elif self.peek() == "ARRAY":
            self.literal()
        elif not self.atom()[0]:
            pos, token = self.i, self.peek()
            self.identifier()
            if self.take("("):
                if token not in calls:
                    self.refuse("function must be allowlisted", pos)
                count = 0
                if not self.take(")"):
                    count = 1
                    expr()
                    while self.take(","):
                        count += 1
                        expr()
                    self.need(")")
                arity = calls[token]
                if (arity is None and count == 0) or (arity is not None and count != arity):
                    self.refuse("invalid argument count for allowlisted function", pos)
            elif not names or token in SQL_VALUES:
                self.refuse("expected a literal or an allowlisted function", pos)
        while self.take("::"):
            self.type_name()
        if self.take("COLLATE"):
            self.collation()
        if self.take("IS"):
            self.take("NOT")
            if self.peek() not in {"NULL", "TRUE", "FALSE"}:
                self.refuse("only IS NULL, TRUE or FALSE is allowed")
            self.i += 1
        if self.peek() in BINARY:
            self.i += 1
            expr()

    def references(self, table):
        pos = self.i - 1
        target = self.identifier()
        if target != table and target not in self.tables:
            self.refuse("REFERENCES targets a historical or undeclared table and requires review", pos)
        if self.take("("):
            self.comma_list(self.identifier, ")")
        while self.take("ON"):
            if not (self.take("DELETE") or self.take("UPDATE")):
                self.refuse("expected DELETE or UPDATE in foreign-key action")
            if not (self.take("NO", "ACTION") or self.take("RESTRICT") or self.take("CASCADE") or
                    self.take("SET", "NULL")):
                self.refuse("unsupported foreign-key action")

    def create_table(self):
        self.take("IF", "NOT", "EXISTS")
        table = self.new_relation()
        if self.take("PARTITION", "OF"):
            self.refuse("PARTITION OF changes the parent table and requires review", self.i - 2)
        if not self.take("("):
            self.refuse("expected CREATE TABLE with a column definition")

        def constraint(*, column):
            named = self.take("CONSTRAINT")
            if named:
                self.identifier()
            if self.take("PRIMARY", "KEY") or self.take("UNIQUE"):
                if not column:
                    self.need("(")
                    self.comma_list(self.identifier, ")")
            elif self.take("CHECK", "("):
                self.expression(names=True, calls=PURE_CALLS | POST_TABLE_CALLS)
                self.need(")")
            elif column and self.take("REFERENCES"):
                self.references(table)
            elif not column and self.take("FOREIGN", "KEY", "("):
                self.comma_list(self.identifier, ")")
                self.need("REFERENCES")
                self.references(table)
            elif named or not column:
                self.refuse("expected an allowlisted table or column constraint")
            else:
                return False
            return True

        def element():
            if self.peek() in {"CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "FOREIGN"}:
                constraint(column=False)
                return
            if self.peek() == "LIKE":
                self.refuse("LIKE targets a historical table or uses an unsupported table form")
            column = self.identifier()
            self.type_name()
            self.add_column(table, column)
            while self.peek() not in {",", ")", ""}:
                if self.take("COLLATE"):
                    self.collation()
                elif self.take("NOT", "NULL") or self.take("NULL"):
                    continue
                elif self.take("DEFAULT"):
                    self.expression(names=False, calls=PURE_CALLS)
                elif not constraint(column=True):
                    self.refuse("unsupported column definition")
        self.comma_list(element, ")")
        if self.peek() == "INHERITS":
            self.refuse("INHERITS changes which rows existing catalogue queries read")
        if not any(owner == table for owner, _ in self.columns):
            self.refuse("expected CREATE TABLE with a column definition")
        self.tables.add(table)

    def historical_index_predicate(self):
        # Build-time and future inserts must not evaluate a function, cast or
        # arithmetic against existing data. Compare bare columns to literals.
        error = "historical index predicate must use plain column comparisons or IS [NOT] NULL"

        def term():
            if self.take("("):
                self.historical_index_predicate()
                self.need(")")
            else:
                self.identifier()
                if self.take("IS"):
                    self.take("NOT")
                    if not self.take("NULL"):
                        self.refuse(error)
                elif self.peek() in HISTORICAL_COMPARISONS:
                    self.i += 1
                    if self.take("-") or self.take("+"):
                        if not NUMBER.fullmatch(self.peek()):
                            self.refuse(error)
                        self.i += 1
                    elif not self.atom()[0]:
                        self.refuse(error)
                else:
                    self.refuse(error)
            if self.peek() not in {"AND", "OR", ")", ""}:
                self.refuse(error)

        term()
        while self.take("AND") or self.take("OR"):
            term()

    def create_index(self, unique):
        self.take("CONCURRENTLY")
        self.take("IF", "NOT", "EXISTS")
        index = self.new_relation()
        self.need("ON")
        table = self.existing_table()
        historical = table not in self.tables
        if unique and historical:
            self.refuse("UNIQUE index on a historical or undeclared table requires review", 1)
        if self.take("USING"):
            method = self.peek()
            if method not in {"BTREE", "HASH", "GIN", "GIST", "SPGIST", "BRIN"}:
                self.refuse("index access method must be allowlisted")
            self.i += 1
        self.need("(")

        def key():
            if historical:
                self.identifier()
                if self.peek() not in {"ASC", "DESC", "NULLS", ",", ")"}:
                    self.refuse("historical index keys must be plain columns")
            else:
                self.expression(names=True, calls=INDEX_CALLS | POST_TABLE_CALLS)
            self.take("ASC") or self.take("DESC")
            if self.take("NULLS") and not (self.take("FIRST") or self.take("LAST")):
                self.refuse("expected NULLS FIRST or NULLS LAST")
        self.comma_list(key, ")")
        if self.take("INCLUDE", "("):
            self.comma_list(self.identifier, ")")
        if self.take("WHERE"):
            if historical:
                self.historical_index_predicate()
            else:
                # LEAST/GREATEST are restricted to index keys and CHECKs.
                self.expression(names=True, calls=INDEX_CALLS)
        self.indexes.add((table, index))

    def add_column(self, table, column):
        if (table, column) == ("outbox", "seq"):
            self.refuse("outbox.seq is a historical PostgreSQL column")
        if (table, column) in self.columns:
            self.refuse("column is already declared by a post-cutover migration")
        self.columns.add((table, column))

    def alter_table(self):
        table = self.existing_table()

        def action():
            pos = self.i
            if self.peek() in {"DROP", "RENAME"}:
                self.refuse(f"{self.peek()} is not additive")
            if self.take("ALTER"):
                self.take("COLUMN")
                self.identifier()
                if self.take("TYPE") or self.take("SET", "DATA", "TYPE"):
                    self.refuse("ALTER COLUMN TYPE is not additive", pos)
                if self.take("SET", "NOT", "NULL"):
                    self.refuse("SET NOT NULL is not additive", pos)
            if not self.take("ADD"):
                self.refuse("only ADD COLUMN alterations can run before a merge", pos)
            self.take("COLUMN")
            guarded = self.take("IF", "NOT", "EXISTS")
            if self.peek() in {"NOT", "CONSTRAINT", "CHECK", "UNIQUE", "PRIMARY", "FOREIGN", "EXCLUDE"}:
                self.refuse("expected ADD COLUMN, not a table constraint", pos)
            column = self.identifier()
            self.add_column(table, column)
            if guarded:
                self.refuse("ADD COLUMN IF NOT EXISTS requires review", pos)
            self.type_name()
            collated = self.take("COLLATE")
            if collated:
                self.collation()
            not_null = self.take("NOT", "NULL")
            if not not_null:
                self.take("NULL")
            if not collated and self.take("COLLATE"):
                self.collation()
            nonnull = False
            if self.take("DEFAULT"):
                try:
                    nonnull = self.literal()
                    if self.peek() not in {"", ",", "NOT", "NULL"}:
                        self.refuse("expected a literal DEFAULT")
                except Failure:
                    if not_null:
                        self.refuse("NOT NULL without DEFAULT supplying a non-NULL literal cannot run before a merge", pos)
                    raise
                if not not_null:
                    not_null = self.take("NOT", "NULL")
                    if not not_null:
                        self.take("NULL")
            if not_null and not nonnull:
                self.refuse("NOT NULL without DEFAULT supplying a non-NULL literal cannot run before a merge", pos)
        action()
        while self.take(","):
            action()

    def insert(self):
        table = self.identifier()
        if table not in self.tables:
            self.refuse("INSERT may only seed a post-cutover table")
        if self.take("("):
            self.comma_list(self.identifier, ")")
        self.need("VALUES")
        while True:
            self.need("(")
            self.comma_list(self.literal, ")")
            if not self.take(","):
                break

    def parse(self):
        for i, (token, _, end) in enumerate(self.spans):
            if token.upper() == "UESCAPE" or (token.upper() == "U" and self.source[self.start + end:self.start + end + 1] == "&"):
                self.refuse("Unicode escapes are not allowed", i)
            if token.upper().startswith("E'"):
                self.refuse("escape strings are not allowed", i)
        if self.take("CREATE", "TABLE"):
            self.create_table()
        elif self.take("CREATE", "UNIQUE", "INDEX"):
            self.create_index(unique=True)
        elif self.take("CREATE", "INDEX"):
            self.create_index(unique=False)
        elif self.take("ALTER", "TABLE"):
            self.alter_table()
        elif self.take("INSERT", "INTO"):
            self.insert()
        elif self.peek() == "DROP":
            self.refuse("DROP is not additive")
        elif self.peek() == "ALTER" and "RENAME" in self.words:
            self.refuse("RENAME is not additive", self.words.index("RENAME"))
        else:
            self.refuse("unsupported statement in an additive migration")
        if self.peek():
            self.refuse("unsupported trailing clause in an additive migration")


def lint_additive(sql, source_statements, tokens_with_spans, name, objects):
    cursor = 0
    for raw in source_statements:
        start = sql.index(raw, cursor)
        cursor = start + len(raw)
        spans = [span for span in tokens_with_spans(raw) if span[0] != ";"]
        try:
            AdditiveStatement(sql, start, spans, name, objects).parse()
        except RecursionError:
            raise Failure(f"{name}: expression nesting exceeds the additive parser limit") from None


def replay_sqlite_twins(d1, twins, declarations):
    """Replay test-only twins in memory and require the same new object names."""
    def inventory(db):
        schema = db.execute("SELECT type, name, tbl_name FROM sqlite_master WHERE sql IS NOT NULL").fetchall()
        tables = {name for kind, name, _ in schema if kind == "table" and not name.startswith("sqlite_")}
        return {"tables": tables,
                "columns": {(table, row[0]) for table in tables
                            for row in db.execute("SELECT name FROM pragma_table_xinfo(?)", (table,))},
                "indexes": {(table, name) for kind, name, table in schema if kind == "index"}}

    # The SQLite text is never executed against the deployed D1 database.
    # Whitelist the operations needed for twins; notably no ATTACH, PRAGMA, temp DDL,
    # file access, or DROP, even if a replay would otherwise leave a matching schema.
    safe = {sqlite3.SQLITE_ALTER_TABLE, sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_INDEX,
            sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_READ, sqlite3.SQLITE_SELECT,
            sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_REINDEX, sqlite3.SQLITE_TRANSACTION}
    with closing(sqlite3.connect(":memory:")) as db:
        for _, body in d1.values():
            db.executescript(body.decode())
        before = inventory(db)
        for version, (name, expected) in declarations.items():
            require(version in twins, f"{name}: missing SQLite twin in migrations-local")
            twin, body = twins[version]
            db.set_authorizer(lambda action, *_: sqlite3.SQLITE_OK if action in safe else sqlite3.SQLITE_DENY)
            try:
                db.executescript(body.decode())
            except sqlite3.Error as error:
                raise Failure(f"migrations-local/{twin}: SQLite replay failed ({error.sqlite_errorname})") from None
            finally:
                db.set_authorizer(None)
            after = inventory(db)
            for kind, original in before.items():
                added = after[kind] - original
                if kind == "columns":
                    require(expected[kind] <= added, f"{name}: SQLite twin {twin} does not add the declared columns")
                require(original <= after[kind] and added == expected[kind],
                        f"{name}: SQLite twin {twin} does not add the same {kind}")
            before = after
    require(set(twins) <= set(declarations), "migrations-local contains a version with no post-cutover PG migration")


def verify_post_cutover(actual, objects):
    """Verify the declared expansion and hand the historical manifest to the D1 comparator."""
    tables, columns, indexes = (objects[kind] for kind in ("tables", "columns", "indexes"))
    observed = (set(actual["tables"] or ()), {tuple(row[:2]) for row in actual["columns"] or ()},
                {tuple(row[:2]) for row in actual["indexes"] or () if row[4]})
    missing = [kind + " " + (entry if isinstance(entry, str) else ".".join(entry))
               for kind, expected, found in zip(("table", "column", "index"), (tables, columns, indexes), observed)
               for entry in sorted(expected - found)]
    if missing:
        raise Failure("post-cutover objects missing or invalid: " + ", ".join(missing))
    actual["tables"] = observed[0] - tables
    for kind in ("columns", "indexes", "foreign_keys", "checks", "triggers"):
        declared = objects.get(kind, ())
        actual[kind] = [row for row in actual[kind] or () if row[0] not in tables and tuple(row[:2]) not in declared]


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
    return validate_f1(json_input(path))


def validate_f1(receipt):
    require(safe_int(receipt.get("f1_started_at_ms")) and receipt["f1_started_at_ms"] >= 0,
            "invalid F1 start timestamp")
    attempt, uuid = receipt.get("f1_attempt_id"), receipt.get("d1_uuid")
    require(isinstance(attempt, str) and ATTEMPT_ID.fullmatch(attempt), "missing or invalid F1 attempt ID")
    require(isinstance(uuid, str) and D1_UUID.fullmatch(uuid), "missing or invalid F1 D1 UUID")
    worker = receipt.get("worker_name")
    require(isinstance(worker, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", worker), "invalid F1 Worker name")
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
    expected.update(id=1, state="replaying", since_ms=-1, reached_after=attempt,
                    started_at=0 if before is None else before["started_at"] + 1)
    require(before is None or before["state"] == "complete" or before["since_ms"] == -1,
            "F1 cannot replace an unfinished replay")
    require(receipt["restore_state_armed"] == expected, "F1 restore_state does not match the expected arm")
    return receipt


def restore_values(record):
    return tuple(record[column] for column in RESTORE_COLUMNS)


def encode_row(digest, row):
    for value in row:
        if value is None:
            digest.update(b"n")
            continue
        if type(value) is int:
            prefix, body = b"i", str(value).encode("ascii")
        elif type(value) is str:
            prefix, body = b"t", value.encode("utf-8")
        elif type(value) is bytes:
            prefix, body = b"b", value
        else:
            raise Failure("unexpected value type while hashing catalogue")
        digest.update(prefix + b":" + str(len(body)).encode("ascii") + b":")
        digest.update(body)


def row_hash(row):
    digest = sha256()
    encode_row(digest, row)
    return digest.digest()


def boundary_select(table, keys, descending):
    cols = idents(keys)
    lower = "-9223372036854775808" if table in INT_KEY else "''"
    order = ", ".join(ident(k) + (" DESC" if descending else " ASC") for k in keys)
    return f"SELECT {cols} FROM {ident(table)} WHERE {ident(keys[0])} >= {lower} ORDER BY {order} LIMIT 1"


def boundary_data(read, receipt):
    results = {}
    for table, keys in SOURCE_KEYS.items():
        fingerprints = []
        for desc in (False, True):
            rows = read(table, boundary_select(table, keys, desc), ())
            require(len(rows) <= 1, f"{table}: source lookup returned extra rows")
            fingerprints.append(row_hash(tuple(rows[0][k] for k in keys)).hex() if rows else None)
        if table in ROWID_TEXT_PK:
            # The export can be rowid-ordered instead of ordered by the text PK.
            # Witness its ends as well; never compare raw rowid numbers.
            for order in ("ASC", "DESC"):
                sql = (f"SELECT {idents(keys)} FROM {ident(table)} WHERE rowid >= -9223372036854775808 "
                       f"ORDER BY rowid {order} LIMIT 1")
                rows = read(table, sql, ())
                require(len(rows) <= 1, f"{table}: rowid boundary lookup returned extra rows")
                fingerprints.append(row_hash(tuple(rows[0][k] for k in keys)).hex() if rows else None)
        results[table] = fingerprints
    # These small tables have no PK; rowid gaps do not survive SQL export and
    # endpoint values could be identical duplicates. Read indexed rowid pages
    # and produce the exact multiset here and on the later SQLite file.
    for table, cols in KEYLESS_COLUMNS.items():
        total, count, last = 0, 0, None
        while True:
            op, lower, params = (">=", "-9223372036854775808", ()) if last is None else (">", "?", (last,))
            page = read(table, f"SELECT rowid, {idents(cols)} FROM {ident(table)} WHERE rowid {op} {lower} ORDER BY rowid LIMIT 250", params)
            require(len(page) <= 250 and count + len(page) <= 10_000, f"{table}: source witness exceeds bounded row budget")
            for r in page:
                require(safe_int(r["rowid"]) and (last is None or r["rowid"] > last), f"{table}: invalid rowid order")
                last = r["rowid"]
                total += int.from_bytes(row_hash(tuple(r[col] for col in cols)), "big")
                count += 1
            if len(page) < 250:
                break
        results[table] = [count, f"{total % (1 << 256):064x}"]
    return dict(format=1, f1_attempt_id=receipt["f1_attempt_id"], d1_uuid=receipt["d1_uuid"], tables=results)


def sqlite_boundaries(db, receipt):
    # sqlite3.Row preserves types and allows name lookup without copying BLOBs.
    original = db.row_factory
    try:
        db.row_factory = sqlite3.Row
        return boundary_data(lambda _t, sql, args: db.execute(sql, args).fetchall(), receipt)
    finally:
        db.row_factory = original


def check_boundaries(db, expected, receipt):
    actual = sqlite_boundaries(db, receipt)
    require(actual["format"] == expected.get("format") and actual["f1_attempt_id"] == expected.get("f1_attempt_id")
            and actual["d1_uuid"] == expected.get("d1_uuid") and isinstance(expected.get("tables"), dict)
            and actual["tables"].keys() == expected["tables"].keys(), "source boundary manifest is missing, invalid, or for another F1")
    for table, value in actual["tables"].items():
        require(value == expected["tables"][table], f"{table}: frozen D1 source boundary mismatch; export is incomplete or changed")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def cloudflare(path, payload=None):
    account = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    require(re.fullmatch(r"[0-9a-f]{32}", account) and token, "missing Cloudflare API credentials")
    req = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{account}{path}",
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "User-Agent": "velmora-cutover"},
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=30) as response:
            body = response.read(JSON_CAP + 1)
    except urllib.error.HTTPError as error:
        raise Failure(f"Cloudflare HTTP {error.code}; stop") from None
    except (OSError, ValueError):
        raise Failure("Cloudflare network failure; stop") from None
    require(len(body) <= JSON_CAP, "Cloudflare response exceeds limit; stop")
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError):
        raise Failure("Cloudflare response is not JSON; stop") from None
    require(isinstance(data, dict) and data.get("success") is True, "Cloudflare API refused the operation; stop")
    return data


def d1_query(uuid, sql, params):
    require(D1_UUID.fullmatch(uuid or ""), "remote D1 operation requires a database UUID")
    # Every caller supplies a fixed SQL template whose '?' occurrences are
    # binds. The D1 REST API accepts only string params; preserve SQLite types
    # explicitly instead of relying on column affinity or implicit conversion.
    fragments = sql.split("?")
    require(len(fragments) == len(params) + 1, "invalid D1 bind count")
    wire_sql, wire_params = [fragments[0]], []
    for value, following in zip(params, fragments[1:]):
        if value is None:
            wire_sql.append("NULL")
        elif safe_int(value):
            wire_sql.append("CAST(? AS INTEGER)")
            wire_params.append(str(value))
        elif type(value) is str:
            wire_sql.append("?")
            wire_params.append(value)
        else:
            raise Failure("unsupported D1 bind type")
        wire_sql.append(following)
    result = cloudflare(f"/d1/database/{uuid}/query", dict(sql="".join(wire_sql), params=wire_params)).get("result")
    require(isinstance(result, list) and len(result) == 1 and isinstance(result[0], dict)
            and result[0].get("success") is True and isinstance(result[0].get("results"), list)
            and isinstance(result[0].get("meta"), dict), "D1 query response invalid; stop")
    return result[0]


def capture_boundaries(receipt, query=d1_query):
    uuid = receipt["d1_uuid"]
    proof = dict(indexed_lookups=0, max_data_rows_read=0)

    def read(table, sql, params, maximum=250):
        if table != "sqlite_schema":
            plan = query(uuid, "EXPLAIN QUERY PLAN " + sql, params)["results"]
            require(len(plan) == 1 and str(plan[0].get("detail", "")).startswith(f"SEARCH {table} USING "),
                    f"{table}: bounded indexed D1 lookup not proven; stop")
        answer = query(uuid, sql, params)
        scanned = answer["meta"].get("rows_read")
        require(type(scanned) is int and 0 <= scanned <= maximum and len(answer["results"]) <= maximum,
                f"{table}: indexed D1 query exceeded its read bound; stop")
        if table != "sqlite_schema":
            proof["indexed_lookups"] += 1
            proof["max_data_rows_read"] = max(proof["max_data_rows_read"], scanned)
        return answer["results"]

    arm_sql = f"SELECT {idents(RESTORE_COLUMNS)} FROM restore_state WHERE id=1"
    require(read("restore_state", arm_sql, (), 1) == [receipt["restore_state_armed"]], "D1 does not match the recorded F1 arm")
    names = read("sqlite_schema", "SELECT name FROM sqlite_schema WHERE rowid BETWEEN 1 AND 1024 AND type='table' ORDER BY rowid LIMIT 65", (), 1024)
    require({r["name"] for r in names} - D1_SYSTEM - {"sqlite_sequence"} == set(TABLES), "frozen D1 table set differs from baseline")
    result = boundary_data(lambda t, sql, args: read(t, sql, args, 1 if t in SOURCE_KEYS else 250), receipt)
    require(read("restore_state", arm_sql, (), 1) == [receipt["restore_state_armed"]], "D1 arm changed during source capture")
    result["proof"] = proof
    return result


def source_manifest(path, receipt):
    manifest = json_input(path)
    require(type(manifest.get("format")) is int and manifest["format"] == 2
            and type(manifest.get("sql_bytes")) is int and manifest["sql_bytes"] > 0
            and isinstance(manifest.get("sql_sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", manifest["sql_sha256"])
            and safe_int(manifest.get("restore_point_ms"))
            and manifest["restore_point_ms"] >= receipt["f1_started_at_ms"], "invalid or stale catalogue export manifest")
    return manifest


def seal_path(sqlite):
    return sqlite.with_name(sqlite.name + ".wp5-seal.json")


def seal_content(sqlite, manifest, receipt, boundaries):
    require(not any(sqlite.with_name(sqlite.name + suffix).exists() for suffix in ("-wal", "-journal")),
            "SQLite source must not have a live journal")
    with sqlite.open("rb") as src:
        return dict(format=1, f1_attempt_id=receipt["f1_attempt_id"], d1_uuid=receipt["d1_uuid"],
                    raw_sql_sha256=manifest["sql_sha256"], raw_sql_bytes=manifest["sql_bytes"],
                    sqlite_sha256=file_digest(src, "sha256").hexdigest(),
                    boundaries_sha256=sha256(json.dumps(boundaries, sort_keys=True).encode()).hexdigest())


def write_seal(sqlite, manifest, receipt, boundaries):
    with seal_path(sqlite).open("x", encoding="utf-8") as out:
        json.dump(seal_content(sqlite, manifest, receipt, boundaries), out, sort_keys=True)
        out.write("\n")


def check_seal(sqlite, manifest, receipt, boundaries):
    require(seal_path(sqlite).is_file(), "SQLite source seal is missing; reload the validated export")
    require(json_input(seal_path(sqlite)) == seal_content(sqlite, manifest, receipt, boundaries),
            "SQLite source, manifest, or F1 attempt does not match its seal")


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
    actual -= D1_SYSTEM
    require(actual == set(TABLES), "D1 export catalogue table set differs from the baseline")
    schema = {}
    for table in TABLES:
        rows = list(db.execute(f"PRAGMA table_xinfo({ident(table)})"))
        require(all(row[2] in PG_TYPES and row[6] == 0 for row in rows), f"{table}: unsupported D1 column definition")
        columns = {row[1]: row[2] for row in rows}
        idents(columns)
        keys = tuple(row[1] for row in sorted(rows, key=lambda row: row[5]) if row[5])
        require(keys == SOURCE_KEYS.get(table, ()), f"{table}: unexpected D1 primary key")
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
        "PGBRANCHID": None,
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
    branch = values.get("PGBRANCHID")
    require(branch is None or re.fullmatch(r"[a-z0-9]{1,63}", branch), "invalid PGBRANCHID")
    user = values.get("PGUSER")
    require(user == role or (branch is not None and user == f"{role}.{branch}"),
            f"PGUSER must name {role} with no suffix or the configured PGBRANCHID")
    require(values.get("PGHOST") and re.fullmatch(r"[A-Za-z0-9_.-]+", values.get("PGDATABASE", "")),
            "literal PGHOST and PGDATABASE required")
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
        require(db.execute("SELECT session_user::text").fetchone() == (role,), "unexpected bare Postgres session role")
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
