"""Measure statements or plan verified, statement-safe D1 restore batches."""

from collections import defaultdict
from contextlib import ExitStack
from graphlib import CycleError, TopologicalSorter
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import sys


def longest_statement(path, limit, require_schema=False):
    buffer = bytearray()
    whitespace = b" \t\r\n\v\f"
    longest = (0, 1)
    has_schema = not require_schema
    # D1 starts each statement on its own line, but a quoted SQL value or
    # schema definition can span lines. Preserve the raw UTF-8 byte count,
    # and use SQLite's tokenizer to find the end without executing SQL.
    with open(path, "rb") as dump:
        read_limit = limit + 1
        for line_number, line in enumerate(iter(lambda: dump.readline(read_limit), b""), 1):
            whole_line = len(line) < read_limit or line.endswith(b"\n")
            if not buffer:
                if whole_line and not line.strip(whitespace):
                    continue
                start_line = line_number
            buffer.extend(line)
            # An unfinished statement can only become complete at a
            # semicolon or at the end of a block comment after one.
            complete = (whole_line and (b";" in line or b"*/" in line)
                        and sqlite3.complete_statement(buffer.decode("utf-8")))
            size = len(buffer)
            # Stop at the first over-limit statement. Reads and buffers
            # stay bounded even if no statement terminator ever arrives.
            if size > limit:
                return (size, start_line) if complete else (size, start_line, "+")
            if complete:
                if size > longest[0]:
                    longest = (size, start_line)
                # Match only at the beginning of a complete statement.
                if not has_schema and CREATE_TABLE.match(buffer):
                    has_schema = True
                buffer.clear()
    if buffer:
        raise SystemExit("the dump ends inside a statement")
    if not has_schema:
        raise SystemExit("catalog-export: the export has no schema")
    return longest


# The D1 dump writer puts each statement on its own line. Whitespace
# inside a statement is significant, and quoted values may span lines.
# Check boundaries with SQLite's tokenizer, never by splitting on ';'.
def dump_statements(path, limit):
    raw = bytearray()
    with path.open("rb") as dump:
        for number, line in enumerate(iter(lambda: dump.readline(limit + 1), b""), 1):
            if not raw:
                start = number
                if not line.strip():
                    continue
            raw.extend(line)
            if len(raw) > limit:
                raise ValueError(f"statement starting at line {start} exceeds {limit} bytes")
            if (b";" in line or b"*/" in line) and sqlite3.complete_statement(raw.decode("utf-8")):
                yield bytes(raw)
                raw.clear()
    if raw:
        raise ValueError("the dump ends inside a statement")


LEADING = rb"(?:\s|--[^\n]*\n|/\*.*?\*/)*"
PRAGMA = re.compile(LEADING + rb"PRAGMA\b", re.I | re.S)
CREATE_TABLE = re.compile(LEADING + rb"CREATE\s+TABLE\b", re.I | re.S)
INSERT = re.compile(LEADING + rb"INSERT\b", re.I | re.S)
INSERT_TABLE = re.compile(
    LEADING + rb'INSERT\s+INTO\s+("(?:[^"]|"")*"|`(?:[^`]|``)*`|\[[^\]]*\]|[^\s(]+)', re.I | re.S)
RECORD = struct.Struct(">I")


def table_name(raw):
    value = raw.decode("utf-8")
    if value.startswith('"'):
        return value[1:-1].replace('""', '"')
    if value.startswith("`"):
        return value[1:-1].replace("``", "`")
    if value.startswith("["):
        return value[1:-1]
    return value


def ddl_only(action, name, second, database, origin):
    # Permit ordinary table schema construction in a disposable SQLite DB.
    # In particular, deny SELECT/CREATE TABLE AS, ATTACH and functions
    # other than the built-ins used by the catalogue's CHECK constraints.
    if action == sqlite3.SQLITE_FUNCTION and origin is None and second in ("glob", "length"):
        return sqlite3.SQLITE_OK
    if database == "main" and origin is None and (
        action in (sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_READ)
        or (action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE) and name in
            ("sqlite_master", "sqlite_schema"))
        or (action == sqlite3.SQLITE_CREATE_INDEX and name.startswith("sqlite_autoindex_"))
    ):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


class Proof:
    def __init__(self):
        self.count = self.size = 0
        self.sha = hashlib.sha256()

    def add(self, statement):
        self.count += 1
        self.size += len(statement)
        self.sha.update(RECORD.pack(len(statement)))
        self.sha.update(statement)

    def signature(self):
        return self.count, self.size, self.sha.digest()


def records(path):
    with path.open("rb") as spool:
        while prefix := spool.read(RECORD.size):
            length, = RECORD.unpack(prefix)
            statement = spool.read(length)
            if len(statement) != length:
                raise ValueError("incomplete private spool")
            yield statement


class BatchWriter:
    def __init__(self, directory, cap, header, header_size):
        self.directory, self.cap, self.header, self.header_size = directory, cap, header, header_size
        self.batches = []
        self.file = None

    def start(self):
        name = f"batch-{len(self.batches):08d}.sql"
        self.batch = dict(file=name, bytes=0, statement_count=0)
        self.file = (self.directory / name).open("xb")
        self.sha = hashlib.sha256()
        for statement in records(self.header):
            self.write(statement)

    def finish(self):
        if self.file is not None:
            self.file.close()
            self.file = None
            self.batch["sha256"] = self.sha.hexdigest()
            self.batches.append(self.batch)

    def write(self, statement):
        size = self.batch["bytes"] + len(statement)
        if size > self.cap:
            raise ValueError("a schema, data or final batch exceeds VELMORA_IMPORT_BATCH_BYTES")
        self.file.write(statement)
        self.sha.update(statement)
        self.batch["bytes"] = size
        self.batch["statement_count"] += 1

    def room(self, needed):
        if needed + self.header_size > self.cap:
            raise ValueError("a statement exceeds VELMORA_IMPORT_BATCH_BYTES with the PRAGMA header")
        if self.file is None or self.batch["bytes"] + needed > self.cap:
            self.finish()
            self.start()


def sql_identifier(name):
    if not isinstance(name, str) or not name or "\0" in name:
        raise ValueError("invalid verification identifier")
    return '"' + name.replace('"', '""') + '"'


def verification_keys(conn, name, without_rowid, allow_unpaged=False):
    if without_rowid:
        index, = conn.execute("SELECT name FROM pragma_index_list(?) WHERE origin='pk'", (name,)).fetchone()
        keys = conn.execute('SELECT name, "desc", coll FROM pragma_index_xinfo(?) WHERE key=1 ORDER BY seqno',
                            (index,)).fetchall()
        if keys and all(desc == 0 and coll.upper() == "BINARY" for _, desc, coll in keys):
            return [key for key, _, _ in keys]
    else:
        columns = {column.lower() for (column,) in conn.execute("SELECT name FROM pragma_table_xinfo(?)", (name,))}
        for alias in ("rowid", "_rowid_", "oid"):
            if alias not in columns:
                return [alias]
    if allow_unpaged:
        return None
    raise ValueError(f"cannot verify {name} with an indexed rowid or ascending binary primary key")


def validate_plan(plan, allow_unpaged=False):
    if (not isinstance(plan, dict) or set(plan) != {"format", "tables"} or type(plan["format"]) is not int
        or plan["format"] != 1 or not isinstance(plan["tables"], list) or not plan["tables"]):
        raise ValueError("unknown verification plan format")
    seen = set()
    for row in plan["tables"]:
        if not isinstance(row, dict) or set(row) != {"name", "expected", "keys"}:
            raise ValueError("invalid verification table")
        name = sql_identifier(row["name"]).lower()
        if name in seen or type(row["expected"]) is not int or not 0 <= row["expected"] < 10**15:
            raise ValueError("invalid expected row count or duplicate table")
        seen.add(name)
        keys = row["keys"]
        if keys is None and allow_unpaged:
            continue
        if not isinstance(keys, list) or not 1 <= len(keys) <= 100:
            raise ValueError("invalid verification keys")
        if len({sql_identifier(key).lower() for key in keys}) != len(keys):
            raise ValueError("duplicate verification keys")


VERIFY_PAGE_SIZE = 5000


def cursor_literal(value):
    if not isinstance(value, list) or len(value) != 2 or not all(isinstance(part, str) for part in value):
        raise ValueError("invalid verification cursor")
    kind, raw = value
    if kind in ("text", "blob") and re.fullmatch(r"(?:[A-F0-9]{2})*", raw):
        encoded = f"X'{raw}'"
        return f"CAST({encoded} AS TEXT)" if kind == "text" else encoded
    if kind == "integer" and re.fullmatch(r"-?[0-9]{1,19}", raw):
        return raw
    if kind == "real" and re.fullmatch(r"-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?", raw):
        return raw
    raise ValueError("invalid verification cursor value")


def verification_query(plan, cursor):
    table = sql_identifier(plan["name"])
    names = plan["keys"]
    if not isinstance(names, list) or not names:
        raise ValueError("missing verification keys")
    keys = [sql_identifier(key) for key in names]
    aliases = [f"key_{idx}" for idx in range(len(keys))]
    order = ", ".join(keys)
    select = ", ".join(f"{key} AS {alias}" for key, alias in zip(keys, aliases))
    def select_rows(where="", limit=str(VERIFY_PAGE_SIZE)):
        return f"SELECT {select} FROM {table}{where} ORDER BY {order} LIMIT {limit}"

    ctes = []
    if cursor is None:
        page = select_rows()
    else:
        if not isinstance(cursor, list) or len(cursor) != len(keys):
            raise ValueError("verification cursor does not match key columns")
        literals = list(map(cursor_literal, cursor))
        if len(keys) == 1:
            page = select_rows(f" WHERE {keys[0]} > {literals[0]}")
        else:
            # The stock row-value comparison may seek only on the first
            # column and rescan an entire equal-prefix group. Seek each
            # disjoint range separately, nearest prefix first. Share a
            # single 5,000-row budget, rather than 5,000 for every branch.
            ranges = []
            for k in range(len(keys) - 1, -1, -1):
                where = [f"{keys[i]} = {literals[i]}" for i in range(k)]
                where.append(f"{keys[k]} > {literals[k]}")
                limit = str(VERIFY_PAGE_SIZE) + "".join(f" - (SELECT COUNT(1) FROM {prior})" for prior in ranges)
                branch = f"key_range_{k}"
                ctes.append(f"{branch} AS MATERIALIZED ({select_rows(' WHERE ' + ' AND '.join(where), limit)})")
                ranges.append(branch)
            union = " UNION ALL ".join(f"SELECT * FROM {branch}" for branch in ranges)
            page = f"SELECT * FROM ({union}) ORDER BY {', '.join(aliases)} LIMIT {VERIFY_PAGE_SIZE}"
    ctes.append(f"page AS MATERIALIZED ({page})")
    desc = ", ".join(f"{alias} DESC" for alias in aliases)
    # Older SQLite can serialize quote(integer) as a JSON number. Force
    # strings so the wire cursor keeps every digit of a 64-bit rowid.
    encode = ", ".join(
        f"json_array(typeof({alias}), CAST(CASE WHEN typeof({alias}) IN ('text','blob') "
        f"THEN hex({alias}) ELSE quote({alias}) END AS TEXT))" for alias in aliases)
    return (f"WITH {', '.join(ctes)} SELECT COUNT(1) AS n, "
            f"(SELECT json_array({encode}) FROM page ORDER BY {desc} LIMIT 1) AS cursor FROM page")


def split_dump(path, directory, cap, limit, discard_staged_sql=False, allow_unpaged=False):
    # Private spools add about one SQL dump's worth of disk. Free the
    # verified SQL before batch creation, then free each spool as used.
    dir_path = Path(directory)
    sql_path = Path(path)
    if discard_staged_sql and (sql_path.name != "catalog.sql" or sql_path.parent.resolve() != dir_path.resolve()):
        raise ValueError("only the catalog.sql staged in the work directory can be discarded")
    paths = {}
    sources = defaultdict(Proof)
    copied = defaultdict(Proof)
    table_names = {}
    conn = sqlite3.connect(":memory:")
    conn.set_authorizer(ddl_only)
    header, schema, final = ("header", "schema", "final")
    leading = True
    total = Proof()
    with ExitStack() as stack:
        files = {}
        for group in (header, schema, final):
            paths[group] = dir_path / f"spool-{group}"
            files[group] = stack.enter_context(paths[group].open("xb"))
        for statement in dump_statements(sql_path, limit):
            total.add(statement)
            if leading and PRAGMA.match(statement):
                group = header
            else:
                leading = False
                if CREATE_TABLE.match(statement):
                    conn.execute(statement.decode("utf-8"))
                    group = schema
                elif INSERT.match(statement):
                    match = INSERT_TABLE.match(statement)
                    if not match:
                        raise ValueError("unsupported INSERT syntax in the dump")
                    name = table_name(match[1]).lower()
                    if name == "sqlite_sequence":
                        # Keep the saved high-water marks after SQLite's
                        # automatic updates and the dump's sequence reset.
                        group = final
                    else:
                        group = ("table", name)
                        if group not in files:
                            paths[group] = dir_path / f"spool-table-{len(paths)}"
                            files[group] = stack.enter_context(paths[group].open("xb"))
                else:
                    group = final
            proof = sources[group]
            proof.add(statement)
            files[group].write(RECORD.pack(len(statement)))
            files[group].write(statement)
    if discard_staged_sql:
        sql_path.unlink()

    # No untrusted SQL is executed below this point. Use a callback rather
    # than None to support Python 3.10's sqlite3 set_authorizer API.
    conn.set_authorizer(lambda *_: sqlite3.SQLITE_OK)
    for (name,) in conn.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*'"):
        table_names[name.lower()] = name
    if not table_names:
        raise ValueError("the dump has no schema")
    for group in sources:
        if isinstance(group, tuple) and group[1] not in table_names:
            raise ValueError(f"INSERT targets unknown table {group[1]}")
    foreign = {}
    for key, name in table_names.items():
        foreign[key] = {row[2].lower() for row in conn.execute("SELECT * FROM pragma_foreign_key_list(?)", (name,))}
        unknown = foreign[key] - table_names.keys()
        if unknown:
            raise ValueError(f"foreign key in {name} names an unknown table: {', '.join(sorted(unknown))}")
    rowidless = {row[1] for row in conn.execute("PRAGMA table_list") if row[0] == "main" and row[4]}
    verify_keys = {key: verification_keys(conn, name, name in rowidless, allow_unpaged)
                   for key, name in table_names.items()}
    conn.close()
    order = tuple(TopologicalSorter({k: sorted(v - {k}) for k, v in foreign.items()}).static_order())
    for key in order:
        proof = sources[("table", key)]
        if key in foreign[key] and proof.size + sources[header].size > cap:
            raise ValueError(f"rows for self-referencing table {table_names[key]} do not fit in one batch")

    writer = BatchWriter(dir_path, cap, paths[header], sources[header].size)

    def replay(group):
        if group in paths:
            for statement in records(paths[group]):
                copied[group].add(statement)
                yield statement
            if group != header:
                paths[group].unlink()

    # The leading PRAGMAs are counted in batch 0; repeat them as overhead
    # in all other batches, without counting them again in the split proof.
    for _ in replay(header):
        pass
    for statement in replay(schema):
        writer.room(len(statement))
        writer.write(statement)
    writer.finish()
    for key in order:
        group = ("table", key)
        if group not in paths:
            continue
        if key in foreign[key]:
            writer.room(sources[group].size)
        for statement in replay(group):
            writer.room(len(statement))
            writer.write(statement)
    writer.finish()
    for statement in replay(final):
        writer.room(len(statement))
        writer.write(statement)
    writer.finish()

    if any(source.signature() != copied[group].signature() for group, source in sources.items()):
        raise ValueError("split proof failed: statement count, byte count or digest mismatch")
    headers_repeated = len(writer.batches) - 1
    if (sum(b["statement_count"] for b in writer.batches) != total.count + headers_repeated * sources[header].count
        or sum(b["bytes"] for b in writer.batches) != total.size + headers_repeated * sources[header].size):
        raise ValueError("split proof failed: batch totals did not match the dump")
    rows = [dict(name=table_names[key], expected=sources[("table", key)].count, keys=verify_keys[key])
            for key in order]
    paths[header].unlink()
    paths[final].unlink(missing_ok=True)
    (dir_path / "split.json").write_text(json.dumps(dict(batches=writer.batches, tables=rows), ensure_ascii=True))
    print(f"split verified: {total.count} statements, {total.size} bytes in {len(writer.batches)} batches")


if __name__ == "__main__":
    if sys.argv[1] == "validate-plan":
        try:
            validate_plan(json.loads(Path(sys.argv[2]).read_text()), allow_unpaged="--skip-verification" in sys.argv[3:])
        except (OSError, ValueError) as exc:
            raise SystemExit(f"invalid verification plan: {exc}") from None
    elif sys.argv[1] == "page":
        try:
            print(verification_query(json.loads(sys.argv[2]), json.loads(sys.argv[3])))
        except (ValueError, KeyError, TypeError):
            raise SystemExit("could not construct bounded verification query") from None
    elif sys.argv[1] == "split":
        try:
            split_dump(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]),
                       discard_staged_sql="--discard-staged-sql" in sys.argv[6:],
                       allow_unpaged="--skip-verification" in sys.argv[6:])
        except CycleError as exc:
            raise SystemExit(f"foreign key cycle: {' -> '.join(exc.args[1])}") from None
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise SystemExit(f"could not split catalogue dump: {exc}") from None
    else:
        try:
            print(*longest_statement(sys.argv[1], int(sys.argv[2]), require_schema="--require-schema" in sys.argv[3:]))
        except (OSError, ValueError):
            raise SystemExit("could not measure SQL statements in the dump") from None
