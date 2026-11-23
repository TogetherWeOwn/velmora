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


def longest_statement(path, limit):
    buffer = bytearray()
    whitespace = b" \t\r\n\v\f"
    longest = (0, 1)
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
                buffer.clear()
    if buffer:
        raise SystemExit("the dump ends inside a statement")
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

    def data_room(self, needed):
        if needed + self.header_size > self.cap:
            raise ValueError("a data statement exceeds VELMORA_IMPORT_BATCH_BYTES with the PRAGMA header")
        if self.file is None or self.batch["bytes"] + needed > self.cap:
            self.finish()
            self.start()


def split_dump(path, directory, cap, limit):
    # Private spools add about one SQL dump's worth of disk, in addition to
    # the verified SQL and the reassembled batch files.
    dir_path = Path(directory)
    paths = {}
    sources = defaultdict(Proof)
    copied = defaultdict(Proof)
    table_names = {}
    conn = sqlite3.connect(":memory:")
    header, schema, final = ("header", "schema", "final")
    leading = True
    total = Proof()
    with ExitStack() as stack:
        files = {}
        for group in (header, schema, final):
            paths[group] = dir_path / f"spool-{group}"
            files[group] = stack.enter_context(paths[group].open("xb"))
        for statement in dump_statements(Path(path), limit):
            total.add(statement)
            if leading and PRAGMA.match(statement):
                group = header
            else:
                leading = False
                if CREATE_TABLE.match(statement):
                    conn.set_authorizer(ddl_only)
                    try:
                        conn.execute(statement.decode("utf-8"))
                    finally:
                        conn.set_authorizer(None)
                    group = schema
                elif INSERT.match(statement):
                    match = INSERT_TABLE.match(statement)
                    if not match:
                        raise ValueError("unsupported INSERT syntax in the dump")
                    group = ("table", table_name(match[1]).lower())
                    if group not in files:
                        paths[group] = dir_path / f"spool-table-{len(paths)}"
                        files[group] = stack.enter_context(paths[group].open("xb"))
                else:
                    group = final
            proof = sources[group]
            proof.add(statement)
            files[group].write(RECORD.pack(len(statement)))
            files[group].write(statement)

    for (name,) in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"):
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

    # The leading PRAGMAs are counted in batch 0; repeat them as overhead
    # in all other batches, without counting them again in the split proof.
    for _ in replay(header):
        pass
    writer.start()
    for statement in replay(schema):
        writer.write(statement)
    writer.finish()
    for key in order:
        group = ("table", key)
        if group not in paths:
            continue
        if key in foreign[key]:
            writer.data_room(sources[group].size)
        for statement in replay(group):
            writer.data_room(len(statement))
            writer.write(statement)
    writer.finish()
    if sources[final].count:
        writer.start()
        for statement in replay(final):
            writer.write(statement)
        writer.finish()

    if any(source.signature() != copied[group].signature() for group, source in sources.items()):
        raise ValueError("split proof failed: statement count, byte count or digest mismatch")
    headers_repeated = len(writer.batches) - 1
    if (sum(b["statement_count"] for b in writer.batches) != total.count + headers_repeated * sources[header].count
        or sum(b["bytes"] for b in writer.batches) != total.size + headers_repeated * sources[header].size):
        raise ValueError("split proof failed: batch totals did not match the dump")
    rows = [dict(name=table_names[key], expected=sources[("table", key)].count,
                 query='SELECT count(*) AS n FROM "' + table_names[key].replace('"', '""') + '"')
            for key in order]
    (dir_path / "split.json").write_text(json.dumps(dict(batches=writer.batches, tables=rows), ensure_ascii=True))
    print(f"split verified: {total.count} statements, {total.size} bytes in {len(writer.batches)} batches")


if __name__ == "__main__":
    if sys.argv[1] == "split":
        try:
            split_dump(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]))
        except CycleError as exc:
            raise SystemExit(f"foreign key cycle: {' -> '.join(exc.args[1])}") from None
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise SystemExit(f"could not split catalogue dump: {exc}") from None
    else:
        try:
            print(*longest_statement(sys.argv[1], int(sys.argv[2])))
        except (OSError, ValueError):
            raise SystemExit("could not measure SQL statements in the dump") from None
