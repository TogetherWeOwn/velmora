#!/usr/bin/env python3
"""Load an existing Wrangler D1 export locally, census it, and optionally COPY to PG."""

import argparse
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from time import monotonic

from pg_catalog import (
    Failure, MARKER, PG_TYPES, SAFE_INT, app_has_usage, capture_boundaries, check_boundaries,
    check_seal, check_source_arm, diagnostic_main, f1_receipt, ident, idents, json_input,
    lock_w1, marker_exists, migrate, pg_columns, postgres, projection, require, restore_values,
    source_manifest, source_schema, sqlite_source, write_seal,
)

# The PostgreSQL stages an import applies: COPY runs after the first, and the
# target is ready only with exactly these recorded.
CUTOVER_BASELINE = ("0001", "0002", "0003")


def verify_dump(stream, manifest):
    digest, n = sha256(), 0
    for part in iter(lambda: stream.read(1 << 20), b""):
        require(b"\0" not in part, "D1 SQL export contains a literal NUL byte; stop before loading")
        n += len(part)
        digest.update(part)
    require(n == manifest["sql_bytes"] and digest.hexdigest() == manifest["sql_sha256"],
            "D1 export byte count or SHA-256 differs from the verified manifest")
    stream.seek(0)


def load_stream(stream, command, manifest):
    # Wrangler's export contains a defer_foreign_keys pragma and no explicit
    # transaction. Wrap it to avoid an fsync per INSERT. Standard SQLite .dump
    # instead has a BEGIN, optionally preceded by comments or a pragma.
    head = stream.read(65_536)
    require(head, "empty D1 export")
    has_begin = re.match(rb"(?:\s|--[^\n]*\n|PRAGMA[^;]*;)*BEGIN\b", head, re.IGNORECASE)
    digest, n = sha256(), 0
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as loader:
        try:
            if not has_begin:
                loader.stdin.write(b"BEGIN;\n")
            part = head
            while part:
                require(b"\0" not in part, "D1 SQL export contains a literal NUL byte; stop before loading")
                n += len(part)
                digest.update(part)
                loader.stdin.write(part)
                part = stream.read(1 << 20)
            require(n == manifest["sql_bytes"] and digest.hexdigest() == manifest["sql_sha256"],
                    "D1 export changed during SQLite load")
            if not has_begin:
                loader.stdin.write(b"\nCOMMIT;\n")
            loader.stdin.close()
        except BrokenPipeError:
            raise Failure(f"local SQLite export load exited {loader.wait()}") from None
        require(loader.wait() == 0, f"local SQLite export load exited {loader.returncode}")


def expand_zstd(inp, expanded, limit):
    with subprocess.Popen(["zstd", "-dc"], stdin=inp, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as decoder:
        with closing(decoder.stdout) as src:
            remaining = limit
            while part := src.read(min(1 << 20, remaining + 1)):
                require(len(part) <= remaining, "zstd output exceeds the verified SQL byte count")
                expanded.write(part)
                remaining -= len(part)
        require(decoder.wait() == 0, "zstd export decompression failed")
    expanded.seek(0)


def load_dump(dump, target, manifest, boundaries, receipt):
    require(not target.exists(), "refusing to overwrite the SQLite source")
    # Safe CLI mode disallows shell escapes and opening another database. The
    # dump may contain trigger bodies and multiline strings; let SQLite parse it.
    with tempfile.NamedTemporaryFile(prefix=".pg-copy-", dir=target.absolute().parent) as work:
        command = ["sqlite3", "-init", "/dev/null", "-batch", "-bail", "-safe", work.name]
        with dump.open("rb", buffering=0) as inp:
            compressed = inp.read(4) == b"\x28\xb5\x2f\xfd"
            inp.seek(0)
            if compressed:
                with tempfile.TemporaryFile(dir=target.absolute().parent) as expanded:
                    expand_zstd(inp, expanded, manifest["sql_bytes"])
                    verify_dump(expanded, manifest)
                    load_stream(expanded, command, manifest)
            else:
                verify_dump(inp, manifest)
                load_stream(inp, command, manifest)
        # Do not publish a merely well-formed prefix with missing tail rows.
        with sqlite_source(Path(work.name)) as db:
            source_schema(db)
            check_source_arm(db, receipt)
            check_boundaries(db, boundaries, receipt)
        # Only publish a fully loaded file, and do not overwrite on races.
        os.link(work.name, target)
        write_seal(target, manifest, receipt, boundaries)


def census(db, schema):
    require(db.execute("PRAGMA encoding").fetchone() == ("UTF-8",), "D1 source must be UTF-8")
    report = {}
    errors = []
    storage_classes = ("integer", "text", "blob", "real", "null")
    for table, (columns, keys) in schema.items():
        checks = []
        for col, kind in columns.items():
            q = ident(col)
            checks.extend((col, storage, f"typeof({q}) = '{storage}'") for storage in storage_classes)
            if kind == "TEXT":
                checks.append((col, "text-nul", f"typeof({q}) = 'text' AND instr({q},char(0)) > 0"))
            if kind == "INTEGER":
                checks.append((col, "integer-range", f"typeof({q}) = 'integer' AND {q} NOT BETWEEN {-SAFE_INT} AND {SAFE_INT}"))
            if table == "articles" and col == "yenc_name":
                checks.append((col, "yenc-name", f"length({q}) NOT BETWEEN 1 AND 64 OR {q} GLOB '*[^0-9a-z]*'"))
        select = ", ".join(f"sum({expr})" for _, _, expr in checks)
        row = db.execute(f"SELECT {select} FROM {ident(table)}").fetchone()
        report[table] = {col: {} for col in columns}
        for (col, label, _), n in zip(checks, row):
            if n:
                if label not in (columns[col].lower(), "null") or (col in keys and label == "null"):
                    errors.append(f"{table}.{col} {label}={n}")
                if label in storage_classes:
                    report[table][col][label] = n
    require(not errors, "D1 type census failed: " + ", ".join(errors))
    return report


def ensure_unclaimed(db, schema):
    require(not marker_exists(db), "target is already claimed; incomplete import marker exists")
    require(not app_has_usage(db, schema), "kofra_app already has schema USAGE")


def claim(db, schema, key, source):
    with db.transaction():
        lock_w1(db, key)
        ensure_unclaimed(db, schema)
        pg_columns(db, schema, source)
        require(db.execute("SELECT version::text FROM schema_migrations ORDER BY version").fetchall() == [("0001",)],
                "target must have exactly pre-COPY migration 0001")
        triggers = db.execute("""SELECT EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
                  JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = %s AND NOT t.tgisinternal)""",
                              (schema,)).fetchone()[0]
        require(not triggers, "target already has application triggers")
        for table in source:
            require(db.execute(f"SELECT 1 FROM {ident(table)} LIMIT 1").fetchone() is None,
                    f"target {table} is non-empty")
        # The row is inserted only when 0002 and all identity resets succeeded.
        db.execute(f"CREATE TABLE {ident(MARKER)} (ready boolean PRIMARY KEY CHECK (ready))")
        # Do not give the application DML rights on the fence via default grants.
        db.execute(f"REVOKE ALL ON {ident(MARKER)} FROM kofra_app")


def copy_data(pg, key, sqlite, source, receipt):
    counts = {}
    with pg.transaction():
        lock_w1(pg, key)
        require(marker_exists(pg), "import claim disappeared")
        require(not app_has_usage(pg, pg.execute("SELECT current_schema()").fetchone()[0]), "import target was activated")
        for table, (columns, _) in source.items():
            dest = dict(columns)
            if table == "restore_state":
                before = receipt["restore_state_before"]
                rows = [restore_values(before)] if before is not None else []
            else:
                order = " ORDER BY rowid" if table == "outbox" else ""
                rows = sqlite.execute(f"SELECT {idents(columns)} FROM {ident(table)}{projection(table)}{order}")
                if table == "outbox":
                    dest["seq"] = "INTEGER"
                    rows = ((*row, seq) for seq, row in enumerate(rows, 1))
            with pg.cursor() as cur:
                try:
                    with cur.copy(f"COPY {ident(table)} ({idents(dest)}) FROM STDIN (FORMAT BINARY)") as copy:
                        copy.set_types([PG_TYPES[dtype] for dtype in dest.values()])
                        for row in rows:
                            copy.write_row(row)
                except Exception as error:
                    code = getattr(error, "sqlstate", None)
                    raise Failure(f"COPY {table} failed ({code or type(error).__name__})") from None
                counts[table] = cur.rowcount
    return counts


def mark_ready(db, key):
    with db.transaction():
        lock_w1(db, key)
        require(marker_exists(db), "import claim disappeared before post-COPY completion")
        # Import-mode migration 0002 installs the post schema and restarts
        # all three identities transactionally; 0003 replaces the per-row
        # usage triggers. Check the same PG connection for exactly that ledger.
        ledger = [v for (v,) in db.execute("SELECT version::text FROM schema_migrations ORDER BY version")]
        require(ledger == list(CUTOVER_BASELINE),
                f"post-COPY ledger must be exactly the cutover baseline {'/'.join(CUTOVER_BASELINE)}")
        db.execute(f"INSERT INTO {ident(MARKER)} VALUES (true)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", type=Path, help="existing Wrangler SQL dump (plain or zstd)")
    parser.add_argument("--sqlite", type=Path, help="local database to create or reuse")
    parser.add_argument("--manifest", type=Path, help="verified catalog-export.sh format-2 manifest")
    parser.add_argument("--source-boundaries", type=Path, help="independent frozen D1 source witness")
    parser.add_argument("--capture-boundaries", action="store_true", help="run bounded indexed reads on the frozen D1 UUID in F1")
    parser.add_argument("--f1", type=Path, required=True, help="recorded before/armed D1 restore_state rows")
    parser.add_argument("--pg-env", type=Path)
    parser.add_argument("--apply", action="store_true", help="initialize and COPY; default is local census only")
    args = parser.parse_args()
    require(args.apply == (args.pg_env is not None), "--pg-env and --apply must be specified together")
    receipt = f1_receipt(args.f1)
    if args.capture_boundaries:
        require(not any((args.apply, args.export, args.sqlite, args.manifest, args.source_boundaries)),
                "--capture-boundaries accepts only --f1")
        print(json.dumps(capture_boundaries(receipt), sort_keys=True))
        return
    require(args.sqlite and args.manifest and args.source_boundaries, "--sqlite, --manifest and --source-boundaries are required")
    manifest = source_manifest(args.manifest, receipt)
    boundaries = json_input(args.source_boundaries)
    timings = {}
    started = monotonic()
    if args.export:
        load_dump(args.export, args.sqlite, manifest, boundaries, receipt)
        timings["sqlite_load_s"] = monotonic() - started
    with sqlite_source(args.sqlite) as db:
        started = monotonic()
        source = source_schema(db)
        check_seal(args.sqlite, manifest, receipt, boundaries)
        check_boundaries(db, boundaries, receipt)
        summary = census(db, source)
        check_source_arm(db, receipt)
        require(db.execute("PRAGMA integrity_check(1)").fetchone() == ("ok",), "D1 SQLite integrity check failed")
        extent_count = db.execute("SELECT count(*) FROM extents").fetchone()[0]
        s_held, held_count = db.execute("SELECT min(created_at),count(*) FROM extents WHERE safety_state IN ('held','releasing')").fetchone()
        timings["sqlite_census_integrity_s"] = monotonic() - started
        report = dict(census=summary, extent_count=extent_count, s_held_ms=s_held, held_count=held_count,
                      f1_attempt_id=receipt["f1_attempt_id"], d1_uuid=receipt["d1_uuid"])
        if args.apply:
            started = monotonic()
            with postgres(args.pg_env) as (pg, schema, key):
                ensure_unclaimed(pg, schema)
                migrate(args.pg_env, "--to", CUTOVER_BASELINE[0], "--import-mode")
                claim(pg, schema, key, source)
                timings["pre_and_claim_s"] = monotonic() - started
                started = monotonic()
                report["copied"] = copy_data(pg, key, db, source, receipt)
                timings["binary_copy_s"] = monotonic() - started
                started = monotonic()
                migrate(args.pg_env, "--to", CUTOVER_BASELINE[-1], "--import-mode")
                mark_ready(pg, key)
                timings["post_and_identities_s"] = monotonic() - started
    report["sqlite_bytes"] = args.sqlite.stat().st_size
    report["timings"] = timings
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(diagnostic_main(main))
