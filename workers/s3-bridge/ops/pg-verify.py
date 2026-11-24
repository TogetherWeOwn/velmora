#!/usr/bin/env python3
"""Verify the transformed D1 snapshot against Postgres; activate only on request."""

import argparse
from hashlib import sha256
from itertools import zip_longest
import json
from pathlib import Path
from time import monotonic

from pg_catalog import (
    MARKER, app_has_usage, check_boundaries, check_seal, check_source_arm, diagnostic_main,
    encode_row, f1_receipt, ident, idents, json_input, lock_w1, marker_exists, migrate,
    pg_columns, postgres, projection, require, restore_values, source_count, source_manifest,
    source_schema, sqlite_source,
)


def stream_pg(db, query, params=()):
    with db.cursor(binary=True) as cur:
        yield from cur.stream(query, params)


def chunks(query, table, columns, keys, limit, placeholder, where=""):
    key_cols = idents(keys)
    col_indexes = tuple(tuple(columns).index(k) for k in keys)
    select = f"SELECT {idents(columns)} FROM {ident(table)}"
    last = None
    while True:
        clause, params = where, ()
        if last is not None:
            lhs = f"({key_cols})" if len(keys) > 1 else key_cols
            rhs = f"({', '.join([placeholder] * len(keys))})" if len(keys) > 1 else placeholder
            clause += (" AND " if where else " WHERE ") + f"{lhs} > {rhs}"
            params = last
        unordered = query(f"{select}{clause} ORDER BY {key_cols} LIMIT {limit}", params)
        digest, count, first = sha256(), 0, None
        for row in unordered:
            key = tuple(row[i] for i in col_indexes)
            require(all(v is not None for v in key) and (last is None or key > last),
                    f"{table}: invalid primary-key order")
            if first is None:
                first = key
            last = key
            encode_row(digest, row)
            count += 1
        if count:
            yield count, first, last, digest.digest()
        if count < limit:
            break


def restore_chunks(receipt):
    row = receipt["restore_state_before"]
    if row is not None:
        digest = sha256()
        encode_row(digest, restore_values(row))
        yield 1, (1,), (1,), digest.digest()


def pk_range(chunk):
    if chunk is None:
        return "empty"
    # Range endpoints may contain customer keys. Emit fingerprints, not values.
    ends = []
    for key in chunk[1:3]:
        digest = sha256()
        encode_row(digest, key)
        ends.append(digest.hexdigest()[:16])
    return "..".join(ends)


def keyed(table, left, right):
    accumulated = (sha256(), sha256())
    counts = [0, 0]
    for number, (a, b) in enumerate(zip_longest(left, right), 1):
        require(a == b, f"{table} chunk {number} mismatch: PK range fingerprints D1={pk_range(a)} PG={pk_range(b)}")
        for i, item in enumerate((a, b)):
            accumulated[i].update(item[3])
            counts[i] += item[0]
    return tuple((n, h.hexdigest()) for n, h in zip(counts, accumulated))


def multiset(rows):
    total, count = 0, 0
    for row in rows:
        digest = sha256()
        encode_row(digest, row)
        total += int.from_bytes(digest.digest(), "big")
        count += 1
    return count, f"{total % (1 << 256):064x}"


def ordered(rows):
    digest, count = sha256(), 0
    for row in rows:
        encode_row(digest, row)
        count += 1
    return count, digest.hexdigest()


def pg_count(pg, table):
    return pg.execute(f"SELECT count(*) FROM {ident(table)}").fetchone()[0]


def compare(db, pg, source, receipt, size):
    report = {}
    for table, (cols, keys) in source.items():
        left_count, right_count = source_count(db, table, receipt), pg_count(pg, table)
        # Hash even on unequal counts so keyed discrepancies identify a range.
        if keys:
            left = restore_chunks(receipt) if table == "restore_state" else chunks(
                db.execute, table, cols, keys, size, "?", projection(table))
            right = chunks(lambda q, p: stream_pg(pg, q, p), table, cols, keys, size, "%s")
            a, b = keyed(table, left, right)
        else:
            query = f"SELECT {idents(cols)} FROM {ident(table)}"
            a, b = multiset(db.execute(query)), multiset(stream_pg(pg, query))
        require(a == b and a[0] == left_count and b[0] == right_count,
                f"{table} mismatch: D1 count={left_count}, PG count={right_count}")
        report[table] = {side: {"count": n, "hash": h} for side, (n, h) in zip(("sqlite", "postgres"), (a, b))}
    src_seq = ((extent, seq) for seq, (extent,) in enumerate(db.execute("SELECT extent_id FROM outbox ORDER BY rowid"), 1))
    a, b = ordered(src_seq), ordered(stream_pg(pg, "SELECT extent_id, seq FROM outbox ORDER BY seq"))
    require(a == b, "outbox.seq does not preserve the exported rowid order")
    return report, a[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite", type=Path, required=True)
    parser.add_argument("--f1", type=Path, required=True)
    parser.add_argument("--pg-env", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source-boundaries", type=Path, required=True)
    parser.add_argument("--chunk-rows", type=int, default=10_000, help="keyset page size, at most 10000")
    parser.add_argument("--activate", action="store_true", help="drop the complete import marker and give kofra_app USAGE")
    args = parser.parse_args()
    require(1 <= args.chunk_rows <= 10_000, "chunk size must be 1–10000")
    receipt = f1_receipt(args.f1)
    manifest = source_manifest(args.manifest, receipt)
    boundaries = json_input(args.source_boundaries)
    with sqlite_source(args.sqlite) as db, postgres(args.pg_env) as (pg, schema, key), pg.transaction():
        source = source_schema(db)
        check_seal(args.sqlite, manifest, receipt, boundaries)
        check_boundaries(db, boundaries, receipt)
        check_source_arm(db, receipt)
        if args.activate:
            # Keep every W1 writer out from the first PG read through the
            # activation commit. A count-only recheck cannot detect an UPDATE.
            lock_w1(pg, key)
        else:
            pg.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        pg_columns(pg, schema, source)
        marked = marker_exists(pg)
        if args.activate:
            require(marked, "cannot activate an unclaimed target")
        if marked:
            require(not app_has_usage(pg, schema), "incomplete target has app schema USAGE")
            require(pg.execute(f"SELECT ready FROM {ident(MARKER)}").fetchall() == [(True,)],
                    "import has not completed COPY, post schema and identity reset")
        start = monotonic()
        tables, seq_hash = compare(db, pg, source, receipt, args.chunk_rows)
        checked = monotonic()
        # WP2 --verify is read-only and does not acquire W1.
        migrate(args.pg_env, "--verify")
        if args.activate:
            for table, info in tables.items():
                require(pg_count(pg, table) == info["postgres"]["count"], f"{table} changed before activation")
            pg.execute(f"DROP TABLE {ident(MARKER)}")
            pg.execute(f"GRANT USAGE ON SCHEMA {ident(schema)} TO kofra_app")
    print(json.dumps(dict(tables=tables, outbox_seq_hash=seq_hash, chunk_rows=args.chunk_rows,
                          activated=args.activate, timings=dict(content_verify_s=checked-start,
                          schema_and_final_s=monotonic()-checked)), sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(diagnostic_main(main))
