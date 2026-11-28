# PostgreSQL catalogue schema

The Postgres catalogue is opt-in. These files do not change the running D1
catalogue or select a Worker backend. Apply them from a host with Python 3
(with SQLite support) and `psql`, connecting directly rather than through a
transaction pooler.

## Roles and connection file

Provision the login roles `kofra_migrate`, `kofra_app` and `kofra_ro` out of
band. An administrator runs `psql -X -v ON_ERROR_STOP=1 -f pg/roles.sql`
from `workers/s3-bridge` once for a new target. Use `-v schema=NAME` with an
already created disposable schema. This bootstrap removes default PUBLIC
schema access and refuses to run after app access has been explicitly granted.
The migration login owns the schema
and its objects. The app role gets DML, sequence access, and trigger function
access, but cannot reach the schema until activation. Its sessions default to
read-only transactions so writes cannot autocommit if a proxy rejects `BEGIN`.
The adapter uses `BEGIN READ WRITE` and takes W1 before any write. The read-only login has
`pg_read_all_data` and is for trusted host tooling, not application traffic.

Pass the path of a regular, caller-owned `0600` file to `ops/pg-migrate.sh`.
The syntax is one literal `NAME=value` per line, with blank lines and `#`
comments allowed: no shell expansion, `export`, quote processing, or inline
comments. Required keys are `PGHOST`, `PGDATABASE`, and `PGUSER`. Use
`PGUSER=kofra_migrate` for direct PostgreSQL or `kofra_migrate.BRANCH_ID` for
PlanetScale routing, with that exact literal branch id in `PGBRANCHID`.
The server session must still identify as the bare SQL role `kofra_migrate`.
Optional libpq keys are `PGPORT`, `PGPASSWORD`, `PGSSLMODE`, `PGSSLROOTCERT`,
and `PGCONNECT_TIMEOUT`. Remote connections require `PGSSLMODE=verify-full`.
No value is passed in command-line arguments. Keep the file outside the repo.

`PGSCHEMA` defaults to `public`. The fixed public writer key (`PGLOCKKEY`, W1)
is `7413000001`; the migrator-only session key (`PGMIGRATELOCKKEY`) is
`7413000002`. For an isolated lane, set `PGSCHEMA` and a unique `PGLOCKKEY`
(signed bigint); the default migration key is the writer key XOR `2^62`.
If overriding a lane's migrator key, keep it distinct from all writer and
other lane keys. Use the same schema and W1 key in every catalogue writer.
To apply the SQL directly in standalone tests, set `search_path` to the test
schema followed by `pg_temp` before
applying the baseline. Seed `usage_global(id)` with `1, 2` only for fresh tests.

## Fresh test databases

```sh
ops/pg-migrate.sh "$CONNECTION_FILE" --to 0001  # tables, constraints and fresh seeds
ops/pg-migrate.sh "$CONNECTION_FILE"            # secondary indexes, triggers, later stages
ops/pg-migrate.sh "$CONNECTION_FILE" --verify   # read-only, no writer lock
ops/pg-migrate.sh "$CONNECTION_FILE" --test     # standalone fixture; rolls back
ops/pg-migrate.sh "$CONNECTION_FILE" --activate # opt-in, never while an import marker exists
```

`--test` uses a fresh disposable schema only. It exercises trigger refusals,
reference maintenance, usage counters and key floors, comparing the same
fixture's checkpoints against SQLite. `--activate` is for fresh test
DDL; it is not the import activation procedure.

## Import path

1. Run `ops/pg-migrate.sh "$CONNECTION_FILE" --to 0001 --import-mode`. The
   pre-stage skips seeds and checks, under the writer lock, that no catalogue
   table contains rows, the app cannot reach the schema, there is no import
   marker, and the post-stage has not run.
2. The importer takes the writer lock and independently checks/claims the
   target, creates `_velmora_import_incomplete`, and copies all source rows,
   including `usage_global` ids 1 and 2. Populate `outbox.seq` in source
   `rowid` order. Copy foreign-key parents before children; constraints are
   live, secondary indexes and triggers are not.
3. Run `ops/pg-migrate.sh "$CONNECTION_FILE" --import-mode` after COPY has
   committed. The post-stage requires the marker, both usage rows and an
   inaccessible app schema. It restarts the `gc.id`, `usage_recounts.id` and
   `outbox.seq` identities above the copied values in the same transaction.
4. Verify source data counts and digests outside this tool. `--verify` also
   works while the verifier holds the writer lock on another connection; it
   checks identity positions without acquiring either advisory lock or
   activating the app. The import verifier removes the marker and grants the
   app schema `USAGE` in one locked transaction.

## Adding migrations

Each numbered PostgreSQL file is applied once and recorded with its SHA-256.
Do not edit an applied migration. Ordinary files are atomic; leave transaction
control and psql metacommands to the runner. Use dollar-quoted routine bodies
and unqualified catalogue object names so the same DDL works in each target
schema. A `55P03` lock timeout retries up to five times after the initial
attempt, with backoff. A statement or transaction budget expiry is not retried.
Use `--to NNNN` to stop
at a shipped stage. Online migrations (app schema access granted) use a 3 s
statement timeout and, on PostgreSQL 17+, a 3 s transaction timeout so an
acquired exclusive lock cannot stall readers indefinitely. Split changes that
cannot fit the budget, or run them with the app offline. Inactive/import
migrations are not subject to the 3 s execution budget. Outside
`--import-mode`, each transactional migration (fresh or online) and the
activation reach the server as one message, so network round trips do not
count against the budget; this needs psql 15 or newer and a batch under
128 KiB. `--verify` and `--import-mode` keep the older transport.

A file whose first line is `-- velmora: no-transaction` may contain only
idempotent `CREATE [UNIQUE] INDEX CONCURRENTLY IF NOT EXISTS` statements.
Only the migrator session lock is held through the index statements; short
precheck and ledger transactions use W1. A competing migrator retries the
session lock without waiting in PostgreSQL with a snapshot. A failed
concurrent index build can leave an invalid index (including after a lock
timeout). The tool refuses
to record the file or skip the invalid index on retry. Inspect and repair the
index before rerunning.

`ops/pg-migrate.sh --check-migrations` is offline. The baseline marker covers
exact historical D1 versions (not gaps). Its fingerprint is the SHA-256 of
lines `<filename> <sha256 of raw file>\n` sorted by migration filename. A
later Postgres translation declares each corresponding D1 file using a comment
`-- velmora: d1-twin <D1 filename> <sha256 of raw D1 file>`. Missing coverage,
renamed files and byte changes fail the gate. `--verify` also compares the live
Postgres manifest against a replay of all shipped D1 migrations in memory;
update the comparison explicitly for any future intentional engine difference
(`STATEMENT_TRIGGERS` in `ops/pg-migrate.sh` is one).

After the cutover the D1 catalogue is frozen: a schema change ships as a
PostgreSQL stage numbered after the baseline (`0003`) and a SQLite twin of the
same version in `../migrations-local/`, which local development and the tests
apply and the frozen D1 never takes. The stage declares it with
`-- velmora: sqlite-twin <twin filename> <sha256 of raw twin file>`; every twin
must be declared exactly once, by the stage of its version, and every stage after
`0003` declares one. `--verify` replays
the D1 migrations and then the twins. Such changes are additive only: no
`DROP`, `RENAME`, column type change, or `NOT NULL` without a `DEFAULT`; no
foreign key from a new table to a table of `0001`–`0003` (a path that removes
such a row removes its child rows in the same batch instead), and no `UNIQUE`
index on one.

The only baseline structural differences from D1 are PostgreSQL's mapped
column types and non-null PKs, the three identities, the `yenc_name` regex,
`tx_guard_ok`, documented index keys/null ordering, the translated
trigger functions, and the statement-level usage triggers (0003). Source PKs that were nullable in SQLite require a copy
census. The verifier ignores only the migration ledger and import-marker
tables as host-tool metadata.

## Usage counters

D1 moves the usage counters with per-row triggers (migrations 0020 and
0025). PostgreSQL writes a new row version per UPDATE and a transaction
cannot prune its own versions, so the same per-row triggers cost O(N^2) for
N rows changed in one transaction. Stage 0003 replaces them with statement
triggers over transition tables: each statement writes each `usage_global`
row at most once, each `usage_buckets` key once and each `usage_hours` row
once per rolled hour, with the same values at every statement boundary.
No query joins the two transition tables. PostgreSQL has no statistics
for them: a join may be cached with the first firing's (often one-row)
size and run as a nested loop, and any join is estimated at about
N*M/200 rows, which crosses the JIT thresholds. Deltas are summed over
`new_rows UNION ALL old_rows`, and rows are paired by key with GROUP BY
over the same union. `usage_outbox_failure` keeps its `last_error` column list to see SET
targets; it marks the statement and `usage_outbox_stage` counts the
failures in the same ascending-hour pass. `--test` compares the shared
fixture with SQLite, including mixed-hour statements that SQLite applies in
key order (checked with `EXPLAIN QUERY PLAN`).
