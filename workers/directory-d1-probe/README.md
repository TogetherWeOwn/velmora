# Directory tests on D1

The directory is its own D1 database. Its tests run on a native SQLite,
which takes some statements that D1 refuses: a `LIKE` or `GLOB` pattern
over 50 bytes is one (`LIKE or GLOB pattern too complex`). This Worker
runs the directory tests' statements on D1 instead, bound and read back as
the Worker's D1 adapter (`workers/s3-bridge/src/d1.rs`) does: `query` reads
`.raw()` rows, `exec` and each statement of `batch` read `meta.changes`,
and `batch` is one `D1Database.batch` transaction.

It is test-only: no route, never deployed.

## Local D1

```sh
cd workers/directory-d1-probe
../s3-bridge/node_modules/.bin/wrangler dev --ip 127.0.0.1 --port 18797
# in another shell
VELMORA_D1_PROBE=http://127.0.0.1:18797 \
  cargo test -p velmora-bridge --test directory_store --test directory_feed -- --test-threads=1
```

## A throwaway remote D1

Create two databases, copy `wrangler.toml` outside the repository with
their ids, run `wrangler dev --remote` with that copy, run the same tests
against it, then delete both databases.

The probe holds two databases (`DB0`, `DB1`), and each test empties the
one it takes and applies the schema again, so a D1 run takes
`--test-threads=1`.
