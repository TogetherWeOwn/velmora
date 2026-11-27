# Vendored tokio-postgres 0.7.18

This directory is the `tokio-postgres` 0.7.18 crate as published on crates.io
(`tokio-postgres-0.7.18.crate`, SHA-256
`a528f7d280f6d5b9cd149635c8705b0dd049754bc67d81d31fa25169a93809d3`,
upstream commit `f1cb6ec0d5766b136cbd68f3010d64142a5daa66`), plus one addition.
The workspace uses it through `[patch.crates-io]` in the root `Cargo.toml`.
It is not a workspace member, so it keeps upstream formatting and lints.
The crate's own `Cargo.lock`, `tests/` and `benches/` are not vendored:
nothing here builds or runs them. `../VENDORED.json` records the package
URL, version and upstream commit.

## The addition

`Client::pipeline_typed` (`src/pipeline.rs`, plus a re-export in `src/lib.rs`,
the method in `src/client.rs` and `pub(crate)` on `encode_bind_raw` in
`src/query.rs`). It sends several extended-protocol statements (unnamed
Parse, Bind, Describe, Execute each) followed by one Sync, as one request.
The connection's rule of one request, one Sync, one ReadyForQuery is kept,
so its request routing is unchanged. The catalogue's write transactions use
it so that a pooler which forwards one request at a time cannot hold the
writer lock across a network wait per statement.

- An encode error in any statement returns before anything is sent.
- An error is reported with the number of statements that completed before
  it: the index of the statement that raised it, or the number of
  statements for an error raised at the Sync itself (for example a deferred
  constraint checked when an implicit transaction commits). The rest of the
  reply is then read up to the ReadyForQuery, whose transaction status is
  returned.
- A statement that starts with COPY is refused before sending: copy mode
  would make the server ignore the Sync.
- Column types come from the built-in type table only. An unknown OID gets
  a placeholder type that no `FromSql` accepts, and no type lookup is sent.
- Nothing in the addition logs.

`upstream.diff` is the complete difference to the published crate.
`vendor/check-tokio-postgres.sh` downloads the crate, checks its SHA-256 and
fails unless this directory equals it plus `upstream.diff` (CI runs it in the
cargo-deny job). `vendor/check-advisories.py` checks this version against the
RustSec database, which lockfile scanners skip for a path crate (CI runs it
there too).

## Updating to a new upstream version

1. Download the new `.crate` from crates.io, check its SHA-256 against the
   crates.io index, extract it as `vendor/tokio-postgres-<version>/`, and
   remove its `Cargo.lock`, `tests/` and `benches/`.
2. Apply `upstream.diff` (`patch -p1`) and resolve any conflict in the four
   files above. Keep the request one Sync, one ReadyForQuery.
3. Update the directory name, the version and SHA-256 in
   `vendor/check-tokio-postgres.sh`, `VENDORED` in
   `vendor/check-advisories.py`, `vendor/VENDORED.json` (version, package
   URL, upstream commit from `.cargo_vcs_info.json`), the
   `[patch.crates-io]` path and `exclude` entry in the root `Cargo.toml`,
   and every version pin (`=0.7.x`): `crates/velmora-bridge/Cargo.toml`,
   `workers/s3-bridge/Cargo.toml` and `workers/pg-load/Cargo.toml`. Then
   regenerate `Cargo.lock` (`cargo update -p tokio-postgres`) and run the
   locked checks, the load Worker's wasm32 check included.
4. Regenerate the diff with `vendor/check-tokio-postgres.sh --write`, then
   review it as a whole.
5. Run the driver tests (`tests/pg_pipeline_driver.rs`), the single-Sync
   failure, latency-proxy and differential tests and the full PostgreSQL
   suite, and repeat the hosted semantics leg before production.
