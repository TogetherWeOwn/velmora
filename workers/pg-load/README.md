# Postgres catalogue load drill

This crate is a standalone Worker and a native binary. It is not deployed by CI, is not part of the S3 Worker, and has no Wrangler deployment configuration. It never talks to S3, R2, queues or NNTP. It creates synthetic catalogue rows, including unrecoverable synthetic objects: **use only a disposable local schema or the sanitized rehearsal copy.** Tear down the copy after the drill.

## Configuration and results

Set `PG_LOAD_CONFIG` to JSON. `mix` weights are relative **write transactions**, not logical requests. Omitted families get no load. PUT and multipart Complete use two transactions (record floor and publish), as does Usage (restart a no-adopt recount and run a bounded 4,000-row step). Delete uses three (raise floor, settle, delete), as does Dispatch (bury, mark one 100-row send batch, record dispatch). Other entries use one transaction. `reads_per_minute` is shared evenly by the three read probes. For example:

```json
{
  "batches_per_minute": 300,
  "minutes": 5,
  "reads_per_minute": 1500,
  "unloaded_seconds": 30,
  "mix": {
    "put_publish": 20, "multipart_create": 2, "multipart_part": 8,
    "multipart_complete": 6, "multipart_abort": 1, "delete": 5,
    "outbox_post_claim": 4, "outbox_post_plan": 4, "outbox_post_mark": 4, "outbox_post_advance": 4,
    "outbox_verify_claim": 4, "outbox_verify_record": 4, "outbox_verify_advance": 4,
    "outbox_release_claim": 4, "outbox_release_advance": 4,
    "permits_acquire": 8, "permits_release": 8, "gc": 4, "usage": 2,
    "dispatch": 2
  }
}
```

- Fixture setup is outside the timed intervals. Open-loop arrivals queue up to 64 logical writes, at most five of which are admitted at once. `write_pool` reports peak occupancy, arrival lag, and p50/p99 queue wait **before admission**, separately from PostgreSQL advisory wait. These figures do not include any internal Hyperdrive queue. The native run uses five admission slots on local PostgreSQL, with a fresh socket per database call rather than a persistent pooler.
- Each Dispatch job gets its own 100-row send batch, seeded before timing; fixture size grows by 100 extents and outbox rows per Dispatch job.
- Mutations run through `SqlCatalog<PgSql>` without driver-level write retries. Only acknowledged transactions count; the report lists completions per elapsed minute, late commits, dropped/unstarted batches and per-family failures.
- The separate read pool runs GET extent lookups, HEAD live-generation lookups, and LIST 101-entry prefix pages on the same fixed timetable before and during writes. Up to three reads are in flight. `statement_p95_ms` (G-L) covers sending the real catalogue SQL through receiving the result. `end_to_end_p95_ms` starts at scheduled arrival and includes queueing, connect, statement, and connection shutdown. Late responses count in both percentiles. A probe that cannot be admitted before the phase deadline or misses its 20 s budget is reported as a timeout, not silently discarded.
- A dedicated read connection samples W1 waiters in `pg_stat_activity` and `pg_locks` on a 250 ms timetable. p99 is the nearest rank of the **observed ages**, not the p99 of all lock waits; `null` means no wait was visible at sample time. Actual, expected and missed ticks are reported; waits shorter than 250 ms may go unseen.
- R3a checklist: `r3a_coverage.status` must be `SUFFICIENT` before comparing throughput, overloads, wait p99 and statement p95. Fewer than 90% of advisory ticks, an advisory sample gap over 500 ms (including either phase boundary), fewer than 200 results per read operation in either phase, any read timeout or read failure is `INCONCLUSIVE`, not a pass. The report includes elapsed query dispatch and receipt timestamps. The gap bound uses each receipt minus the previous dispatch, since the server may have sampled anywhere within each window. Configurations unable to schedule 200 reads per operation in both phases are rejected before opening connections.
- The PG adapter collapses `55P03` and five other SQLSTATEs into `pg: overloaded`. `overloaded_upper_bound_on_55p03` counts every such error. A nonzero count fails the zero-`55P03` condition conservatively. Refused or unexpected operations also invalidate the run, even if the requested rate was met.

## Native run

Use Postgres 18 with peer auth on the local `/var/run/postgresql` socket and database `postgres`. Create a schema whose name starts with `velmora_pg_load_`. On that schema's search path apply the catalogue pre-schema, seed `usage_global` rows 1 and 2, then apply the post-schema. With the schema still selected, explicitly arm it for one run:

```sql
INSERT INTO meta(k,v) VALUES ('pg_load_fixture_v1',1);
```

Set `PG_LOAD_SCHEMA` to that name and set `PG_LOAD_CONFIG`. `PG_LOAD_SOCKET_DIR` can select an absolute Unix socket directory for an isolated local instance. Keep the writer role's `default_transaction_read_only=on` when testing the rehearsal configuration. Run `cargo run --locked -p velmora-pg-load`. The binary returns nonzero if any minute falls outside ±5%, any operation fails, or there is no usable read or sampler data. Drop the scratch schema after the run, including on failure. The marker cannot be reused; the runner claims it before creating fixture rows.

## Rehearsal only

Build the library for `wasm32-unknown-unknown` with the Workers Rust SDK. The operator must use a private, access-controlled route and separate uncached `DRILL_PG_WRITE` and `DRILL_PG_READ` bindings pointing to the **same sanitized rehearsal copy**. Configure the writer origin pool at five connections; the reader and sampler use the read pool. Explicitly set `PG_LOAD_ENABLE=drill-only` and provision the `PG_LOAD_TOKEN` secret (at least 32 bytes). Use only the Hyperdrive config IDs designated for R3a while they point at the sanitized clone. Never use them after cutover or expose the endpoint publicly. Set `PG_LOAD_CONFIG` with `minutes: 20` and the rehearsal load. Arm the clone using the marker SQL above; the runner refuses an unarmed catalogue or one containing rollback stamps. The sampler needs the writer's database role or `pg_read_all_stats`. The fixture writer needs permission to create temporary tables. Keep `default_transaction_read_only=on` on the writer role; writes explicitly open READ WRITE transactions. At most five writer and three read probes are in flight; the sampler's connection is already open. Workers also bound concurrent connection establishment, so any additional front-end socket queueing is included in end-to-end probe timing. Check the [Workers limits](https://developers.cloudflare.com/workers/platform/limits/) for the intended rate and duration against the rehearsal Worker configuration.

Make one `POST /run` request with `Authorization: Bearer <drill token>` and keep it open through the unloaded and loaded phases for the JSON report. Do not log the authorization header. Do not retry against a claimed catalogue; recreate the rehearsal copy and re-arm it before running again. The report is evidence for the rehearsal gate, not a substitute for the gate's throughput and latency comparisons.
