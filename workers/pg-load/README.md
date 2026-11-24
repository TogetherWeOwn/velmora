# Postgres catalogue load drill

This crate is a standalone Worker and a native binary. It is not deployed by CI, is not part of the S3 Worker, and has no Wrangler deployment configuration. It never talks to S3, R2, queues or NNTP. It creates synthetic catalogue rows, including unrecoverable synthetic objects: **use only a disposable local schema or the sanitized rehearsal copy.** Tear down the copy after the drill.

## Configuration and results

Set `PG_LOAD_CONFIG` to JSON. `mix` weights are relative **write transactions**, not logical requests. Omitted families get no load. PUT and multipart Complete use two transactions (record floor and publish); Delete uses three (raise floor, settle, delete). Other entries use a single transaction. `reads_per_minute` is shared evenly by the three read probes. For example:

```json
{
  "batches_per_minute": 300,
  "minutes": 5,
  "reads_per_minute": 600,
  "unloaded_seconds": 30,
  "mix": {
    "put_publish": 20, "multipart_create": 2, "multipart_part": 8,
    "multipart_complete": 6, "multipart_abort": 1, "delete": 5,
    "outbox_post_claim": 4, "outbox_post_advance": 4,
    "outbox_verify_claim": 4, "outbox_verify_advance": 4,
    "outbox_release_claim": 4, "outbox_release_advance": 4,
    "permits_acquire": 8, "permits_release": 8, "gc": 4, "usage": 2,
    "dispatch": 2
  }
}
```

- Fixture setup is outside the timed intervals. Three paced writers execute through `SqlCatalog<PgSql>` without driver-level write retries. Only acknowledged transactions count; the report lists completions per elapsed minute, late commits and per-family failures. Work not executed before the deadline does not count.
- The read probe uses a separate connector. GET measures the extent lookup with a known generation, HEAD the live-generation lookup, and LIST a 101-entry prefix page. Timings include adapter and connection round trips; they exclude blob I/O. The same rate, keys and queries run just before and during write load.
- A dedicated read connection samples W1 waiters in `pg_stat_activity` and `pg_locks` every 250 ms. p99 is the nearest rank of the **observed ages**, not the p99 of all lock waits; `null` means no wait was visible at sample time. Check retained vs expected sampling ticks. Under 250 ms waits may go unseen.
- The PG adapter collapses `55P03` and five other SQLSTATEs into `pg: overloaded`. `overloaded_upper_bound_on_55p03` counts every such error. A nonzero count fails the zero-`55P03` condition conservatively. Refused or unexpected operations also invalidate the run, even if the requested rate was met.

## Native run

Use Postgres 18 with peer auth on the local `/var/run/postgresql` socket and database `postgres`. Create a schema whose name starts with `velmora_pg_load_`. On that schema's search path apply the catalogue pre-schema, seed `usage_global` rows 1 and 2, then apply the post-schema. With the schema still selected, explicitly arm it for one run:

```sql
INSERT INTO meta(k,v) VALUES ('pg_load_fixture_v1',1);
```

Set `PG_LOAD_SCHEMA` to that name and set `PG_LOAD_CONFIG`. Run `cargo run --locked -p velmora-pg-load`. The binary returns nonzero if any minute falls outside ±5%, any operation fails, or there is no usable read or sampler data. Drop the scratch schema after the run, including on failure. The marker cannot be reused; the runner claims it before creating fixture rows.

## Rehearsal only

Build the library for `wasm32-unknown-unknown` with the Workers Rust SDK. The operator must use a private, access-controlled route, separate uncached `DRILL_PG_WRITE` and `DRILL_PG_READ` bindings pointing to the **same sanitized rehearsal copy**, and explicitly set `PG_LOAD_ENABLE=drill-only`. Never use production bindings or expose the endpoint publicly. Set `PG_LOAD_CONFIG` with `minutes: 20` and the rehearsal load. Arm the clone using the marker SQL above; the runner refuses an unarmed catalogue or one containing rollback stamps. The sampler needs the writer's database role or `pg_read_all_stats`. The fixture writer needs permission to create temporary tables. The harness uses at most five live client connections total: three writers, one read probe, one sampler. The runbook owns Hyperdrive's origin-connection limits independently of this client limit.

Make one `POST /run` request and keep it open through the unloaded and loaded phases for the JSON report. Do not retry against a claimed catalogue; recreate the rehearsal copy and re-arm it before running again. The report is evidence for the rehearsal gate, not a substitute for the gate's throughput and latency comparisons.
