# Benchmark: work, cost and speed per operation

One command per layer, repeatable, so a change can be measured before and
after.

## Layer 1: local and deterministic

```sh
bench/run-local.sh [--ref <git ref>] [--name <name>] [--tiny <n>] [--cpu <cpu.json>]
```

- Runs `crates/velmora-bridge/tests/bench_counts.rs`: the real `Bridge` over
  the SQLite catalogue, in-memory blob stores and a real NNTP client against
  the in-process fake server, with the top-level `[vars]` of
  `workers/s3-bridge/wrangler.toml` (the overrides are listed in the test:
  dev environment for plaintext loopback providers, `VERIFY_MODE=light`,
  `GC_MODE=disposable`, fake providers shaped like production: one post-only
  provider on a backbone that does not count, two read providers on two that
  do).
- Every port is metered and every figure is charged to the operation or
  stage that ran: D1 calls, statements, rows written (the rows-written meter),
  R2 operations by price class and bytes, queue messages and redeliveries,
  NNTP connects, posts, STAT/size asks and bodies, invocations.
- The D1 trace of the run is replayed in order through the local D1 runtime
  (`d1-replay.mjs`, wrangler's `getPlatformProxy`), which gives D1's own
  `rows_read` and `rows_written` for every statement. The replay must agree
  with the native run on every call (0 disagreements), and its rows written
  equal the native meter's.
- `report.py` writes `results.json` and `results.md`: per S3 operation, per
  pipeline stage and extent (classes `big` = 16 MiB extents, `mix`, `tiny`),
  the statements that read the most rows, and the cost model.
- `--ref` measures another commit with this checkout's harness (temporary
  worktree, removed at the end). `--tiny <n>` changes the number of small
  objects, to see which figures grow with the size of the catalogue.
- `report.py --compare <run A> <run B>` prints the change between two runs.

What it does not measure: Worker CPU (the native run is not the Worker; pass
`--cpu` with figures measured on a deployed Worker to price it), the
recovery copy pass (run by the Worker adapter), GET fan-out sub-requests
(only above `GET_FANOUT_BYTES`), and anything a real provider or network adds.

Scratch goes to `$BENCH_WORK` (default `/var/tmp/velmora-bench`). A full run
takes about 6 minutes, most of it the D1 replay.

## Layer 2: a deployed Worker

```sh
bench/drill.py <mpu|many|get|list|evict|status> --base <url> --bucket <name> ...
```

The client side of a drill against a throwaway deployment: ingest MiB/s (one
multipart upload, many small PutObjects), GET time to first byte and MiB/s
(hot from R2, cold from Usenet after an admin evict), ListObjectsV2 latency.
Concurrency defaults to 4, rclone's default. Standard library only;
credentials are read from `AWS_SHARED_CREDENTIALS_FILE` and the admin bearer
from the header file named by `VELMORA_ADMIN_HEADER_FILE`, never printed.
The deployment itself, the timings of the pipeline (from the catalogue) and
the platform analytics of the run window are the operator's runbook.

## Prices

`prices.json`: Workers Paid list prices with the date they were read and
their sources. The model prices usage with no included allowance (the unit
cost once the allowance is used up).
