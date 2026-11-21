# Benchmark: work, cost and speed per operation

One command per layer, repeatable, so a change can be measured before and
after.

## Layer 1: local and deterministic

```sh
bench/run-local.sh [--ref <git ref>] [--name <name>] [--out <dir>] [--tiny <n>] [--cpu <cpu.json>]
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
  with the native run on every call (0 disagreements): a disagreement is a
  call that succeeded in one runtime and failed in the other. Returned rows
  and write effects are not compared call by call. The rows read and
  written that are reported and priced are D1's. The native rows-written
  meter is compared with them label by label: `results.md` and
  `results.json` (`rows_written_check`) say whether it agrees, and where
  not.
- `report.py` writes `results.json` and `results.md`: per S3 operation, per
  pipeline stage and extent (classes `big` = 16 MiB extents, `mix`, `tiny`),
  the statements that read the most rows, and the cost model.
- `BENCH_VARS=KEY=VALUE,...` (environment) changes Worker variables for one
  run, for example `BENCH_VARS=PARITY=on,POST_SOCKETS=6`. The variables that
  run the rig itself are refused; `results.json` lists the change under
  `bench_vars`, and `report.py --compare` shows it beside the counts.
- Permits: as production binds the permit gate, the rig always builds the
  gate client; `PERMITS` (`d1` from the `[vars]`, or `BENCH_VARS=PERMITS=do`),
  `PERMIT_GATES` and `PERMIT_SHARDS` choose where permits come from. The gate
  objects run in process over the same metered D1, out of memory between two
  invocations (the most starts a hibernating object can have). Counted per
  label: `do_requests` (sessions opened, requests outside one),
  `do_messages` (messages and closes on a session, billed 1/20 each),
  `do_starts` and `do_storage_writes`; the report prices them, and the
  gate's duration from `--cpu do_gb_s_per_request` (a deployed Worker's
  figure). Where the measured commit binds no `PERMIT_GATE` (before deploy 3
  of the gate) the rig builds no client and refuses `PERMITS=do`; the harness
  compiles only against commits that have the gate module (#136 on).
- `--ref` measures another commit with this checkout's harness (temporary
  worktree and cargo target of its own, removed at the end, so runs may
  overlap). `--tiny <n>` changes the number of small
  objects, to see which figures grow with the size of the catalogue; without
  `--name` or `--out` such a run is named `<sha>-tiny<n>`, apart from the
  full run. `--out` and `--cpu` may be relative to the caller's directory.
- The D1 storage line of the cost model uses the fixture's average
  catalogue bytes per extent over every class, so it moves with `--tiny`
  (more small objects, more rows per byte stored); it is not the footprint
  of a 16 MiB extent alone.
- The dispatcher's runs in the release phase are charged to ingest
  (`stage:cron`); those of the delete phase to `stage:cron_gc`, shown in
  the stage table and not in the ingest price. `GC_MODE=off` skips the wait
  for garbage collection; `SERVER_SIDE_COPY=off` expects 501 from CopyObject.
- `report.py --compare <run A> <run B>` prints the change between two runs.

Repeatability: every figure is a count, and two runs of one commit give
the same counts but for two things. The light check reads a sample of the
extents in full, and the sample is drawn from the extent ids, which are
random: how many extents are read in full, and in which class they fall,
changes from run to run (each one is 1 D1 call, 1 row written and the
bodies of one extent, charged to that class's verify stage). Bytes posted
and read over NNTP change by less than 0.01% with the random keys. Measured
on two runs of one commit with `--tiny 20`: one sampled extent fell in
`mix` in one run and in `tiny` in the other, and nothing else differed.

What it does not measure: Worker CPU (the native run is not the Worker; pass
`--cpu` with figures measured on a deployed Worker to price it), the
recovery copy pass (run by the Worker adapter), GET fan-out sub-requests
(only above `GET_FANOUT_BYTES`), and anything a real provider or network adds.
Jobs run one at a time against providers that never refuse, so no job is
put off for a connection slot or the byte budget (queue redeliveries are 0
here; a deployed Worker under load has several per extent), and the clock
jumps past the minimum age, so a release's delayed wake-up is delivered
once, not once per 12 hours of the wait.

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
