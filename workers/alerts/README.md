# velmora-alerts

A small Worker that emails the operator when velmora needs attention. It
runs apart from the S3 Worker, so a broken S3 Worker cannot silence it,
and changing it never redeploys the S3 Worker.

## What it watches

Every 5 minutes it takes a few index-only readings of the S3 Worker's
catalogue. Each statement reads 0 to 4 rows (measured), and nothing is
ever written there. Each condition below emails when it holds:

| Key | Holds when | Emails after |
|---|---|---|
| `posting-stalled` | the oldest due post row has been due 30 min and has not changed since the last tick (a post job's every outcome moves it, and the dispatcher sends the oldest first) | 30 min more |
| `verify-backlog` | the oldest due verify row has waited over `VERIFY_BACKLOG_ALERT_SECS` (12 h) | at once |
| `dlq` | at least `DLQ_ALERT_MIN` (1) messages reached the dead-letter queue in the last hour | at once |
| `outbox-dead` | outbox rows are in stage `dead` | at once |
| `provider-cooldown:<id>` | a provider is cooling (skipped) | 15 min |
| `catalog-export-stale` | the newest export manifest in the export bucket is over 26 h old (listed hourly) | at once |
| `check-error` | a reading failed (its check did not run) | 15 min |

It also takes reports on `POST /v1/alert` (bearer `INGEST_TOKEN`) from:

- the operator host: migration and health-check alert files, a cost
  meter jump, a failed export run, and a rollback seen in the Worker's
  deployments;
- CI: the `deploy-alert` job when the production deploy fails.

```json
{ "source": "host", "key": "run48", "title": "...", "detail": "...", "severity": "page" }
```

`severity: "info"` goes to the digest only.

## Email rules

- **Per key:** one email, then reminders while it keeps holding, after
  1 h, 2 h, 4 h, and so on, up to once a day. A key never emails twice
  within an hour.
- **Cap:** at most `DAILY_EMAIL_CAP` (30) alert emails in 24 h. Past the
  cap, alerts still show in the digest.
- **Daily digest** at 07:30 UTC: what holds, what cleared, the notices,
  dead-letter counts and the current figures. It arrives every day, so
  if it stops, alerting itself is down.
- **Dead-letter queue:** the Worker is the queue's only consumer. It keeps
  a count and one sample per batch for 30 days, then acknowledges. Each
  dead-lettered job's outbox row is still due, and the S3 Worker's
  dispatcher sends it again, so acknowledging loses no work.
- **Failed send:** the claim is given back and the next tick retries.
- **Outside monitor (optional):** set `HEARTBEAT_URL`, and every check run
  pings it (`<url>/fail` if the run threw). If the pings stop, the outside
  monitor emails you.

## Cost

Email goes through the `send_email` binding to a verified Email Routing
destination address. That is free on every plan, and needs no sending
domain. The rest:

- 8,640 cron runs a month;
- under 100,000 catalogue rows read a month;
- a few thousand writes to the Worker's own D1;
- about 720 R2 list calls a month.

All of it is well inside the included usage.

## Setup

1. **Email Routing.** Enable it on a zone of the account, add the
   operator's address under Email Routing, then Destination addresses,
   and click the link in the verification email. The sender (`ALERT_FROM`)
   is any address on that zone.
2. **State database.** `wrangler d1 create velmora-alerts`, then
   `wrangler d1 migrations apply velmora-alerts --remote`.
3. **Config.** Copy `wrangler.toml` and fill in:
   - `ALERT_FROM`;
   - the state database id;
   - the catalogue id.

   Remove the `EXPORTS` binding if there is no export bucket. Keep the copy
   out of the repository.
4. **Deploy.** `wrangler deploy -c <copy>`, then set the secrets with the
   values on stdin:

   ```sh
   wrangler secret put ALERT_EMAIL_TO -c <copy>
   wrangler secret put INGEST_TOKEN -c <copy>
   wrangler secret put HEARTBEAT_URL -c <copy>   # optional
   ```
5. **CI.** In the `production` environment, set the variable
   `ALERTS_INGEST_URL` (this Worker's URL) and the secret
   `ALERTS_INGEST_TOKEN` (the same token).

The thresholds are vars; their defaults are in `src/checks.js`.

## Tests

```sh
node --test test/*.test.js   # Node 22.13 or later (node:sqlite)
```

The tests run the real SQL:

- this Worker's migrations;
- the S3 Worker's catalogue schema, built from
  `workers/s3-bridge/migrations`.
