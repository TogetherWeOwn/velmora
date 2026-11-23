# velmora-alerts

A small Worker that emails the operator when velmora needs attention. It
runs apart from the S3 Worker, so a broken S3 Worker cannot silence it,
and changing it never redeploys the S3 Worker.

## What it watches

Every 5 minutes it takes bounded, indexed readings of the S3 Worker's
catalogue. The alerts Worker never writes to the catalogue. Each
condition below emails when it holds:

| Key | Holds when | Emails after |
|---|---|---|
| `posting-stalled` | the oldest due post row has been due 30 min and has not changed since the last tick (a post job's every outcome moves it, and the dispatcher sends the oldest first) | 30 min more |
| `post-failing`, `verify-failing` | at least half of the 20 soonest rows of the stage (3 rows or more) have `FAILING_ATTEMPTS` (3) or more attempts: jobs run and fail, which moves the head and hides it from the two checks around this one | 30 min |
| `verify-backlog` | the oldest due verify row has waited over `VERIFY_BACKLOG_ALERT_SECS` (12 h) | at once |
| `dlq` | at least `DLQ_ALERT_MIN` (1) messages reached the dead-letter queue in the last hour | at once |
| `outbox-dead` | outbox rows are in stage `dead` | at once |
| `provider-cooldown:<id>` | a provider is cooling (skipped) | 15 min |
| `catalog-export-stale` | the newest export manifest in the export bucket is over 26 h old (listed hourly) | at once |
| `recovery-copy-refused` | both of the last two completed scheduled recovery-copy passes had a remote refusal | at once |
| `recovery-copy-stale` | no completed recovery-copy pass in more than three 15-minute intervals | at once |
| `check-error` | a reading failed (its check did not run) | 15 min |

It also takes reports on `POST /v1/alert` (bearer `INGEST_TOKEN`) from:

- the operator host: migration and health-check alert files, a cost
  meter jump, a failed export run, and a rollback seen in the Worker's
  deployments;
- CI: the `deploy-alert` job when the production deploy fails.

A reporter is any script that can POST JSON with the token. The
operator host's own feeder is private to that host, as are its paths.

```json
{ "source": "host", "key": "run48", "title": "...", "detail": "...", "severity": "page" }
```

`severity: "info"` goes to the digest only.

## Email rules

- **Per key:** one email, then reminders while it keeps holding, after
  1 h, 2 h, 4 h, and so on, up to once a day. A key never emails twice
  within an hour.
- **Cap:** at most `DAILY_EMAIL_CAP` (30) alert emails in 24 h, a soft
  limit (sends racing at the limit can pass it by one or two). When it
  holds an email back, one notice says so; held alerts still show in the
  digest.
- **Reports inside the hour:** a key reported again inside its hour is
  emailed by the first tick after the hour.
- **Daily digest** at 07:30 UTC: what holds, what cleared, the notices,
  dead-letter counts and the current figures. It arrives every day, so
  if it stops, alerting itself is down.
- **Dead-letter queue:** the Worker is the queue's only consumer. It keeps
  a count and one sample per batch for 30 days, then acknowledges. Each
  dead-lettered job's outbox row is still due, and the S3 Worker's
  dispatcher sends it again, so acknowledging loses no work.
- **Failed send:** the claim is given back and the next tick retries.
- **Outside monitor (optional):** set `HEARTBEAT_URL`, and every check run
  pings it (`<url>/fail` if the run threw or an email could not be sent). If the pings stop, the outside
  monitor emails you.

## Recovery-copy monitoring

Apply the bridge catalogue migrations before updating either Worker.
Monitoring is on by default. Set `RECOVERY_ALARM=off` on the alerts
Worker if recovery copy is intentionally off or the bridge is in restore
maintenance. The same var on the bridge Worker stops telemetry writes;
turning it off there alone does not disable the stale alert.

A zero-copy pass is not a refusal. Hints, retries and incomplete chains
do not count as completed passes. A copy walk can continue while no pass
completes: a stale page reports missing **completed-pass telemetry**, not
a claim that no copy work ran. Each pass records at most 256 steps; going
past that bound has the same effect on monitoring but does not stop copying.
The bridge prunes telemetry after seven days, retaining one last verified
copy timestamp for the age reported in the email. Recovery notices use the
same email cap and cooldown as the other conditions.

Rolling the bridge back to a version without the optional queue sequence
can drop in-flight sequenced copy messages. The next scheduled pass resumes
normal copy work. Leave the additive telemetry table in place on rollback.

## Cost

Email goes through the `send_email` binding to a verified Email Routing
destination address. That is free on every plan, and needs no sending
domain. The rest:

- 8,640 cron runs a month;
- under 100,000 baseline catalogue rows read a month before recovery-copy
  monitoring;
- recovery-copy reads scale with the number of jobs in the last two complete
  passes, bounded by four indexed pass reads of up to 256 jobs each per tick;
- a few thousand writes to the Worker's own D1;
- about 720 R2 list calls a month.

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
