import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { FakeD1, FakeBucket, FakeEmail } from "./d1.js";
import { evaluate, figures, DEFAULTS } from "../src/checks.js";
import { SQL, newestExport, readSnapshot } from "../src/catalog.js";
import * as store from "../src/store.js";
import worker, { tick, ingest, digest } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const MIG = join(here, "..", "migrations");
// The S3 Worker's catalogue schema, from its own migrations.
const CATALOG_MIG = join(here, "..", "..", "s3-bridge", "migrations");

const MIN = 60_000;
const HOUR = 60 * MIN;
const T0 = Date.UTC(2026, 10, 19, 12, 0, 0);

function catalog() {
  const d = new FakeD1();
  d.applyDir(CATALOG_MIG);
  // Outbox rows here stand alone, without their extents.
  d.db.exec("PRAGMA foreign_keys = OFF");
  return d;
}

function outbox(cat, id, stage, nextAt) {
  cat.db
    .prepare("INSERT INTO outbox(extent_id, generation_id, stage, next_at, updated_at) VALUES (?, 'g', ?, ?, ?)")
    .run(id, stage, nextAt, nextAt);
}

function env(over = {}) {
  return {
    STATE: new FakeD1().applyDir(MIG),
    CATALOG: catalog(),
    ALERT_EMAIL: new FakeEmail(),
    ALERT_EMAIL_TO: "operator@example.invalid",
    ALERT_FROM: "alerts@example.invalid",
    INGEST_TOKEN: "test-ingest-token",
    ...over,
  };
}

// ---- checks.js (pure) ----

test("no readings, no conditions", () => {
  assert.deepEqual(evaluate({ now: T0, providers: [], deadRows: 0, dlqLastHour: 0, errors: [] }), []);
});

test("posting stalled needs the same head as last tick, due for 30 min", () => {
  const head = { id: "x1", nextAt: T0 - 31 * MIN };
  const base = { now: T0, postHead: head, deadRows: 0, dlqLastHour: 0, providers: [], errors: [] };
  assert.equal(evaluate({ ...base, prevPostHead: null }).length, 0, "no previous reading");
  assert.equal(evaluate({ ...base, prevPostHead: { id: "x0", nextAt: head.nextAt } }).length, 0, "head moved");
  assert.equal(
    evaluate({ ...base, postHead: { id: "x1", nextAt: T0 - 5 * MIN }, prevPostHead: { id: "x1", nextAt: T0 - 5 * MIN } }).length,
    0,
    "due for less than 30 min",
  );
  const c = evaluate({ ...base, prevPostHead: { ...head } });
  assert.equal(c.length, 1);
  assert.equal(c[0].key, "posting-stalled");
  assert.equal(c[0].forMs, DEFAULTS.POST_STALL_SECS * 1000);
});

test("verify backlog, DLQ, dead rows, cooldown and export thresholds", () => {
  const snap = {
    now: T0,
    verifyHead: { nextAt: T0 - 13 * HOUR },
    deadRows: 2,
    dlqLastHour: 3,
    providers: [
      { id: "p1", coolingUntil: T0 + MIN, reason: "auth" },
      { id: "p2", coolingUntil: T0 - MIN, reason: null },
    ],
    exportNewestAt: T0 - 27 * HOUR,
    errors: [],
  };
  const keys = evaluate(snap).map((c) => c.key).sort();
  assert.deepEqual(keys, ["catalog-export-stale", "dlq", "outbox-dead", "provider-cooldown:p1", "verify-backlog"]);
  const cool = evaluate(snap).find((c) => c.key === "provider-cooldown:p1");
  assert.equal(cool.forMs, 15 * MIN);
  // Thresholds come from vars.
  const quiet = evaluate(snap, { VERIFY_BACKLOG_ALERT_SECS: "86400", DLQ_ALERT_MIN: "10", EXPORT_MAX_AGE_SECS: "200000" });
  assert.deepEqual(quiet.map((c) => c.key).sort(), ["outbox-dead", "provider-cooldown:p1"]);
  // An export never checked (no binding) raises nothing; none found does.
  assert.equal(evaluate({ ...snap, exportNewestAt: undefined }).some((c) => c.key === "catalog-export-stale"), false);
  assert.equal(evaluate({ ...snap, exportNewestAt: null }).some((c) => c.key === "catalog-export-stale"), true);
});

// ---- catalog.js ----

test("catalogue readings are SELECTs only, and read the oldest due rows", async () => {
  for (const s of Object.values(SQL)) assert.match(s, /^SELECT /);
  const e = env();
  outbox(e.CATALOG, "x_new", "post", T0 - 1 * MIN);
  outbox(e.CATALOG, "x_old", "post", T0 - 40 * MIN);
  outbox(e.CATALOG, "x_future", "post", T0 + 10 * MIN);
  outbox(e.CATALOG, "v1", "verify", T0 - 2 * HOUR);
  outbox(e.CATALOG, "d1", "dead", T0);
  e.CATALOG.db.prepare("INSERT INTO provider_health(provider_id, cooldown_until, last_failure_reason) VALUES ('p1', ?, 'login')").run(T0 + HOUR);
  const s = await readSnapshot(e, T0);
  assert.deepEqual(s.errors, []);
  assert.deepEqual(s.postHead, { id: "x_old", nextAt: T0 - 40 * MIN });
  assert.equal(s.verifyHead.nextAt, T0 - 2 * HOUR);
  assert.equal(s.releaseHead, null);
  assert.equal(s.deadRows, 1);
  assert.deepEqual(s.providers, [{ id: "p1", coolingUntil: T0 + HOUR, reason: "login" }]);
  assert.ok(e.CATALOG.log.includes(SQL.scrub));
  for (const sql of e.CATALOG.log) assert.match(sql, /^SELECT /, "catalogue is never written");
  // The head reading rides the outbox_due index.
  const plan = e.CATALOG.db.prepare(`EXPLAIN QUERY PLAN ${SQL.head}`).all("post", T0);
  assert.match(plan.map((r) => r.detail).join(" "), /USING (COVERING )?INDEX outbox_due/);
});

test("a fresh scrub state raises no scrub condition", async () => {
  const e = env();
  const r = await tick(e, T0);
  assert.deepEqual(r.conditions, []);
  assert.deepEqual(r.snap.scrub, {
    runs: 0, checked: 0, unrecoverable: 0, stalled: 0,
    lastRunAt: null, lastUnrecoverableAt: null, lastIncidentAt: null, incident: [],
  });
  assert.ok(figures(r.snap).includes("scrub: runs 0, checked 0, unrecoverable 0, stalled 0, breaker on: none, last run: never"));
});

test("scrub unrecoverable alerts at once within its window", async () => {
  const e = env();
  e.CATALOG.db.prepare("UPDATE scrub_state SET unrecoverable = 2, last_unrecoverable_at = ? WHERE id = 1")
    .run(T0 - 6 * HOUR);
  const s = await readSnapshot(e, T0);
  const [c] = evaluate(s, e);
  assert.equal(c.key, "scrub-unrecoverable");
  assert.equal(c.forMs, 0);
  assert.match(c.detail, /6\.0 h ago.*2 finding/);
  assert.match(c.detail, /clears when no re-check has found an unrecoverable extent for 6\.0 h/);
  assert.ok(c.detail.includes("Check the digest's unrecoverable total and run SELECT id FROM extents WHERE scrub_result = 'unrecoverable'"));
  assert.deepEqual(evaluate({ ...s, now: T0 + 1 }, e), []);
  assert.deepEqual(evaluate(s, { SCRUB_UNRECOVERABLE_WINDOW_SECS: "3600" }), []);
});

test("scrub unrecoverable uses a one-hour floor even with a zero window", async () => {
  const e = env({ SCRUB_UNRECOVERABLE_WINDOW_SECS: "0" });
  e.CATALOG.db.prepare("UPDATE scrub_state SET last_unrecoverable_at = ? WHERE id = 1").run(T0 - 30 * MIN);
  const s = await readSnapshot(e, T0);
  assert.deepEqual(evaluate(s, e).map((c) => c.key), ["scrub-unrecoverable"]);
  assert.deepEqual(evaluate({ ...s, now: T0 + 30 * MIN + 1 }, e), []);
});

test("scrub breaker alerts with the affected backbones", async () => {
  const e = env();
  const update = e.CATALOG.db.prepare("UPDATE scrub_state SET last_incident = ?, last_incident_at = ? WHERE id = 1");
  update.run('["highwinds"]', T0 - HOUR);
  const [c] = evaluate(await readSnapshot(e, T0), e);
  assert.equal(c.key, "scrub-incident");
  assert.equal(c.forMs, 0);
  assert.match(c.detail, /highwinds/);
  assert.ok(c.detail.includes(`Repairs there are held to one a run (last trip ${new Date(T0 - HOUR).toISOString()}).`));
  update.run('["highwinds"]', null);
  const [unknown] = evaluate(await readSnapshot(e, T0), e);
  assert.match(unknown.detail, /\(last trip unknown\)/);
  for (const raw of [null, "[]", "not json", "{}", '["highwinds", 3]']) {
    update.run(raw, T0 - HOUR);
    assert.deepEqual(evaluate(await readSnapshot(e, T0), e), [], String(raw));
  }
});

test("scrub stopped is opt-in and needs an old or missing run", async () => {
  const e = env();
  const update = e.CATALOG.db.prepare("UPDATE scrub_state SET last_run_at = ? WHERE id = 1");
  update.run(T0 - 2 * HOUR);
  assert.deepEqual(evaluate(await readSnapshot(e, T0), e), []);
  e.SCRUB_STALE_SECS = "3600";
  for (const [lastRunAt, detail] of [[T0 - 2 * HOUR, /2\.0 h ago/], [null, /never ran/]]) {
    update.run(lastRunAt);
    const [c] = evaluate(await readSnapshot(e, T0), e);
    assert.equal(c.key, "scrub-stopped");
    assert.equal(c.forMs, 0);
    assert.match(c.detail, detail);
    assert.match(c.detail, /threshold 1\.0 h/);
  }
  update.run(T0 - HOUR);
  assert.deepEqual(evaluate(await readSnapshot(e, T0), e), []);
  assert.deepEqual(evaluate(await readSnapshot(e, T0 + 1), e).map((c) => c.key), ["scrub-stopped"]);
});

test("scrub stopped detects the missing table or row when enabled", async () => {
  for (const sql of ["DROP TABLE scrub_state", "DELETE FROM scrub_state"]) {
    const e = env();
    e.CATALOG.db.exec(sql);
    const r = await tick(e, T0);
    assert.deepEqual(r.conditions, []);
    assert.deepEqual(r.snap.errors, []);
    assert.equal(r.snap.scrub, null);
    assert.equal(r.snap.scrubMissing, true);
    assert.ok(figures(r.snap).includes("scrub: not deployed (no scrub_state)"));
    e.SCRUB_STALE_SECS = "3600";
    const enabled = await tick(e, T0 + 5 * MIN);
    assert.deepEqual(enabled.conditions, ["scrub-stopped"]);
    assert.ok(e.ALERT_EMAIL.sent[0].text.includes("The catalogue has no scrub_state (migration 0023 not applied) while SCRUB_STALE_SECS is set."));
  }
  const e = env({ CATALOG: undefined, SCRUB_STALE_SECS: "3600" });
  assert.deepEqual((await tick(e, T0)).conditions, []);
});

test("a failed reading is named, the others still count", async () => {
  const e = env();
  e.CATALOG.db.exec("DROP TABLE provider_health");
  const s = await readSnapshot(e, T0);
  assert.equal(s.errors.length, 1);
  assert.match(s.errors[0], /^provider health/);
  assert.equal(s.deadRows, 0);
});

test("newest export reads only manifests of the last three days", async () => {
  const p = "d1/velmora-catalog/";
  const b = new FakeBucket([
    `${p}${T0 - 10 * 86_400_000}.manifest.json`,
    `${p}${T0 - 30 * HOUR}.manifest.json`,
    `${p}${T0 - 5 * HOUR}.sql.zst.part-000`, // no manifest: incomplete
  ]);
  assert.equal(await newestExport(b, T0), T0 - 30 * HOUR);
  assert.equal(await newestExport(new FakeBucket([]), T0), null);
});

// ---- store.js ----

test("one email per key per hour, then backing off while it holds", async () => {
  const db = new FakeD1().applyDir(MIG);
  const a = { key: "cron:x", source: "cron", severity: "page", title: "t", detail: "d" };
  let row = await store.observe(db, a, T0);
  assert.ok(await store.claimSend(db, row, T0));
  row = await store.observe(db, a, T0 + 5 * MIN);
  assert.equal(await store.claimSend(db, row, T0 + 5 * MIN), null, "within the hour");
  row = await store.observe(db, a, T0 + HOUR);
  const c2 = await store.claimSend(db, row, T0 + HOUR);
  assert.ok(c2, "an hour later");
  assert.equal(c2.covered, 2, "covers the reports since the last email");
  row = await store.observe(db, a, T0 + 2 * HOUR);
  assert.equal(await store.claimSend(db, row, T0 + 2 * HOUR), null, "second reminder waits 2 h");
  row = await store.observe(db, a, T0 + 3 * HOUR);
  assert.ok(await store.claimSend(db, row, T0 + 3 * HOUR));
  assert.equal(store.reminderGap(10), store.DAY, "capped at a day");
});

test("a condition that clears and comes back emails again, not within the hour", async () => {
  const db = new FakeD1().applyDir(MIG);
  const a = { key: "cron:x", source: "cron", severity: "page", title: "t", detail: "d" };
  let row = await store.observe(db, a, T0);
  await store.claimSend(db, row, T0);
  await store.resolveCron(db, [], T0 + 10 * MIN);
  row = await store.observe(db, a, T0 + 20 * MIN);
  assert.equal(row.active_since, T0 + 20 * MIN, "a new active run");
  assert.equal(row.sent_in_run, 0);
  assert.equal(await store.claimSend(db, row, T0 + 20 * MIN), null, "an hour after the last email at the soonest");
  row = await store.observe(db, a, T0 + HOUR);
  assert.ok(await store.claimSend(db, row, T0 + HOUR));
});

test("forMs: no email until the condition held that long", async () => {
  const db = new FakeD1().applyDir(MIG);
  const a = { key: "cron:p", source: "cron", severity: "page", title: "t", detail: "d" };
  let row = await store.observe(db, a, T0);
  assert.equal(await store.claimSend(db, row, T0, { forMs: 15 * MIN }), null);
  row = await store.observe(db, a, T0 + 15 * MIN);
  assert.ok(await store.claimSend(db, row, T0 + 15 * MIN, { forMs: 15 * MIN }));
});

test("daily cap, info severity, and giving a claim back", async () => {
  const db = new FakeD1().applyDir(MIG);
  for (let i = 0; i < 3; i++) {
    const row = await store.observe(db, { key: `k${i}`, source: "host", title: "t", detail: "d" }, T0);
    const ok = await store.claimSend(db, row, T0, { dailyCap: 2 });
    assert.equal(Boolean(ok), i < 2);
  }
  const info = await store.observe(db, { key: "i", source: "host", severity: "info", title: "t", detail: "d" }, T0);
  assert.equal(await store.claimSend(db, info, T0), null, "info is digest-only");
  const row = await store.observe(db, { key: "u", source: "host", title: "t", detail: "d" }, T0);
  const c = await store.claimSend(db, row, T0);
  await store.unclaimSend(db, c, T0);
  const again = await store.observe(db, { key: "u", source: "host", title: "t", detail: "d" }, T0 + MIN);
  assert.equal(again.last_sent_at, null);
  assert.equal(again.sent_in_run, 0);
  assert.ok(await store.claimSend(db, again, T0 + MIN), "retried on the next tick");
});

test("event alerts expire after two hours without a report, never before their email", async () => {
  const db = new FakeD1().applyDir(MIG);
  const row = await store.observe(db, { key: "host:a", source: "host", title: "t", detail: "d" }, T0);
  await store.expireEvents(db, T0 + 3 * HOUR);
  assert.equal((await db.prepare("SELECT active FROM alerts").first()).active, 1, "not emailed yet: kept");
  assert.ok(await store.claimSend(db, row, T0 + 3 * HOUR));
  await store.observe(db, { key: "host:a", source: "host", title: "t", detail: "d" }, T0 + 3 * HOUR);
  await store.claimSend(db, row, T0 + 3 * HOUR); // held: inside the hour; seen_unsent stays 1
  await db.prepare("UPDATE alerts SET seen_unsent = 0").run(); // as if its email went out
  await store.expireEvents(db, T0 + 4 * HOUR);
  assert.equal((await db.prepare("SELECT active FROM alerts").first()).active, 1, "reported an hour ago");
  await store.expireEvents(db, T0 + 6 * HOUR);
  assert.equal((await db.prepare("SELECT active FROM alerts").first()).active, 0);
});

// ---- index.js ----

test("tick: the first stalled scrub reading is quiet and a rise stays active for six hours", async () => {
  const e = env();
  e.CATALOG.db.exec("UPDATE scrub_state SET stalled = 2 WHERE id = 1");
  const first = await tick(e, T0);
  assert.deepEqual(first.conditions, []);
  assert.equal(first.sent, 0);
  assert.deepEqual(await store.getMeta(e.STATE, "scrub_stalled"), { seen: 2, roseAt: null });
  e.CATALOG.db.exec("UPDATE scrub_state SET stalled = 5 WHERE id = 1");
  const next = await tick(e, T0 + 5 * MIN);
  assert.deepEqual(next.conditions, ["scrub-stalled"]);
  assert.equal(next.sent, 1);
  assert.equal(e.ALERT_EMAIL.sent[0].subject, "[velmora] Scrub repair stalled");
  assert.ok(e.ALERT_EMAIL.sent[0].text.includes(
    "A scrub repair is still pinned in R2 at its bound (the stalled total rose 0 min ago; 5 in all): verify could not make every backbone hold the extent again. " +
    "The scrub-stalled line in the S3 Worker log says whether the safety copy is intact, written again or missing; the extent's outbox row is in stage verify. " +
    "This alert clears 6.0 h after the last rise.",
  ));
  assert.deepEqual(await store.getMeta(e.STATE, "scrub_stalled"), { seen: 5, roseAt: T0 + 5 * MIN });
  const same = await tick(e, T0 + 10 * MIN);
  assert.deepEqual(same.conditions, ["scrub-stalled"]);
  assert.equal(e.ALERT_EMAIL.sent.length, 1);
  const row = e.STATE.prepare("SELECT active FROM alerts WHERE key = 'scrub-stalled'");
  assert.equal((await row.first()).active, 1);
  const end = T0 + 5 * MIN + 6 * HOUR;
  assert.deepEqual((await tick(e, end)).conditions, ["scrub-stalled"]);
  assert.deepEqual((await tick(e, end + 1)).conditions, []);
  assert.equal((await row.first()).active, 0);
});

test("tick: a lower stalled scrub total lowers seen and allows a later rise to alert", async () => {
  const e = env();
  e.CATALOG.db.exec("UPDATE scrub_state SET stalled = 5 WHERE id = 1");
  await tick(e, T0);
  e.CATALOG.db.exec("UPDATE scrub_state SET stalled = 2 WHERE id = 1");
  const lower = await tick(e, T0 + 5 * MIN);
  assert.deepEqual(lower.conditions, []);
  assert.equal(lower.sent, 0);
  assert.deepEqual(await store.getMeta(e.STATE, "scrub_stalled"), { seen: 2, roseAt: null });
  e.CATALOG.db.exec("UPDATE scrub_state SET stalled = 3 WHERE id = 1");
  const rise = await tick(e, T0 + 10 * MIN);
  assert.deepEqual(rise.conditions, ["scrub-stalled"]);
  assert.equal(rise.sent, 1);
  assert.deepEqual(await store.getMeta(e.STATE, "scrub_stalled"), { seen: 3, roseAt: T0 + 10 * MIN });
  e.CATALOG.db.exec("UPDATE scrub_state SET stalled = 2 WHERE id = 1");
  assert.equal((await tick(e, T0 + 15 * MIN)).sent, 0);
  assert.deepEqual(await store.getMeta(e.STATE, "scrub_stalled"), { seen: 2, roseAt: T0 + 10 * MIN });
});

test("tick: a failed scrub-stalled email is retried on the next tick", async () => {
  const e = env();
  await tick(e, T0);
  e.CATALOG.db.exec("UPDATE scrub_state SET stalled = 1 WHERE id = 1");
  e.ALERT_EMAIL.fail = "E_RECIPIENT_NOT_ALLOWED";
  const failed = await tick(e, T0 + 5 * MIN);
  assert.deepEqual(failed.conditions, ["scrub-stalled"]);
  assert.equal(failed.sendFailures, 1);
  assert.equal(e.ALERT_EMAIL.sent.length, 0);
  assert.deepEqual(await store.getMeta(e.STATE, "scrub_stalled"), { seen: 1, roseAt: T0 + 5 * MIN });
  e.ALERT_EMAIL.fail = null;
  const retried = await tick(e, T0 + 10 * MIN);
  assert.deepEqual(retried.conditions, ["scrub-stalled"]);
  assert.equal(retried.sent, 1);
  assert.deepEqual(await store.getMeta(e.STATE, "scrub_stalled"), { seen: 1, roseAt: T0 + 5 * MIN });
});

test("tick: hourly scrub stalls keep one active run and back off emails", async () => {
  const e = env();
  await tick(e, T0 - 5 * MIN);
  const update = e.CATALOG.db.prepare("UPDATE scrub_state SET stalled = ? WHERE id = 1");
  const sentAt = [];
  for (let hour = 0; hour < 12; hour++) {
    update.run(hour + 1);
    const now = T0 + hour * HOUR;
    const rise = await tick(e, now);
    assert.deepEqual(rise.conditions, ["scrub-stalled"]);
    if (rise.sent) sentAt.push(hour);
    assert.deepEqual(await store.getMeta(e.STATE, "scrub_stalled"), { seen: hour + 1, roseAt: now });
    assert.deepEqual((await tick(e, now + 5 * MIN)).conditions, ["scrub-stalled"]);
  }
  assert.deepEqual(sentAt, [0, 1, 3, 7]);
  assert.equal(e.ALERT_EMAIL.sent.length, 4);
});

test("tick: a zero stalled window is floored at one hour", async () => {
  const e = env({ SCRUB_STALLED_WINDOW_SECS: "0" });
  await tick(e, T0 - 5 * MIN);
  e.CATALOG.db.exec("UPDATE scrub_state SET stalled = 1 WHERE id = 1");
  assert.equal((await tick(e, T0)).sent, 1);
  assert.deepEqual((await tick(e, T0 + HOUR)).conditions, ["scrub-stalled"]);
  assert.deepEqual((await tick(e, T0 + HOUR + 1)).conditions, []);
});

test("tick: a failed scrub reading keeps scrub keys and the last stalled total", async () => {
  const e = env({ SCRUB_STALE_SECS: "3600" });
  e.CATALOG.db.prepare("UPDATE scrub_state SET stalled = 2, last_unrecoverable_at = ?, last_incident = ? WHERE id = 1")
    .run(T0, '["highwinds"]');
  await tick(e, T0);
  e.CATALOG.db.exec("UPDATE scrub_state SET stalled = 3 WHERE id = 1");
  const active = await tick(e, T0 + 5 * MIN);
  assert.deepEqual(active.conditions, ["scrub-unrecoverable", "scrub-incident", "scrub-stalled", "scrub-stopped"]);
  e.CATALOG.db.exec("ALTER TABLE scrub_state RENAME COLUMN stalled TO old_stalled");
  const r = await tick(e, T0 + 10 * MIN);
  assert.deepEqual(r.conditions, ["check-error"]);
  assert.equal(r.snap.errors.length, 1);
  assert.match(r.snap.errors[0], /^scrub state: no such column: stalled/);
  assert.equal(r.snap.scrubMissing, false);
  assert.ok(figures(r.snap).includes("scrub: could not read"));
  assert.deepEqual(await store.getMeta(e.STATE, "scrub_stalled"), { seen: 3, roseAt: T0 + 5 * MIN });
  for (const key of active.conditions) {
    const row = await e.STATE.prepare("SELECT active FROM alerts WHERE key = ?1").bind(key).first();
    assert.equal(row.active, 1, key);
  }
});

test("tick: a missing scrub table leaves the stalled metadata unchanged", async () => {
  const e = env();
  await store.setMeta(e.STATE, "scrub_stalled", { seen: 3, roseAt: T0 });
  e.CATALOG.db.exec("DROP TABLE scrub_state");
  const result = await tick(e, T0 + 5 * MIN);
  assert.equal(result.snap.scrubMissing, true);
  assert.deepEqual(await store.getMeta(e.STATE, "scrub_stalled"), { seen: 3, roseAt: T0 });
});

test("tick: a stalled post head emails once after 30 + 30 min, then clears", async () => {
  const e = env();
  outbox(e.CATALOG, "x1", "post", T0 - 31 * MIN);
  let r = await tick(e, T0);
  assert.deepEqual(r.conditions, [], "first reading has nothing to compare");
  r = await tick(e, T0 + 5 * MIN);
  assert.deepEqual(r.conditions, ["posting-stalled"]);
  assert.equal(e.ALERT_EMAIL.sent.length, 0, "held only 0 min");
  for (let t = 10; t <= 35; t += 5) await tick(e, T0 + t * MIN);
  assert.equal(e.ALERT_EMAIL.sent.length, 1);
  const m = e.ALERT_EMAIL.sent[0];
  assert.equal(m.subject, "[velmora] Posting stalled");
  assert.equal(m.to, "operator@example.invalid");
  assert.equal(m.from.email, "alerts@example.invalid");
  // The head moves: resolved, no more email.
  e.CATALOG.db.exec("UPDATE outbox SET stage = 'verify', next_at = next_at + 99999999 WHERE extent_id = 'x1'");
  r = await tick(e, T0 + 40 * MIN);
  assert.deepEqual(r.conditions, []);
  const row = await e.STATE.prepare("SELECT active FROM alerts WHERE key = 'posting-stalled'").first();
  assert.equal(row.active, 0);
});

test("tick: dead-letter batches raise the DLQ alert; the queue handler acks", async () => {
  const e = env();
  let acked = false;
  await worker.queue({ queue: "velmora-dlq", messages: [{ body: { extent: "x1" } }, { body: "b" }], ackAll: () => (acked = true) }, e);
  assert.ok(acked);
  const r = await tick(e, Date.now());
  assert.ok(r.conditions.includes("dlq"));
  assert.match(e.ALERT_EMAIL.sent[0].text, /2 job message/);
});

test("tick: export bucket is listed hourly and its reading is kept between", async () => {
  const b = new FakeBucket([`d1/velmora-catalog/${T0 - 30 * HOUR}.manifest.json`]);
  const e = env({ EXPORTS: b });
  let r = await tick(e, T0);
  assert.ok(r.conditions.includes("catalog-export-stale"));
  r = await tick(e, T0 + 5 * MIN);
  assert.ok(r.conditions.includes("catalog-export-stale"), "held between listings");
  assert.equal(b.lists, 1);
  await tick(e, T0 + HOUR);
  assert.equal(b.lists, 2);
});

test("tick: a failed email is retried on the next tick", async () => {
  const e = env();
  outbox(e.CATALOG, "d", "dead", T0);
  e.ALERT_EMAIL.fail = "E_RECIPIENT_NOT_ALLOWED";
  await tick(e, T0);
  assert.equal(e.ALERT_EMAIL.sent.length, 0);
  e.ALERT_EMAIL.fail = null;
  await tick(e, T0 + 5 * MIN);
  assert.equal(e.ALERT_EMAIL.sent.length, 1);
});

test("tick: a failed reading keeps only its own keys, and alerts after 15 min", async () => {
  const e = env();
  outbox(e.CATALOG, "d", "dead", T0);
  e.CATALOG.db.prepare("INSERT INTO provider_health(provider_id, cooldown_until) VALUES ('p1', ?)").run(T0 + 9 * HOUR);
  await tick(e, T0);
  e.CATALOG.db.exec("DROP TABLE provider_health");
  e.CATALOG.db.exec("DELETE FROM outbox");
  const r = await tick(e, T0 + 5 * MIN);
  assert.deepEqual(r.conditions, ["check-error"]);
  const get = async (k) => (await e.STATE.prepare("SELECT active FROM alerts WHERE key = ?1").bind(k).first()).active;
  assert.equal(await get("provider-cooldown:p1"), 1, "its reading failed: kept");
  assert.equal(await get("outbox-dead"), 0, "its reading worked: cleared");
  await tick(e, T0 + 20 * MIN);
  assert.ok(e.ALERT_EMAIL.sent.some((m) => m.subject === "[velmora] Alert checks could not read"));
});

test("failing: most of the soonest rows with 3+ attempts, held 30 min", async () => {
  const base = { now: T0, deadRows: 0, dlqLastHour: 0, providers: [], errors: [] };
  assert.deepEqual(evaluate({ ...base, attempts: { post: [0, 1, 0, 4], verify: [] } }), []);
  assert.deepEqual(evaluate({ ...base, attempts: { post: [5, 5], verify: [] } }), [], "too few rows");
  const c = evaluate({ ...base, attempts: { post: [3, 7, 0, 4], verify: [9, 9, 9] } });
  assert.deepEqual(c.map((x) => x.key), ["post-failing", "verify-failing"]);
  assert.equal(c[0].forMs, 30 * MIN);
  // End to end: post rows that fail cleanly move their next_at every time.
  const e = env();
  for (let i = 0; i < 5; i++) {
    e.CATALOG.db
      .prepare("INSERT INTO outbox(extent_id, generation_id, stage, next_at, attempts, updated_at) VALUES (?, 'g', 'post', ?, 6, 0)")
      .run(`x${i}`, T0 + (i + 1) * MIN);
  }
  for (let t = 0; t <= 30; t += 5) await tick(e, T0 + t * MIN);
  assert.ok(e.ALERT_EMAIL.sent.some((m) => m.subject === "[velmora] Posting keeps failing"));
});

test("a second event report inside the hour is emailed once the hour is up", async () => {
  const e = env();
  const a = { source: "ci", key: "deploy-failed", title: "Production deploy failed", detail: "commit a" };
  await ingest(req(a), e, T0);
  await ingest(req({ ...a, detail: "commit b" }), e, T0 + 10 * MIN);
  assert.equal(e.ALERT_EMAIL.sent.length, 1);
  await tick(e, T0 + 30 * MIN);
  assert.equal(e.ALERT_EMAIL.sent.length, 1, "still inside the hour");
  await tick(e, T0 + 61 * MIN);
  assert.equal(e.ALERT_EMAIL.sent.length, 2);
  assert.match(e.ALERT_EMAIL.sent[1].text, /commit b/);
  await tick(e, T0 + 66 * MIN);
  assert.equal(e.ALERT_EMAIL.sent.length, 2, "nothing new to send");
});

test("cap reached: one notice a day", async () => {
  const e = env({ DAILY_EMAIL_CAP: "2" });
  for (const k of ["a", "b", "c"]) await ingest(req({ source: "host", key: k, title: k }), e, T0);
  assert.equal(e.ALERT_EMAIL.sent.length, 2);
  await tick(e, T0 + MIN);
  await tick(e, T0 + 6 * MIN);
  const notices = e.ALERT_EMAIL.sent.filter((m) => m.subject === "[velmora] Alert email cap reached");
  assert.equal(notices.length, 1);
});

test("heartbeat reports failure when an email cannot be sent", async () => {
  const e = env({ HEARTBEAT_URL: "https://hb.example.invalid/x" });
  outbox(e.CATALOG, "d", "dead", T0);
  e.ALERT_EMAIL.fail = "E_RECIPIENT_NOT_ALLOWED";
  const pinged = [];
  const realFetch = globalThis.fetch;
  const realErr = console.error;
  globalThis.fetch = async (u) => (pinged.push(String(u)), new Response(""));
  const logged = [];
  console.error = (m) => logged.push(m);
  try {
    const waits = [];
    await worker.scheduled({ cron: "*/5 * * * *", scheduledTime: T0 }, e, { waitUntil: (p) => waits.push(p) });
    await Promise.all(waits);
  } finally {
    globalThis.fetch = realFetch;
    console.error = realErr;
  }
  assert.deepEqual(pinged, ["https://hb.example.invalid/x/fail"]);
  assert.ok(logged.every((m) => !m.includes("@")), "no address in logs");
});

function req(body, token = "test-ingest-token") {
  return new Request("https://alerts.example.invalid/v1/alert", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

test("ingest: auth, validation, dedupe", async () => {
  const e = env();
  const a = { source: "host", key: "run48:not-ok", title: "run48 check failed", detail: "x" };
  assert.equal((await ingest(req(a, "wrong"), e, T0)).status, 401);
  assert.equal((await ingest(req({ ...a, key: "Bad Key!" }), e, T0)).status, 400);
  assert.equal((await ingest(req({ ...a, source: "cron" }), e, T0)).status, 400, "cannot pose as a cron check");
  let r = await (await ingest(req(a), e, T0)).json();
  assert.deepEqual(r, { key: "host:run48:not-ok", emailed: true });
  r = await (await ingest(req(a), e, T0 + MIN)).json();
  assert.equal(r.emailed, false, "deduped within the hour");
  r = await (await ingest(req({ ...a, key: "x", severity: "info" }), e, T0)).json();
  assert.equal(r.emailed, false, "info goes to the digest");
  assert.equal(e.ALERT_EMAIL.sent.length, 1);
  const big = await ingest(req({ ...a, key: "big", detail: "x".repeat(20_000) }), e, T0);
  assert.equal(big.status, 413);
  r = await (await ingest(req({ ...a, key: "crlf", title: "a\r\nBcc: x" }), e, T0)).json();
  const row = await e.STATE.prepare("SELECT title FROM alerts WHERE key = 'host:crlf'").first();
  assert.equal(row.title, "a Bcc: x");
  const none = env({ INGEST_TOKEN: undefined });
  assert.equal((await ingest(req(a), none, T0)).status, 401, "no token configured: closed");
});

test("fetch: health and unknown paths", async () => {
  const e = env();
  assert.equal(await (await worker.fetch(new Request("https://a.invalid/"), e)).text(), "ok\n");
  assert.equal((await worker.fetch(new Request("https://a.invalid/x"), e)).status, 404);
});

test("digest lists what holds, what cleared and the figures", async () => {
  const e = env();
  outbox(e.CATALOG, "v", "verify", T0 - 20 * HOUR);
  await tick(e, T0);
  await store.observe(e.STATE, { key: "host:n", source: "host", severity: "info", title: "Version changed outside CI", detail: "d" }, T0);
  await digest(e, T0 + MIN);
  const m = e.ALERT_EMAIL.sent.at(-1);
  assert.equal(m.subject, "[velmora] Daily digest: 1 problem(s)");
  assert.match(m.text, /Verify backlog is old/);
  assert.match(m.text, /Version changed outside CI/);
  assert.match(m.text, /oldest due verify row: 20\.0 h/);
  const quiet = env();
  await digest(quiet, T0);
  assert.equal(quiet.ALERT_EMAIL.sent[0].subject, "[velmora] Daily digest: all clear");
});

test("scheduled routes the digest cron and pings the heartbeat", async () => {
  const e = env({ HEARTBEAT_URL: "https://hb.example.invalid/x" });
  const pinged = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (u) => {
    pinged.push(String(u));
    return new Response("");
  };
  try {
    const waits = [];
    await worker.scheduled({ cron: "*/5 * * * *", scheduledTime: T0 }, e, { waitUntil: (p) => waits.push(p) });
    await Promise.all(waits);
    assert.deepEqual(pinged, ["https://hb.example.invalid/x"]);
    await worker.scheduled({ cron: "30 7 * * *", scheduledTime: T0 }, e, { waitUntil: () => {} });
    assert.match(e.ALERT_EMAIL.sent.at(-1).subject, /Daily digest/);
  } finally {
    globalThis.fetch = realFetch;
  }
});

// ---- regressions from review ----

test("an export written as one .sql object counts; split parts alone do not", async () => {
  const p = "d1/velmora-catalog/";
  assert.equal(await newestExport(new FakeBucket([`${p}${T0 - 2 * HOUR}.sql`]), T0), T0 - 2 * HOUR);
  assert.equal(await newestExport(new FakeBucket([`${p}${T0 - 2 * HOUR}.sql.zst.part-000`]), T0), null);
});

test("a verify waiting for propagation (missing-pending) is not a failing job", async () => {
  const e = env();
  for (let i = 0; i < 5; i++) {
    e.CATALOG.db
      .prepare("INSERT INTO outbox(extent_id, generation_id, stage, next_at, attempts, last_error, updated_at) VALUES (?, 'g', 'verify', ?, 4, ?, 0)")
      .run(`v${i}`, T0 + MIN, i < 3 ? "missing-pending" : "provider");
  }
  const s = await readSnapshot(e, T0);
  assert.deepEqual(s.attempts.verify, [0, 0, 0, 4, 4]);
  assert.equal(evaluate(s).some((c) => c.key === "verify-failing"), false);
  const plan = e.CATALOG.db.prepare(`EXPLAIN QUERY PLAN ${SQL.attempts}`).all("verify");
  assert.match(plan.map((r) => r.detail).join(" "), /INDEX outbox_due/, "ordered along the index, no sort");
  assert.doesNotMatch(plan.map((r) => r.detail).join(" "), /TEMP B-TREE/);
});

test("a cooldown with 15 min or more left alerts at once", () => {
  const base = { now: T0, deadRows: 0, dlqLastHour: 0, errors: [] };
  const long = evaluate({ ...base, providers: [{ id: "p1", coolingUntil: T0 + 16 * MIN }] });
  assert.equal(long[0].forMs, 0);
  const short = evaluate({ ...base, providers: [{ id: "p1", coolingUntil: T0 + 13 * MIN }] });
  assert.equal(short[0].forMs, 15 * MIN);
});

test("the email carries the newest report, even if it came after the row was read", async () => {
  const db = new FakeD1().applyDir(MIG);
  const a = { key: "ci:deploy-failed", source: "ci", severity: "page", title: "t", detail: "commit a" };
  const stale = await store.observe(db, a, T0);
  await store.observe(db, { ...a, detail: "commit b" }, T0 + MIN);
  const c = await store.claimSend(db, stale, T0 + MIN);
  assert.equal(c.detail, "commit b");
});

test("reports email once an hour without backoff", async () => {
  const db = new FakeD1().applyDir(MIG);
  const a = { key: "ci:deploy-failed", source: "ci", severity: "page", title: "t", detail: "d" };
  for (let h = 0; h < 5; h++) {
    const row = await store.observe(db, a, T0 + h * HOUR);
    assert.ok(await store.claimSend(db, row, T0 + h * HOUR), `hour ${h}`);
  }
});

test("cap notice: sent when the cap held an email, even if the count dropped before the tick", async () => {
  const e = env({ DAILY_EMAIL_CAP: "1" });
  await ingest(req({ source: "host", key: "a", title: "a" }), e, T0);
  await ingest(req({ source: "host", key: "b", title: "b" }), e, T0 + MIN); // held by the cap
  await tick(e, T0 + store.DAY + 2 * MIN); // the first send has aged out of the window
  assert.ok(e.ALERT_EMAIL.sent.some((m) => m.subject === "[velmora] Alert email cap reached"));
});

test("a redelivered dead-letter batch counts once", async () => {
  const e = env();
  const batch = { queue: "velmora-dlq", messages: [{ id: "m1", body: "x" }, { id: "m2", body: "y" }], ackAll() {} };
  await worker.queue(batch, e);
  await worker.queue(batch, e);
  assert.equal(await store.dlqSince(e.STATE, 0), 2);
});

test("digest: failed readings are said, not shown as all clear", async () => {
  const e = env();
  e.CATALOG.db.exec("DROP TABLE outbox");
  await digest(e, T0);
  const m = e.ALERT_EMAIL.sent[0];
  assert.equal(m.subject, "[velmora] Daily digest: checks could not read");
  assert.match(m.text, /oldest due verify row: could not read/);
});

test("a failed digest is sent again by a later tick, and the heartbeat fails until then", async () => {
  const e = env({ HEARTBEAT_URL: "https://hb.example.invalid/x" });
  const pinged = [];
  const realFetch = globalThis.fetch;
  const realErr = console.error;
  globalThis.fetch = async (u) => (pinged.push(String(u)), new Response(""));
  console.error = () => {};
  const run = async (cron, t) => {
    const waits = [];
    try {
      await worker.scheduled({ cron, scheduledTime: t }, e, { waitUntil: (p) => waits.push(p) });
    } catch {
      // the failed digest run throws
    }
    await Promise.all(waits);
  };
  try {
    await run("30 7 * * *", T0); // first digest works
    e.ALERT_EMAIL.fail = "E_DELIVERY_FAILED";
    await run("30 7 * * *", T0 + store.DAY);
    await run("*/5 * * * *", T0 + store.DAY + 5 * MIN); // retried at once, fails again
    e.ALERT_EMAIL.fail = null;
    await run("*/5 * * * *", T0 + store.DAY + 10 * MIN);
    await run("*/5 * * * *", T0 + store.DAY + 15 * MIN); // sent: no more retries
  } finally {
    globalThis.fetch = realFetch;
    console.error = realErr;
  }
  assert.deepEqual(pinged.slice(1), [
    "https://hb.example.invalid/x/fail",
    "https://hb.example.invalid/x/fail",
    "https://hb.example.invalid/x",
    "https://hb.example.invalid/x",
  ]);
  assert.equal(e.ALERT_EMAIL.sent.filter((m) => /Daily digest/.test(m.subject)).length, 2);
});

test("a first digest that fails is retried by the next tick", async () => {
  const e = env();
  e.ALERT_EMAIL.fail = "E_DELIVERY_FAILED";
  const realErr = console.error;
  console.error = () => {};
  try {
    await assert.rejects(worker.scheduled({ cron: "30 7 * * *", scheduledTime: T0 }, e, { waitUntil() {} }));
    e.ALERT_EMAIL.fail = null;
    await worker.scheduled({ cron: "*/5 * * * *", scheduledTime: T0 + 5 * MIN }, e, { waitUntil() {} });
  } finally {
    console.error = realErr;
  }
  assert.equal(e.ALERT_EMAIL.sent.filter((m) => /Daily digest/.test(m.subject)).length, 1);
});

test("at the cap, a condition not due for its own reminder holds nothing back", async () => {
  const e = env({ DAILY_EMAIL_CAP: "1" });
  outbox(e.CATALOG, "d", "dead", T0);
  await tick(e, T0); // the one email of the day
  await tick(e, T0 + 5 * MIN); // within the key's hour: not due, not held by the cap
  assert.equal(await store.getMeta(e.STATE, "cap_hit_at"), null);
  assert.equal(e.ALERT_EMAIL.sent.filter((m) => /cap reached/.test(m.subject)).length, 0);
});

test("a report's email states the one-hour wait", async () => {
  const e = env();
  const a = { source: "ci", key: "deploy-failed", title: "t" };
  for (let h = 0; h < 3; h++) await ingest(req(a), e, T0 + h * HOUR);
  assert.match(e.ALERT_EMAIL.sent[2].text, new RegExp(`not before ${new Date(T0 + 3 * HOUR).toISOString().replace(".000Z", "Z")}`));
});
