import assert from "node:assert/strict";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";

import { tick } from "../src/index.js";
import { SQL } from "../src/recovery.js";
import { FakeD1, FakeEmail } from "./d1.js";

const MIN = 60_000;
const HOUR = 60 * MIN;
const T0 = Date.UTC(2026, 0, 1);
const FAILING = "recovery-copy-failing";
const STALE = "recovery-copy-stale";
const AUDIT = "recovery-copy-audit";

function fixture() {
  const dir = (url) => fileURLToPath(new URL(url, import.meta.url));
  const env = {
    STATE: new FakeD1().applyDir(dir("../migrations/")),
    CATALOG: new FakeD1().applyDir(dir("../../s3-bridge/migrations/")),
    ALERT_EMAIL: new FakeEmail(),
    ALERT_EMAIL_TO: "operator@example.invalid",
    ALERT_FROM: "alerts@example.invalid",
  };
  const insert = env.CATALOG.db.prepare(
    "INSERT INTO recovery_copy_log(at, kind, pass, swept, problems, checked, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
  );
  const row = (kind, at, { pass = at, swept = 0, problems = 0, checked = 0, detail = null } = {}) =>
    insert.run(at, kind, pass, swept, problems, checked, detail);
  function healthy(at) {
    row("job", at, { swept: 1 });
    row("walk", at);
    row("audit", at, { checked: 1 });
  }
  return { env, row, healthy, check: (at) => tick(env, at) };
}

function has(result, key) {
  return result.conditions.includes(key);
}

test("one problem pass including retries does not page; two distinct passes do, until the 6 h window expires", async () => {
  const f = fixture();
  f.healthy(T0);
  f.row("job", T0, { problems: 1 });
  f.row("job", T0 + MIN, { pass: T0, problems: 50 });
  assert.equal(has(await f.check(T0 + MIN), FAILING), false);
  f.row("job", T0 + 15 * MIN, { problems: 1 });
  assert.equal(has(await f.check(T0 + 15 * MIN), FAILING), true);
  assert.equal(f.env.ALERT_EMAIL.sent.length, 1);
  f.healthy(T0 + 6 * HOUR + 2 * MIN);
  assert.equal(has(await f.check(T0 + 6 * HOUR + 2 * MIN), FAILING), false);
  assert.equal(f.env.ALERT_EMAIL.sent.length, 1, "no recovered email");
});

test("four passes copying other keys cannot hide one persistent 403", async () => {
  const f = fixture();
  for (const at of [T0, T0 + 3 * HOUR]) f.row("job", at, { problems: 1 });
  for (let i = 1; i <= 4; i++) {
    const at = T0 + 3 * HOUR + i * 15 * MIN;
    f.healthy(at);
    f.row("job", at, { checked: 10, detail: '{"copied":10}' });
  }
  const now = T0 + 4 * HOUR;
  assert.equal(has(await f.check(now), FAILING), true);
});

test("idle jobs and per-record retryable failures do not trigger the refusal alarm", async () => {
  const f = fixture();
  f.healthy(T0);
  for (let i = 0; i < 4; i++) f.row("job", T0 + i * MIN, { detail: '{"failed":10}' });
  assert.equal(has(await f.check(T0 + 4 * MIN), FAILING), false);
});

test("a new walk cannot refresh the 2 h sweep window, and a sweep cannot refresh the 48 h walk window", async () => {
  const f = fixture();
  f.healthy(T0);
  assert.equal(has(await f.check(T0 + 2 * HOUR - 1), STALE), false);
  f.row("walk", T0 + 2 * HOUR);
  assert.equal(has(await f.check(T0 + 2 * HOUR), STALE), true);
  f.row("job", T0 + 50 * HOUR - 1, { swept: 1 });
  assert.equal(has(await f.check(T0 + 50 * HOUR - 1), STALE), false);
  assert.equal(has(await f.check(T0 + 50 * HOUR), STALE), true);
});

test("an audit mismatch remains active for 24 h; 2 h with no checks pages; unavailable alone does not", async () => {
  const f = fixture();
  f.healthy(T0);
  f.row("audit", T0, { checked: 1, problems: 1 });
  assert.equal(has(await f.check(T0), AUDIT), true);
  const before = T0 + 24 * HOUR - 1;
  f.healthy(before);
  f.row("audit", before + 1, { checked: 1, detail: '{"unavailable":1}' });
  assert.equal(has(await f.check(before), AUDIT), true);
  assert.equal(has(await f.check(before + 1), AUDIT), false);
  assert.equal(has(await f.check(before + 1 + 2 * HOUR), AUDIT), true);
});

const unavailable = { checked: 5, detail: '{"counts":{"unavailable":5}}' };

test("a persistent GET-only 503 pages within 60 min while copier jobs are healthy", async () => {
  const f = fixture();
  f.healthy(T0);
  assert.equal(has(await f.check(T0), AUDIT), false);
  for (const minutes of [15, 30, 45, 60]) {
    const at = T0 + minutes * MIN;
    f.row("job", at, { swept: 1 });
    // The sampler's fallback can turn a missed tenant probe into one
    // checked-but-unavailable flat record (the Rust sampler test).
    f.row("audit", at, minutes > 30 ? { checked: 1, detail: '{"counts":{"unavailable":1}}' } : unavailable);
    const checked = await f.check(at);
    assert.equal(has(checked, FAILING), false);
    assert.equal(has(checked, AUDIT), minutes === 60);
  }
});

test("a single 503 does not page, even if no further audit runs by the hour", async () => {
  const f = fixture();
  f.healthy(T0);
  f.row("audit", T0 + 15 * MIN, unavailable);
  assert.equal(has(await f.check(T0 + 15 * MIN), AUDIT), false);
  assert.equal(has(await f.check(T0 + HOUR), AUDIT), false);
});

test("an empty log waits from first seen before missing history can page", async () => {
  const f = fixture();
  assert.deepEqual((await f.check(T0)).conditions, []);
  assert.equal(f.env.ALERT_EMAIL.sent.length, 0);
  assert.deepEqual((await f.check(T0 + 2 * HOUR - 1)).conditions, []);
  const expired = await f.check(T0 + 2 * HOUR);
  assert.ok(has(expired, STALE) && has(expired, AUDIT));
  for (const at of [T0 + 48 * HOUR - 1, T0 + 48 * HOUR]) {
    f.row("job", at, { swept: 1 });
    f.row("audit", at, { checked: 1 });
    assert.equal(has(await f.check(at), STALE), at === T0 + 48 * HOUR);
  }
});

test("successful empty audits during the quiet-upload sampling gap do not page", async () => {
  const f = fixture();
  f.healthy(T0); // Final recent sample, four hours after the upload.
  const empty = { detail: '{"counts":{"checked":0,"source_errors":0}}' };
  for (let hour = 1; hour <= 44; hour++) {
    const at = T0 + hour * HOUR;
    f.row("job", at, { swept: 1 });
    f.row("audit", at, empty);
    assert.equal(has(await f.check(at), AUDIT), false, `hour ${hour}`);
  }
  const deadline = T0 + 46 * HOUR;
  f.row("job", deadline, { swept: 1 });
  for (const detail of [null, "invalid JSON", '{"counts":{"checked":0,"source_errors":1}}']) {
    f.row("audit", deadline, { detail });
    assert.equal(has(await f.check(deadline), AUDIT), true, "failed or unknown runs do not count as clean");
  }
});

test("a mismatch during startup can page before the missing-history thresholds", async () => {
  const f = fixture();
  f.row("audit", T0, { checked: 1, problems: 1 });
  assert.deepEqual((await f.check(T0)).conditions, [AUDIT]);
});

test("a new failure seven hours after the last page sends its own first email", async () => {
  const f = fixture();
  for (const at of [T0, T0 + 7 * HOUR]) {
    if (at !== T0) {
      f.healthy(T0 + 6 * HOUR);
      assert.equal(has(await f.check(T0 + 6 * HOUR), FAILING), false);
    }
    f.healthy(at);
    f.row("job", at - 15 * MIN, { problems: 1 });
    f.row("job", at, { problems: 1 });
    assert.equal(has(await f.check(at), FAILING), true);
    assert.equal(f.env.ALERT_EMAIL.sent.length, at === T0 ? 1 : 2);
  }
});

test("a usable comparison clears and suppresses the GET-only condition after startup", async () => {
  const f = fixture();
  f.healthy(T0 - 49 * HOUR);
  f.healthy(T0);
  for (const minutes of [15, 30, 45, 60]) f.row("audit", T0 + minutes * MIN, unavailable);
  assert.equal(has(await f.check(T0 + HOUR), AUDIT), true);
  f.row("audit", T0 + 65 * MIN, { checked: 1, detail: '{"counts":{"equal":1,"unavailable":0}}' });
  assert.equal(has(await f.check(T0 + 65 * MIN), AUDIT), false);
  f.row("audit", T0 + 75 * MIN, unavailable);
  assert.equal(has(await f.check(T0 + 75 * MIN), AUDIT), false);
});

test("62 h of 403 for writes and reads pages within 35 min and reminds at most once per day", async () => {
  const f = fixture();
  f.healthy(T0);
  const onset = T0 + 1;
  const first = new Map();
  const pages = new Map();
  for (let delta = 5 * MIN; delta <= 62 * HOUR; delta += 5 * MIN) {
    const at = T0 + delta;
    if (delta % (15 * MIN) === 0) f.row("job", at, { problems: 52, swept: 1 });
    if (delta % (15 * MIN) === 5 * MIN) f.row("audit", at, { checked: 15, problems: 15 });
    const result = await f.check(at);
    for (const key of result.conditions) if (!first.has(key)) first.set(key, at);
    if (result.sent) {
      for (const { key, last_sent_at } of f.env.STATE.db.prepare("SELECT key, last_sent_at FROM alerts WHERE last_sent_at = ?").all(at)) {
        const times = pages.get(key) ?? [];
        times.push(last_sent_at);
        pages.set(key, times);
      }
    }
  }
  for (const [key, max] of [[FAILING, 35], [AUDIT, 20]]) {
    assert.ok(first.get(key) - onset <= max * MIN, key);
    assert.equal(pages.get(key).length, 3, key);
    assert.equal(pages.get(key)[1] - pages.get(key)[0], 24 * HOUR, key);
    assert.equal(pages.get(key)[2] - pages.get(key)[1], 24 * HOUR, key);
  }
});

for (const op of ["put", "verify", "plan", "list"]) {
  for (const status of [403, 503]) {
    test(`${op} ${status} for three days pages when the job reports a store problem`, async () => {
      const f = fixture();
      for (const day of [0, 1, 2]) {
        const at = T0 + day * 24 * HOUR;
        f.healthy(at);
        f.row("job", at - 15 * MIN, { problems: 1, detail: JSON.stringify({ first: { op, status } }) });
        f.row("job", at, { problems: 1, detail: JSON.stringify({ first: { op, status } }) });
        assert.equal(has(await f.check(at), FAILING), true);
      }
      assert.equal(f.env.ALERT_EMAIL.sent.length, 3);
    });
  }
}

test("pruning catches up after a seven-day gap in batches of at most 1000", (t) => {
  const f = fixture();
  const db = f.env.CATALOG.db;
  const prune = readFileSync(new URL("../../s3-bridge/src/recovery_log_prune.sql", import.meta.url), "utf8");
  const cutoff = T0 - 7 * 24 * HOUR;
  f.env.CATALOG.exec("BEGIN");
  for (let n = 1; n <= 30_240; n++) f.row("job", cutoff - n * 20_000);
  f.row("walk", cutoff - 1);
  f.row("audit", cutoff - 1);
  f.healthy(cutoff);
  f.env.CATALOG.exec("COMMIT");
  const plan = db.prepare(`EXPLAIN QUERY PLAN ${prune}`).all(cutoff).map((r) => r.detail);
  assert.ok(plan.some((s) => s.includes("USING COVERING INDEX recovery_copy_log_kind_at (kind=? AND at<?)")), plan.join("; "));
  assert.ok(!plan.some((s) => s.includes("TEMP B-TREE")), plan.join("; "));
  const counts = Array.from({length: 32}, () => db.prepare(prune).run(cutoff).changes);
  assert.deepEqual(counts, [...Array(30).fill(1000), 242, 0]);
  assert.equal(db.prepare("SELECT count(*) AS n FROM recovery_copy_log WHERE at >= ?").get(cutoff).n, 3);
  assert.equal(db.prepare("SELECT count(*) AS n FROM recovery_copy_log WHERE at < ?").get(cutoff).n, 0);
  t.diagnostic(`prune: ${plan.join("; ")}; removed 30,242 expired rows in 31 capped batches`);
});

test("indexed SQLite dry run at one job per two seconds, healthy and saturated", async (t) => {
  const f = fixture();
  f.env.CATALOG.exec("BEGIN");
  for (let n = 1; n <= 7 * 96; n++) {
    const pass = T0 - n * 15 * MIN;
    if (n <= 24) for (let j = 1; j <= 450; j++) f.row("job", pass + j * 2000, { pass });
    f.row("audit", pass + 5 * MIN, { pass, checked: n === 1 ? 1 : 0 });
    if (n % 96 === 0) f.row("walk", pass + MIN, { pass });
  }
  f.env.CATALOG.exec("COMMIT");
  const db = f.env.CATALOG.db;
  const failing = [T0, T0 - 6 * HOUR];
  const stale = [T0, T0 - 2 * HOUR, T0 - 48 * HOUR];
  for (const [name, params, index] of [
    ["failing", failing, "recovery_copy_log_problem_at"],
    ["stale", stale, "recovery_copy_log_swept_at"],
    ["audit", [T0, T0 - 2 * HOUR, T0 - 24 * HOUR, T0 - HOUR], "recovery_copy_log_kind_at"],
  ]) {
    const steps = db.prepare(`EXPLAIN QUERY PLAN ${SQL[name]}`).all(...params).map((r) => r.detail);
    assert.ok(steps.some((s) => s.includes(`INDEX ${index}`) && s.includes("at>? AND at<?")), steps.join("; "));
    assert.ok(!steps.some((s) => s.includes("SCAN recovery_copy_log") || s.includes("TEMP B-TREE FOR ORDER BY")), steps.join("; "));
    t.diagnostic(`${name}: ${steps.join("; ")}`);
  }
  const count = db.prepare("SELECT COUNT(*) AS n FROM recovery_copy_log WHERE kind = ? AND at > ? AND at <= ?");
  for (const [kind, hours, n] of [["job", 6, 10_800], ["job", 2, 3600], ["walk", 48, 2], ["audit", 24, 96]]) {
    assert.equal(count.get(kind, T0 - hours * HOUR, T0).n, n);
  }
  const readProblems = db.prepare(SQL.failing);
  assert.equal(readProblems.all(...failing).length, 0, "healthy 10,800-job window reads no problem-index rows");
  assert.equal(db.prepare(SQL.stale).get(...stale).sweep_at, null, "no completed sweep to read");
  db.prepare("UPDATE recovery_copy_log SET swept = 1 WHERE kind = 'job' AND at = ?").run(T0);
  assert.equal(db.prepare(SQL.stale).get(...stale).sweep_at, T0, "one indexed swept row");
  assert.equal(has(await f.check(T0), FAILING), false);
  db.prepare("UPDATE recovery_copy_log SET problems = 1 WHERE kind = 'job' AND pass = ?").run(T0 - 15 * MIN);
  const atLimit = readProblems.all(...failing);
  assert.equal(atLimit.length, 200);
  assert.equal(new Set(atLimit.map((r) => r.pass)).size, 1, "the 200 row cap fails safe even for one pass");
  assert.equal(has(await f.check(T0), FAILING), true);
  t.diagnostic("10,800 jobs in 6 h and 3,600 in 2 h: 0 healthy / 200 saturated problem-index entries; 0 absent / 1 present sweep-index entry; at most 2 walk and 96 audit candidates");
});
