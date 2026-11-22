// Cheap readings of the S3 Worker's catalogue (D1) and export bucket (R2).
//
// Read-only: every statement here is a SELECT (a test holds it to that),
// and each reads a handful of rows along an existing index:
//   - the oldest due row of a stage: outbox_due (stage, next_at), 1 row;
//   - dead rows: outbox_due, at most DEAD_CAP rows (normally none);
//   - provider_health: one row per provider that ever failed (a few).
//   - the attempts of the 20 soonest rows of a stage: outbox_due, 20 rows.
// Measured against production: 0 to 20 rows read per statement.

export const DEAD_CAP = 1000;

export const SQL = Object.freeze({
  head:
    "SELECT extent_id, next_at FROM outbox WHERE stage = ?1 AND next_at <= ?2 " +
    "ORDER BY next_at LIMIT 1",
  dead: `SELECT count(*) AS n FROM (SELECT 1 FROM outbox WHERE stage = 'dead' LIMIT ${DEAD_CAP})`,
  providers: "SELECT provider_id, cooldown_until, last_failure_reason FROM provider_health",
  // The attempts of the 20 soonest rows of a stage, due or not: a row that
  // fails is put back with a later next_at, so when every attempt fails
  // the soonest rows carry high counts too. Healthy production: 0 or 1.
  // Ordered along outbox_due; reads the 20 table rows (attempts and
  // last_error are not in the index).
  attempts: "SELECT attempts, last_error FROM outbox WHERE stage = ?1 ORDER BY next_at LIMIT 20",
});

// Complete exports: d1/<database>/<restore point ms>.sql (one object, as
// workers/s3-bridge/ops/catalog-export.sh writes it) or
// d1/<database>/<restore point ms>.manifest.json (a split export, whose
// manifest is written last; its parts alone are an incomplete export).
export const EXPORT_PREFIX = "d1/velmora-catalog/";

async function head(db, stage, now) {
  const r = await db.prepare(SQL.head).bind(stage, now).first();
  return r ? { id: String(r.extent_id), nextAt: Number(r.next_at) } : null;
}

/** Newest complete export time (ms) among the recent ones; null when none. */
export async function newestExport(bucket, now, prefix = EXPORT_PREFIX) {
  // Keys sort by their 13-digit ms, so listing from three days back reads
  // a few keys, however many exports have piled up before that.
  const startAfter = `${prefix}${String(now - 3 * 86_400_000).padStart(13, "0")}`;
  let newest = null;
  let cursor;
  do {
    const page = await bucket.list({ prefix, startAfter, cursor, limit: 1000 });
    for (const o of page.objects) {
      const m = /^(\d{13})\.(?:manifest\.json|sql)$/.exec(o.key.slice(prefix.length));
      if (m) newest = Math.max(newest ?? 0, Number(m[1]));
    }
    // "More to come" with no cursor is an error, never the end: a
    // listing that stopped there could miss the newest export.
    if (page.truncated && !page.cursor) throw new Error("list: more to come and no cursor");
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);
  return newest;
}

/**
 * Takes the readings. A reading that fails is left out and named in
 * `errors`; the others still count.
 * opts.checkExport: list the export bucket this tick (hourly is enough).
 */
export async function readSnapshot(env, now, opts = {}) {
  const snap = {
    now,
    postHead: null,
    verifyHead: null,
    releaseHead: null,
    deadRows: 0,
    providers: [],
    attempts: { post: [], verify: [] },
    errors: [],
  };
  const db = env.CATALOG;
  if (db) {
    const tries = [
      ["post head", async () => (snap.postHead = await head(db, "post", now))],
      ["verify head", async () => (snap.verifyHead = await head(db, "verify", now))],
      ["release head", async () => (snap.releaseHead = await head(db, "release", now))],
      ...["post", "verify"].map((stage) => [
        `${stage} attempts`,
        async () => {
          const r = await db.prepare(SQL.attempts).bind(stage).all();
          // A verify that finds articles not yet propagated is put back as
          // a failure (missing-pending) and counts an attempt: that is a
          // scheduled wait, not a failing job.
          snap.attempts[stage] = (r.results ?? []).map((x) =>
            x.last_error === "missing-pending" ? 0 : Number(x.attempts),
          );
        },
      ]),
      ["dead rows", async () => (snap.deadRows = Number((await db.prepare(SQL.dead).first())?.n ?? 0))],
      [
        "provider health",
        async () => {
          const r = await db.prepare(SQL.providers).all();
          snap.providers = (r.results ?? []).map((p) => ({
            id: String(p.provider_id),
            coolingUntil: Number(p.cooldown_until ?? 0),
            reason: p.last_failure_reason ? String(p.last_failure_reason).slice(0, 120) : null,
          }));
        },
      ],
    ];
    for (const [name, f] of tries) {
      try {
        await f();
      } catch (e) {
        snap.errors.push(`${name}: ${String(e?.message ?? e).slice(0, 160)}`);
      }
    }
  }
  if (env.EXPORTS && opts.checkExport) {
    try {
      snap.exportNewestAt = await newestExport(env.EXPORTS, now);
    } catch (e) {
      snap.errors.push(`export list: ${String(e?.message ?? e).slice(0, 160)}`);
    }
  }
  return snap;
}
