// Alert state on the Worker's own D1 (binding STATE): dedupe, the
// per-key rate limit, the daily cap, and what the digest reports.

export const HOUR = 3_600_000;
export const DAY = 24 * HOUR;
// Event alerts (host, ci) have no "still holds" signal: one that has not
// been reported again for this long counts as resolved.
export const EVENT_TTL = 2 * HOUR;

export async function getMeta(db, k) {
  const r = await db.prepare("SELECT v FROM meta WHERE k = ?1").bind(k).first();
  return r ? JSON.parse(r.v) : null;
}

export async function setMeta(db, k, v) {
  await db
    .prepare("INSERT INTO meta(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v")
    .bind(k, JSON.stringify(v))
    .run();
}

/**
 * Records that `a` holds now. A key that was not active starts a new
 * active run (active_since = now). Returns the row after the update.
 */
export async function observe(db, a, now) {
  return db
    .prepare(
      "INSERT INTO alerts(key, source, severity, title, detail, active, active_since, last_seen_at, seen_unsent) " +
        "VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6, ?6, 1) " +
        "ON CONFLICT(key) DO UPDATE SET source = excluded.source, severity = excluded.severity, " +
        "  title = excluded.title, detail = excluded.detail, " +
        "  active_since = CASE WHEN alerts.active = 1 THEN alerts.active_since ELSE ?6 END, " +
        "  sent_in_run = CASE WHEN alerts.active = 1 THEN alerts.sent_in_run ELSE 0 END, " +
        "  active = 1, last_seen_at = ?6, seen_unsent = alerts.seen_unsent + 1 " +
        "RETURNING key, source, severity, title, detail, active_since, last_seen_at, last_sent_at, seen_unsent, sent_in_run",
    )
    .bind(a.key, a.source, a.severity ?? "page", a.title, a.detail, now)
    .first();
}

/**
 * Marks cron keys that did not hold in this tick as resolved, except those
 * for which `keep(key)` is true (their reading failed this tick).
 */
export async function resolveCron(db, activeKeys, now, keep = () => false) {
  const rows = (
    await db.prepare("SELECT key FROM alerts WHERE source = 'cron' AND active = 1").all()
  ).results;
  const held = new Set(activeKeys);
  const gone = rows.map((r) => r.key).filter((k) => !held.has(k) && !keep(k));
  for (const k of gone) {
    await db
      .prepare("UPDATE alerts SET active = 0, resolved_at = ?2, seen_unsent = 0 WHERE key = ?1")
      .bind(k, now)
      .run();
  }
  return gone;
}

/** Event alerts (host, ci) reported again after their last email: retried by the tick. */
export async function unsentEvents(db) {
  return (
    await db
      .prepare(
        "SELECT key, source, severity, title, detail, active_since, last_seen_at, last_sent_at, seen_unsent, sent_in_run " +
          "FROM alerts WHERE source <> 'cron' AND active = 1 AND severity = 'page' AND seen_unsent > 0",
      )
      .all()
  ).results ?? [];
}

/** Resolves event alerts not reported for EVENT_TTL. */
export async function expireEvents(db, now) {
  await db
    .prepare(
      "UPDATE alerts SET active = 0, resolved_at = ?1, seen_unsent = 0 " +
        "WHERE source <> 'cron' AND active = 1 AND last_seen_at < ?2",
    )
    .bind(now, now - EVENT_TTL)
    .run();
}

export async function sentSince(db, since, kind = "alert") {
  const r = await db
    .prepare("SELECT count(*) AS n FROM sends WHERE at >= ?1 AND kind = ?2")
    .bind(since, kind)
    .first();
  return Number(r?.n ?? 0);
}

/**
 * The wait before the next email of an active run that has sent `sentInRun`
 * emails: none before the first, then 1 h, 2 h, 4 h ... up to 24 h. A new
 * active run (the condition cleared and came back) starts at the first again,
 * but never sooner than an hour after the last email for the key.
 */
export function reminderGap(sentInRun) {
  if (sentInRun <= 0) return HOUR;
  return Math.min(DAY, HOUR * 2 ** (sentInRun - 1));
}

/**
 * Claims the right to email for this key now: at most one email per key
 * per hour (less often while it keeps holding), and none past the daily cap. The claim is one conditional
 * UPDATE, so a cron tick and a report racing for the same key send once.
 * Returns the claimed row (with the number of reports it covers), or null.
 */
export async function claimSend(db, row, now, { forMs = 0, dailyCap = 30 } = {}) {
  if (row.severity !== "page") return null;
  if (now - Number(row.active_since) < forMs) return null;
  if ((await sentSince(db, now - DAY)) >= dailyCap) return null;
  const claimed = await db
    .prepare(
      "UPDATE alerts SET last_sent_at = ?2, seen_unsent = 0 " +
        "  , sent_in_run = sent_in_run + 1 " +
        "WHERE key = ?1 AND active = 1 AND (last_sent_at IS NULL OR last_sent_at <= ?3) " +
        "RETURNING key, last_sent_at",
    )
    .bind(row.key, now, now - reminderGap(Number(row.sent_in_run ?? 0)))
    .first();
  if (!claimed) return null;
  await db.prepare("INSERT INTO sends(at, key, kind) VALUES (?1, ?2, 'alert')").bind(now, row.key).run();
  return { ...row, covered: Number(row.seen_unsent), prevSentAt: row.last_sent_at ?? null };
}

/** Gives a claim back after the email could not be sent. */
export async function unclaimSend(db, claim, now) {
  await db
    .prepare("UPDATE alerts SET last_sent_at = ?2, seen_unsent = seen_unsent + ?3, sent_in_run = max(sent_in_run - 1, 0) " +
        "WHERE key = ?1 AND last_sent_at = ?4")
    .bind(claim.key, claim.prevSentAt, claim.covered, now)
    .run();
  await db.prepare("DELETE FROM sends WHERE key = ?1 AND at = ?2 AND kind = 'alert'").bind(claim.key, now).run();
}

export async function recordDlq(db, queue, count, sample, now) {
  await db
    .prepare("INSERT INTO dlq(at, queue, count, sample) VALUES (?1, ?2, ?3, ?4)")
    .bind(now, queue, count, sample)
    .run();
}

export async function dlqSince(db, since) {
  const r = await db.prepare("SELECT coalesce(sum(count), 0) AS n FROM dlq WHERE at >= ?1").bind(since).first();
  return Number(r?.n ?? 0);
}

export async function prune(db, now) {
  await db.prepare("DELETE FROM sends WHERE at < ?1").bind(now - 8 * DAY).run();
  await db.prepare("DELETE FROM dlq WHERE at < ?1").bind(now - 30 * DAY).run();
}

/** What the daily digest lists. */
export async function digestData(db, now) {
  const since = now - DAY;
  const all = async (sql, ...p) => (await db.prepare(sql).bind(...p).all()).results ?? [];
  return {
    active: await all(
      "SELECT key, severity, title, detail, active_since, last_sent_at FROM alerts WHERE active = 1 ORDER BY active_since",
    ),
    resolved: await all(
      "SELECT key, title, resolved_at FROM alerts WHERE active = 0 AND resolved_at >= ?1 ORDER BY resolved_at",
      since,
    ),
    info: await all(
      "SELECT key, title, detail, last_seen_at FROM alerts WHERE severity = 'info' AND last_seen_at >= ?1 ORDER BY last_seen_at",
      since,
    ),
    emailsSent: await sentSince(db, since),
    dlq24h: await dlqSince(db, since),
    dlqSample: (await db.prepare("SELECT sample FROM dlq WHERE at >= ?1 ORDER BY at DESC LIMIT 1").bind(since).first())
      ?.sample,
  };
}
