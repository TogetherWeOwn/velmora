// Levels, not incident latches. A healthy row doesn't erase a problem row;
// it ages out of its own window. The walk, not this sample, covers all keys.
const HOUR = 3_600_000;
const PROBLEM_LIMIT = 200;
const unavailable = "COALESCE(json_extract(CASE WHEN json_valid(detail) THEN detail END, '$.counts.unavailable'), 0)";
const firstOf = (kind) => `COALESCE((SELECT at FROM recovery_copy_log WHERE kind = '${kind}' ORDER BY at LIMIT 1), ?1)`;

export const SQL = Object.freeze({
  failing: `SELECT pass FROM recovery_copy_log INDEXED BY recovery_copy_log_problem_at
    WHERE kind = 'job' AND at > ?2 AND at <= ?1 AND problems > 0
    ORDER BY at DESC LIMIT ${PROBLEM_LIMIT}`,
  stale: `SELECT (SELECT at FROM recovery_copy_log INDEXED BY recovery_copy_log_swept_at
      WHERE kind = 'job' AND at > ?2 AND at <= ?1 AND swept = 1 ORDER BY at DESC LIMIT 1) AS sweep_at,
    (SELECT at FROM recovery_copy_log
      WHERE kind = 'walk' AND at > ?3 AND at <= ?1 ORDER BY at DESC LIMIT 1) AS walk_at,
    MIN(${["job", "walk", "audit"].map(firstOf).join(", ")}) AS first_at`,
  audit: `SELECT MAX(problems) AS problems,
      MAX(CASE WHEN at > ?2 AND checked > 0 THEN at END) AS checked_at,
      MAX(CASE WHEN at > ?4 AND checked > ${unavailable} THEN at END) AS readable_at,
      COUNT(DISTINCT CASE WHEN at > ?4 AND checked > 0 AND checked = ${unavailable} THEN pass END) AS unavailable_passes
    FROM recovery_copy_log WHERE kind = 'audit' AND at > ?3 AND at <= ?1`,
});

export async function recoveryConditions(db, now, firstSeen = now) {
  const read = (name, ...bounds) => db.prepare(SQL[name]).bind(now, ...bounds).first();
  const [failing, stale, audit] = await Promise.all([
    db.prepare(SQL.failing).bind(now, now - 6 * HOUR).all(),
    read("stale", now - 2 * HOUR, now - 48 * HOUR),
    read("audit", now - 2 * HOUR, now - 24 * HOUR, now - HOUR),
  ]);
  // Missing history needs a full observation window. Observed problems don't.
  const age = now - Math.min(firstSeen, stale.first_at);
  const out = [];
  const problems = failing.results ?? [];
  const passes = new Set(problems.map(({ pass }) => pass)).size;
  // At the cap we might have hidden another pass, and that much trouble
  // merits a page on its own. Healthy job rows never enter this read.
  if (passes >= 2 || problems.length >= PROBLEM_LIMIT) {
    out.push({
      key: "recovery-copy-failing",
      title: "Offsite recovery copy is failing",
      detail: problems.length >= PROBLEM_LIMIT
        ? `At least ${PROBLEM_LIMIT} jobs in the last 6 h reported a refusal or store failure.`
        : `${passes} copy passes in the last 6 h reported a refusal or store failure.`,
    });
  }
  const sweepStale = age >= 2 * HOUR && stale.sweep_at == null;
  const walkStale = age >= 48 * HOUR && stale.walk_at == null;
  if (sweepStale || walkStale) {
    const notes = [];
    if (sweepStale) notes.push("No fresh sweep completed in the last 2 h.");
    else if (stale.sweep_at != null) notes.push(`Last fresh sweep: ${new Date(stale.sweep_at).toISOString()}.`);
    if (walkStale) notes.push("No walk completed in the last 48 h.");
    out.push({ key: "recovery-copy-stale", title: "Offsite recovery copy is stale", detail: notes.join(" ") });
  }
  const notes = [];
  if (audit.problems > 0) notes.push("An audit in the last 24 h found missing, different or refused records.");
  if (age >= 2 * HOUR && audit.checked_at == null) notes.push("No audit checked any records in the last 2 h.");
  if (age >= HOUR && audit.readable_at == null && audit.unavailable_passes >= 2) {
    notes.push("Audit GETs were unavailable in multiple passes, with no usable result in the last hour.");
  }
  if (notes.length) {
    out.push({ key: "recovery-copy-audit", title: "Offsite recovery copy audit needs attention", detail: notes.join(" ") });
  }
  return out;
}
