// The cron-checked condition list. Pure: it turns a snapshot of cheap
// readings (see catalog.js) into conditions, and touches no binding.
//
// A condition is { key, title, detail, forMs }. It is "active" in the tick
// that returns it; the store (store.js) remembers since when, and an email
// goes out only once it has been active for forMs without a break.

const MIN = 60_000;
const HOUR = 60 * MIN;

/** Defaults; every one can be overridden by a var of the same name. */
export const DEFAULTS = Object.freeze({
  // A post row that has been due this long, and is still the oldest due
  // post row after as long again, means no post job is finishing.
  POST_STALL_SECS: 1800,
  // The oldest due verify row has waited longer than this.
  VERIFY_BACKLOG_ALERT_SECS: 43200,
  // A provider has been cooling (skipped) for at least this long.
  PROVIDER_COOLDOWN_ALERT_SECS: 900,
  // Dead-letter messages received in the last hour, at least this many.
  DLQ_ALERT_MIN: 1,
  // The newest catalogue export manifest is older than this.
  EXPORT_MAX_AGE_SECS: 26 * 3600,
  // A row with this many attempts in its stage counts as failing.
  FAILING_ATTEMPTS: 3,
});

/** Which reading each check needs (a failed reading leaves its keys as they were). */
export function readingOf(key) {
  if (key === "posting-stalled") return "post head";
  if (key === "verify-backlog") return "verify head";
  if (key === "post-failing") return "post attempts";
  if (key === "verify-failing") return "verify attempts";
  if (key === "outbox-dead") return "dead rows";
  if (key.startsWith("provider-cooldown:")) return "provider health";
  if (key === "catalog-export-stale") return "export list";
  return null;
}

/** Reads a positive integer var, falling back to the default. */
export function setting(env, name) {
  const raw = env?.[name];
  if (raw !== undefined && raw !== null && raw !== "") {
    const n = Number(raw);
    if (Number.isFinite(n) && n >= 0) return n;
  }
  return DEFAULTS[name];
}

function ageText(ms) {
  if (ms < HOUR) return `${Math.round(ms / MIN)} min`;
  return `${(ms / HOUR).toFixed(1)} h`;
}

/**
 * snapshot: {
 *   now,
 *   postHead:   { id, nextAt } | null   oldest due post row
 *   prevPostHead: { id, nextAt } | null the same reading from the tick before
 *   verifyHead: { nextAt } | null       oldest due verify row
 *   releaseHead:{ nextAt } | null       (digest only)
 *   deadRows:   number                  outbox rows in stage 'dead' (capped)
 *   providers:  [{ id, coolingUntil, reason }]
 *   dlqLastHour: number                 dead-letter messages received in the last hour
 *   exportNewestAt: number | null | undefined  ms of the newest export manifest;
 *                                       undefined = not checked (no binding)
 *   errors:     [string]                readings that failed
 * }
 */
export function evaluate(snap, env = {}) {
  const now = snap.now;
  const out = [];

  // Posting stalled: posts are due, and the oldest due post row has been
  // due for POST_STALL_SECS and has not changed since the last tick. A
  // claim does not move next_at, but every way a post job ends (advance,
  // fail, defer) does, and the dispatcher sends the oldest rows first, so
  // with posting going the head changes within minutes even while a large
  // backlog waits. The store's forMs then asks for the same head for
  // POST_STALL_SECS more.
  const stallMs = setting(env, "POST_STALL_SECS") * 1000;
  const head = snap.postHead;
  if (
    head &&
    now - head.nextAt >= stallMs &&
    snap.prevPostHead &&
    snap.prevPostHead.id === head.id &&
    snap.prevPostHead.nextAt === head.nextAt
  ) {
    out.push({
      key: "posting-stalled",
      title: "Posting stalled",
      detail:
        `Posts are due, and the oldest due post row has not moved: due for ${ageText(now - head.nextAt)}. ` +
        "No post job is finishing. Check provider health and the post queues in /_admin/status.",
      forMs: stallMs,
    });
  }

  // Failing: the stall and backlog checks above see a head that moves, and
  // a failed or deferred job moves it too. So also: at least half of the
  // soonest rows of a stage (3 or more rows) have FAILING_ATTEMPTS or more.
  const failAt = setting(env, "FAILING_ATTEMPTS");
  for (const stage of ["post", "verify"]) {
    const a = snap.attempts?.[stage] ?? [];
    const bad = a.filter((n) => n >= failAt).length;
    if (a.length >= 3 && bad * 2 >= a.length) {
      out.push({
        key: `${stage}-failing`,
        title: stage === "post" ? "Posting keeps failing" : "Verifying keeps failing",
        detail:
          `${bad} of the ${a.length} soonest ${stage} rows have ${failAt} or more attempts: ` +
          `${stage} jobs run but do not succeed. Check provider health in /_admin/status, and the ` +
          "rows' last_error in the outbox.",
        forMs: stallMs,
      });
    }
  }

  const verifyMax = setting(env, "VERIFY_BACKLOG_ALERT_SECS") * 1000;
  if (snap.verifyHead && now - snap.verifyHead.nextAt >= verifyMax) {
    out.push({
      key: "verify-backlog",
      title: "Verify backlog is old",
      detail:
        `The oldest due verify row has waited ${ageText(now - snap.verifyHead.nextAt)} ` +
        `(threshold ${ageText(verifyMax)}). Unverified copies stay pinned in R2 until it clears.`,
      forMs: 0,
    });
  }

  const dlqMin = setting(env, "DLQ_ALERT_MIN");
  if (dlqMin > 0 && snap.dlqLastHour >= dlqMin) {
    out.push({
      key: "dlq",
      title: "Dead-letter queue has messages",
      detail:
        `${snap.dlqLastHour} job message(s) reached the dead-letter queue in the last hour ` +
        "(their retries ran out). The dispatcher sends a due row again, so this is a symptom: find the cause.",
      forMs: 0,
    });
  }

  if (snap.deadRows > 0) {
    out.push({
      key: "outbox-dead",
      title: "Outbox rows are dead",
      detail:
        `${snap.deadRows >= 1000 ? "1000 or more" : snap.deadRows} outbox row(s) are in stage 'dead': ` +
        "their attempts ran out and nothing retries them.",
      forMs: 0,
    });
  }

  const coolMs = setting(env, "PROVIDER_COOLDOWN_ALERT_SECS") * 1000;
  for (const p of snap.providers ?? []) {
    if (p.coolingUntil > now) {
      out.push({
        key: `provider-cooldown:${p.id}`,
        title: `Provider ${p.id} cooling down`,
        detail:
          `Provider ${p.id} is skipped (cooling) until ${new Date(p.coolingUntil).toISOString()}` +
          (p.reason ? `; last failure: ${p.reason}` : "") +
          ".",
        // A cooldown with coolMs or more still to run alerts at once;
        // a shorter one alerts once it has held coolMs.
        forMs: p.coolingUntil - now >= coolMs ? 0 : coolMs,
      });
    }
  }

  if (snap.exportNewestAt !== undefined) {
    const maxAge = setting(env, "EXPORT_MAX_AGE_SECS") * 1000;
    if (snap.exportNewestAt === null || now - snap.exportNewestAt > maxAge) {
      out.push({
        key: "catalog-export-stale",
        title: "Catalogue export missing",
        detail:
          snap.exportNewestAt === null
            ? "No complete catalogue export (manifest) was found."
            : `The newest complete catalogue export is ${ageText(now - snap.exportNewestAt)} old ` +
              `(limit ${ageText(maxAge)}). The daily export failed or did not run.`,
        forMs: 0,
      });
    }
  }

  if ((snap.errors ?? []).length > 0) {
    out.push({
      key: "check-error",
      title: "Alert checks could not read",
      detail: `Some readings failed, so their checks did not run: ${snap.errors.join("; ")}`,
      forMs: 15 * MIN,
    });
  }

  return out;
}

/** One-line figures for the daily digest. */
export function figures(snap) {
  const now = snap.now;
  const failed = new Set((snap.errors ?? []).map((e) => e.split(":")[0]));
  const na = (reading, text) => (failed.has(reading) ? "could not read" : text);
  const age = (h) => (h ? ageText(now - h.nextAt) : "none due");
  const lines = [
    `oldest due post row: ${na("post head", age(snap.postHead))}`,
    `oldest due verify row: ${na("verify head", age(snap.verifyHead))}`,
    `oldest due release row: ${na("release head", age(snap.releaseHead))}`,
    `dead outbox rows: ${na("dead rows", snap.deadRows)}`,
    `providers cooling: ${na("provider health", (snap.providers ?? []).filter((p) => p.coolingUntil > now).map((p) => p.id).join(", ") || "none")}`,
  ];
  if (snap.exportNewestAt !== undefined) {
    lines.push(
      `newest catalogue export: ${snap.exportNewestAt === null ? "none" : ageText(now - snap.exportNewestAt) + " old"}`,
    );
  }
  return lines;
}
