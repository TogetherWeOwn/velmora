// Recovery-copy telemetry lives in CATALOG; the independently scheduled
// alerts Worker can see a stale pass even if the copy Worker stops running.
import { DAY, getMeta, setMeta } from "./store.js";

const MINUTE = 60_000;
const STALE_MS = 3 * 15 * MINUTE; // Three copy::PASS_INTERVAL_MS intervals.
const HISTORY_MS = 7 * DAY; // Bridge retention, excluding the last-verified marker.
const REFUSED = "recovery-copy-refused";
const STALE = "recovery-copy-stale";
export const READING = "recovery copy";
const OPERATIONS = ["put", "verify", "plan"];
const COUNTS = ["copied", "pending", "source_unreadable", "failed", "unsignable"];

export const SQL = {
  finals: `SELECT pass_id, job_seq, at FROM recovery_pass_job
    WHERE final = 1 AND pass_id BETWEEN ?1 AND ?2 ORDER BY pass_id DESC LIMIT 4`,
  jobs: `SELECT cursor_tag, next_tag, copied, pending, source_unreadable, failed, unsignable, skipped_sweep,
    refused_put, put_status, put_code, refused_verify, verify_status, verify_code,
    refused_plan, plan_status, plan_code
    FROM recovery_pass_job WHERE pass_id = ?1 AND job_seq BETWEEN 0 AND ?2 ORDER BY job_seq`,
  verified: "SELECT at FROM recovery_pass_job WHERE copied > 0 AND at BETWEEN 1 AND ?1 ORDER BY at DESC LIMIT 1",
};

function summary(final, jobs) {
  const pass = { id: final.pass_id, at: final.at };
  for (const key of COUNTS) pass[key] = jobs.reduce((sum, job) => sum + job[key], 0);
  for (const op of OPERATIONS) {
    const key = `refused_${op}`;
    const last = jobs.findLast((job) => job[key] > 0);
    pass[key] = {
      count: jobs.reduce((sum, job) => sum + job[key], 0),
      status: last?.[`${op}_status`] ?? null,
      code: last?.[`${op}_code`] ?? null,
    };
  }
  return pass;
}

function minutes(ms) {
  return `${Math.max(0, Math.floor(ms / MINUTE))} min`;
}

function detail(pass, verified, now) {
  const counts = ["copied", "pending", "source_unreadable"].map((k) => `${k}=${pass[k]}`);
  for (const op of OPERATIONS) {
    const key = `refused_${op}`;
    const { count, status, code } = pass[key];
    counts.push(`${key}=${count} (status=${status ?? "—"}, code=${code ?? "—"})`);
  }
  counts.push(`unsignable=${pass.unsignable} (no HTTP request sent)`);
  const age = verified == null ? "not recorded" : minutes(now - verified) + " ago";
  return `${counts.join(" ")}. Last verified copy: ${age}.`;
}

const anyRefusal = (pass) => pass && OPERATIONS.some((op) => pass[`refused_${op}`].count > 0);

export async function readRecovery(env, now) {
  if (!env.CATALOG || env.RECOVERY_ALARM === "off") return null;
  const db = env.CATALOG;
  const finals = (await db.prepare(SQL.finals).bind(now - HISTORY_MS, now).all()).results;
  const passes = [];
  for (const final of finals) {
    const { results } = await db.prepare(SQL.jobs).bind(final.pass_id, final.job_seq).all();
    // Continuation enqueue and D1 are separate. A final job can arrive
    // first, but must never make a partial pass eligible for a decision.
    // A pass that skipped its sweep can still supply a verified age.
    if (results.length !== final.job_seq + 1 || results.some((job, i) =>
      job.skipped_sweep || (results[i + 1]?.cursor_tag ?? null) !== job.next_tag)) continue;
    passes.push(summary(final, results));
    if (passes.length === 2) break;
  }
  const verified = (await db.prepare(SQL.verified).bind(now).first())?.at;
  const lastLogged = await getMeta(env.STATE, "recovery_logged_pass");
  for (const pass of passes.slice().reverse()) {
    if (pass.id <= lastLogged) continue;
    console.log(`recovery copy: pass=${pass.id} ${detail(pass, verified, now)}`);
  }
  const [last, previous] = passes;
  if (last && last.id > lastLogged) await setMeta(env.STATE, "recovery_logged_pass", last.id);
  // On first activation, allow the same three intervals as after a pass.
  let started = await getMeta(env.STATE, "recovery_started");
  if (started == null) {
    started = now;
    await setMeta(env.STATE, "recovery_started", started);
  }
  const lastAt = last ? Math.max(last.at, previous?.at ?? last.at) : started;
  const stale = now - lastAt > STALE_MS;
  const conditions = [];
  if (anyRefusal(last) && anyRefusal(previous)) {
    conditions.push({
      key: REFUSED, title: "Recovery copy refused in consecutive passes", forMs: 0,
      detail: `Pass ${last.id}: ${detail(last, verified, now)} Previous pass ${previous.id}: ${detail(previous, verified, now)}`,
    });
  }
  if (stale) {
    conditions.push({
      key: STALE, title: "Recovery copy pass telemetry is stale", forMs: 0,
      detail: last
        ? `No completed pass in ${minutes(now - lastAt)}. ${detail(last, verified, now)}`
        : `No completed pass recorded in ${minutes(now - lastAt)}.`,
    });
  }
  return { conditions, last, verified, clean: last && !anyRefusal(last) && last.unsignable === 0 && last.failed === 0, stale };
}

/** A recovery notice is due only if the matching incident actually paged. */
export async function recoveryNotices(env, reading, now, sendNotice) {
  const keep = new Set();
  const results = [];
  if (!reading) return { keep, results };
  for (const [key, recovered, title] of [
    [REFUSED, reading.clean, "Recovery copy recovered"],
    [STALE, reading.last && !reading.stale, "Recovery copy passes resumed"],
  ]) {
    const row = await env.STATE.prepare("SELECT sent_in_run FROM alerts WHERE key = ?1 AND active = 1").bind(key).first();
    if (!row) continue;
    if (!recovered) {
      // A missing/unsignable pass is not evidence the refusal went away.
      keep.add(key);
    } else if (row.sent_in_run > 0) {
      const result = await sendNotice({
        key: `${key}-recovered`, title,
        detail: `Pass ${reading.last.id}: ${detail(reading.last, reading.verified, now)}`,
      });
      results.push(result);
      if (result !== "sent") keep.add(key);
    }
  }
  return { keep, results };
}
