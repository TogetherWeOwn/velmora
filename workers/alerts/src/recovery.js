// Read copy observations from CATALOG, independently of the bridge cron.
import { getMeta, setMeta } from "./store.js";

const MINUTE = 60_000;
const PASS_MS = 15 * MINUTE; // copy::PASS_INTERVAL_MS
const REFUSED = "recovery-copy-refused";
const STALE = "recovery-copy-stale";
export const READING = "recovery copy";
const OPERATIONS = ["put", "verify", "plan"];
const COUNTS = ["copied", "pending", "source_unreadable", "unsignable"];

export const SQL = {
  state: `SELECT last_job_at, last_refused_at, last_verified_write_at, opened_at, last_refused_pass
    FROM recovery_alarm_state WHERE id = 1`,
  jobs: `SELECT copied, pending, source_unreadable, unsignable,
    refused_put, put_status, put_code, refused_verify, verify_status, verify_code,
    refused_plan, plan_status, plan_code
    FROM recovery_pass_job WHERE pass_id = ?1 ORDER BY at, message_id LIMIT 256`,
};

function summary(jobs) {
  const pass = {};
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

function verifiedAge(verified, now) {
  return `Last verified copy: ${verified > 0 ? minutes(now - verified) + " ago" : "not recorded"}.`;
}

function detail(pass, verified, now) {
  const counts = ["copied", "pending", "source_unreadable"].map((k) => `${k}=${pass[k]}`);
  for (const op of OPERATIONS) {
    const key = `refused_${op}`;
    const { count, status, code } = pass[key];
    counts.push(`${key}=${count} (status=${status ?? "—"}, code=${code ?? "—"})`);
  }
  counts.push(`unsignable=${pass.unsignable} (no HTTP request sent)`);
  return `${counts.join(" ")}. ${verifiedAge(verified, now)}`;
}

export async function readRecovery(env, now) {
  if (!env.CATALOG || env.RECOVERY_ALARM === "off") return null;
  const db = env.CATALOG;
  const state = await db.prepare(SQL.state).first();
  let started = await getMeta(env.STATE, "recovery_started");
  if (started == null) {
    started = now;
    await setMeta(env.STATE, "recovery_started", started);
  }

  const stale = now - (state?.last_job_at ?? started) > 3 * PASS_MS;
  const verified = state?.last_verified_write_at ?? 0;
  const refused = state?.last_refused_at ?? 0;
  const open = refused > verified;
  const conditions = [];
  if (open && now - state.opened_at > 2 * PASS_MS) {
    const { results } = await db.prepare(SQL.jobs).bind(state.last_refused_pass).all();
    const report = results.length ? `Pass ${state.last_refused_pass} observed jobs: ${detail(summary(results), verified, now)}`
      : `Pass summary not retained. ${verifiedAge(verified, now)}`;
    conditions.push({
      key: REFUSED, title: "Recovery copy refused", forMs: 0,
      detail: `Refusals without a subsequent verified write for ${minutes(now - state.opened_at)}. ` +
        `Latest refusal: ${minutes(now - refused)} ago. ${report}`,
    });
  }
  if (stale) {
    conditions.push({
      key: STALE, title: "Recovery copy job telemetry is stale", forMs: 0,
      detail: `No scheduled copy job recorded in ${minutes(now - (state?.last_job_at ?? started))}. ` +
        verifiedAge(verified, now),
    });
  }
  return { conditions, lastJob: state?.last_job_at, verified, refused, open, stale };
}

/** A recovery notice is due only if the matching incident actually paged. */
export async function recoveryNotices(env, reading, now, sendNotice) {
  const keep = new Set();
  const results = [];
  if (!reading) return { keep, results };
  for (const [key, recovered, title] of [
    [REFUSED, !reading.open && reading.verified > reading.refused, "Recovery copy recovered"],
    [STALE, reading.lastJob && !reading.stale, "Recovery copy job telemetry resumed"],
  ]) {
    const row = await env.STATE.prepare("SELECT sent_in_run, active_since FROM alerts WHERE key = ?1 AND active = 1")
      .bind(key).first();
    if (!row) continue;
    // A verified write can reach storage after paging while having
    // happened before the email. Compare it to the refusal, not the email.
    if (!recovered || (key === STALE && reading.lastJob < row.active_since)) {
      keep.add(key);
    } else if (row.sent_in_run > 0) {
      const result = await sendNotice({ key: `${key}-recovered`, title, detail: verifiedAge(reading.verified, now) });
      results.push(result);
      if (result !== "sent") keep.add(key);
    }
  }
  return { keep, results };
}
