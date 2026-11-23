// Read recovery copy observations from CATALOG, independently of the bridge cron.
import { getMeta, setMeta } from "./store.js";

const MINUTE = 60_000;
const ALARM_MS = 30 * MINUTE;
const STALE_MS = 120 * MINUTE;
const PROBLEM = "recovery-copy-problem";
const STALE = "recovery-copy-stale";
export const READING = "recovery copy";
export const SQL = `SELECT last_problem_at, problem_operation, problem_kind, problem_status,
  problem_code, problem_counts, opened_at, last_clean_sweep_at, last_clean_walk_start,
  last_verified_write_at FROM recovery_alarm_state WHERE id = 1`;

function minutes(ms) {
  return `${Math.max(0, Math.floor(ms / MINUTE))} min`;
}

function age(at, now) {
  return at > 0 ? `${minutes(now - at)} ago` : "not recorded";
}

function timeDetail(state, now) {
  return `Last clean sweep: ${age(state?.last_clean_sweep_at, now)}. ` +
    `Last verified copy: ${age(state?.last_verified_write_at, now)}.`;
}

function problemDetail(state, now) {
  const detail = [`Latest problem: ${state.problem_operation} ${state.problem_kind} ` +
    `(status=${state.problem_status ?? "—"}, code=${state.problem_code ?? "—"}), ${age(state.last_problem_at, now)}.`];
  if (state.problem_counts) {
    const c = JSON.parse(state.problem_counts);
    detail.push(`Observed job: copied=${c.copied} pending=${c.pending} source_unreadable=${c.source_unreadable} ` +
      `refused_put=${c.refused_put.count} refused_verify=${c.refused_verify.count} ` +
      `refused_plan=${c.refused_plan.count} unsignable=${c.unsignable.count}.`);
  }
  return detail.join(" ");
}

export async function readRecovery(env, now) {
  if (!env.CATALOG || env.RECOVERY_ALARM === "off") return null;
  const state = await env.CATALOG.prepare(SQL).first();
  let lastClean = state?.last_clean_sweep_at || 0;
  if (!lastClean) {
    let started = await getMeta(env.STATE, "recovery_started");
    if (started == null) {
      started = now;
      await setMeta(env.STATE, "recovery_started", started);
    }
    lastClean = state?.opened_at ? Math.min(started, state.opened_at) : started;
  }

  const conditions = [];
  if (state?.opened_at && now - state.opened_at > ALARM_MS) {
    conditions.push({
      key: PROBLEM, title: "Recovery copy problems persist", forMs: 0,
      detail: `Open for ${minutes(now - state.opened_at)}. ${problemDetail(state, now)} ${timeDetail(state, now)}`,
    });
  }
  const stale = now - lastClean > STALE_MS;
  if (stale) {
    conditions.push({
      key: STALE, title: "Recovery copy clean sweep is stale", forMs: 0,
      detail: `No clean sweep in ${minutes(now - lastClean)}. ${timeDetail(state, now)}` +
        (state?.opened_at ? ` ${problemDetail(state, now)}` : ""),
    });
  }
  return { conditions, state, stale };
}

/** Only a proved clean walk recovers destination problems. */
export async function recoveryNotices(env, reading, now, sendNotice) {
  const keep = new Set();
  const results = [];
  if (!reading) return { keep, results };
  const { state, stale } = reading;
  for (const [key, recovered, title] of [
    [PROBLEM, state && !state.opened_at && state.last_clean_walk_start > state.last_problem_at,
      "Recovery copy recovered"],
    [STALE, state?.last_clean_sweep_at && !stale, "Recovery copy clean sweeps resumed"],
  ]) {
    const row = await env.STATE.prepare("SELECT sent_in_run, active_since FROM alerts WHERE key = ?1 AND active = 1")
      .bind(key).first();
    if (!row) continue;
    if (!recovered || (key === STALE && state.last_clean_sweep_at < row.active_since)) {
      keep.add(key);
    } else if (row.sent_in_run > 0) {
      const result = await sendNotice({ key: `${key}-recovered`, title, detail: timeDetail(state, now) });
      results.push(result);
      if (result !== "sent") keep.add(key);
    }
  }
  return { keep, results };
}
