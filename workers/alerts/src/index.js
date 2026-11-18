// velmora-alerts: emails the operator when something important breaks.
//
//   scheduled (every 5 min)  cheap checks of the catalogue (catalog.js,
//                            checks.js), then emails what holds
//   scheduled (daily)        the digest
//   queue (dead-letter)      counts what lands in the dead-letter queue
//   POST /v1/alert           reports from the operator host and CI
//                            (bearer INGEST_TOKEN)
//   GET /                    "ok", for an uptime check
//
// It is its own Worker so that a broken S3 Worker cannot silence it, and so
// that changing it never redeploys the S3 Worker.

import { evaluate, figures } from "./checks.js";
import { readSnapshot } from "./catalog.js";
import * as store from "./store.js";
import { alertMessage, digestMessage, send } from "./email.js";

const KEY_RE = /^[a-z0-9][a-z0-9._:-]{0,99}$/;
const SOURCES = new Set(["host", "ci"]);

function dailyCap(env) {
  const n = Number(env.DAILY_EMAIL_CAP);
  return Number.isFinite(n) && n > 0 ? n : 30;
}

/** Emails the alert row if its claim succeeds. Returns true when sent. */
export async function maybeSend(env, row, now, forMs) {
  const claim = await store.claimSend(env.STATE, row, now, { forMs, dailyCap: dailyCap(env) });
  if (!claim) return false;
  try {
    await send(env, alertMessage(claim, now, store.reminderGap(Number(row.sent_in_run ?? 0) + 1)));
    return true;
  } catch (e) {
    await store.unclaimSend(env.STATE, claim, now);
    console.error(`alert email failed for ${row.key}: ${e?.code ?? ""} ${String(e?.message ?? e).slice(0, 200)}`);
    return false;
  }
}

async function heartbeat(env, ok) {
  if (!env.HEARTBEAT_URL) return;
  try {
    await fetch(ok ? env.HEARTBEAT_URL : `${env.HEARTBEAT_URL}/fail`, { method: "POST" });
  } catch {
    // The monitor notices the missing ping.
  }
}

/** One check tick. Exported for tests. */
export async function tick(env, now) {
  const db = env.STATE;
  const prevPostHead = await store.getMeta(db, "post_head");
  // The export bucket is listed once an hour; between, the last reading holds.
  const lastExport = await store.getMeta(db, "export_check");
  const checkExport = !lastExport || now - lastExport.at >= store.HOUR;
  const snap = await readSnapshot(env, now, { checkExport });
  if (env.EXPORTS) {
    if (checkExport && snap.exportNewestAt !== undefined) {
      await store.setMeta(db, "export_check", { at: now, newest: snap.exportNewestAt });
    } else if (!checkExport) {
      snap.exportNewestAt = lastExport.newest;
    }
  }
  snap.prevPostHead = prevPostHead;
  snap.dlqLastHour = await store.dlqSince(db, now - store.HOUR);
  if (!snap.errors.some((e) => e.startsWith("post head"))) {
    await store.setMeta(db, "post_head", snap.postHead);
  }

  const conds = evaluate(snap, env);
  let sent = 0;
  for (const c of conds) {
    const row = await store.observe(db, { ...c, source: "cron", severity: "page" }, now);
    if (await maybeSend(env, row, now, c.forMs)) sent++;
  }
  // A reading that failed hides its condition; nothing is cleared then.
  if (snap.errors.length === 0) await store.resolveCron(db, conds.map((c) => c.key), now);
  await store.expireEvents(db, now);
  await store.prune(db, now);
  return { conditions: conds.map((c) => c.key), sent, snap };
}

export async function digest(env, now) {
  const db = env.STATE;
  const snap = await readSnapshot(env, now, { checkExport: true });
  const d = await store.digestData(db, now);
  const msg = digestMessage(d, env.CATALOG ? figures(snap) : [], now);
  await send(env, msg);
  await db.prepare("INSERT INTO sends(at, key, kind) VALUES (?1, 'digest', 'digest')").bind(now).run();
  await store.setMeta(db, "last_digest", now);
}

function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const x = enc.encode(a);
  const y = enc.encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

const json = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** POST /v1/alert: { key, title, detail?, severity?: "page"|"info", source: "host"|"ci" }. */
export async function ingest(request, env, now) {
  const auth = request.headers.get("authorization") ?? "";
  if (!env.INGEST_TOKEN || !timingSafeEqual(auth, `Bearer ${env.INGEST_TOKEN}`)) {
    return json(401, { error: "unauthorized" });
  }
  let b;
  try {
    b = await request.json();
  } catch {
    return json(400, { error: "body must be JSON" });
  }
  const source = String(b?.source ?? "");
  const key = String(b?.key ?? "").toLowerCase();
  const severity = b?.severity === "info" ? "info" : "page";
  if (!SOURCES.has(source) && source !== "test") return json(400, { error: "source must be host or ci" });
  if (!KEY_RE.test(key)) return json(400, { error: "key: 1-100 of a-z 0-9 . _ : -" });
  if (typeof b?.title !== "string" || b.title.length === 0) return json(400, { error: "title required" });
  const row = await store.observe(
    env.STATE,
    {
      key: `${source}:${key}`,
      source,
      severity,
      title: b.title.slice(0, 200),
      detail: String(b.detail ?? "").slice(0, 4000),
    },
    now,
  );
  const sent = severity === "page" ? await maybeSend(env, row, now, 0) : false;
  return json(200, { key: row.key, emailed: sent });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/") return new Response("ok\n");
    if (request.method === "POST" && url.pathname === "/v1/alert") return ingest(request, env, Date.now());
    return new Response("not found\n", { status: 404 });
  },

  async scheduled(event, env, ctx) {
    const now = event.scheduledTime ?? Date.now();
    if (event.cron === (env.DIGEST_CRON ?? "30 7 * * *")) {
      await digest(env, now);
      return;
    }
    let ok = false;
    try {
      const r = await tick(env, now);
      ok = true;
      console.log(`alerts tick: holding=${r.conditions.join(",") || "none"} emailed=${r.sent}`);
    } finally {
      ctx.waitUntil(heartbeat(env, ok));
    }
  },

  // The dead-letter queue: count it, keep a sample, and acknowledge. Every
  // dead-lettered job's outbox row is still due, and the S3 Worker's
  // dispatcher sends it again, so acknowledging loses no work.
  async queue(batch, env) {
    const now = Date.now();
    let sample = null;
    try {
      const body = batch.messages[0]?.body;
      sample = (typeof body === "string" ? body : JSON.stringify(body) ?? "").slice(0, 300);
    } catch {
      sample = "(unreadable body)";
    }
    await store.recordDlq(env.STATE, batch.queue, batch.messages.length, sample, now);
    batch.ackAll();
  },
};
