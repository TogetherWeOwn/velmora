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

import { evaluate, figures, readingOf } from "./checks.js";
import { readSnapshot } from "./catalog.js";
import * as store from "./store.js";
import { alertMessage, digestMessage, send } from "./email.js";

const KEY_RE = /^[a-z0-9][a-z0-9._:-]{0,99}$/;
const MAX_BODY = 16 * 1024;
// Control characters (CR, LF ...) never reach a subject line.
const oneLine = (s) => String(s).replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
const SOURCES = new Set(["host", "ci"]);
// Keep the set finite: an alert can page once per code per hour. Never
// persist caller-provided text, mail addresses, or message metadata.
const MAIL_TITLES = new Map(Object.entries({
  delivery_dlq: "Mail delivery dead-lettered",
  delivery_failed: "Mail delivery exhausted its retries",
  delivery_stuck: "Mail delivery is still retrying",
  restore_skipped: "Mailbox restore skipped deliveries with missing mail",
  backup_stale: "Mailbox backup is stale",
  restore_blocked: "Mailbox restore is blocked",
  backup_conflict: "Mailbox state diverged from its backup",
  holder_confirm_stale: "A published mailbox holder is still unconfirmed",
  holder_source_lost: "A mailbox source object is missing",
  send_invariant: "A send is held after a release invariant failed",
  handoff_stuck: "An internal delivery handoff keeps failing",
  link_reported: "A file link was reported for abuse",
  send_dlq: "Outbound mail queue message dead-lettered",
  send_outage: "The outbound mail provider is unavailable",
  send_unknown_error: "The outbound mail provider returned an unknown error",
  send_ambiguous_cap: "An outbound send reached the ambiguous-result cap",
  send_deadline: "An outbound send reached the provider retry deadline",
  send_held: "An outbound send is held after repeated unfinished attempts",
  send_result_unapplied: "A stored provider acceptance cannot be recorded",
  send_result_stuck: "A stored provider result keeps failing to record",
  send_quota_release: "The send quota object could not release a charge",
  send_quota_failed: "The send quota object could not reserve or confirm a charge",
  send_quota_gate_hit: "A mail account quota gate was reached",
  send_stale_release_failed: "A stale send charge could not be released",
  send_request_invalid: "An outbound request could not be built",
  send_stalled: "An outbound send has stalled",
}).map(([code, title]) => [`mail:${code}`, title]));

function dailyCap(env) {
  const n = Number(env.DAILY_EMAIL_CAP);
  return Number.isFinite(n) && n > 0 ? n : 30;
}

/**
 * Emails the alert row if its claim succeeds: "sent", "failed" (the claim
 * is given back, the next tick retries) or "held" (not due, or capped).
 */
export async function maybeSend(env, row, now, forMs) {
  const claim = await store.claimSend(env.STATE, row, now, { forMs, dailyCap: dailyCap(env) });
  if (!claim) return "held";
  try {
    await send(env, alertMessage(claim, now, store.gapFor(row, Number(row.sent_in_run ?? 0) + 1)));
    return "sent";
  } catch (e) {
    await store.unclaimSend(env.STATE, claim, now);
    // The code only: a provider message may name the recipient.
    console.error(`alert email failed for ${row.key}: ${e?.code ?? e?.name ?? "error"}`);
    return "failed";
  }
}

/**
 * Once the daily cap is reached, one email (outside the cap) says so, at
 * most once a day, so that a new problem is not muted without a word.
 */
async function capNotice(env, now) {
  const db = env.STATE;
  const cap = dailyCap(env);
  // The cap held an email since the last notice (claimSend marks it).
  const hit = await store.getMeta(db, "cap_hit_at");
  const last = await store.getMeta(db, "cap_notice_at");
  if (!hit || (last && hit <= last)) return "held";
  if (last && now - last < store.DAY) return "held";
  try {
    await send(env, {
      subject: "[velmora] Alert email cap reached",
      text:
        `${cap} alert emails went out within 24 h, the daily cap, and at least one more was held back. Further alerts are not emailed ` +
        "until the count drops; they still appear in the daily digest. Something is badly wrong, or an alert is too noisy.",
    });
    await store.setMeta(db, "cap_notice_at", now);
    return "sent";
  } catch (e) {
    console.error(`cap notice failed: ${e?.code ?? e?.name ?? "error"}`);
    return "failed";
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
  const recoveryFirstSeen = env.CATALOG ? await store.getMeta(db, "recovery_copy_first_seen") : null;
  const snap = await readSnapshot(env, now, { checkExport, recoveryFirstSeen: recoveryFirstSeen ?? now });
  if (recoveryFirstSeen == null && snap.recovery !== undefined) {
    await store.setMetaIfAbsent(db, "recovery_copy_first_seen", now);
  }
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
  const results = [];
  for (const c of conds) {
    const row = await store.observe(db, { ...c, source: "cron", severity: "page" }, now);
    results.push(await maybeSend(env, row, now, c.forMs));
  }
  // Reports that came in while their key waited out its hour.
  for (const row of await store.unsentEvents(db)) results.push(await maybeSend(env, row, now, 0));
  results.push(await capNotice(env, now));
  // A reading that failed hides its condition: its keys are not cleared.
  const failed = new Set(snap.errors.map((e) => e.split(":")[0]));
  await store.resolveCron(db, conds.map((c) => c.key), now, (k) => failed.has(readingOf(k)));
  await store.expireEvents(db, now);
  await store.prune(db, now);
  if (env.MAIL_ALERTS_ENABLED === "on") await store.pruneMailIdem(db, now);
  return {
    conditions: conds.map((c) => c.key),
    sent: results.filter((r) => r === "sent").length,
    sendFailures: results.filter((r) => r === "failed").length,
    snap,
  };
}

export async function digest(env, now) {
  const db = env.STATE;
  const snap = await readSnapshot(env, now, { checkExport: true });
  const d = await store.digestData(db, now);
  d.readErrors = snap.errors;
  const msg = digestMessage(d, env.CATALOG ? figures(snap) : [], now);
  await send(env, msg);
  await db.prepare("INSERT INTO sends(at, key, kind) VALUES (?1, 'digest', 'digest')").bind(now).run();
  await store.setMeta(db, "last_digest", now);
  await store.setMeta(db, "digest_failed", false);
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
  if (Number(request.headers.get("content-length") ?? 0) > MAX_BODY) return json(413, { error: "body too large" });
  if (!env.INGEST_TOKEN || !timingSafeEqual(auth, `Bearer ${env.INGEST_TOKEN}`)) {
    return json(401, { error: "unauthorized" });
  }
  return ingestEvent(request, env, now);
}

/** Called only by the named service-binding entrypoint, never by default fetch. */
export async function ingestMail(request, env, now, ctx) {
  if (env.MAIL_ALERTS_ENABLED !== "on") return json(503, { error: "mail alerts disabled" });
  if (Number(request.headers.get("content-length") ?? 0) > MAX_BODY) return json(413, { error: "body too large" });
  return ingestEvent(request, env, now, ctx);
}

async function ingestEvent(request, env, now, mailCtx) {
  let b;
  try {
    const raw = await request.text();
    if (raw.length > MAX_BODY) return json(413, { error: "body too large" });
    b = JSON.parse(raw);
  } catch {
    return json(400, { error: "body must be JSON" });
  }
  const source = mailCtx ? b?.source : String(b?.source ?? "");
  const key = String(b?.key ?? "").toLowerCase();
  const severity = b?.severity === "info" ? "info" : "page";
  let title;
  if (mailCtx) {
    title = MAIL_TITLES.get(source);
    if (!title) return json(400, { error: "source must be mail:<event>" });
  } else if (!SOURCES.has(source) && source !== "test") {
    return json(400, { error: "source must be host or ci" });
  }
  if (!KEY_RE.test(key)) return json(400, { error: "key: 1-100 of a-z 0-9 . _ : -" });
  if (!mailCtx) {
    if (typeof b?.title !== "string" || b.title.length === 0) return json(400, { error: "title required" });
    title = oneLine(b.title).slice(0, 200);
  }
  const idempotencyKey = mailCtx ? request.headers.get("idempotency-key") : null;
  if (idempotencyKey !== null && idempotencyKey !== b.key) return json(400, { error: "idempotency key must match key" });
  const namespacedKey = mailCtx ? source : `${source}:${key}`;
  const row = await store.observe(
    env.STATE,
    { key: namespacedKey, source, severity, title, detail: mailCtx ? "" : String(b.detail ?? "").slice(0, 4000) },
    now,
    { mailOccurrence: idempotencyKey === null ? undefined : `${source}:${key}` },
  );
  if (!row || severity !== "page") return json(200, { key: namespacedKey, emailed: false });
  const sending = maybeSend(env, row, now, 0);
  // Finish the email claim even if the calling Worker times out. A replay
  // must not be needed to recover a claim that was already taken.
  mailCtx?.waitUntil(sending);
  return json(200, { key: namespacedKey, emailed: (await sending) === "sent" });
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
    // The heartbeat reports failure when the run threw or an email could
    // not be sent, so a broken email path is seen from outside.
    let ok = false;
    try {
      if (event.cron === (env.DIGEST_CRON ?? "30 7 * * *")) {
        try {
          await digest(env, now);
        } catch (e) {
          await store.setMeta(env.STATE, "digest_failed", true);
          throw e;
        }
        ok = true;
        return;
      }
      const r = await tick(env, now);
      ok = r.sendFailures === 0;
      // A digest that failed is sent again by the next tick (and until it
      // goes, the heartbeat keeps reporting failure).
      const lastDigest = await store.getMeta(env.STATE, "last_digest");
      const digestFailed = await store.getMeta(env.STATE, "digest_failed");
      if (digestFailed || (lastDigest && now - lastDigest > 25 * store.HOUR)) {
        try {
          await digest(env, now);
        } catch (e) {
          console.error(`digest retry failed: ${e?.code ?? e?.name ?? "error"}`);
          ok = false;
        }
      }
      console.log(`alerts tick: holding=${r.conditions.join(",") || "none"} emailed=${r.sent} failed=${r.sendFailures}`);
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
    await store.recordDlq(env.STATE, batch.queue, batch.messages.length, sample, now, batch.messages[0]?.id ?? null);
    batch.ackAll();
  },
};
