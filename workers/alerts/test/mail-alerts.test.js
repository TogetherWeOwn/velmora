import assert from "node:assert/strict";
import { register } from "node:module";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { FakeD1, FakeEmail } from "./d1.js";
import { HOUR, unsentEvents } from "../src/store.js";

// Only the runtime-supplied base class is a stub. Invoke the named export from
// the actual Wrangler main module, with SQLite and the existing email fixture.
register(new URL("./worker-module-loader.js", import.meta.url));
const main = /^main = "([^"]+)"$/m.exec(readFileSync(new URL("../wrangler.toml", import.meta.url), "utf8"))[1];
const { default: worker, MailAlerts } = await import(new URL(`../${main}`, import.meta.url).href);

function fixture(enabled = "on") {
  return {
    STATE: new FakeD1().applyDir(fileURLToPath(new URL("../migrations", import.meta.url))),
    ALERT_EMAIL: new FakeEmail(),
    ALERT_EMAIL_TO: "operator@example.invalid",
    ALERT_FROM: "alerts@example.invalid",
    INGEST_TOKEN: "fixture-token",
    DAILY_EMAIL_CAP: "1",
    MAIL_ALERTS_ENABLED: enabled,
  };
}

const event = { source: "mail:send_dlq", key: "first", title: "Outbound mail queue message dead-lettered" };
function request(body = event, headers = {}, method = "POST", path = "/v1/alert", signal) {
  return new Request(`https://alerts.internal${path}`, {
    method,
    headers: { "content-type": "application/json", ...headers },
    body: method === "POST" ? JSON.stringify(body) : undefined,
    signal,
  });
}

const rows = (env) => env.STATE.db.prepare("SELECT key, source, seen_unsent, sent_in_run FROM alerts ORDER BY key").all()
  .map((row) => ({ ...row }));

function entrypoint(env, ctx = { waitUntil() {} }) {
  assert.equal(typeof MailAlerts, "function", "the configured Worker must export MailAlerts");
  return new MailAlerts(ctx, env);
}

test("MailAlerts stores and emails a mail event, sharing the existing cap", async () => {
  const env = fixture();
  const service = entrypoint(env);
  const first = await service.fetch(request(event, { "idempotency-key": event.key }));
  assert.equal(first.status, 200);
  assert.deepEqual(await first.json(), { key: "mail:send_dlq:first", emailed: true });
  const second = await service.fetch(request({ ...event, key: "second" }));
  assert.equal(second.status, 200);
  assert.deepEqual(await second.json(), { key: "mail:send_dlq:second", emailed: false });
  assert.deepEqual(rows(env), [
    { key: "mail:send_dlq:first", source: "mail:send_dlq", seen_unsent: 0, sent_in_run: 1 },
    { key: "mail:send_dlq:second", source: "mail:send_dlq", seen_unsent: 1, sent_in_run: 0 },
  ]);
  assert.equal(env.ALERT_EMAIL.sent.length, 1);
});

test("replaying the same idempotency key after the cooldown does not requeue an email", async (t) => {
  t.mock.method(Date, "now", () => 24 * HOUR);
  const env = { ...fixture(), DAILY_EMAIL_CAP: "30" };
  const service = entrypoint(env);
  const send = () => service.fetch(request(event, { "idempotency-key": event.key }));
  const responses = await Promise.all([send(), send()]);
  assert.ok(responses.every((response) => response.status === 200));
  t.mock.method(Date, "now", () => 26 * HOUR);
  const replay = await send();
  assert.equal(replay.status, 200);
  assert.equal((await replay.json()).emailed, false);
  assert.equal(env.ALERT_EMAIL.sent.length, 1);
  assert.equal((await unsentEvents(env.STATE)).length, 0);
});

test("an started email claim stays in the Worker context after the caller aborts", async () => {
  const env = fixture();
  const started = Promise.withResolvers();
  const finish = Promise.withResolvers();
  const originalSend = env.ALERT_EMAIL.send.bind(env.ALERT_EMAIL);
  env.ALERT_EMAIL.send = async (message) => {
    started.resolve();
    await finish.promise;
    return originalSend(message);
  };
  const protectedTasks = [];
  const service = entrypoint(env, { waitUntil(promise) { protectedTasks.push(promise); } });
  const abort = new AbortController();
  const response = service.fetch(request(event, { "idempotency-key": event.key }, "POST", "/v1/alert", abort.signal));
  await started.promise;
  abort.abort();
  finish.resolve();
  await response;
  assert.equal(protectedTasks.length, 1, "the email claim and send must be registered with waitUntil");
  await Promise.all(protectedTasks);
  assert.equal(env.ALERT_EMAIL.sent.length, 1);
});

test("public alert ingress refuses a mail source even with a valid bearer and idempotency key", async () => {
  const env = fixture();
  const response = await worker.fetch(request(event, { authorization: `Bearer ${env.INGEST_TOKEN}`, "idempotency-key": event.key }), env);
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "source must be host or ci" });
  assert.deepEqual(rows(env), []);
  assert.equal(env.ALERT_EMAIL.sent.length, 0);
});

test("MailAlerts fails closed when off, unset, or misspelled", async () => {
  for (const value of ["off", undefined, "On"]) {
    const env = { ...fixture(), MAIL_ALERTS_ENABLED: value };
    const response = await entrypoint(env).fetch(request());
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), { error: "mail alerts disabled" });
    assert.deepEqual(rows(env), []);
    assert.equal(env.ALERT_EMAIL.sent.length, 0);
  }
});

test("MailAlerts refuses the wrong route, source, or idempotency key before writing", async () => {
  const env = fixture();
  const service = entrypoint(env);
  const cases = [
    [request(event, {}, "POST", "/internal"), 404, null],
    [request(event, {}, "GET"), 404, null],
    [request({ ...event, source: "host" }), 400, "source must be mail:<event>"],
    [request({ ...event, source: "mail:" }), 400, "source must be mail:<event>"],
    [request(event, { "idempotency-key": "different" }), 400, "idempotency key must match key"],
  ];
  for (const [input, status, error] of cases) {
    const response = await service.fetch(input);
    assert.equal(response.status, status);
    if (error) assert.deepEqual(await response.json(), { error });
  }
  assert.deepEqual(rows(env), []);
  assert.equal(env.ALERT_EMAIL.sent.length, 0);
});
