// entry.mjs: the default entrypoint never lets a client set the entry
// marker; the named WebDAV entrypoint always sets it.
import { register } from "node:module";
import test from "node:test";
import assert from "node:assert/strict";

register("./entry-hooks.mjs", import.meta.url);
const entry = await import("../entry.mjs");
const marker = await import("../entry-marker.mjs");
const calls = globalThis.__entryCalls;

const ctx = { waitUntil() {} };
const env = { name: "env" };

function last() {
  return calls[calls.length - 1];
}

test("the default entrypoint passes an unmarked request on as the same object", async () => {
  const req = new Request("https://s3.test/b/k", { headers: { "x-amz-date": "1" } });
  const out = new entry.default(ctx, env).fetch(req);
  assert.equal(out, "fetched");
  assert.equal(last().request, req);
  assert.equal(last().ctx, ctx);
  assert.equal(last().env, env);
});

test("the default entrypoint deletes a marker a client sent", async () => {
  for (const value of ["webdav", "WebDAV", "s3", ""]) {
    const req = new Request("https://s3.test/b/k", {
      method: "PUT",
      body: "abc",
      headers: { "x-velmora-entry": value, "x-amz-date": "1" },
    });
    new entry.default(ctx, env).fetch(req);
    const seen = last().request;
    assert.equal(seen.headers.has("x-velmora-entry"), false, value);
    assert.equal(seen.headers.get("x-amz-date"), "1");
    assert.equal(seen.method, "PUT");
    assert.equal(await seen.text(), "abc");
  }
});

test("the WebDAV entrypoint sets the marker, replacing any sent", async () => {
  const req = new Request("https://s3.test/b/k", {
    headers: { "x-velmora-entry": "s3", authorization: "AWS4-HMAC-SHA256 x" },
  });
  new entry.DavEntry(ctx, env).fetch(req);
  const seen = last().request;
  assert.equal(seen.headers.get("x-velmora-entry"), "webdav");
  assert.equal(seen.headers.get("authorization"), "AWS4-HMAC-SHA256 x");
});

test("the management entrypoint sets its marker, replacing any sent", async () => {
  for (const value of ["webdav", "s3", "mgmt", null]) {
    const headers = { authorization: "Bearer x" };
    if (value !== null) {
      headers["x-velmora-entry"] = value;
    }
    const req = new Request("https://mgmt.internal/v1/tenants", {
      method: "POST",
      body: "{}",
      headers,
    });
    new entry.MgmtEntry(ctx, env).fetch(req);
    const seen = last().request;
    assert.equal(seen.headers.get("x-velmora-entry"), "mgmt", String(value));
    assert.equal(seen.headers.get("authorization"), "Bearer x");
    assert.equal(seen.method, "POST");
    assert.equal(await seen.text(), "{}");
  }
});

test("the default entrypoint deletes a management marker a client sent", () => {
  const req = new Request("https://s3.test/v1/tenants", {
    headers: { "x-velmora-entry": "mgmt" },
  });
  new entry.default(ctx, env).fetch(req);
  assert.equal(last().request.headers.has("x-velmora-entry"), false);
});

test("queue and scheduled reach the Rust Worker unchanged", () => {
  const worker = new entry.default(ctx, env);
  const batch = { messages: [] };
  assert.equal(worker.queue(batch), "queued");
  assert.equal(last().batch, batch);
  const controller = { cron: "* * * * *" };
  assert.equal(worker.scheduled(controller), "scheduled");
  assert.equal(last().controller, controller);
  assert.equal(last().env, env);
});

test("the main module exports entrypoints and classes only", () => {
  assert.equal(typeof entry.PermitGate, "function");
  // The runtime refuses a main module with any other export.
  for (const [name, value] of Object.entries(entry)) {
    assert.equal(typeof value, "function", name);
  }
  assert.equal(marker.ENTRY_HEADER, "x-velmora-entry");
  assert.equal(marker.WEBDAV, "webdav");
  assert.equal(marker.MGMT, "mgmt");
  // The named entrypoints have no queue or cron handler.
  for (const named of [entry.DavEntry, entry.MgmtEntry]) {
    assert.equal(named.prototype.queue, undefined);
    assert.equal(named.prototype.scheduled, undefined);
  }
});
