import { test } from "node:test";
import assert from "node:assert/strict";
import { AccessDenied, createAccessVerifier } from "../src/access.js";
import { handle } from "../src/worker.js";
import { AUD, EMAIL, NOW, TEAM, env, fakeUpstream, makeIssuer } from "./helpers.js";

const issuer = await makeIssuer();
const verifier = (over = {}) =>
  createAccessVerifier({ teamDomain: TEAM, aud: AUD, allowedEmails: [EMAIL], fetchCerts: issuer.fetchCerts, now: () => NOW, ...over });

async function denied(promise, reason) {
  await assert.rejects(promise, (e) => e instanceof AccessDenied && e.reason === reason);
}

test("a valid token passes and returns its claims", async () => {
  const claims = await verifier()(await issuer.token());
  assert.equal(claims.email, EMAIL);
});

test("aud may be a plain string", async () => {
  await verifier()(await issuer.token({ aud: AUD }));
});

test("missing token is refused", async () => {
  await denied(verifier()(null), "missing");
  await denied(verifier()(""), "missing");
});

test("wrong aud is refused", async () => {
  await denied(verifier()(await issuer.token({ aud: ["b".repeat(64)] })), "aud");
});

test("wrong issuer is refused", async () => {
  await denied(verifier()(await issuer.token({ iss: "https://other.cloudflareaccess.com" })), "iss");
});

test("expired token is refused", async () => {
  await denied(verifier()(await issuer.token({ exp: NOW / 1000 - 120 })), "expired");
  await denied(verifier()(await issuer.token({ exp: undefined })), "expired");
});

test("not-yet-valid token is refused", async () => {
  await denied(verifier()(await issuer.token({ nbf: NOW / 1000 + 600 })), "not-yet-valid");
});

test("email outside the allow list is refused", async () => {
  await denied(verifier()(await issuer.token({ email: "someone@example.com" })), "email");
  await denied(verifier()(await issuer.token({ email: undefined })), "email");
});

test("a token signed by another key is refused", async () => {
  const other = await makeIssuer("k1");
  await denied(verifier()(await other.token()), "signature");
});

test("a tampered payload is refused", async () => {
  const t = (await issuer.token()).split(".");
  const evil = Buffer.from(JSON.stringify({ iss: `https://${TEAM}`, aud: [AUD], email: EMAIL, exp: NOW / 1000 + 9999 }))
    .toString("base64url");
  await denied(verifier()(`${t[0]}.${evil}.${t[2]}`), "signature");
});

test("alg other than RS256 is refused before any key work", async () => {
  await denied(verifier()(await issuer.token({}, { alg: "HS256" })), "alg");
  await denied(verifier()(await issuer.token({}, { alg: "none" })), "alg");
});

test("unknown kid is refused and refreshes certs at most once a minute", async () => {
  let t = NOW;
  const v = verifier({ now: () => t });
  await v(await issuer.token()); // warm
  t += 61 * 1000;
  const before = issuer.certFetches;
  await denied(v(await issuer.token({}, { kid: "nope" })), "unknown-kid");
  await denied(v(await issuer.token({}, { kid: "nope" })), "unknown-kid");
  assert.equal(issuer.certFetches - before, 1);
});

test("malformed tokens are refused", async () => {
  await denied(verifier()("a.b"), "shape");
  await denied(verifier()("!!.??.**"), "encoding");
});

test("missing configuration refuses everything", async () => {
  const token = await issuer.token();
  await denied(verifier({ aud: "" })(token), "not-configured");
  await denied(verifier({ teamDomain: "evil.example.com" })(token), "not-configured");
  await denied(verifier({ allowedEmails: [] })(token), "not-configured");
});

test("certs endpoint failure refuses", async () => {
  const v = verifier({ fetchCerts: async () => new Response("down", { status: 503 }) });
  await denied(v(await issuer.token()), "certs-status");
  const v2 = verifier({ fetchCerts: async () => { throw new Error("net"); } });
  await denied(v2(await issuer.token()), "certs-unreachable");
});

// Through the Worker entry: every path answers 403 without a valid JWT,
// and velmora is never called.

async function workerStatus(token, path = "/api/buckets", extraEnv = {}) {
  const up = fakeUpstream(() => new Response("<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>"));
  const headers = token ? { "cf-access-jwt-assertion": token } : {};
  const res = await handle(new Request(`https://files.example.test${path}`, { headers }), env(up, extraEnv), {
    fetchCerts: issuer.fetchCerts,
    now: () => NOW,
  });
  return { status: res.status, calls: up.calls.length };
}

test("worker: missing JWT → 403 on API and on the page", async () => {
  assert.deepEqual(await workerStatus(null), { status: 403, calls: 0 });
  assert.deepEqual(await workerStatus(null, "/"), { status: 403, calls: 0 });
});

test("worker: bad aud → 403", async () => {
  assert.deepEqual(await workerStatus(await issuer.token({ aud: ["c".repeat(64)] })), { status: 403, calls: 0 });
});

test("worker: expired → 403", async () => {
  assert.deepEqual(await workerStatus(await issuer.token({ exp: NOW / 1000 - 3600 })), { status: 403, calls: 0 });
});

test("worker: unset ACCESS_AUD → 403 even with a token", async () => {
  assert.deepEqual(await workerStatus(await issuer.token(), "/api/buckets", { ACCESS_AUD: undefined }), { status: 403, calls: 0 });
});

test("worker: valid JWT reaches the API", async () => {
  assert.deepEqual(await workerStatus(await issuer.token()), { status: 200, calls: 1 });
});

test("a failing certs endpoint is fetched at most once a minute, by one request at a time", async () => {
  let fetches = 0;
  let t = NOW;
  const v = createAccessVerifier({
    teamDomain: TEAM,
    aud: AUD,
    allowedEmails: [EMAIL],
    now: () => t,
    fetchCerts: async () => {
      fetches++;
      return new Response("down", { status: 503 });
    },
  });
  const token = await issuer.token();
  await Promise.allSettled([v(token), v(token), v(token)]);
  assert.equal(fetches, 1);
  await denied(v(token), "certs-unavailable");
  assert.equal(fetches, 1);
  t += 61 * 1000;
  await denied(v(await issuer.token({ exp: t / 1000 + 600 })), "certs-status");
  assert.equal(fetches, 2);
});

test("a hung certs fetch is not waited on forever", async () => {
  const v = createAccessVerifier({
    teamDomain: TEAM,
    aud: AUD,
    allowedEmails: [EMAIL],
    now: () => NOW,
    fetchCerts: () => new Promise(() => {}),
  });
  const started = Date.now();
  await denied(v(await issuer.token()), "certs-timeout");
  assert.ok(Date.now() - started < 8000);
});

test("an abandoned (hung) certs fetch does not lock everyone out for a minute", async () => {
  let t = NOW;
  let calls = 0;
  const v = createAccessVerifier({
    teamDomain: TEAM,
    aud: AUD,
    allowedEmails: [EMAIL],
    now: () => t,
    fetchCerts: (url) => (++calls === 1 ? new Promise(() => {}) : issuer.fetchCerts(url)),
  });
  await denied(v(await issuer.token()), "certs-timeout");
  t += 7000; // past the in-flight bound, well inside a minute
  const claims = await v(await issuer.token());
  assert.equal(claims.email, EMAIL);
  assert.equal(calls, 2);
});
