import { test } from "node:test";
import assert from "node:assert/strict";
import { handle } from "../src/worker.js";
import { EMPTY_SHA256, sha256Base64, sha256Hex, sign } from "../src/sigv4.js";
import { ADMIN, EMAIL, NOW, SECRET, env, fakeUpstream, makeIssuer } from "./helpers.js";

const issuer = await makeIssuer();
const ORIGIN = "https://files.example.test";

async function call(up, path, { method = "GET", headers = {}, body, origin = ORIGIN } = {}) {
  const h = { "cf-access-jwt-assertion": await issuer.token(), ...headers };
  if (origin && method !== "GET" && method !== "HEAD") h.origin = origin;
  if (body !== undefined && typeof body === "object" && !(body instanceof Uint8Array)) {
    body = JSON.stringify(body);
    h["content-type"] = "application/json";
  }
  if (body !== undefined && !h["content-length"]) h["content-length"] = String(typeof body === "string" ? Buffer.byteLength(body) : body.length);
  const req = new Request(ORIGIN + path, { method, headers: h, body });
  return handle(req, env(up), { fetchCerts: issuer.fetchCerts, now: () => NOW });
}

/** Recomputes the signature of a request velmora received. */
async function assertSigned(c, payloadHash) {
  const auth = c.headers.authorization;
  const m = auth.match(/^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/auto\/s3\/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$/);
  assert.ok(m, auth);
  assert.equal(m[1], "AKVLTESTTESTTESTTEST");
  assert.equal(c.headers["x-amz-content-sha256"], payloadHash);
  const signed = m[3].split(";");
  for (const name of Object.keys(c.headers)) {
    if (name.startsWith("x-amz-") || ["range", "content-type", "if-none-match", "if-match"].includes(name)) {
      assert.ok(signed.includes(name), `${name} must be signed`);
    }
  }
  const headers = {};
  for (const n of signed) if (n !== "host" && n !== "x-amz-date" && n !== "x-amz-content-sha256") headers[n] = c.headers[n];
  const query = [...c.url.searchParams.entries()];
  const again = await sign({
    method: c.method,
    host: c.url.host,
    path: c.url.pathname,
    query,
    headers,
    payloadHash,
    accessKeyId: "AKVLTESTTESTTESTTEST",
    secretAccessKey: SECRET,
    region: "auto",
    now: NOW,
  });
  assert.equal(again.signature, m[4]);
  // The secret itself is never sent.
  assert.ok(!JSON.stringify(c.headers).includes(SECRET));
}

test("ListBuckets is signed with the console key and parsed", async () => {
  const up = fakeUpstream(
    () =>
      new Response(
        "<ListAllMyBucketsResult><Buckets><Bucket><Name>files</Name><CreationDate>2026-11-01T00:00:00Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>",
      ),
  );
  const res = await call(up, "/api/buckets");
  assert.equal(res.status, 200);
  assert.deepEqual((await res.json()).buckets, [{ name: "files", created: "2026-11-01T00:00:00Z" }]);
  const c = up.calls[0];
  assert.equal(c.url.href, "https://s3.example.test/");
  assert.equal(c.headers["x-amz-date"], "20261116T120000Z");
  // Over a service binding the callee sees only the Request's headers.
  assert.equal(c.headers.host, "s3.example.test");
  await assertSigned(c, EMPTY_SHA256);
});

test("ListObjectsV2 sends a signed, encoded query and decodes url-encoded keys", async () => {
  const up = fakeUpstream(
    () =>
      new Response(
        `<ListBucketResult><EncodingType>url</EncodingType><Prefix>a%20b/</Prefix><IsTruncated>true</IsTruncated>` +
          `<NextContinuationToken>tok/=+</NextContinuationToken>` +
          `<Contents><Key>a%20b/%C3%BC%26.txt</Key><Size>5</Size><LastModified>2026-11-16T00:00:00Z</LastModified><ETag>&quot;e&quot;</ETag></Contents>` +
          `<CommonPrefixes><Prefix>a%20b/sub/</Prefix></CommonPrefixes></ListBucketResult>`,
      ),
  );
  const res = await call(up, "/api/list?bucket=files&prefix=" + encodeURIComponent("a b/"));
  const out = await res.json();
  assert.deepEqual(out.folders, ["a b/sub/"]);
  assert.deepEqual(out.files, [{ key: "a b/ü&.txt", size: 5, modified: "2026-11-16T00:00:00Z", etag: '"e"' }]);
  assert.equal(out.next, "tok/=+");
  const c = up.calls[0];
  assert.equal(c.url.pathname, "/files");
  assert.equal(c.url.searchParams.get("delimiter"), "/");
  await assertSigned(c, EMPTY_SHA256);
});

test("download forwards a single Range, signs it, and streams the answer as an attachment", async () => {
  const up = fakeUpstream(
    () =>
      new Response("hello", {
        status: 206,
        headers: { "content-range": "bytes 0-4/100", "content-length": "5", "content-type": "text/html", etag: '"x"' },
      }),
  );
  const res = await call(up, "/api/download?bucket=files&key=" + encodeURIComponent("dir/ä b.html"), {
    headers: { range: "bytes=0-4" },
  });
  assert.equal(res.status, 206);
  assert.equal(await res.text(), "hello");
  assert.equal(res.headers.get("content-range"), "bytes 0-4/100");
  assert.equal(res.headers.get("content-type"), "application/octet-stream");
  assert.match(res.headers.get("content-disposition"), /^attachment; filename="_ b.html"; filename\*=UTF-8''%C3%A4%20b\.html$/);
  assert.match(res.headers.get("content-security-policy"), /sandbox/);
  const c = up.calls[0];
  assert.equal(c.url.pathname, "/files/dir/%C3%A4%20b.html");
  assert.equal(c.headers.range, "bytes=0-4");
  await assertSigned(c, EMPTY_SHA256);
});

test("download does not forward a multi-range header", async () => {
  const up = fakeUpstream(() => new Response("all"));
  await call(up, "/api/download?bucket=files&key=k", { headers: { range: "bytes=0-1,5-6" } });
  assert.equal(up.calls[0].headers.range, undefined);
});

test("download body is the upstream stream, not a buffered copy", async () => {
  let pulled = 0;
  const stream = new ReadableStream({
    pull(ctrl) {
      pulled++;
      if (pulled > 3) ctrl.close();
      else ctrl.enqueue(new Uint8Array(4));
    },
  });
  const upstream = { calls: [], fetch: async () => new Response(stream) };
  const res = await call(upstream, "/api/download?bucket=files&key=k");
  // Nothing beyond the first chunk was read before the client reads.
  assert.ok(pulled <= 2, `pulled ${pulled}`);
  assert.equal((await res.arrayBuffer()).byteLength, 12);
});

test("part upload is UNSIGNED-PAYLOAD, carries its length and refuses more than 16 MiB", async () => {
  const up = fakeUpstream(() => new Response("", { headers: { etag: '"p1"' } }));
  const body = new Uint8Array(1024).fill(7);
  const res = await call(up, "/api/mpu/part?bucket=files&key=big.bin&uploadId=abc-1&partNumber=3", { method: "PUT", body });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { etag: '"p1"' });
  const c = up.calls[0];
  assert.equal(c.url.search, "?partNumber=3&uploadId=abc-1");
  assert.equal(c.body.length, 1024);
  await assertSigned(c, "UNSIGNED-PAYLOAD");

  const big = await call(up, "/api/mpu/part?bucket=files&key=big.bin&uploadId=abc-1&partNumber=4", {
    method: "PUT",
    headers: { "content-length": String(16 * 1024 * 1024 + 1) },
    body: new Uint8Array(1),
  });
  assert.equal(big.status, 400);
  assert.equal(up.calls.length, 1);
});

test("complete sends signed XML with its real payload hash", async () => {
  const up = fakeUpstream(() => new Response("<CompleteMultipartUploadResult><ETag>&quot;m-2&quot;</ETag></CompleteMultipartUploadResult>"));
  const res = await call(up, "/api/mpu/complete", {
    method: "POST",
    body: { bucket: "files", key: "big.bin", uploadId: "abc-1", parts: [{ partNumber: 1, etag: '"a1"' }, { partNumber: 2, etag: '"a2"' }] },
  });
  assert.deepEqual(await res.json(), { etag: '"m-2"' });
  const c = up.calls[0];
  const xml = new TextDecoder().decode(c.body);
  assert.match(xml, /<Part><PartNumber>1<\/PartNumber><ETag>&quot;a1&quot;<\/ETag><\/Part>/);
  await assertSigned(c, await sha256Hex(c.body));
});

test("a complete that fails inside a 200 is an error", async () => {
  const up = fakeUpstream(() => new Response("  <Error><Code>InvalidPart</Code><Message>m</Message></Error>"));
  const res = await call(up, "/api/mpu/complete", {
    method: "POST",
    body: { bucket: "files", key: "k", uploadId: "u", parts: [{ partNumber: 1, etag: "a" }] },
  });
  assert.equal(res.status, 502);
  assert.equal((await res.json()).error, "InvalidPart");
});

test("DeleteObjects carries a checksum of its body", async () => {
  const up = fakeUpstream(() => new Response("<DeleteResult></DeleteResult>"));
  const res = await call(up, "/api/delete", { method: "POST", body: { bucket: "files", keys: ["a&b", "c"] } });
  assert.deepEqual(await res.json(), { errors: [] });
  const c = up.calls[0];
  assert.equal(c.url.search, "?delete=");
  assert.match(new TextDecoder().decode(c.body), /<Key>a&amp;b<\/Key>/);
  assert.equal(c.headers["x-amz-checksum-sha256"], await sha256Base64(c.body));
  await assertSigned(c, await sha256Hex(c.body));
});

test("move copies with If-None-Match then deletes the source", async () => {
  const up = fakeUpstream((c) => new Response(c.method === "PUT" ? "<CopyObjectResult/>" : null, { status: c.method === "PUT" ? 200 : 204 }));
  const res = await call(up, "/api/move", { method: "POST", body: { bucket: "files", from: "a b.txt", to: "dir/c.txt" } });
  assert.equal(res.status, 200);
  const [copy, del] = up.calls;
  assert.equal(copy.method, "PUT");
  assert.equal(copy.url.pathname, "/files/dir/c.txt");
  assert.equal(copy.headers["x-amz-copy-source"], "/files/a%20b.txt");
  assert.equal(copy.headers["if-none-match"], "*");
  await assertSigned(copy, EMPTY_SHA256);
  assert.equal(del.method, "DELETE");
  assert.equal(del.url.pathname, "/files/a%20b.txt");
});

test("move onto an existing key is refused and deletes nothing", async () => {
  const up = fakeUpstream(() => new Response("<Error><Code>PreconditionFailed</Code></Error>", { status: 412 }));
  const res = await call(up, "/api/move", { method: "POST", body: { bucket: "files", from: "a", to: "b" } });
  assert.equal(res.status, 409);
  assert.equal(up.calls.length, 1);
});

test("create bucket: admin create (non-disposable) then grant of the console key", async () => {
  const up = fakeUpstream(() => Response.json({ ok: true }));
  const res = await call(up, "/api/buckets", { method: "POST", body: { name: "photos" } });
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.ok(!text.includes(ADMIN) && !text.includes(SECRET));
  const [create, grant] = up.calls;
  assert.equal(create.url.pathname, "/_admin/buckets");
  assert.equal(create.headers.authorization, `Bearer ${ADMIN}`);
  assert.deepEqual(JSON.parse(new TextDecoder().decode(create.body)), { name: "photos", disposable: false });
  assert.equal(grant.url.pathname, "/_admin/keys/AKVLTESTTESTTESTTEST/grants");
  assert.deepEqual(JSON.parse(new TextDecoder().decode(grant.body)), { bucket: "photos", perm: "rw" });
});

test("invalid bucket names never reach velmora", async () => {
  const up = fakeUpstream(() => Response.json({}));
  for (const name of ["_admin", "UPPER", "a", "x/../y"]) {
    const res = await call(up, "/api/buckets", { method: "POST", body: { name } });
    assert.equal(res.status, 400);
  }
  const res = await call(up, "/api/list?bucket=_admin");
  assert.equal(res.status, 400);
  assert.equal(up.calls.length, 0);
});

test("upstream errors carry no secret and no admin token", async () => {
  const up = fakeUpstream(() => new Response("<Error><Code>AccessDenied</Code><Message>nope</Message></Error>", { status: 403 }));
  const res = await call(up, "/api/list?bucket=files");
  assert.equal(res.status, 403);
  const text = await res.text();
  assert.ok(!text.includes(SECRET) && !text.includes(ADMIN));
});

test("session answers the verified email", async () => {
  const res = await call(fakeUpstream(() => new Response()), "/api/session");
  assert.deepEqual(await res.json(), { email: EMAIL });
});

// Same-origin rules.

test("a mutation without Origin is refused", async () => {
  const up = fakeUpstream(() => Response.json({}));
  const res = await call(up, "/api/delete", { method: "POST", body: { bucket: "files", keys: ["a"] }, origin: null });
  assert.equal(res.status, 403);
  assert.equal(up.calls.length, 0);
});

test("a mutation from another origin is refused", async () => {
  const up = fakeUpstream(() => Response.json({}));
  const res = await call(up, "/api/delete", { method: "POST", body: { bucket: "files", keys: ["a"] }, origin: "https://evil.example" });
  assert.equal(res.status, 403);
  const res2 = await call(up, "/api/delete", {
    method: "POST",
    body: { bucket: "files", keys: ["a"] },
    headers: { "sec-fetch-site": "same-site" },
  });
  assert.equal(res2.status, 403);
  assert.equal(up.calls.length, 0);
});

test("a cross-site read is refused", async () => {
  const up = fakeUpstream(() => new Response(""));
  const res = await call(up, "/api/download?bucket=files&key=a", { headers: { "sec-fetch-site": "cross-site" } });
  assert.equal(res.status, 403);
  assert.equal(up.calls.length, 0);
});

test("JSON routes require a JSON content type (no form posts)", async () => {
  const up = fakeUpstream(() => Response.json({}));
  const res = await call(up, "/api/delete", {
    method: "POST",
    body: "bucket=files",
    headers: { "content-type": "application/x-www-form-urlencoded" },
  });
  assert.equal(res.status, 400);
  assert.equal(up.calls.length, 0);
});

test("pages get a strict CSP and no wildcard CORS", async () => {
  const res = await call(fakeUpstream(() => new Response()), "/");
  assert.equal(res.status, 200);
  const csp = res.headers.get("content-security-policy");
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval|\*/);
  assert.equal(res.headers.get("access-control-allow-origin"), null);
});

// Review fixes.

test("a query value with ( ) ! * is sent encoded exactly as it was signed", async () => {
  const up = fakeUpstream(() => new Response("<ListBucketResult></ListBucketResult>"));
  await call(up, "/api/list?bucket=files&prefix=" + encodeURIComponent("Photos (2019)!*/"));
  const raw = up.calls[0].url.search;
  assert.match(raw, /prefix=Photos%20%282019%29%21%2A%2F/);
  // velmora canonicalises the raw query: the signature must be over these bytes.
  const pairs = raw.slice(1).split("&").map((p) => p.split("="));
  const { canonicalQuery, uriEncode } = await import("../src/sigv4.js");
  const decoded = pairs.map(([k, v]) => [decodeURIComponent(k), decodeURIComponent(v)]);
  assert.deepEqual(
    pairs.map(([k, v]) => `${k}=${v}`).sort(),
    canonicalQuery(decoded).split("&").sort(),
  );
  assert.equal(uriEncode("(x)"), "%28x%29");
});

test("keys with . or .. segments never reach velmora", async () => {
  const up = fakeUpstream(() => Response.json({}));
  for (const key of ["../../keys", "a/../b", "./a", "a/.", ".."]) {
    const res = await call(up, "/api/info?bucket=files&key=" + encodeURIComponent(key));
    assert.equal(res.status, 400, key);
  }
  assert.equal(up.calls.length, 0);
});

test("a malformed (lone surrogate) key is a 400, not a 500", async () => {
  const up = fakeUpstream(() => Response.json({}));
  const res = await call(up, "/api/move", { method: "POST", body: { bucket: "files", from: "a", to: "b\ud800" } });
  assert.equal(res.status, 400);
});

test("moving a file onto a folder path is refused", async () => {
  const up = fakeUpstream(() => new Response(""));
  const res = await call(up, "/api/move", { method: "POST", body: { bucket: "files", from: "report.pdf", to: "archive/" } });
  assert.equal(res.status, 400);
  assert.equal(up.calls.length, 0);
});

test("the page itself may be reached cross-site (Access login redirect)", async () => {
  const res = await call(fakeUpstream(() => new Response()), "/", { headers: { "sec-fetch-site": "cross-site" } });
  assert.equal(res.status, 200);
});

test("small uploads never overwrite unless asked", async () => {
  let exists = true;
  const up = fakeUpstream((c) =>
    exists && c.headers["if-none-match"] === "*"
      ? new Response("<Error><Code>PreconditionFailed</Code></Error>", { status: 412 })
      : new Response("", { headers: { etag: '"n"' } }),
  );
  const body = new Uint8Array(3);
  const res = await call(up, "/api/object?bucket=files&key=a.txt&type=text/plain", { method: "PUT", body });
  assert.equal(res.status, 409);
  assert.equal(up.calls[0].headers["if-none-match"], "*");
  await assertSigned(up.calls[0], "UNSIGNED-PAYLOAD");
  const res2 = await call(up, "/api/object?bucket=files&key=a.txt&type=text/plain&overwrite=1", { method: "PUT", body });
  assert.equal(res2.status, 200);
  assert.equal(up.calls[1].headers["if-none-match"], undefined);
  exists = false;
});

test("complete is conditional unless overwrite is set", async () => {
  const up = fakeUpstream((c) =>
    c.headers["if-none-match"] === "*"
      ? new Response("<Error><Code>PreconditionFailed</Code></Error>", { status: 412 })
      : new Response("<CompleteMultipartUploadResult><ETag>&quot;m-1&quot;</ETag></CompleteMultipartUploadResult>"),
  );
  const parts = [{ partNumber: 1, etag: '"a1"' }];
  const res = await call(up, "/api/mpu/complete", { method: "POST", body: { bucket: "files", key: "k", uploadId: "u", parts } });
  assert.equal(res.status, 409);
  const res2 = await call(up, "/api/mpu/complete", { method: "POST", body: { bucket: "files", key: "k", uploadId: "u", parts, overwrite: true } });
  assert.equal(res2.status, 200);
  await assertSigned(up.calls[1], await sha256Hex(up.calls[1].body));
});

test("HEAD of a download is a HeadObject, never a GET of the bytes", async () => {
  const up = fakeUpstream(() => new Response(null, { headers: { "content-length": "42", etag: '"e"' } }));
  const res = await call(up, "/api/download?bucket=files&key=k", { method: "HEAD" });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-length"), "42");
  assert.equal(up.calls[0].method, "HEAD");
});
