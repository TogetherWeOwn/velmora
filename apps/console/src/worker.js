// velmora console: a small file manager in front of velmora's S3 API.
//
// Every request passes the Cloudflare Access JWT check first; without a
// valid token the answer is 403, whatever the path. The browser talks to
// `/api/*` on this origin only. This Worker signs the S3 requests and
// calls the admin API itself, through the service binding `S3`; the S3
// secret and the admin token never leave it.

import { AccessDenied, createAccessVerifier, parseEmails } from "./access.js";
import { UpstreamError, createClient } from "./s3.js";

export const PART_BYTES = 16 * 1024 * 1024;
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const MAX_DELETE_KEYS = 1000;

const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "connect-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

function secure(headers, csp = CSP) {
  headers.set("content-security-policy", csp);
  headers.set("x-content-type-options", "nosniff");
  headers.set("x-frame-options", "DENY");
  headers.set("referrer-policy", "no-referrer");
  headers.set("cross-origin-opener-policy", "same-origin");
  headers.set("cross-origin-resource-policy", "same-origin");
  headers.set("strict-transport-security", "max-age=31536000");
  return headers;
}

function json(status, value) {
  const h = secure(new Headers({ "content-type": "application/json", "cache-control": "no-store" }));
  return new Response(JSON.stringify(value), { status, headers: h });
}

function error(status, code, message) {
  return json(status, { error: code, message });
}

const exists = () => error(409, "DestinationExists", "Something already has that name.");

const forbidden = () => {
  const h = secure(new Headers({ "content-type": "text/plain", "cache-control": "no-store" }));
  return new Response("Forbidden", { status: 403, headers: h });
};

class BadRequest extends Error {}

const BUCKET_RE = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;
const UPLOAD_ID_RE = /^[A-Za-z0-9._~+=/-]{1,512}$/;
const CONTENT_TYPE_RE = /^[A-Za-z0-9!#$&^_.+-]{1,64}\/[A-Za-z0-9!#$&^_.+-]{1,128}$/;
const RANGE_RE = /^bytes=(\d{1,15}-\d{0,15}|-\d{1,15})$/;
const ETAG_RE = /^"?[A-Za-z0-9-]{1,80}"?$/;

export function bucketName(v) {
  if (typeof v !== "string" || !BUCKET_RE.test(v)) throw new BadRequest("bucket");
  return v;
}

export function objectKey(v, { allowSlashEnd = true, inPath = true } = {}) {
  if (typeof v !== "string" || v.length === 0 || !v.isWellFormed()) throw new BadRequest("key");
  if (new TextEncoder().encode(v).length > 1024) throw new BadRequest("key");
  // A `.` or `..` segment would be resolved away by the URL parser.
  // (Keys sent in an XML body, as for DeleteObjects, are not parsed as a path.)
  if (inPath && v.split("/").some((seg) => seg === "." || seg === "..")) throw new BadRequest("key");
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(v)) throw new BadRequest("key");
  if (!allowSlashEnd && v.endsWith("/")) throw new BadRequest("key");
  return v;
}

function prefixOf(v) {
  if (v === undefined || v === null || v === "") return "";
  // A prefix travels in the query, never in the path.
  objectKey(v, { inPath: false });
  return v;
}

function contentType(v) {
  return typeof v === "string" && CONTENT_TYPE_RE.test(v) ? v : "application/octet-stream";
}

function uploadId(v) {
  if (typeof v !== "string" || !UPLOAD_ID_RE.test(v)) throw new BadRequest("uploadId");
  return v;
}

function partNumber(v) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 10000) throw new BadRequest("partNumber");
  return n;
}

function declaredLength(request, max) {
  const raw = request.headers.get("content-length");
  if (raw === null || !/^\d{1,12}$/.test(raw)) throw new BadRequest("content-length");
  const n = Number(raw);
  if (n > max) throw new BadRequest("too-large");
  return n;
}

async function readJson(request) {
  const type = request.headers.get("content-type") ?? "";
  if (!type.toLowerCase().startsWith("application/json")) throw new BadRequest("content-type");
  const len = Number(request.headers.get("content-length") ?? "NaN");
  if (!Number.isFinite(len) || len > MAX_JSON_BYTES) throw new BadRequest("body-size");
  const raw = await request.text();
  if (raw.length > MAX_JSON_BYTES) throw new BadRequest("body-size");
  try {
    const v = JSON.parse(raw);
    if (v === null || typeof v !== "object" || Array.isArray(v)) throw new Error();
    return v;
  } catch {
    throw new BadRequest("json");
  }
}

/**
 * Mutations must come from this origin: `Origin` must be present and
 * equal, and `Sec-Fetch-Site`, when sent, must be `same-origin`. Reads
 * refuse only an explicit cross-site fetch.
 */
export function sameOrigin(request) {
  const url = new URL(request.url);
  const site = request.headers.get("sec-fetch-site");
  if (request.method === "GET" || request.method === "HEAD") {
    // The page itself may be reached from elsewhere (the Access login
    // redirect is cross-site); it holds no data. API reads may not.
    if (!url.pathname.startsWith("/api")) return true;
    return site === null || site === "same-origin" || site === "none";
  }
  const origin = request.headers.get("origin");
  if (origin !== url.origin) return false;
  return site === null || site === "same-origin";
}

function asciiName(name) {
  return name.replace(/[^\x20-\x7e]|["\\]/g, "_");
}

function contentDisposition(key) {
  const name = key.split("/").filter(Boolean).pop() || "download";
  return `attachment; filename="${asciiName(name)}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

async function download(s3, url, request) {
  const bucket = bucketName(url.searchParams.get("bucket"));
  const key = objectKey(url.searchParams.get("key"));
  if (request.method === "HEAD") {
    // A HEAD never starts a read of the object's bytes.
    const head = await s3.head(bucket, key);
    const h = secure(new Headers({ "cache-control": "private, no-store", "content-type": "application/octet-stream" }), "default-src 'none'; sandbox");
    h.set("content-length", String(head.size));
    h.set("accept-ranges", "bytes");
    if (head.etag) h.set("etag", head.etag);
    return new Response(null, { status: 200, headers: h });
  }
  const range = request.headers.get("range");
  // A multi-range or odd value is not forwarded: the whole object comes.
  const upstream = await s3.get(bucket, key, range && RANGE_RE.test(range) ? range : undefined);
  if (!upstream.ok && upstream.status !== 206) {
    if (upstream.status === 416) {
      const h = secure(new Headers({ "cache-control": "no-store" }));
      const cr = upstream.headers.get("content-range");
      if (cr) h.set("content-range", cr);
      return new Response(null, { status: 416, headers: h });
    }
    await upstream.body?.cancel();
    return error(upstream.status === 404 ? 404 : 502, upstream.status === 404 ? "NoSuchKey" : "UpstreamError", "");
  }
  const h = new Headers();
  for (const name of ["content-length", "content-range", "accept-ranges", "etag", "last-modified"]) {
    const v = upstream.headers.get(name);
    if (v !== null) h.set(name, v);
  }
  h.set("content-type", "application/octet-stream");
  h.set("content-disposition", contentDisposition(key));
  h.set("cache-control", "private, no-store");
  // Object bytes are never a document of this origin.
  secure(h, "default-src 'none'; sandbox");
  return new Response(upstream.body, { status: upstream.status, headers: h });
}

async function api(request, env, s3, claims, url) {
  const path = url.pathname.slice("/api".length);
  const m = request.method;
  const q = (n) => url.searchParams.get(n);

  if (path === "/session" && m === "GET") return json(200, { email: claims.email });

  if (path === "/buckets" && m === "GET") return json(200, { buckets: await s3.listBuckets() });

  if (path === "/buckets" && m === "POST") {
    const body = await readJson(request);
    const name = bucketName(body.name);
    // `adopt`: grant the console key on a bucket that already exists (made
    // elsewhere, or a create whose grant failed). Off unless the deploy
    // allows it: grants are never narrowed, so this cannot be undone.
    if (body.adopt === true) {
      if (!adoptAllowed(env, name)) return error(403, "AdoptDisabled", "This console may not take over existing buckets.");
    } else {
      await s3.createBucket(name);
    }
    // The console's key is scoped to named buckets: it grants itself the bucket.
    await s3.grant(env.S3_ACCESS_KEY_ID, name, "rw");
    return json(200, { name });
  }

  if (path === "/list" && m === "GET") {
    const bucket = bucketName(q("bucket"));
    const out = await s3.list(bucket, {
      prefix: prefixOf(q("prefix")),
      delimiter: q("recursive") === "1" ? "" : "/",
      token: q("token") || undefined,
    });
    return json(200, out);
  }

  if (path === "/download" && (m === "GET" || m === "HEAD")) return download(s3, url, request);

  // Existence only (no velmora state lookup): used before large uploads.
  if (path === "/head" && m === "GET") {
    const bucket = bucketName(q("bucket"));
    const key = objectKey(q("key"));
    try {
      const head = await s3.head(bucket, key);
      return json(200, { exists: true, size: head.size, etag: head.etag });
    } catch (e) {
      if (e instanceof UpstreamError && e.status === 404) return json(200, { exists: false });
      throw e;
    }
  }

  if (path === "/info" && m === "GET") {
    const bucket = bucketName(q("bucket"));
    const key = objectKey(q("key"));
    const head = await s3.head(bucket, key);
    let state = null;
    try {
      state = await s3.objectState(bucket, key);
    } catch (e) {
      if (!(e instanceof UpstreamError)) throw e;
      state = { unavailable: e.code };
    }
    return json(200, { head, state });
  }

  if (path === "/object" && m === "PUT") {
    const bucket = bucketName(q("bucket"));
    const key = objectKey(q("key"), { allowSlashEnd: false });
    const len = declaredLength(request, PART_BYTES);
    // Nothing is replaced unless the caller says so: velmora keeps no versions.
    const extra = q("overwrite") === "1" ? {} : { "if-none-match": "*" };
    try {
      const out = await s3.put(bucket, key, request.body ?? new Uint8Array(0), len, contentType(q("type")), extra);
      return json(200, out);
    } catch (e) {
      if (e instanceof UpstreamError && e.status === 412) return exists();
      throw e;
    }
  }

  if (path === "/folder" && m === "POST") {
    const body = await readJson(request);
    const bucket = bucketName(body.bucket);
    let prefix = objectKey(body.prefix);
    if (!prefix.endsWith("/")) prefix += "/";
    // An empty marker object; If-None-Match keeps an existing one as it is.
    try {
      await s3.put(bucket, prefix, new Uint8Array(0), 0, "application/x-directory", { "if-none-match": "*" });
    } catch (e) {
      if (!(e instanceof UpstreamError && e.status === 412)) throw e;
    }
    return json(200, { prefix });
  }

  if (path === "/mpu/create" && m === "POST") {
    const body = await readJson(request);
    const bucket = bucketName(body.bucket);
    const key = objectKey(body.key, { allowSlashEnd: false });
    return json(200, await s3.createUpload(bucket, key, contentType(body.contentType)));
  }

  if (path === "/mpu/part" && m === "PUT") {
    const bucket = bucketName(q("bucket"));
    const key = objectKey(q("key"));
    const len = declaredLength(request, PART_BYTES);
    if (!request.body) throw new BadRequest("body");
    const out = await s3.uploadPart(bucket, key, uploadId(q("uploadId")), partNumber(q("partNumber")), request.body, len);
    return json(200, out);
  }

  if (path === "/mpu/parts" && m === "GET") {
    const bucket = bucketName(q("bucket"));
    const key = objectKey(q("key"));
    return json(200, { parts: await s3.listParts(bucket, key, uploadId(q("uploadId"))) });
  }

  if (path === "/mpu/complete" && m === "POST") {
    const body = await readJson(request);
    const bucket = bucketName(body.bucket);
    const key = objectKey(body.key);
    if (!Array.isArray(body.parts) || body.parts.length === 0 || body.parts.length > 10000) {
      throw new BadRequest("parts");
    }
    const parts = body.parts.map((p) => {
      if (typeof p?.etag !== "string" || !ETAG_RE.test(p.etag)) throw new BadRequest("etag");
      return { partNumber: partNumber(p.partNumber), etag: p.etag };
    });
    try {
      return json(200, await s3.completeUpload(bucket, key, uploadId(body.uploadId), parts, body.overwrite === true));
    } catch (e) {
      // A refused complete leaves the upload open with its parts.
      if (e instanceof UpstreamError && e.status === 412) return exists();
      throw e;
    }
  }

  if (path === "/mpu/abort" && m === "POST") {
    const body = await readJson(request);
    await s3.abortUpload(bucketName(body.bucket), objectKey(body.key), uploadId(body.uploadId));
    return json(200, {});
  }

  if (path === "/mpu/list" && m === "GET") {
    return json(200, { uploads: await s3.listUploads(bucketName(q("bucket"))) });
  }

  if (path === "/move" && m === "POST") {
    const body = await readJson(request);
    const bucket = bucketName(body.bucket);
    const from = objectKey(body.from);
    const to = objectKey(body.to);
    if (from === to) throw new BadRequest("same");
    // An object moved onto `dir/` would become that folder's marker.
    if (to.endsWith("/") && !from.endsWith("/")) throw new BadRequest("destination-is-folder");
    // The move is of this version of the source: the copy takes only it,
    // and the delete removes only it, so a concurrent replacement is kept.
    const { etag } = await s3.head(bucket, from);
    if (!etag) return error(502, "UpstreamError", "The source has no ETag; nothing was moved.");
    try {
      await s3.copy(bucket, from, to, etag);
    } catch (e) {
      if (e instanceof UpstreamError && e.status === 412) {
        return error(409, "MoveRefused", "The destination exists or the source changed; nothing was moved.");
      }
      throw e;
    }
    try {
      await s3.deleteObject(bucket, from, etag);
    } catch (e) {
      if (e instanceof UpstreamError && e.status === 412) {
        return error(409, "SourceChanged", "Copied, but the source changed meanwhile and was kept.");
      }
      // Deleted by someone else in between: the copy stands, so it moved.
      if (e instanceof UpstreamError && e.status === 404) return json(200, { from, to });
      throw e;
    }
    return json(200, { from, to });
  }

  if (path === "/delete" && m === "POST") {
    const body = await readJson(request);
    const bucket = bucketName(body.bucket);
    if (!Array.isArray(body.keys) || body.keys.length === 0 || body.keys.length > MAX_DELETE_KEYS) {
      throw new BadRequest("keys");
    }
    const keys = body.keys.map((k) => objectKey(k, { inPath: false }));
    return json(200, await s3.deleteObjects(bucket, keys));
  }

  // Not polled by the UI: velmora's status reads the outbox.
  if (path === "/status" && m === "GET") return json(200, await s3.status());

  return error(404, "NotFound", "No such route.");
}

/** `ALLOW_ADOPT=1`, or the exact name in the comma-separated `ADOPT_BUCKETS`. */
export function adoptAllowed(env, name) {
  if (env.ALLOW_ADOPT === "1") return true;
  return String(env.ADOPT_BUCKETS ?? "")
    .split(",")
    .map((s) => s.trim())
    .includes(name);
}

let cachedVerifier = null;
let cachedFor = "";

function verifierFor(env, deps) {
  if (deps.fetchCerts || deps.now) {
    return createAccessVerifier({
      teamDomain: env.ACCESS_TEAM_DOMAIN,
      aud: env.ACCESS_AUD,
      allowedEmails: parseEmails(env.ALLOWED_EMAILS),
      fetchCerts: deps.fetchCerts,
      now: deps.now,
    });
  }
  const sig = `${env.ACCESS_TEAM_DOMAIN}|${env.ACCESS_AUD}|${env.ALLOWED_EMAILS}`;
  if (!cachedVerifier || cachedFor !== sig) {
    cachedVerifier = createAccessVerifier({
      teamDomain: env.ACCESS_TEAM_DOMAIN,
      aud: env.ACCESS_AUD,
      allowedEmails: parseEmails(env.ALLOWED_EMAILS),
    });
    cachedFor = sig;
  }
  return cachedVerifier;
}

function configured(env) {
  return Boolean(
    env.S3 && env.S3_HOST && env.S3_ACCESS_KEY_ID && env.S3_SECRET_ACCESS_KEY && env.ADMIN_TOKEN && env.ASSETS,
  );
}

/** The whole request path; `deps` lets tests swap the clock and certs. */
export async function handle(request, env, deps = {}) {
  let claims;
  try {
    claims = await verifierFor(env, deps)(request.headers.get("cf-access-jwt-assertion"));
  } catch (e) {
    if (!(e instanceof AccessDenied)) console.log(JSON.stringify({ event: "access-check-error" }));
    else console.log(JSON.stringify({ event: "access-denied", reason: e.reason }));
    return forbidden();
  }
  if (!configured(env)) {
    console.log(JSON.stringify({ event: "not-configured" }));
    return forbidden();
  }

  const url = new URL(request.url);
  if (!sameOrigin(request)) return error(403, "CrossOrigin", "Cross-origin request refused.");

  if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
    const s3 = createClient({
      upstream: env.S3,
      host: env.S3_HOST,
      region: env.S3_REGION || "auto",
      accessKeyId: env.S3_ACCESS_KEY_ID,
      secretAccessKey: env.S3_SECRET_ACCESS_KEY,
      adminToken: env.ADMIN_TOKEN,
      now: deps.now,
      fixedLength: deps.fixedLength ?? defaultFixedLength,
    });
    try {
      return await api(request, env, s3, claims, url);
    } catch (e) {
      if (e instanceof BadRequest) return error(400, "BadRequest", e.message);
      if (e instanceof UpstreamError) {
        const status = e.status >= 400 && e.status < 500 ? e.status : 502;
        return error(status, e.code, e.message);
      }
      console.log(JSON.stringify({ event: "api-error", name: e?.name }));
      return error(500, "InternalError", "The request failed.");
    }
  }

  if (request.method !== "GET" && request.method !== "HEAD") return error(405, "MethodNotAllowed", "");
  const asset = await env.ASSETS.fetch(request);
  const h = secure(new Headers(asset.headers));
  h.set("cache-control", "no-store");
  return new Response(asset.body, { status: asset.status, headers: h });
}

/** Keeps a declared length on a stream body (Workers runtime only). */
function defaultFixedLength(len, body) {
  if (typeof FixedLengthStream === "undefined" || !(body instanceof ReadableStream)) return body;
  // eslint-disable-next-line no-undef
  const fixed = new FixedLengthStream(len);
  body.pipeTo(fixed.writable).catch(() => {});
  return fixed.readable;
}

export default {
  fetch(request, env) {
    return handle(request, env);
  },
};
