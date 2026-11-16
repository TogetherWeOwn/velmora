// S3 and admin calls to velmora through the service binding. The S3
// secret and the admin token stay in this module's closure: nothing here
// returns them or puts them in a response.

import { blocks, decodeEntities, escapeXml, strip, text } from "./xml.js";
import { EMPTY_SHA256, UNSIGNED_PAYLOAD, encodeKey, sha256Base64, sha256Hex, sign, uriEncode } from "./sigv4.js";

export class UpstreamError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

async function failure(res) {
  let body = "";
  try {
    body = await res.text();
  } catch {
    /* ignore */
  }
  let code = text(body, "Code");
  let message = text(body, "Message");
  if (!code) {
    try {
      const j = JSON.parse(body);
      code = j.error;
      message = j.message;
    } catch {
      /* not JSON */
    }
  }
  return new UpstreamError(res.status, code || `HTTP${res.status}`, message || "");
}

function urlDecode(s, encoded) {
  if (s === undefined || !encoded) return s;
  try {
    return decodeURIComponent(s.replace(/\+/g, "%20"));
  } catch {
    return s;
  }
}

/**
 * Second guard behind key validation: the URL parser must not have
 * changed the path (dot segments, for one), or the request would go
 * somewhere other than what was checked and signed.
 */
function assertPath(url, path) {
  if (new URL(url).pathname !== path) throw new UpstreamError(400, "InvalidKey", "The key does not map to a path.");
}

/**
 * @param {object} cfg
 * @param {{fetch: (req: Request) => Promise<Response>}} cfg.upstream service binding
 * @param {string} cfg.host       the S3 host velmora answers to
 * @param {string} cfg.region
 * @param {string} cfg.accessKeyId
 * @param {string} cfg.secretAccessKey
 * @param {string} cfg.adminToken
 * @param {() => number} [cfg.now]
 * @param {(len: number, body: ReadableStream) => ReadableStream} [cfg.fixedLength]
 */
export function createClient(cfg) {
  const now = cfg.now ?? (() => Date.now());

  async function send({ method, bucket, key, query = [], headers = {}, body, payloadHash }) {
    let path = "/";
    if (bucket) path += bucket;
    if (key !== undefined) path += "/" + encodeKey(key);
    const hash = payloadHash ?? (body === undefined ? EMPTY_SHA256 : UNSIGNED_PAYLOAD);
    const signed = await sign({
      method,
      host: cfg.host,
      path,
      query,
      headers,
      payloadHash: hash,
      accessKeyId: cfg.accessKeyId,
      secretAccessKey: cfg.secretAccessKey,
      region: cfg.region,
      now: now(),
    });
    // The query is sent exactly as it was signed: velmora canonicalises
    // the raw query string, and encodeURIComponent leaves `!'()*` alone.
    const qs = query.length ? "?" + query.map(([k, v]) => `${uriEncode(k)}=${uriEncode(v ?? "")}`).join("&") : "";
    const url = `https://${cfg.host}${path}${qs}`;
    assertPath(url, path);
    const init = { method, headers: signed.headers };
    if (body !== undefined) {
      init.body = body;
      if (body instanceof ReadableStream) init.duplex = "half";
    }
    return cfg.upstream.fetch(new Request(url, init));
  }

  async function ok(res) {
    if (!res.ok) throw await failure(res);
    return res;
  }

  async function xmlBody(bodyText) {
    const bytes = new TextEncoder().encode(bodyText);
    return { body: bytes, payloadHash: await sha256Hex(bytes), checksum: await sha256Base64(bytes) };
  }

  async function admin(method, path, json) {
    const headers = { authorization: `Bearer ${cfg.adminToken}` };
    let body;
    if (json !== undefined) {
      body = JSON.stringify(json);
      headers["content-type"] = "application/json";
    }
    const url = `https://${cfg.host}/_admin${path}`;
    assertPath(url, `/_admin${path}`);
    const res = await cfg.upstream.fetch(new Request(url, { method, headers, body }));
    if (!res.ok) throw await failure(res);
    return res.status === 204 ? null : res.json();
  }

  /** A stream body with a declared length, so velmora gets Content-Length. */
  function sized(stream, len) {
    return cfg.fixedLength ? cfg.fixedLength(len, stream) : stream;
  }

  return {
    send,

    async listBuckets() {
      const xml = await (await ok(await send({ method: "GET" }))).text();
      return blocks(xml, "Bucket").map((b) => ({ name: text(b, "Name"), created: text(b, "CreationDate") }));
    },

    async list(bucket, { prefix = "", delimiter = "/", token, maxKeys = 1000 } = {}) {
      const query = [
        ["list-type", "2"],
        ["encoding-type", "url"],
        ["max-keys", String(maxKeys)],
        ["prefix", prefix],
      ];
      if (delimiter) query.push(["delimiter", delimiter]);
      if (token) query.push(["continuation-token", token]);
      const xml = await (await ok(await send({ method: "GET", bucket, query }))).text();
      const encoded = text(xml, "EncodingType") === "url";
      const folders = blocks(xml, "CommonPrefixes").map((b) => urlDecode(text(b, "Prefix"), encoded));
      const files = blocks(xml, "Contents").map((b) => ({
        key: urlDecode(text(b, "Key"), encoded),
        size: Number(text(b, "Size") ?? 0),
        modified: text(b, "LastModified"),
        etag: text(b, "ETag"),
      }));
      const top = strip(strip(xml, "Contents"), "CommonPrefixes");
      return {
        folders,
        files,
        truncated: text(top, "IsTruncated") === "true",
        next: text(top, "NextContinuationToken") || null,
      };
    },

    async head(bucket, key) {
      const res = await send({ method: "HEAD", bucket, key });
      if (!res.ok) throw new UpstreamError(res.status, res.status === 404 ? "NoSuchKey" : `HTTP${res.status}`, "");
      const h = res.headers;
      return {
        size: Number(h.get("content-length") ?? 0),
        etag: h.get("etag"),
        contentType: h.get("content-type"),
        modified: h.get("last-modified"),
      };
    },

    /** The raw upstream response, streamed; the caller maps it. */
    get(bucket, key, range) {
      const headers = range ? { range } : {};
      return send({ method: "GET", bucket, key, headers });
    },

    async put(bucket, key, stream, len, contentType, extra = {}) {
      const headers = { "content-type": contentType, ...extra };
      const res = await ok(await send({ method: "PUT", bucket, key, headers, body: sized(stream, len) }));
      return { etag: res.headers.get("etag") };
    },

    async createUpload(bucket, key, contentType) {
      const res = await ok(
        await send({ method: "POST", bucket, key, query: [["uploads", ""]], headers: { "content-type": contentType } }),
      );
      return { uploadId: text(await res.text(), "UploadId") };
    },

    async uploadPart(bucket, key, uploadId, partNumber, stream, len) {
      const query = [
        ["partNumber", String(partNumber)],
        ["uploadId", uploadId],
      ];
      const res = await ok(await send({ method: "PUT", bucket, key, query, body: sized(stream, len) }));
      return { etag: res.headers.get("etag") };
    },

    async listParts(bucket, key, uploadId) {
      const parts = [];
      let marker;
      for (let i = 0; i < 100; i++) {
        const query = [["uploadId", uploadId]];
        if (marker) query.push(["part-number-marker", marker]);
        const xml = await (await ok(await send({ method: "GET", bucket, key, query }))).text();
        for (const b of blocks(xml, "Part")) {
          parts.push({ partNumber: Number(text(b, "PartNumber")), etag: text(b, "ETag"), size: Number(text(b, "Size")) });
        }
        const top = strip(xml, "Part");
        if (text(top, "IsTruncated") !== "true") break;
        marker = text(top, "NextPartNumberMarker");
        if (!marker) break;
      }
      return parts;
    },

    async listUploads(bucket) {
      const xml = await (await ok(await send({ method: "GET", bucket, query: [["uploads", ""]] }))).text();
      return blocks(xml, "Upload").map((b) => ({
        key: text(b, "Key"),
        uploadId: text(b, "UploadId"),
        initiated: text(b, "Initiated"),
      }));
    },

    async completeUpload(bucket, key, uploadId, parts, overwrite = false) {
      const xml =
        "<CompleteMultipartUpload>" +
        parts
          .map((p) => `<Part><PartNumber>${p.partNumber}</PartNumber><ETag>${escapeXml(p.etag)}</ETag></Part>`)
          .join("") +
        "</CompleteMultipartUpload>";
      const b = await xmlBody(xml);
      const res = await ok(
        await send({
          method: "POST",
          bucket,
          key,
          query: [["uploadId", uploadId]],
          headers: overwrite ? { "content-type": "application/xml" } : { "content-type": "application/xml", "if-none-match": "*" },
          body: b.body,
          payloadHash: b.payloadHash,
        }),
      );
      // A complete can fail inside a 200 answer.
      const out = await res.text();
      if (blocks(out, "Error").length) throw new UpstreamError(500, text(out, "Code") || "InternalError", text(out, "Message"));
      return { etag: text(out, "ETag") };
    },

    async abortUpload(bucket, key, uploadId) {
      await ok(await send({ method: "DELETE", bucket, key, query: [["uploadId", uploadId]] }));
    },

    /** Same-bucket copy that never overwrites an existing destination. */
    async copy(bucket, from, to) {
      const headers = { "x-amz-copy-source": `/${bucket}/${encodeKey(from)}`, "if-none-match": "*" };
      const res = await ok(await send({ method: "PUT", bucket, key: to, headers }));
      const out = await res.text();
      if (blocks(out, "Error").length) throw new UpstreamError(500, text(out, "Code") || "InternalError", text(out, "Message"));
    },

    async deleteObject(bucket, key) {
      await ok(await send({ method: "DELETE", bucket, key }));
    },

    async deleteObjects(bucket, keys) {
      const xml =
        "<Delete><Quiet>true</Quiet>" +
        keys.map((k) => `<Object><Key>${escapeXml(k)}</Key></Object>`).join("") +
        "</Delete>";
      const b = await xmlBody(xml);
      const res = await ok(
        await send({
          method: "POST",
          bucket,
          query: [["delete", ""]],
          headers: { "content-type": "application/xml", "x-amz-checksum-sha256": b.checksum },
          body: b.body,
          payloadHash: b.payloadHash,
        }),
      );
      const out = await res.text();
      // Keep-alive whitespace can precede the document; errors are per key.
      const errors = blocks(out, "Error").map((e) => ({ key: text(e, "Key"), code: text(e, "Code") }));
      return { errors };
    },

    createBucket(name) {
      return admin("POST", "/buckets", { name, disposable: false });
    },
    grant(accessKeyId, bucket, perm) {
      return admin("POST", `/keys/${encodeURIComponent(accessKeyId)}/grants`, { bucket, perm });
    },
    objectState(bucket, key) {
      return admin("GET", `/objects/${bucket}/${encodeKey(key)}`);
    },
    status() {
      return admin("GET", "/status");
    },
  };
}

export { decodeEntities };
