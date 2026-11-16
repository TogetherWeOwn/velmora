// AWS Signature Version 4 for S3 (header-signed requests only).

export const EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
export const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

const enc = new TextEncoder();

export function toHex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(data) {
  const bytes = typeof data === "string" ? enc.encode(data) : data;
  return toHex(await crypto.subtle.digest("SHA-256", bytes));
}

export async function sha256Base64(data) {
  const bytes = typeof data === "string" ? enc.encode(data) : data;
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  let s = "";
  for (const b of d) s += String.fromCharCode(b);
  return btoa(s);
}

async function hmac(key, data) {
  const k = await crypto.subtle.importKey(
    "raw",
    typeof key === "string" ? enc.encode(key) : key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, enc.encode(data)));
}

/** RFC 3986 encoding as SigV4 wants it: only unreserved characters stay. */
export function uriEncode(s) {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

/** An object key as a path: every segment encoded, `/` kept. */
export function encodeKey(key) {
  return key.split("/").map(uriEncode).join("/");
}

/** `[[name, value], ...]` → canonical query string (sorted, encoded). */
export function canonicalQuery(params) {
  return params
    .map(([k, v]) => [uriEncode(k), uriEncode(v ?? "")])
    .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
}

export function amzDate(ms) {
  return new Date(ms).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
}

/**
 * Signs a request. `path` is already encoded (see `encodeKey`); `query`
 * is a list of `[name, value]` pairs; `headers` is a plain object. Every
 * header given is signed, so callers pass only what they send. Returns
 * the headers to send, including `authorization`.
 */
export async function sign({
  method,
  host,
  path,
  query = [],
  headers = {},
  payloadHash,
  accessKeyId,
  secretAccessKey,
  region,
  service = "s3",
  now,
}) {
  const date = amzDate(now);
  const day = date.slice(0, 8);
  const all = {};
  for (const [k, v] of Object.entries(headers)) all[k.toLowerCase()] = String(v).trim().replace(/\s+/g, " ");
  all.host = host;
  all["x-amz-date"] = date;
  all["x-amz-content-sha256"] = payloadHash;
  const names = Object.keys(all).sort();
  const canonicalHeaders = names.map((n) => `${n}:${all[n]}\n`).join("");
  const signedHeaders = names.join(";");
  const canonical = [method, path, canonicalQuery(query), canonicalHeaders, signedHeaders, payloadHash].join("\n");
  const scope = `${day}/${region}/${service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", date, scope, await sha256Hex(canonical)].join("\n");
  let k = await hmac(`AWS4${secretAccessKey}`, day);
  k = await hmac(k, region);
  k = await hmac(k, service);
  k = await hmac(k, "aws4_request");
  const signature = toHex(await hmac(k, toSign));
  // `host` is sent as a header too: over a service binding the callee
  // sees only the headers of the Request, not one made from its URL.
  const out = { ...all };
  out.authorization = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { headers: out, signature, canonical };
}
