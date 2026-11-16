// Cloudflare Access JWT verification (RS256 against the team's certs).
//
// Every request must carry `Cf-Access-Jwt-Assertion`. The token is
// accepted only if its signature verifies under a key of the team's
// certs endpoint, `iss` is the team domain, `aud` holds the application's
// AUD tag, it is inside its validity window and its email is allowed.
// Anything else, including a configuration gap or a certs fetch failure,
// is a refusal.

const LEEWAY_S = 30;
const CERTS_TTL_MS = 10 * 60 * 1000;
// An unknown `kid` forces a certs refresh at most this often, so forged
// tokens cannot make every request fetch the certs.
const REFRESH_MIN_INTERVAL_MS = 60 * 1000;
const TEAM_DOMAIN_RE = /^[a-z0-9][a-z0-9-]{0,62}\.cloudflareaccess\.com$/;
const AUD_RE = /^[0-9a-f]{64}$/;

export class AccessDenied extends Error {
  constructor(reason) {
    super(reason);
    this.name = "AccessDenied";
    this.reason = reason;
  }
}

function deny(reason) {
  throw new AccessDenied(reason);
}

function b64urlToBytes(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) deny("encoding");
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  let bin;
  try {
    bin = atob(b64);
  } catch {
    deny("encoding");
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function decodeJson(part) {
  try {
    const v = JSON.parse(new TextDecoder().decode(b64urlToBytes(part)));
    if (v === null || typeof v !== "object" || Array.isArray(v)) deny("json");
    return v;
  } catch (e) {
    if (e instanceof AccessDenied) throw e;
    deny("json");
  }
}

/** Parses the comma-separated allow list into lower-case emails. */
export function parseEmails(list) {
  return String(list ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * @param {object} opts
 * @param {string} opts.teamDomain  e.g. `example.cloudflareaccess.com`
 * @param {string} opts.aud         the Access application's AUD tag
 * @param {string[]} opts.allowedEmails
 * @param {(url: string) => Promise<Response>} [opts.fetchCerts]
 * @param {() => number} [opts.now] milliseconds
 */
export function createAccessVerifier({ teamDomain, aud, allowedEmails, fetchCerts, now }) {
  const configured =
    typeof teamDomain === "string" &&
    TEAM_DOMAIN_RE.test(teamDomain) &&
    typeof aud === "string" &&
    AUD_RE.test(aud) &&
    Array.isArray(allowedEmails) &&
    allowedEmails.length > 0;
  const issuer = `https://${teamDomain}`;
  const certsUrl = `${issuer}/cdn-cgi/access/certs`;
  const getCerts = fetchCerts ?? ((url) => fetch(url, { signal: AbortSignal.timeout(5000) }));
  const clock = now ?? (() => Date.now());
  const allowed = new Set((allowedEmails ?? []).map((e) => String(e).toLowerCase()));

  let keys = new Map(); // kid -> CryptoKey
  let fetchedAt = -Infinity;
  let lastRefresh = -Infinity;

  async function refresh() {
    lastRefresh = clock();
    let res;
    try {
      res = await getCerts(certsUrl);
    } catch {
      deny("certs-unreachable");
    }
    if (!res.ok) deny("certs-status");
    let body;
    try {
      body = await res.json();
    } catch {
      deny("certs-json");
    }
    const next = new Map();
    for (const jwk of Array.isArray(body?.keys) ? body.keys : []) {
      if (jwk?.kty !== "RSA" || typeof jwk.kid !== "string" || !jwk.n || !jwk.e) continue;
      try {
        const key = await crypto.subtle.importKey(
          "jwk",
          { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
          { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
          false,
          ["verify"],
        );
        next.set(jwk.kid, key);
      } catch {
        // A key that does not import is skipped, never trusted.
      }
    }
    if (next.size === 0) deny("certs-empty");
    keys = next;
    fetchedAt = clock();
  }

  // One certs fetch at a time; concurrent requests wait for it.
  let inflight = null;
  function refreshOnce() {
    if (!inflight) inflight = refresh().finally(() => (inflight = null));
    return inflight;
  }

  async function keyFor(kid) {
    if (clock() - fetchedAt > CERTS_TTL_MS) {
      if (inflight) await inflight;
      // The last attempt failed, and recently: refuse without fetching again.
      else if (fetchedAt < lastRefresh && clock() - lastRefresh < REFRESH_MIN_INTERVAL_MS) deny("certs-unavailable");
      else await refreshOnce();
    }
    let key = keys.get(kid);
    if (!key && (inflight || clock() - lastRefresh >= REFRESH_MIN_INTERVAL_MS)) {
      await refreshOnce();
      key = keys.get(kid);
    }
    if (!key) deny("unknown-kid");
    return key;
  }

  /** Returns the verified claims, or throws `AccessDenied`. */
  return async function verify(token) {
    if (!configured) deny("not-configured");
    if (typeof token !== "string" || token.length === 0) deny("missing");
    if (token.length > 16384) deny("too-long");
    const parts = token.split(".");
    if (parts.length !== 3) deny("shape");
    const header = decodeJson(parts[0]);
    if (header.alg !== "RS256") deny("alg");
    if (typeof header.kid !== "string") deny("kid");
    const key = await keyFor(header.kid);
    const signature = b64urlToBytes(parts[2]);
    const signed = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, signed);
    if (!ok) deny("signature");

    const claims = decodeJson(parts[1]);
    if (claims.iss !== issuer) deny("iss");
    const auds = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!auds.includes(aud)) deny("aud");
    const nowS = clock() / 1000;
    if (typeof claims.exp !== "number" || nowS > claims.exp + LEEWAY_S) deny("expired");
    if (claims.nbf !== undefined && (typeof claims.nbf !== "number" || nowS + LEEWAY_S < claims.nbf)) {
      deny("not-yet-valid");
    }
    if (typeof claims.email !== "string" || !allowed.has(claims.email.toLowerCase())) deny("email");
    return claims;
  };
}
