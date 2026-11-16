// Test helpers: an Access-like signer and a fake velmora upstream.

export const TEAM = "example-team.cloudflareaccess.com";
export const AUD = "a".repeat(64);
export const EMAIL = "owner@example.com";
export const NOW = Date.UTC(2026, 10, 16, 12, 0, 0);

const b64url = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const b64urlJson = (v) => b64url(new TextEncoder().encode(JSON.stringify(v)));

export async function makeIssuer(kid = "k1") {
  const pair = await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const certs = { keys: [{ kty: "RSA", kid, alg: "RS256", use: "sig", n: jwk.n, e: jwk.e }] };
  let certFetches = 0;
  return {
    kid,
    get certFetches() {
      return certFetches;
    },
    fetchCerts: async (url) => {
      certFetches++;
      if (url !== `https://${TEAM}/cdn-cgi/access/certs`) return new Response("no", { status: 404 });
      return Response.json(certs);
    },
    async token(claims = {}, header = {}) {
      const h = { alg: "RS256", kid, typ: "JWT", ...header };
      const c = {
        iss: `https://${TEAM}`,
        aud: [AUD],
        email: EMAIL,
        iat: NOW / 1000 - 60,
        nbf: NOW / 1000 - 60,
        exp: NOW / 1000 + 3600,
        ...claims,
      };
      const input = `${b64urlJson(h)}.${b64urlJson(c)}`;
      const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, new TextEncoder().encode(input));
      return `${input}.${b64url(sig)}`;
    },
  };
}

/** A recording fake of velmora behind the service binding. */
export function fakeUpstream(handler) {
  const calls = [];
  return {
    calls,
    async fetch(req) {
      const body = req.body ? new Uint8Array(await req.arrayBuffer()) : null;
      calls.push({ method: req.method, url: new URL(req.url), headers: Object.fromEntries(req.headers), body });
      return handler(calls.at(-1));
    },
  };
}

export const SECRET = "SECRETsecretSECRETsecretSECRETsecret0000";
export const ADMIN = "admin-token-for-tests-admin-token-for-tests";

export function env(upstream, extra = {}) {
  return {
    S3: upstream,
    S3_HOST: "s3.example.test",
    S3_REGION: "auto",
    S3_ACCESS_KEY_ID: "AKVLTESTTESTTESTTEST",
    S3_SECRET_ACCESS_KEY: SECRET,
    ADMIN_TOKEN: ADMIN,
    ACCESS_TEAM_DOMAIN: TEAM,
    ACCESS_AUD: AUD,
    ALLOWED_EMAILS: EMAIL,
    ASSETS: { fetch: async () => new Response("<!doctype html><title>x</title>", { headers: { "content-type": "text/html" } }) },
    ...extra,
  };
}
