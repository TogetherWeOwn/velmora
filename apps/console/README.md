# velmora console

A small web file manager for one velmora account, as a Cloudflare Worker
with a static page. It is a stopgap until a full frontend exists.

It lists and creates buckets; browses prefixes as folders, with
breadcrumbs, sizes, dates and a filter; and uploads files and folders by
drag and drop. Files of 16 MiB or more go up as multipart in 16 MiB parts,
with progress, cancel and resume. Downloads support Range. It also does
rename and move, new folders, and single or bulk delete. Each object has
an info view that shows velmora's state for it (posting, verifying,
verified, released). A status panel shows `/_admin/status` and refreshes
only on demand.

## How it is put together

- `src/worker.js`: the entry point, the same-origin checks, the `/api/*`
  routes and the security headers.
- `src/access.js`: Cloudflare Access JWT verification. It checks RS256
  against the team's certs, then `iss`, `aud`, `exp`/`nbf` and an email
  allow list.
- `src/sigv4.js`, `src/s3.js`, `src/xml.js`: SigV4 signing and the S3 and
  admin calls.
- `public/`: the page. It is plain HTML, CSS and JavaScript, with no build
  step.

The browser only ever talks to this Worker. The Worker calls velmora
through a service binding. It signs S3 requests with its own access key
and calls the admin API with the admin token. Both are Worker secrets and
never reach the browser.

## Security

- **Access JWT.** Every request, the page included, needs a valid
  `Cf-Access-Jwt-Assertion`; otherwise the answer is `403`. If the Access
  configuration is missing, everything is refused. Put the hostname behind
  a Cloudflare Access application, with a policy that matches
  `ALLOWED_EMAILS`.
- **Same origin only.** Mutations need an `Origin` equal to the page's own
  origin, and JSON routes need a JSON content type. There are no CORS
  headers at all.
- **CSP.** The page gets a strict CSP (`default-src 'none'`, scripts and
  styles from `'self'` only, `frame-ancestors 'none'`).
- **Downloads.** Downloads are always attachments, with a sandbox CSP, so
  object bytes never run as this origin.

## Buckets and the console key

velmora access keys are scoped to named buckets. When the console creates
a bucket, it calls `POST /_admin/keys/<id>/grants` to grant its own key
`rw` on the new bucket. To use the console with existing buckets, mint its
key with those buckets, or grant them the same way.

## Deploy

1. Copy `wrangler.example.toml` outside the repo and fill it in.
2. Set the three secrets with `npx wrangler secret put`, value on stdin.
3. Run `npx wrangler deploy -c <copy>`.
4. Attach the hostname as a Workers custom domain, and put it behind
   Access.

At idle it costs nothing beyond the Workers plan. It uses no KV, no
Durable Objects and no Logs.

## Tests

    node --test test/*.test.js

They cover:
- the JWT check: missing token, wrong `aud`, wrong issuer, expired, bad
  signature, unknown key and email, each one a `403`;
- SigV4 against AWS's worked examples, and the signing of every request
  type;
- streamed downloads with Range;
- the same-origin rules and the CSP.
