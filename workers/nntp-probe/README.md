# velmora-nntp-probe

A throwaway Cloudflare Worker that answers questions about real Usenet
providers before (and while) bridge code is built:

1. Can a Worker reach a provider over implicit TLS (port 563, or an
   alternate TLS port), authenticate, `POST` one velmora-shaped article,
   and read it back with `STAT` + `BODY` byte-exactly?
2. Provider discovery for the pool: greeting code and posting rights,
   `CAPABILITIES`, which backbone an account reads from (selected `HEAD`
   headers of known articles), how many concurrent sessions an account
   accepts, and which documented endpoint is fastest from Cloudflare.
3. What does the Workers runtime preserve of the raw request target and
   headers? SigV4 verification needs the original encoded path and query.

It uses the engine as-is (`velmora` with `worker-transport`) for POST/STAT/BODY:
`WorkerTransport`, `NntpClient`, `article::obfuscate_article` /
`render_obfuscated_headers` / `assemble_article`, `yenc::encode_segment` /
`decode_to`, and `media::Sealer` for real `velmora.media.v1` ciphertext. The
discovery routes need exact greeting and AUTHINFO reply codes, which the
engine's handshake folds away, so they use a minimal line-level session over
the same `connect()` socket. It is not part of the root workspace and is not
a production component. Deploy it, gather evidence, then delete it.

## Routes

Every route requires `Authorization: Bearer <PROBE_TOKEN>` and compares it in
constant time. Anything else returns `401`.

Every NNTP route takes `p=<n>` (1-9) to select account `NNTP_P<n>_*`; without
it the single-account secrets `NNTP_*` are used. Every NNTP route also takes
`alt=<k>` to use entry `k` (0-based) of that account's `NNTP_P<n>_ALT` list
instead of its configured host and port. Alternate endpoints come only from
that operator-set secret, so credentials are never sent to a host named in a
request.

| Route | What it does |
|---|---|
| `POST /probe/post?p=&size=<bytes>&payload=media\|random` | Builds one article (default: article 0 of a file, 48-byte header + 11 chunks = 721,120 B of `media.v1` ciphertext; `size` caps the ciphertext, 1 B to 8 MiB, anything else is a 400; `payload=random` posts exactly `size` random bytes; any other `payload` is a 400), opens one TLS socket, runs greeting + `MODE READER` + `AUTHINFO`, `POST`s, then `STAT` + `BODY` on the same connection, yEnc-decodes and compares SHA-256. Returns per-step timings and reply-code classes. |
| `GET /probe/body?p=&mid=<message-id>` | New connection, `STAT` + `BODY` of an article (angle brackets optional), decoded SHA-256 and timings. Used for propagation and read latency. |
| `GET /probe/caps?p=` | One connection: greeting code (200 = posting allowed, 201 = not), `CAPABILITIES` before and after auth, `MODE READER` and `AUTHINFO USER`/`PASS` codes, timings. |
| `GET /probe/head?p=&mid=<id>[&mid=<id>]...` | One connection, `HEAD` of 1 to 3 articles. Returns only `Path`, `Xref`, `Injection-Info` and `NNTP-Posting-Host`, redacted, plus the first three Path elements and the Xref server name. |
| `GET /probe/ramp?p=&n=<1-6>&hold=<0-15>` | Opens `n` sessions at once (the runtime allows six open sockets per invocation; run invocations in parallel to go higher), authenticates each, holds them `hold` seconds (default 5), sends `DATE` to check each is still alive, then `QUIT`s. Reports per-session greeting/AUTHINFO/DATE codes and timings. |
| `GET\|PUT /raw/<anything>` | Echoes `req.inner().url()`, `req.url()` (parsed), `req.path()`, the parsed query and the header list as the Worker sees them. Values are echoed only for `x-amz-*`, `content-*`, `host`, `user-agent`, `accept`, `expect` and `range`; other headers are listed by name only. For `PUT`, the body is not read; the declared `content-length` is reported. |

Responses never contain credentials. Errors are reported as a class plus the
numeric NNTP code; I/O errors from the engine routes also carry the runtime's
detail string with the selected account's host, user and password and any IP
address removed. Provider free text (greeting line, capability lines) and the
selected headers are returned only after redaction: every configured host
(shown as `<configured-host:p<n>>`), every alternate host (`<alt-host:p<n>:<k>>`),
user and password of every account is replaced, every IPv4/IPv6-shaped
substring becomes `<redacted>`, the `NNTP-Posting-Host` value is replaced
whole, and `Injection-Info` keeps only the injecting server name and
well-formed parameter names.

## Configuration

`NEWSGROUPS` (a plain var in `wrangler.toml`) is the posting allow-list.
Secrets are set with `wrangler secret put`, with the value on stdin, never on
the command line:

| Secret | Meaning |
|---|---|
| `PROBE_TOKEN` | Bearer token for every route (e.g. `openssl rand -hex 32`). |
| `NNTP_P<n>_HOST` | Account `n` provider hostname (implicit TLS). `NNTP_HOST` without `p`. |
| `NNTP_P<n>_PORT` | Account `n` TLS port, normally `563`. |
| `NNTP_P<n>_USER` | Account `n` username. |
| `NNTP_P<n>_PASS` | Account `n` password. |
| `NNTP_P<n>_ALT` | Optional: comma-separated `host:port` alternates for `alt=<k>`. |

Set many secrets at once with `wrangler secret bulk`, which reads a JSON
object from stdin; generate the JSON inside the process that reads the
credential store, so values never reach argv, a file or the terminal.

```sh
# from this directory; CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN in the environment
npx wrangler@4 deploy
printf '%s' "$VALUE" | npx wrangler@4 secret put NNTP_HOST   # repeat per secret
curl -H @auth-header-file -X POST "https://<worker>.workers.dev/probe/post"
npx wrangler@4 delete velmora-nntp-probe                      # when done
```

Keep the bearer header in a mode-0600 file (`curl -H @file`) so the token
never appears in a process list. Run probes one at a time and one account at
a time: each call except `/probe/ramp` opens one provider connection. Accounts
sold as one bundle can share a connection limit, so never ramp two of them at
once, and stop a ramp at the first refusal.

## Build

```sh
cargo install worker-build   # once
worker-build --release       # run by `wrangler deploy` via [build]
cargo clippy --target wasm32-unknown-unknown -- -D warnings
cargo test   # native unit tests for the redaction and parsing helpers
```
