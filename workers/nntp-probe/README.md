# velmora-nntp-probe

A throwaway Cloudflare Worker that answers two questions before any bridge
code is built:

1. Can a Worker reach a real Usenet provider over implicit TLS (port 563),
   authenticate, `POST` one velmora-shaped article, and read it back with
   `STAT` + `BODY` byte-exactly?
2. What does the Workers runtime preserve of the raw request target and
   headers? SigV4 verification needs the original encoded path and query.

It uses the engine as-is (`velmora` with `worker-transport`): `WorkerTransport`,
`NntpClient`, `article::obfuscate_article` / `render_obfuscated_headers` /
`assemble_article`, `yenc::encode_segment` / `decode_to`, and `media::Sealer`
for real `velmora.media.v1` ciphertext. It is not part of the root workspace
and is not a production component. Deploy it, gather evidence, then delete it.

## Routes

Every route requires `Authorization: Bearer <PROBE_TOKEN>` and compares it in
constant time. Anything else returns `401`.

| Route | What it does |
|---|---|
| `POST /probe/post?size=<bytes>&payload=media\|random` | Builds one article (default: article 0 of a file, 48-byte header + 11 chunks = 721,120 B of `media.v1` ciphertext; `size` caps the ciphertext, 1 B to 8 MiB, anything else is a 400; `payload=random` posts exactly `size` random bytes; any other `payload` is a 400), opens one TLS socket, runs greeting + `MODE READER` + `AUTHINFO`, `POST`s, then `STAT` + `BODY` on the same connection, yEnc-decodes and compares SHA-256. Returns per-step timings and reply-code classes. |
| `GET /probe/body?mid=<message-id>` | New connection, `STAT` + `BODY` of an earlier post, decoded SHA-256 and timings. Used to measure propagation. |
| `GET\|PUT /raw/<anything>` | Echoes `req.inner().url()`, `req.url()` (parsed), `req.path()`, the parsed query and the header list as the Worker sees them. Values are echoed only for `x-amz-*`, `content-*`, `host`, `user-agent`, `accept`, `expect` and `range`; other headers are listed by name only. For `PUT`, the body is not read; the declared `content-length` is reported. |

Responses never contain provider reply text, the provider host or account
values. Errors are reported as a class plus the numeric NNTP code.

## Configuration

`NEWSGROUPS` (a plain var in `wrangler.toml`) is the posting allow-list.
Secrets are set with `wrangler secret put`, with the value on stdin, never on
the command line:

| Secret | Meaning |
|---|---|
| `PROBE_TOKEN` | Bearer token for every route (e.g. `openssl rand -hex 32`). |
| `NNTP_HOST` | Provider hostname (implicit TLS). |
| `NNTP_PORT` | Provider TLS port, normally `563`. |
| `NNTP_USER` | Account username. |
| `NNTP_PASS` | Account password. |

```sh
# from this directory; CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN in the environment
npx wrangler@4 deploy
printf '%s' "$VALUE" | npx wrangler@4 secret put NNTP_HOST   # repeat per secret
curl -H @auth-header-file -X POST "https://<worker>.workers.dev/probe/post"
npx wrangler@4 delete velmora-nntp-probe                      # when done
```

Keep the bearer header in a mode-0600 file (`curl -H @file`) so the token
never appears in a process list. Run probes one at a time: each call opens
one provider connection.

## Build

```sh
cargo install worker-build   # once
worker-build --release       # run by `wrangler deploy` via [build]
cargo clippy --target wasm32-unknown-unknown -- -D warnings
```
