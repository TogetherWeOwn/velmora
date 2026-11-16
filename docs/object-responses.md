# Object responses behind the edge

GetObject and HeadObject answers pass through the Cloudflare edge before
they reach the client. Two settings keep them byte-exact, with the
`Content-Length` and the strong `ETag` that S3 clients read the size and
the MD5 from.

## `Cache-Control: no-transform` (bridge, `service/get.rs`)

Without it, the edge does two things that drop `Content-Length` and drop
or weaken `ETag`, on HEAD as well:

- it compresses compressible types (`text/*`, JSON, JavaScript, SVG, ...)
  for clients that accept gzip or brotli;
- it rewrites every `text/html` response (email obfuscation and similar
  features), whatever the client accepts.

Range answers (`206`) are left alone. rclone, for one, reads a missing
length as size 0, takes the upload for corrupt and deletes it.

Every object answer (`200`, `206`, `304`) therefore carries `no-transform`:

| Stored `Cache-Control` | Served `Cache-Control` |
|---|---|
| none | `no-transform` |
| `max-age=60` | `max-age=60, no-transform` |
| one that has `no-transform` already | unchanged |

The stored metadata is not changed, and the directive only forbids changing
the bytes. This is a deliberate deviation from returning the stored value
verbatim: a client that compares HeadObject's `CacheControl` with what it
uploaded sees the appended directive.

## `encodeBody: "manual"` (Worker, `workers/s3-bridge/src/http.rs`)

An object stored with `Content-Encoding` (for example a gzip body uploaded
with `--content-encoding gzip`) is served with that header. Under the
runtime's default (`automatic`) the Worker compresses such a body again and
drops its length. Every response is therefore built with
`encodeBody: "manual"`, so the stored bytes are sent as they are.

One difference from S3 remains outside the Worker. For a compressible
`Content-Type` (`text/*`, JSON) and a client that does not accept gzip,
the runtime in front of the Worker leaves the `Content-Encoding` header out
of the answer. Under `wrangler dev` this was measured on HEAD, with
`manual` and `no-transform` set as well. `application/octet-stream` keeps
it.
