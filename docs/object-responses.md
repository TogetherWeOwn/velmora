# Object responses behind the edge

GetObject and HeadObject answers pass through the Cloudflare edge before
they reach the client. Two settings keep them byte-exact, with the
`Content-Length` and the strong `ETag` that S3 clients read the size and
the MD5 from. Two more headers keep a browser from treating an object as
a page of the service.

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

## `X-Content-Type-Options: nosniff` and `Content-Security-Policy: sandbox` (bridge, `service/get.rs`)

Every object answer (`200`, `206`, `304`, and HEAD) carries both. An
object is data, never a page of the host that serves it:

- `nosniff`: the browser takes the stored `Content-Type` as it is and does
  not guess a more powerful one (an upload named `.jpg` that holds HTML
  stays an image or a download).
- `sandbox`: an object opened as a document, HTML or SVG for one, runs no
  script, submits no form and gets an origin of its own, so it reads no
  cookie and no storage of the serving site's origin.

A stored header of either name is replaced (an object cannot store one
today). `Content-Disposition` is left as stored, so audio and video play
and downloads work as before. Error answers are unchanged.

Known costs: a document view that needs script (a browser's built-in PDF
viewer, for one) may not run inside a sandboxed document; downloading the
object works. An object stored without a `Content-Type` is served without
one, which a browser shows as text under `nosniff`.

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
