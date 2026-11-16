# Conditional writes

A write can be held to the state of the key it writes. The condition is
judged inside the database batch that publishes the write, so no write
is published on a condition that another write has made false in the
meantime.

## What is understood

| Header | PutObject, CopyObject (destination), CompleteMultipartUpload | DeleteObject |
| --- | --- | --- |
| `If-None-Match: *` | written only if the key has no object; else `412 PreconditionFailed` | `501 NotImplemented` |
| `If-Match: <etag>` | written only if the object of the key has this ETag; another ETag is `412 PreconditionFailed`, no object is `404 NoSuchKey` | deleted only if the object has this ETag; else `412`, no object `404 NoSuchKey` |
| `If-Match: *` | as above, for any object of the key | as above, for any object |

The ETag is the one a GET or HEAD of the object gives, with or without
its quotes.

Everything else is `501 NotImplemented`. A condition is never ignored:

- `If-Modified-Since` and `If-Unmodified-Since` on any write;
- `If-None-Match` with an ETag, a list of ETags, a weak ETag (`W/"…"`),
  `If-Match` together with `If-None-Match`;
- any of these headers on CreateMultipartUpload, UploadPart,
  AbortMultipartUpload and DeleteObjects;
- a condition on one key of a DeleteObjects document (`ETag`,
  `LastModifiedTime`, `Size`).

The conditions of a copy on its source (`x-amz-copy-source-if-*`) are
separate headers and not part of this.

## What a refused write leaves

- A PutObject whose condition does not hold when the request arrives is
  answered before its body is read.
- A write that is refused leaves no published generation, no object
  row and no recovery record: a replay of the recovery records does not
  bring it back. A refused DeleteObject leaves no tombstone that deletes
  anything.
- A write whose condition does not hold when it is first looked at
  leaves nothing at all. One that loses its key during the request
  (a race) can leave the internal marker of the newest id of the key
  (its floor), as any write that is not published can. A bucket with
  such a marker counts as in use for DeleteBucket until the key is
  written again.
- A PutObject that loses the key after its body was stored leaves the
  stored bytes behind unreferenced, like any PUT that is not published,
  and they are handled the same way.
- Of two writes that race for one key under a condition the first one
  makes false (`If-None-Match: *`, or `If-Match` on an ETag the write
  replaces by another), one is published. The other is answered `412`
  (or `404`, when the object it named was deleted). After several lost
  rounds in a row a request is answered `503 SlowDown` instead and can
  be sent again.
- A condition that still holds after another write is not a lock: two
  `If-Match: *` writes on a live key both succeed, one after the other,
  and so do two `If-Match` writes that leave the ETag as it was.

## CompleteMultipartUpload

A Complete that is refused with `412` or `404` changes nothing about the
upload: it stays open with all its parts. The client can send Complete
again (with or without a condition), or abort the upload.

A Complete that is sent again after it succeeded is answered `200` from
the result of the first one, whatever the key holds by then: it is the
same request, not a second write.

## DeleteObject beside a write

A DeleteObject, with or without a condition, is answered `204` only as
the newest thing that happened to its key. When a write on the key began
or was published after the delete chose its place in the order, the
delete changes nothing and starts again after that write:

- a write that was answered before the delete is deleted by it;
- a conditional write that is still under way when the delete is done
  finds the key empty (`404`, or `412` for another object by then), and
  its recovery record, should it stay behind, sorts below the delete: a
  replay of the records does not publish it over the delete.

A delete that meets a newer write several times in a row is answered
`503 SlowDown` (in DeleteObjects: for that key) and can be sent again.

## DeleteObjects

A DeleteObjects request deletes each key it names the way a DeleteObject
does, and leaves what one DeleteObject per key leaves: the same
tombstone record for each key, stored before the catalogue changes, and
the same catalogue rows. What differs is the number of calls. The keys
are taken in chunks of up to 50 (less for long keys: 32 KiB of key text
a chunk), four chunks at a time, and each step of a chunk is one
catalogue call for all its keys: one read of their ids, one batch that
raises their floors, one that settles them, one that deletes. The
tombstones are stored one record a key, six at a time within a chunk.

- A key named more than once is deleted once; every mention gets the
  answer of the first.
- A key whose tombstone cannot be stored is reported with
  `InternalError`; the other keys are not affected. A catalogue call
  before the deleting batch that fails does so for every key of its
  chunk: they are reported with `InternalError`, the keys of the other
  chunks are not affected.
- When the deleting batch of a chunk is refused (a write or another
  delete moved one of its keys meanwhile), nothing of it is applied and
  each of its keys goes on alone, on the path of a DeleteObject, with
  the tombstone it already has on record.
- When the deleting batch of a chunk is not answered, it failed or it
  was applied. Each of its keys is tried once more alone, under the
  tombstone it has, and never under a new one: a key is reported
  deleted when it is gone, and with `InternalError` when a write has
  taken it meanwhile or the outcome cannot be told.

A request of 1,000 live keys with nothing else at work on them makes
about 100 catalogue calls and 1,000 store calls (before: about 7,000 and
1,000). When every chunk is refused once it is about 6 calls a key; a
key that keeps meeting newer writes ends as `SlowDown` after four
tries, as before.

### The answer of a long DeleteObjects

The tombstone puts take time: a request of 1,000 keys can take longer
than a client waits for an answer (aws-cli: 60 s with nothing read).
So DeleteObjects answers the way S3 does for long operations:

- Everything that can fail the request comes first: authentication,
  the gates, the integrity check and the reading of the document. A
  failure there is answered with its status code, as before.
- After that the answer is `200`. When all keys are settled within
  2 s, the `DeleteResult` is sent as one buffered body with its
  length, byte for byte as before.
- Otherwise the headers go out at 2 s, with
  `<?xml version="1.0" encoding="UTF-8"?>` at once, then one newline
  every 5 s while the keys are deleted, then the `DeleteResult`. White
  space between the declaration and the root element is allowed by the
  XML grammar; aws-cli and the JS SDK v3 read it. The streamed body
  carries `cache-control: no-transform` and no length.
- A failure once the headers are out is the answer of the keys it hits
  (`InternalError`, `ServiceUnavailable` or `SlowDown`, as above). The
  body always ends with a whole `DeleteResult`. If the work ends without
  its answer, or has not answered after 10 minutes, every key is
  reported `InternalError`, and the request can be sent again.
- The deletes run apart from the body, so a client that stops reading
  does not stop them at once. But the runtime gives them at most 30 s
  more once the client is gone. Keys not done by then stay as they are
  (each key is deleted whole or not at all, its tombstone first), and
  the client sends the request again to finish them.

## Limits

- The answer `412`/`404` is given only when the recovery record of the
  refused write is gone. If the record cannot be removed, or a replay
  has already read it, the answer is `500` and the outcome is not known
  to the client; the record that stays sorts below the write that took
  the key, so a replay keeps that write on top.
- A DeleteObject stores its tombstone before it changes the catalogue.
  One that is then answered `500` or `503` (in DeleteObjects: a key
  reported with `InternalError`, `ServiceUnavailable` or `SlowDown`), or
  not answered at all, may
  have deleted nothing now and still take effect when the catalogue is
  rebuilt from the recovery records: the outcome of such a delete is not
  known until it is sent again and answered.
