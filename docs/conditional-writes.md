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
