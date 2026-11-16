# Conditional writes

A write can be held to the state of the key it writes. The condition is
judged inside the database batch that publishes the write, so two
requests that race for one key cannot both pass it.

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
- A write that is refused leaves no published generation, no catalogue
  row of its own and no recovery record: a replay of the recovery
  records does not bring it back. A refused DeleteObject leaves no
  tombstone that deletes anything.
- A PutObject that loses the key after its body was stored leaves the
  stored bytes behind unreferenced, like any PUT that is not published,
  and they are handled the same way.
- Of two conditional writes that race for one key, one is published. The
  other is answered `412` (or `404`, when the object it named was
  deleted). After several lost rounds in a row a request is answered
  `503 SlowDown` instead and can be sent again.

## CompleteMultipartUpload

A Complete that is refused with `412` or `404` changes nothing about the
upload: it stays open with all its parts. The client can send Complete
again (with or without a condition), or abort the upload.

A Complete that is sent again after it succeeded is answered `200` from
the result of the first one, whatever the key holds by then: it is the
same request, not a second write.

## Limits

- The answer `412`/`404` is given only when the recovery record of the
  refused write is gone. If the record cannot be removed, the answer is
  `500` and the outcome is not known to the client; the record that
  stays sorts below the write that took the key, so a replay keeps that
  write on top.
- One case is not covered by that ordering. A DeleteObject without a
  condition, started before a conditional write and finished between
  the write's look at the key and its batch, makes the batch refuse the
  write. If the process dies before the record of that write is removed,
  and the catalogue is later lost and replayed from the records, the
  replay publishes the write: its condition held when the record was
  stored. No acknowledged write is lost by this, and no client was told
  `412` for it.
- A DeleteObject without a condition that races with a write may answer
  `204` and leave the object of that write in place. Conditional deletes
  do not change this.
