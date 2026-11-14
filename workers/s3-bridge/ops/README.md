# Catalogue recovery

The catalogue (D1) says which Usenet articles make up which object. Without
it the data is unreachable, so it can be rebuilt from two things that are
kept outside it:

1. **Recovery records** in the `SAFETY` bucket, written by the Worker
   before every commit and never deleted:
   - `m/<generation id>`: one per PutObject, CopyObject or CompleteMultipartUpload.
     Bucket (id, name, wrapped key), object key, metadata and every extent
     (sizes, offsets, digests, media header, wrapped file key).
   - `m/del/<tombstone id>`: one per DeleteObject that removed an object.
   - `m/art/<extent id>`: the article plan of an extent (message ids,
     newsgroup, headers, spans, digests), written before its first POST.

   Each record is sealed with XChaCha20-Poly1305 under a key derived from
   the KEK and is bound to its own name. Ids are time-ordered, so "every
   record newer than T" is one listing.

2. **The KEK** in the escrow file. Without it neither the records nor the
   data can be opened.

A periodic **catalogue export** shortens a restore and brings back what
the records do not hold (access keys, grants, verification history).

## What a restore gives back

| State | From the export | From the records |
|---|---|---|
| Acknowledged PutObject, CopyObject, CompleteMultipartUpload, DeleteObject | up to the export | all of them |
| Buckets | yes | those with at least one write |
| Article plans | yes | for every extent that reached posting |
| Access keys and grants | yes | no: issue them again |
| Verification history | yes | no: pinned extents are posted (a no-op for articles that exist) and verified again; released extents come back as done, and every read still checks every byte |
| Open multipart uploads | up to the export | no: clients restart them |

The recovery point for acknowledged writes and deletes is zero as long as
`SAFETY` survives. With only the records (no export), the extents that
were never posted are read from their pinned copy in `SAFETY`, and posted
extents from Usenet.

Limits to know:

- A write that failed after its record was stored can become visible
  after a replay. S3 allows this (the request had no definite outcome).
- Replay order is id order, and an id carries the time its request
  started. Two requests on one key that overlapped in time (two writes,
  or a write and a delete) may come back in the other order; either
  order is a valid outcome for overlapping requests. This relies on
  clocks of two Worker instances differing by less than a request
  takes. Requests that did not overlap are replayed in their order.
- An extent restored from its article plan record alone (no pinned
  copy) is assumed posted: the record is written before the first POST,
  so a replay cannot tell an extent that was fully posted from one whose
  posting never finished and whose pinned copy was then lost. Such an
  extent is counted in `safety_missing`, not in `damaged`; a read of it
  fails loudly.
- An article plan record that does not open is listed under
  `unreadable` and its extent is restored without a plan.
- An extent with neither a pinned copy nor an article plan record cannot
  be read. Its object is restored anyway, reads of it fail, and the replay
  lists it under `damaged`.
- An empty bucket that never had a write is not in the records.

## Routine: export

`ops/catalog-export.sh` runs `wrangler d1 export` and stores the SQL file
in the bucket `velmora-catalog-export` (create it once with
`npx wrangler r2 bucket create velmora-catalog-export`). Run it from cron,
for example daily. It prints the **restore point**, which is also the
object's name. D1 does not answer queries while an export runs.

D1 Time Travel (30 days) is the faster tool when the database still
exists: restore it to a timestamp, then replay from that timestamp.

## Restore

1. Set `MAINTENANCE = "restore"` and deploy. Every write now answers 503,
   and the jobs and the cron do nothing.
2. Bring the database back, one of:
   - Time Travel: `npx wrangler d1 time-travel restore <db> --timestamp <T>`.
     The restore point is `T` in milliseconds.
   - Export: create an empty database (do not apply the migrations: the
     export carries the schema), download the newest
     `d1/<db>/<restore point>.sql` and load it with
     `npx wrangler d1 execute <db> --remote --file <file>`.
   - Nothing: create a database and apply the migrations. The restore
     point is `0`.
3. If the Worker secret is gone too: `ops/kek-restore.sh <escrow file>`.
4. `VELMORA_ADMIN_TOKEN_FILE=<file> ops/catalog-replay.sh <base-url> <restore point>`.
   It prints the counts. Exit status 2 means damage was found: read the
   lists before going on.
5. Check: `GET /_admin/status`, a listing, and a GET of a recent object.
6. Set `MAINTENANCE = "off"` and deploy. Issue access keys again if the
   database was rebuilt from the records alone.

The replay is idempotent. It can be stopped, repeated, or run over a
catalogue that already holds some of the records.

## The route

`POST /_admin/restore` (admin bearer; 409 unless `MAINTENANCE=restore`)
does one bounded step and answers with counts and `next`. Send
`{"since_ms": <restore point>}` first (optionally `"margin_ms"`, default
one hour: records that much older than the restore point are replayed
too), then `{"cursor": <next>}` until `next` is null. The answer names
generation ids and record names, never object keys.

## KEK

The escrow file holds one `VELMORA_KEK_<version>=<base64 of 32 bytes>` line
per version, mode 0600, outside any repository. `ops/kek-restore.sh` sets
each one as a Worker secret through stdin. Nothing else can replace a lost
KEK.
