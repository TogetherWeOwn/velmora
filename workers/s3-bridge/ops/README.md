# Catalogue recovery

The catalogue (D1) says which Usenet articles make up which object. Without
it the data is unreachable, so it can be rebuilt from two things that are
kept outside it:

1. **Recovery records** in the `SAFETY` bucket, written by the Worker
   before every commit and never deleted:
   - `m/<generation id>`: one per PutObject, CopyObject or CompleteMultipartUpload.
     Bucket (id, name, wrapped key), object key, metadata and every extent
     (sizes, offsets, digests, media header, wrapped file key).
   - `m/del/<tombstone id>`: one per DeleteObject that found an object.
   - `m/art/<extent id>`: the article plan of an extent (message ids,
     newsgroup, headers, spans, digests), written before its first POST.
   - `m/rk/<access key id>`: one per revoked access key (the id and the
     time, never the secret), written before the key's row is deleted.

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
| Access keys and grants | yes, less the keys revoked since: the first replay step deletes them | no: issue them again |
| Verification history | yes | no: pinned extents are posted (a no-op for articles that exist) and verified again; released extents come back as done, and every read still checks every byte |
| Open multipart uploads | up to the export | no: clients restart them |

The recovery point for acknowledged writes and deletes is zero as long as
`SAFETY` survives. With only the records (no export), the extents that
were never posted are read from their pinned copy in `SAFETY`, and posted
extents from Usenet.

Limits to know:

- A write that failed after its record was stored can become visible
  after a replay: one whose catalogue batch failed (the client got a
  500 and cannot know the outcome), or one that was refused and whose
  record could not be removed. It becomes visible only in its place in
  the order: every write and delete that was acknowledged on the key
  after it sorts after it and stays on top. It is visible after a replay
  only when nothing was acknowledged on the key after it.
  - A DeleteObject of such a key, also when nothing is live on it,
    leaves a tombstone above the record, so the delete holds in a
    replay. The exception is a record of a write that failed before the
    migration `0007_key_floors.sql` was applied: the catalogue has no
    mark for it, a DeleteObject that finds nothing live records
    nothing, and a replay publishes the record. A PutObject followed by
    a DeleteObject of the key, made now, covers it, provided the clock
    has not moved back since the failed write: without a mark, the
    order of the new ids against the record's rests on the clock alone.
- Replay order is id order. Before a record is stored, the catalogue
  raises the floor of the key to the record's id, in a statement of its
  own, and it accepts a publication or a tombstone only if its id sorts
  after the live generation and is not below the floor. So everything
  that is acknowledged on a key sorts after every record that was
  stored on the key before it, whatever became of that record's own
  request (a DeleteObject that found nothing left to delete, a batch
  that failed). A request whose id sorts lower (its Worker's clock is
  behind) is refused and tries again under a later id; a record such an
  attempt leaves behind sorts below what was acknowledged and changes
  nothing. None of this depends on the clocks of Worker instances.
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
  lists it under `damaged`. The exception: when the key has an older
  generation, live or deleted, the key stays as the older records leave
  it and the record is listed under `damaged_unpublished`, in every
  replay, with its id, the name of its bucket and its key. Such a
  record is far more often what a failed write left behind (a
  CompleteMultipartUpload whose parts were then collected) than an
  acknowledged object that lost its data, and the replay cannot tell
  the two apart. If it was acknowledged, the key answers with the
  object before it, or with 404 after a delete before it, instead of an
  error.
  - What to do about one: find out whether the write was acknowledged
    (the client's log, the application that owns the key).
    - Not acknowledged (a failed upload): nothing. The key holds what it
      should.
    - Acknowledged: the object is lost. Put it again from its source,
      or tell its owner.
  - The record stays in `SAFETY` either way, and no command removes it.
    A replay leaves it out only while the key has a live object that
    is newer than the record, so a PutObject on the key ends the report
    for replays over a catalogue where that object is live. The record
    is listed again after a DeleteObject of the key, and by a replay
    into an empty database, which reads the record before the newer
    ones; the key ends as the newer records say all the same.
  - Every replay that lists such a record exits with status 2, and for
    a record that stays listed that does not end. Exit status 2 from
    this list alone is then no new damage: compare the list with the
    list of the replay before.
- A CompleteMultipartUpload that got no answer from the catalogue and
  was sent again can leave two records of one object. The replay
  publishes one and counts the other in `duplicate`; nothing is missing.
  The object stands under the id of the later record, so a delete that
  came between the two attempts does not remove it.
- The record of a publication that the catalogue refused is deleted
  again, three tries in all. If the store fails every one, the record
  stays and a replay publishes it in its place in the order, as in the
  first limit above. A refused PUT or copy answers 500 then. A
  CompleteMultipartUpload goes on and can answer that the upload does
  not exist (it was aborted): after a replay the key then holds an
  object that the client was told was not made, in place of the object
  the key held before, unless a write or delete was acknowledged on the
  key afterwards. Compare the replay's object list with what is expected
  and delete or overwrite such an object by hand.
- If a bucket was made again under the name of a lost one before the
  replay, the two have different ids and data keys. The replay does not
  touch the new bucket: it skips the records of the old one and lists
  them under `other_bucket`. Which of the two keeps the name is for the
  operator to decide; the records of the old one stay in the store.
- A bucket that never held anything can be deleted (`DELETE /<bucket>`
  with the admin token), and its name given to a new bucket. A catalogue
  from before that deletion names the deleted bucket again, so this is
  the case above the other way round: the replay skips the records of
  the new bucket, the one with the data, and lists them under
  `other_bucket`. To set it right, stay in `MAINTENANCE=restore` for all
  of this, because the stale bucket has its old grants again and one
  client write into it would keep it for good:
  1. run the replay to its end (`catalog-replay.sh` exits with status 2
     because of the `other_bucket` list; that is expected here);
  2. delete the stale bucket with `DELETE /<bucket>` and the admin
     token. This one change is accepted under maintenance once no replay
     is unfinished. The answer is `204`. Do not delete a bucket after
     the database was brought back and before the restore is armed
     (Restore, step 2): the catalogue cannot tell yet that records are
     still to be read;
  3. run the replay again from the same `since_ms`: it makes the bucket
     of the records and publishes them, and `other_bucket` is empty;
  4. turn `MAINTENANCE` off, make new access keys for the bucket
     (`POST /_admin/keys`, or grant an existing key with
     `POST /_admin/keys/<id>/grants`) and give them to the clients:
     grants are not in the records.

  A `409` in step 2 means the bucket in the catalogue has data on record
  as well. Then both buckets hold data under one name and nothing merges
  them: leave `MAINTENANCE` on, keep the list under `other_bucket`, and
  decide which bucket keeps the name as in the case above. The records of
  the other one stay in the store.
- A pinned copy is deleted once its extent was read back from Usenet
  and `SAFETY_MIN_AGE_SECS` have passed. A catalogue from before that
  moment still says `held` for the extent, and a replay from the restore
  point does not read records that old. The replay checks every `held`
  row against the store at its end and counts the ones without a copy
  in `held_missing_total`; a replay from `0` sets them right.
- An empty bucket that never had a write is not in the records.

## Revoking an access key

```
curl -X DELETE -H @<0600 header file with the bearer> <base-url>/_admin/keys/<access key id>
```

`204`: the key is gone. The Worker first stores `m/rk/<id>` in `SAFETY`,
then deletes the key's row (the wrapped secret with it) and its grants
in one batch. Earlier catalogue exports and D1 Time Travel (30 days)
still hold the wrapped secret, sealed under the KEK like every secret
in them. The next request with the key, signed or presigned (also
a URL presigned before), answers `403 InvalidAccessKeyId`. `404`: no
such key, also for a second call. After a `500` the key may still work,
and its record may already be stored (a later restore then deletes the
key): send the call again until it answers `204` or `404`. Revocation is accepted
under maintenance and during a replay.

`GET /_admin/keys` lists every key: id, status, created time and its
grants (bucket and permission), never a secret, 500 per page in id
order; follow `next` with `?after=<next>`.

## Granting a key on another bucket

```
curl -X POST -H @<0600 header file with the bearer> -H 'content-type: application/json' \
  --data '{"bucket":"<bucket>","perm":"rw"}' <base-url>/_admin/keys/<access key id>/grants
```

`200` with `{access_key_id, bucket, perm}`: the key now has `perm`
(`rw` or `ro`) on the bucket. A second call may repeat the permission
or widen it from `ro` to `rw`. It never narrows it: `rw` to `ro`
answers `409 GrantNarrowingRefused` and changes nothing. The only way
to reduce a key's access is to revoke it (and mint a new one), because
a revocation has a record and survives a restore, where a narrowed grant
would silently come back wide. A
client that holds one key and creates buckets uses this to open each
new bucket to its key. `404 NoSuchAccessKey` or `404 NoSuchBucket`: no
such key (also a revoked one) or bucket; `400`: `perm` is not `rw` or
`ro`, or the body has another field. Refused with `503` under
maintenance and while a replay is unfinished. The grant is stored in
one statement that writes only while the key and the bucket both exist,
so a revocation or bucket deletion running at the same time never
leaves it behind. Grants are not removed one by one (`DELETE` answers
`405`); revoke the key instead.

Grants, like keys, are catalogue rows only: a catalogue restored from an
export older than a grant does not have it, a widening (`ro` to `rw`)
made after the export is lost the same way, and a replay brings neither
back. Grant the key again after such a restore.

A remote run of `e2e/slice.sh` revokes the keys it made when it exits.

An export, or a Time Travel point, from before a revocation still holds
the key's row. The first call of a replay (`since_ms`) deletes every key
that has a `m/rk/` record before it replays anything. Until then, while
`MAINTENANCE = "restore"`, every request also checks the key against
its `m/rk/` record (one `SAFETY` lookup per request, in that mode only),
so a key revoked after the export stays refused although maintenance
serves reads. Keep maintenance on until the replay has ended (Restore,
step 6): with maintenance off, only the replay's first call deletes such
a key, so that call is never skipped. A revocation record is never deleted: every later
replay deletes that id again. The ids the Worker mints are random, so a
new key does not get the id of a revoked one.

## Routine: export

`ops/catalog-export.sh` runs `wrangler d1 export` and stores the SQL file
in the bucket `velmora-catalog-export` (create it once with
`npx wrangler r2 bucket create velmora-catalog-export`). Run it from cron,
for example daily. It prints the **restore point**, which is also the
object's name. D1 does not answer queries while an export runs.

Take a fresh export after every deploy that applied a migration. An
export carries the schema of its day and the list of the migrations
that were applied (`d1_migrations`), so an older one can still be
loaded and brought up to date (restore, step 2); a fresh one does not
depend on that.

D1 Time Travel (30 days) is the faster tool when the database still
exists: restore it to a timestamp, then replay from that timestamp.

## Restore

1. Set `MAINTENANCE = "restore"` and deploy. Every write now answers 503,
   and the jobs and the cron do nothing.
2. Bring the database back, one of:
   - Time Travel: `npx wrangler d1 time-travel restore <db> --timestamp <T>`.
     The restore point is `T` in milliseconds.
   - Export: create an empty database (do not apply the migrations
     first: the export carries the schema and the list of applied
     migrations), download the newest `d1/<db>/<restore point>.sql` and
     load it with `npx wrangler d1 execute <db> --remote --file <file>`.
   - Nothing: create a database. The restore point is `0`.

   Then, in every case, bring the schema up to date and close the
   catalogue:

   ```
   npx wrangler d1 migrations apply <db> --remote
   npx wrangler d1 execute <db> --remote --file ops/restore-arm.sql
   ```

   The first applies the migrations the copy does not have yet (all of
   them on a new database, none on a current copy). The second records
   a replay as started. From then on the catalogue refuses every write
   until a replay has run to its end, whatever `MAINTENANCE` says: a
   deploy that switches maintenance off too early still answers 503.
3. If the Worker secret is gone too: `ops/kek-restore.sh <escrow file>`.
4. `VELMORA_ADMIN_TOKEN_FILE=<file> ops/catalog-replay.sh <base-url> <restore point>`.
   It prints the counts. Exit status 2 means damage was found: read the
   lists before going on.
   - Use restore point `0` if the database copy is older than
     `SAFETY_MIN_AGE_SECS`, or if the replay ends with
     `held_missing_total` above 0. It reads every record, so it takes
     longer; it is always correct.
5. Check: `GET /_admin/status` (`replay_unfinished` must be `false`), a
   listing, and a GET of a recent object.
6. Set `MAINTENANCE = "off"` and deploy. Issue access keys again if the
   database was rebuilt from the records alone. Keys revoked after the
   restore point stay revoked (`GET /_admin/keys` to check).

From the first call of the replay to its last, the catalogue itself
refuses every write with 503, also when `MAINTENANCE` is already `off`:
a catalogue that holds a part of the records must not take new writes.
The same holds for the admin routes that change something, the queue
jobs and the cron. If a replay was stopped, run it again to its end.
Starting a replay again makes the earlier one void: a step sent with a
cursor of the earlier one answers 409 and does nothing, and the
catalogue stays closed until the replay that was started last has
ended. A replay that is started while another one has not ended must
start from the same restore point or an earlier one; a later one
answers 409. A database that was brought back without the last command
of step 2 is not closed at once: nothing in it says that a replay is
due. The rollback stamp (below) closes it at the next cron run.

The catalogue refuses the commit as well, not only the request: a write
that was already under way when a replay started answers 503 and
publishes nothing. A DeleteObject in that place answers 503 too; its
tombstone can stay on record, and the replay then applies it. The same
holds at any time for a DeleteObject whose catalogue batch failed
(500): its tombstone stays, and a later replay applies it. The object
the client still sees is then gone after a replay, unless a write was
acknowledged on the key after the failed delete.

No rollback while `restore_state` is `replaying` (`replay_unfinished`
is `true`): do not roll the Worker back to an earlier version, and do
not restore the database to an earlier point without step 2. A Worker
version from before this gate does not read the row and takes writes
into a catalogue that holds a part of the records.

The replay is idempotent. It can be stopped, repeated, or run over a
catalogue that already holds some of the records.

## The rollback stamp

It finds a catalogue that was brought back to an earlier point without
the steps above (a Time Travel restore or an import with the Worker
serving).

- The catalogue holds a counter (`rollback_stamp`). `SAFETY` holds one
  small object per value the counter has reached:
  `rs/<catalogue id>/<counter, 20 digits>`. The objects are only put; no
  delete removes one. The body is the time of the raise in milliseconds.
- The counter is raised by every cron run, and by a write that must be
  covered at once, after its commit and before its `200`. A cron run
  whose raise loses to such a write goes on without a raise of its own.
- A restore takes the counter back and leaves the objects. **A counter
  behind the newest object, or no counter while an object exists, means
  the catalogue was rolled back.** The cron run checks this before it
  does anything else, and before it moves the counter. It checks it
  while a replay is on record as unfinished too. Garbage collection and
  eviction check it themselves before they delete anything.
- When it is found: `GET /_admin/status` shows
  `"catalogue_rolled_back": true` (and `replay_unfinished: true`), the
  cron logs it on every run, every write answers 503, and the jobs and
  the cron do nothing. Reads are served.
- **Way out: the restore above, from step 1.** In step 2 the database
  is already "brought back"; run the two commands. The restore point is
  the time the database was restored to, with one exception: if the
  database came back with a replay on record as unfinished (after the
  arming statement of step 2, `SELECT since_ms FROM restore_state` is
  not `-1`), the restore point is that replay's, not a later one. The catalogue holds
  the records up to that point at most. The route enforces it: a first
  call with a later `since_ms` answers 409 and names the value to send
  (`unfinished_since_ms`, with `margin_ms` 0). A second exception, which
  the route cannot see: if the row is already `replaying` with
  `since_ms` `-1` before you run the arming statement (check with
  `SELECT state, since_ms FROM restore_state` first), the database was
  restored a second time, to a point after an earlier arming and before
  that replay's first call. The time of this restore is then too late:
  take the restore point from the stamp object as described next, not
  from the bookmark time. If the time is not known,
  take the body of the stamp object of the counter the catalogue holds
  (`SELECT counter FROM rollback_stamp`) minus one cron interval, or
  `0`. The last step of the replay sets the counter level with the
  newest object and opens the catalogue.
- Only a replay that is started after the rollback does that. The last
  step of a replay that was started before it answers 409
  (`The catalogue was rolled back after this replay started`) and leaves
  the catalogue closed, whether that replay had ended or was still
  running at the point the database went back to: start a new replay
  with `since_ms`. The route tells the two apart by the time in the
  newest stamp object, so it also refuses in one harmless case: a raise
  that was under way at the moment the replay was started. Start the
  replay again then.
- `CATALOGUE_ID` (default `main`) is the `<catalogue id>` of the keys.
  Two catalogues over one `SAFETY` bucket need two ids. Do not change it
  for a catalogue in use: its objects would no longer be found, and a
  rollback would go unseen. The row keeps the id it was created with,
  so a Worker with another id refuses to use the stamp: the cron run
  fails before it sends a job, garbage collection and eviction retry,
  no stamp is raised, and `GET /_admin/status` shows
  `"catalogue_id_mismatch": true` with `"catalogue_rolled_back": null`.
  Put the id back.
- A new, empty database over a `SAFETY` bucket that already has stamp
  objects of its id counts as rolled back. That is the restore case
  "Nothing"; run the replay.
- A database restored from an export made before this table existed has
  no counter. The same holds: the replay sets it.

What the stamp does not see. In both cases the catalogue is rolled back
to a point after the last raise and before a commit, so counter and
newest object are level and nothing closes:

- **A.** A handler is killed between its commit and its raise. The
  write was not acknowledged. The window ends with the next raise, at
  the latest the next cron run (5 minutes).
- **B.** The raise fails after the commit (the counter cannot be moved,
  or three puts of the object fail). The write is answered `200`,
  because it is committed. The window ends with the next raise that
  succeeds. The cron logs `the rollback stamp was not raised` while its
  own raise fails.
- Writes that do not raise on their own are covered by the cron run
  only: a rollback to a point after the last cron run is not seen.

For all of these the rule stays: after any restore of the database,
run the restore steps above. The recovery records of every acknowledged
PutObject, CompleteMultipartUpload, CopyObject and DeleteObject are in
`SAFETY`, where a database restore cannot reach them, and the replay
brings them back.

## Rollback floor

A Worker rollback (`wrangler rollback <version>`, or the dashboard) can
go to any of the 100 most recent versions. Some of those are older than
the code real data relies on. Never roll back past the floor:

- **Real buckets:** never to a version older than the first one built
  from a commit that contains #71 (`keep generation ids on a key in
  commit order`). An older Worker refuses a PutObject on a real bucket
  but still takes multipart uploads on one, with the ordering bugs #71
  fixed: a recovery record can then sort before the write it should
  follow, and a replay can bring back the wrong generation.
- **With `SERVER_SIDE_COPY=on`:** also never to a version older than the
  first one built from a commit that contains #76 (`harden CopyObject
  retries, replay and rollback repair`). A Worker from before migration
  0005 cannot read a copy, and does not know that a copy shares the
  extents of its source; one from before #76 lacks the fixes to copy
  retries and to the replay of copies. Today the #71 floor is the later
  of the two, so it covers both.

Above the floor a rollback is still not free:

- A version from before `REAL_DATA_READY` was set refuses PutObject,
  CopyObject and DeleteObject on a real bucket (403), while multipart
  uploads still go through. Clients see failed writes until the
  Worker is rolled forward again.
- The rule of the restore section still holds: no rollback while
  `replay_unfinished` is `true`.
- (Versions from before the recovery records, #64, write no record at
  all; they are below the #71 floor anyway.)

The CI auto-rollback only ever goes back to the version that served
before that run's deploy, which is above the floor once the floor has
been deployed. The floor matters for a rollback by hand.

To find the floor (version IDs are per account, so they are not listed
here):

1. List every version, not only the last 10 that
   `wrangler versions list` shows: `GET
   /accounts/<account>/workers/scripts/<script>/versions?page=N&per_page=50`
   on the Cloudflare API, page by page.
2. A CI deploy carries the message `ci <run>.<attempt> <commit>`. A
   version made by a secret change (`workers/triggered_by` = `secret`)
   runs the code of the version before it.
3. For each version, oldest first, check the commit:
   `git merge-base --is-ancestor <merge commit of #71> <commit>`. The
   first version for which it succeeds is the floor. A secret-change
   version takes the answer of the version before it. Treat any other
   version without a CI message (an upload by hand) as below the floor.

## A PutObject or an UploadPart above one extent

With `MAX_PUT_BYTES` above `MAX_EXTENT_BYTES` (shipped: 99 MiB over
16 MiB), the body of one PutObject or one UploadPart may be larger than
one extent. It is stored as slices of `SLICE_BYTES` (8 MiB), each an
extent of its own, one in memory at a time. The object is one
generation with one recovery record, like any other. The ETag of a
PutObject, and of a part, is the MD5 of its body. A part made by
UploadPartCopy stays at `MAX_EXTENT_BYTES`.

**How large an object can be.** One object is made of at most
`MAX_OBJECT_EXTENTS` extents (10 000, the most this build takes): one
recovery record names them all, and one request publishes them.
CompleteMultipartUpload counts the extents of every part the upload
holds, listed or not, and answers 400 `EntityTooLarge` above the limit.
The upload stays open.

| Part size | Extents per part | Largest object |
|---|---|---|
| 16 MiB (one extent) | 1 | 156 GiB |
| above 16 MiB, up to 99 MiB | one per 8 MiB | 78 GiB |
| 5 MiB | 1 | 48 GiB |

A part above 16 MiB saves requests, not extents: 95 MiB is one request
for twelve extents. For the largest objects use parts of 16 MiB. An
object above 156 GiB does not fit this build.

- A request body above 100 MiB is refused before the Worker runs, so
  99 MiB is the most `MAX_PUT_BYTES` takes. That limit counts the bytes
  on the wire: a body sent in signed chunks carries 89 bytes of framing
  per chunk. With chunks of 8 KiB, the smallest S3 allows, a body above
  about 98.9 MiB is over it and is refused there; chunks of 16 KiB or
  more fit up to 99 MiB. A client has to send larger
  files as multipart uploads. aws-cli does so from 8 MiB. rclone does so
  from 200 MiB by default: run it with `--s3-upload-cutoff 95M` and
  `--s3-chunk-size 16M` (or `upload_cutoff = 95M` and `chunk_size = 16M`
  in the remote's section of `rclone.conf`). A part of 16 MiB is one
  full extent; rclone's default part of 5 MiB makes about three times as
  many extents. Parts up to 95 MiB work too (`--s3-chunk-size 95M`;
  aws-cli: `multipart_chunksize = 95MB`), within the object size above.
- Before its first slice is stored, the request writes one row per
  slice into `write_intents`. The commit removes the rows. A request
  that died leaves its rows, and its slices in `SAFETY`.
- A sliced UploadPart has no recovery record: an open upload is in none
  (see the table at the top). Its commit stores the part and removes
  the rows in one batch, and the request raises the rollback stamp
  after it, before it answers. If that raise fails it answers 503
  `SlowDown`; the part is stored all the same, and the client's retry
  replaces it. A client may instead take the part from ListParts, so
  CompleteMultipartUpload raises the stamp again, before the recovery
  record, for an upload that holds a sliced part. If that raise fails
  it answers 503 `SlowDown` and publishes nothing; the upload stays
  open and the same Complete succeeds once the stamp object (`rs/` in
  `SAFETY`) can be written.
- A sliced UploadPart that would take the upload above
  `MAX_OBJECT_EXTENTS` answers 400 `EntityTooLarge` before its body is
  stored. Parts in flight at the same moment are not counted, so
  CompleteMultipartUpload checks again and answers the same.
- A build before this one cannot complete an upload that holds a sliced
  part (it answers 400), and its AbortMultipartUpload leaves the slices
  after the first in `SAFETY` with nothing that collects them. Before a
  rollback to such a build, let the open uploads finish or abort them
  on this one. `SELECT COUNT(DISTINCT upload_id) FROM
  upload_part_extents` counts them.
- The request raises the rollback stamp before it writes its recovery
  record, and once more after the commit. If the first raise fails, it
  answers 503 `SlowDown` and publishes nothing.
- Such a request counts two slices (16 MiB) against
  `INFLIGHT_BUDGET_BYTES`, so with the shipped 48 MiB one isolate reads
  three at once. A fourth waits a bounded time for room and then
  answers 503 `SlowDown`. Measured on a test deployment: with three
  95 MiB bodies at once in one isolate, its wasm memory stayed at
  41.9 MiB or less (1.4 MiB before any large body).

**The sweep** (`INTENT_SWEEP = "on"`, independent of `GC_MODE`) removes
what such a request left. Each cron run sends a job for up to 20
writes, the oldest first, whose rows are a day old or were given up by
their request. The job deletes the slices and then the rows. It deletes
nothing:

- of a write that has a recovery record in `SAFETY`. Its rows are
  marked `kept` and stay;
- while a replay is under way;
- while the catalogue is behind its rollback stamp.

With the switch off nothing is deleted and the rows stay; a later run
with the switch on removes them. Production ships with the switch off:
`waiting_writes` and `oldest_waiting_at` below count what the sweep
would take. Turn it on in `wrangler.toml` after a restore drill on a
deployed Worker has passed.

`GET /_admin/status` shows the table under `write_intents`:

| Field | Meaning | If it stays above 0 |
|---|---|---|
| `open_writes` | requests under way, and dead ones younger than a day | nothing to do |
| `waiting_writes`, `oldest_waiting_at` | writes that are due for the sweep: bytes in `SAFETY` that no object uses | the sweep is off, a replay is unfinished, the catalogue is rolled back, or the cron could not send the jobs (it logs `dispatch: the sweep of unpublished writes was not sent`) |
| `kept_writes`, `kept_slices`, `oldest_kept_at` | writes with a recovery record and without an object in the catalogue: the request died between the two, its publication was refused and the record could not be removed, or the database was restored to a point before the commit and the restore was not noticed | run the restore steps above with a `since_ms` no later than `oldest_kept_at`. The replay reads only the records from `since_ms` (less the margin) on: it publishes those, and its first step removes their rows. A `kept` row whose record is older than that stays, and so does the figure |
| `anomalies` | how often a write was marked `kept`, ever; it does not go down | see `kept_writes` |

These figures describe the catalogue as it is now. In a catalogue that
was never restored, no client was told `200` for a write that is
`open`, `waiting` or `kept`. After a restore of the database that no
longer holds: the rows are those of the restored point, and a write
that is `open`, `waiting` or `kept` there may have been answered `200`
later. Its recovery record is in `SAFETY`, the sweep deletes nothing of
it (the rules above), and a replay that starts before its record
publishes it. A row is never proof that an upload failed.

One such restore is not found by the rollback check: to a point after
the request raised the stamp and before its commit, when the request's
raise after the commit failed and no cron run has raised the stamp
since. The object was answered `200` and is missing from the catalogue.
A day later the sweep finds its record and marks the write `kept`:
treat `kept_writes` above 0 as an object that may be missing until a
replay from `oldest_kept_at` or earlier has run.

**With a restore.** The first step of a replay removes from
`write_intents` every row but the `kept` rows whose record the replay
does not read (a record from before its `since_ms`, less the margin): a
row of an earlier point may name slices that the replay publishes.
Slices of requests that were under way at that moment and never
published stay in `SAFETY` without a row, and no figure counts them.

A Worker version from before this table does not empty it. If such a
version ran a restore, run `DELETE FROM write_intents` on the database
before a version with the sweep is deployed again.

Going back to a Worker version from before this table needs nothing
else: the objects are ordinary generations, which it reads, posts,
verifies and replays. It answers `EntityTooLarge` to a new PutObject
above one extent.

## The route

`POST /_admin/restore` (admin bearer; 409 unless `MAINTENANCE=restore`)
does one bounded step and answers with counts and `next`. Send
`{"since_ms": <restore point>}` first (optionally `"margin_ms"`, default
one hour: records that much older than the restore point are replayed
too), then `{"cursor": <next>}` until `next` is null. The answer names
generation ids and record names, never object keys.

The catalogue keeps the place the replay has come to. A cursor that is
ahead of it (a later phase, a later record, another restore point)
answers 400, so no part of the records can be left out; a cursor that
is behind repeats a step, which changes nothing.

## KEK

The escrow file holds one `VELMORA_KEK_<version>=<base64 of 32 bytes>` line
per version, mode 0600, outside any repository. `ops/kek-restore.sh` sets
each one as a Worker secret through stdin. Nothing else can replace a lost
KEK.
