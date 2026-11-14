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
  after a replay: one whose catalogue batch failed (the client got a
  500 and cannot know the outcome), or one that was refused and whose
  record could not be removed. It becomes visible only in its place in
  the order: every write and delete that was acknowledged on the key
  after it sorts after it and stays on top. It is visible after a replay
  only when nothing was acknowledged on the key after it.
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
  replay. Such a record is far more often what a failed write left
  behind (a CompleteMultipartUpload whose parts were then collected)
  than an acknowledged object that lost its data, and the replay cannot
  tell the two apart. If it was acknowledged, the key answers with the
  object before it, or with 404 after a delete before it, instead of an
  error.
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
- A pinned copy is deleted once its extent was read back from Usenet
  and `SAFETY_MIN_AGE_SECS` have passed. A catalogue from before that
  moment still says `held` for the extent, and a replay from the restore
  point does not read records that old. The replay checks every `held`
  row against the store at its end and counts the ones without a copy
  in `held_missing_total`; a replay from `0` sets them right.
- An empty bucket that never had a write is not in the records.

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
   database was rebuilt from the records alone.

From the first call of the replay to its last, the catalogue itself
refuses every write with 503, also when `MAINTENANCE` is already `off`:
a catalogue that holds a part of the records must not take new writes.
The same holds for the admin routes that change something, the queue
jobs and the cron. If a replay was stopped, run it again to its end.
Starting a replay again makes the earlier one void: a step sent with a
cursor of the earlier one answers 409 and does nothing, and the
catalogue stays closed until the replay that was started last has
ended. A database that was brought back without the last command
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
  covered at once, after its commit and before its `200`.
- A restore takes the counter back and leaves the objects. **A counter
  behind the newest object, or no counter while an object exists, means
  the catalogue was rolled back.** The cron run checks this before it
  does anything else, and before it moves the counter.
- When it is found: `GET /_admin/status` shows
  `"catalogue_rolled_back": true` (and `replay_unfinished: true`), the
  cron logs it on every run, every write answers 503, and the jobs and
  the cron do nothing. Reads are served.
- **Way out: the restore above, from step 1.** In step 2 the database
  is already "brought back"; run the two commands. The restore point is
  the time the database was restored to. If it is not known, take the
  body of the stamp object of the counter the catalogue holds
  (`SELECT counter FROM rollback_stamp`) minus one cron interval, or
  `0`. The last step of the replay sets the counter level with the
  newest object and opens the catalogue.
- `CATALOGUE_ID` (default `main`) is the `<catalogue id>` of the keys.
  Two catalogues over one `SAFETY` bucket need two ids. Do not change it
  for a catalogue in use: its objects would no longer be found, and a
  rollback would go unseen.
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
