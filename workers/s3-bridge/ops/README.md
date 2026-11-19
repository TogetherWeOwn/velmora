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

   With `RECORD_LAYOUT=tenant` the first three are written under the
   tenant they belong to instead: `m/x/<tenant id>/<generation id>`,
   `m/x/<tenant id>/del/<tombstone id>` and
   `m/x/<tenant id>/art/<extent id>` (see "Record layout" below). Both
   forms are read, always.

   Each record is sealed with XChaCha20-Poly1305 under a key derived from
   the KEK and is bound to its own name. Ids are time-ordered, so "every
   record newer than T" is one listing per layout.

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
- A packed plan in the catalogue that cannot be read is replaced by the
  plan of the extent's record. When the record has no plan to give (it
  is absent, it does not open, or its plan does not fit the row), the
  stored value stays as it is, and the name of the extent's plan record
  (`m/art/<extent id>`) is listed under `unreadable`, whether or not
  such a record exists. That extent cannot be read from Usenet, and
  it is not counted in `damaged`. When it has no pinned copy either and
  its key has an older generation, its record is not published over
  that generation and is listed under `damaged_unpublished`, as below.
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
    - Acknowledged: the object cannot be read. Put it again from its
      source, or tell its owner. (When the cause is a packed plan that
      cannot be read, listed under `unreadable`, the articles may still
      be on Usenet; without a plan nothing finds them.)
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
- One id stored under the names of both layouts (`m/<id>` and
  `m/x/<tenant id>/<id>`) is replayed once. The flat name is read
  first, and the tenant name only when the flat one gives no record
  (it does not open, and is then listed under `unreadable`). The tenant
  name is listed under `twins` either way. A write stores its record
  under one name only, so a twin is the trace of a blob that was put
  into `SAFETY` by hand; `catalog-replay.sh` exits with status 2 for it.
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

## Record layout

`RECORD_LAYOUT` says under which names the Worker writes **new**
generation, tombstone and article plan records:

| `RECORD_LAYOUT` | Generation | Tombstone | Article plan |
|---|---|---|---|
| `flat` (default, also when unset) | `m/<id>` | `m/del/<id>` | `m/art/<extent>` |
| `tenant` | `m/x/<tenant>/<id>` | `m/x/<tenant>/del/<id>` | `m/x/<tenant>/art/<extent>` |

Every write belongs to tenant `t_0000000000000000` today. The names
under `m/seg/` and `m/x/<tenant>/seg/` are the segments of a segmented
generation record: each holds a run of the extents of one object. A
restore reads a segment only through the generation record that names
it; the recovery copy also sends it to the remote store as a key of its
own, like any other key under `m/`, and before the record that names
it. No build writes them yet. Any other value of the variable refuses to start.

- A record is never renamed, moved or rewritten: it is sealed under its
  whole name and would not open under another. Changing the setting
  changes where the next record goes, nothing else, and it can be
  changed in either direction at any time.
- Every reader reads both layouts whatever the setting says: the
  replay, the recovery copy, the intent sweep, and the lookup of an
  article plan (in the layout of
  the record that names it first, then in the other one, because a plan
  can be written after the setting changed and a copy shares the
  extents of its source).
- The replay reads the two listings as one, in id order. A cursor of
  an older build is still read, so a replay can be continued across a
  deploy. Not across a rollback to a build from before segmented
  records: a cursor that stops inside a record carries the `name` of
  that record, which such a build refuses. Start that replay again from
  the beginning; a replay can be repeated.
- The names stay under `m/`, so what is true of `m/` stays true of
  them: the store refuses to delete them, and the recovery copy sends
  them under the same names.
- Revocation records (`m/rk/`) and tenant keys (`m/tk/`) keep their
  names in both settings.
- The directory is `m/x/`, after every other name under `m/` in key
  order, and it holds these records only. The names `m/t/`, `m/k/`,
  `m/u/` and `m/tref/` are left free for records about a tenant itself
  (its state, keys and usage), which are listed and numbered in ways
  that must not meet millions of object records.
- The tenant id is the whole prefix; there is no shard in the name. A
  record is never renamed, and a tenant can be moved from one shard to
  another, so the name holds what does not change. A shard is found
  from the tenant.

Turning it on, in two deploys:

1. Deploy a version that knows `RECORD_LAYOUT`, with the variable unset
   or `flat`. Let it serve until a rollback to an earlier version is no
   longer wanted.
2. Set `RECORD_LAYOUT = "tenant"` and deploy. From this deploy on the
   rollback floor below applies.

Turning it off again (`flat`) is safe at any time and does not lower
the floor: the tenant records that were written stay.

With the recovery copy on, a pass that finds nothing to send costs 6
list calls here and 6 at the other provider (4 and 4 before), in either
setting, because both layouts are listed. Each of the four sweeps (the
tombstones and the generations of each layout) costs one more call on
each side while it holds records of the last hour, so a pass in the
hour after the setting changed, with fresh records in both layouts, can
cost 8 and 8.

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
  retries and to the replay of copies. The #71 floor is later than
  #76, so it covers both.
- **Once `PACKED_PLANS=on` has been deployed:** never to a version older
  than the first one that knows `PACKED_PLANS` (migrations 0016 and
  0017). From then on the article plan of an extent can be one value on
  its row (`extents.plan`) and not rows in `articles`. An older Worker
  sees such an extent as one without a plan: it cannot read it from
  Usenet (cold reads answer unavailable), and its post, verify and
  release jobs of that extent fail and retry until they reach the
  dead-letter queue. With the switch on, this is the latest floor, so
  it covers the #71 and #76 floors too. A rollback to a version that knows the switch is safe with the
  switch on or off: off only stops new plans from being packed, and
  every such version reads both forms.

- **Once `RECORD_LAYOUT=tenant` has been deployed:** never to a version
  older than the first one that knows `RECORD_LAYOUT`. From then on a
  recovery record can be stored under `m/x/<tenant id>/`. An older
  Worker reads the flat names only:
  - its replay lists `m/g_` and `m/del/g_` and so passes over every
    write and delete recorded in the tenant layout: after a restore
    those objects are missing and those deletes are undone, with no
    error;
  - its replay looks for the article plan of an extent under
    `m/art/<extent id>` only. An extent whose plan was written in the
    tenant layout comes back without a plan and without a report, also
    when its object has a flat record (an extent is posted after its
    object is published; a copy shares the extents of its source). Once
    its pinned copy is released, such an extent cannot be read;
  - with `INTENT_SWEEP=on` it looks for the record of a sliced write
    under `m/<id>` only. For a write whose record is stored and whose
    commit is not in the catalogue (the write stalled or failed after
    the record, or the catalogue was brought back to a point before
    it) it finds none and removes the slices a day after the write; a
    later replay then publishes an object whose data is gone;
  - its recovery copy still sends the tenant records (they are under
    `m/`), but as plain keys: a generation record goes out without the
    two-minute wait and without its article plans first, a plan of the
    tenant layout is not sent when its extent is posted but by the next
    pass, and every pass lists the whole tenant layout (one list call
    per 1000 records, every 15 minutes).

  The store still refuses to delete the tenant records, because they
  are under `m/`. A rollback to a version that knows the switch is safe
  with either value: every such version reads both layouts. Setting the
  variable back to `flat` does not lower the floor, because the tenant
  records that were written stay. This floor is independent of the
  `PACKED_PLANS` floor: the later of the two versions is the floor.

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
3. Take the latest floor that applies: the merge commit of #121 (the
   one that brought `PACKED_PLANS`) once the switch has been deployed
   on, else the merge commit of #71. For each version, oldest first,
   check the commit: `git merge-base --is-ancestor <that merge commit>
   <commit>`. The first version for which it succeeds is the floor. A secret-change
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
`MAX_OBJECT_EXTENTS` extents (10 000 as shipped; the build takes up to
131 072, see "Large objects" below): one recovery record names them
all, and one request publishes them.
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
object above 156 GiB does not fit the shipped limit.

- A request body above 100 MiB is refused before the Worker runs, so
  99 MiB is what `MAX_PUT_BYTES` is set to (the build takes up to
  199 MiB, for a plan whose edge takes 200 MiB). That limit counts the bytes
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

## Large objects

An object of more than 10 000 extents has a recovery record in parts
(a segmented record): segments of 4 096 extents under `m/seg/<set>/`,
stored first, and a head under the name of the record, stored last.
Only the head is the record. Segments without a head are named by
nothing and are read by nothing; they are left by a Complete that
failed or lost a race, and no job removes them. An object of 10 000
extents or fewer is recorded in one document, byte for byte as before.

**Shipped: off.** `MAX_OBJECT_EXTENTS` is not set, so the limit is
10 000 and no segmented record is written. This build alone changes
nothing: the limit is raised by a setting, and only after a drill of
the segmented path on a deployment of its own has passed. Raise it only
on a build in which:

1. DeleteObject, a conditional write and UploadPartCopy read no extent
   rows they do not need, and CopyObject refuses a source above 10 000
   extents: without that, those calls load every extent row of a large
   object in one result.
2. The cut of a Complete by the runtime has been drilled on a deployed
   Worker ("The cut drill" below) and the 32 MiB came back.
3. The drill has measured a Complete beside running post jobs: how long
   it waited for its charge and how many answered 503 (see the charge
   below).

| Setting | Shipped | The build takes | What it bounds |
|---|---|---|---|
| `MAX_OBJECT_EXTENTS` | 10 000 (not set) | 1 to 131 072 | extents of one object |
| `MAX_PUT_BYTES` | 99 MiB | up to 199 MiB | one request body; set it to the edge limit of the plan less 1 MiB |
| `SLICE_BYTES` | 8 MiB (not set) | 16 slices a body at most | extents per part |

- With `MAX_OBJECT_EXTENTS` above 10 000 the Worker refuses to start
  unless an upload of 10 000 parts of `MAX_PUT_BYTES` fits the limit:
  `ceil(MAX_PUT_BYTES / SLICE_BYTES) x 10 000` must not be more. At
  99 MiB in slices of 8 MiB that is 130 000 extents, so 131 072 passes.
  A client can then use every part number at its largest part and never
  meets the extent limit: 10 000 parts of 96 MiB are 937 GiB.
- A plan with a higher edge limit is a change of settings only. With an
  edge of 200 MiB: `MAX_PUT_BYTES = 208666624` (199 MiB) and
  `SLICE_BYTES = 16777216` (13 slices a part, 130 000 extents). The
  Worker refuses to start with 199 MiB in slices of 8 MiB (25 slices).
- **Client settings for a large object:** aws-cli and boto3
  `multipart_chunksize = 96MB`; rclone `--s3-chunk-size 96M`. A part of
  96 MiB from aws-cli 2.31 with its default checksum settings is a body
  of 100 664 300 bytes (1 004 bytes of chunk framing and trailer; over
  HTTP/1.1 another 971 bytes of transfer chunking): 4 MiB under the
  edge limit of 104 857 600.
  The 1 MiB between `MAX_PUT_BYTES` and the edge limit is for that
  framing. A client that signs every chunk adds about 89 bytes a chunk:
  1 MiB covers chunks of 16 KiB at 99 MiB and of 32 KiB at 199 MiB
  A client with smaller signed chunks uses a smaller part, or the edge
  refuses the body with 413 before the Worker runs.
- **CompleteMultipartUpload of an upload above 10 000 extents** reads
  the extents a run of 256 part numbers at a time, stores the segments
  as it goes, then the head, then publishes in one transaction. It
  answers `200` at once and the document follows when the work is done,
  with a newline every 5 s in between; a failure after the headers is
  an `<Error>` document in that `200`, as S3 itself answers this call.
  aws-cli, boto3 and rclone read it. When the client goes away the work
  goes on for at most 30 s more. Work that is cut there is not run and
  not dropped by the runtime, so what it holds would stay held: the
  isolate keeps such work in a table, the work marks it every 5 s, and
  each request and each queue batch first drops the work that has not
  marked it for 60 s. That gives the 32 MiB back and logs
  `work table: abandoned work dropped: ... budget_in_use_before=...
  budget_in_use=...`. Work that is cut has either
  published the object or left it unpublished (with its segments, and
  perhaps its head, as they are); a missing answer says neither. Send
  the request again: after a publication it is answered from the
  receipt, otherwise it publishes.
  Refusals that need no work (unknown upload, a part that does not
  match, too many extents, a condition that does not hold) keep their
  status code.
- One such Complete is charged 32 MiB of `INFLIGHT_BUDGET_BYTES` while
  it runs; without room it answers 503 `SlowDown`. With
  `MAX_OBJECT_EXTENTS` above 10 000 the Worker refuses to start with a
  budget below that. With the budget of 48 MiB one isolate runs one such
  Complete at a time.
  Beside it the jobs have 24 MiB of their 72 MiB: one post job of a
  16 MiB extent (22 MiB), not two. So that jobs which come one after
  another do not keep a Complete out for good, a job that would keep a
  waiting Complete out waits itself (it gives its lease back unspent
  when it has waited 20 s, as for any full budget) until the Complete
  has its charge or gives up; the jobs that run finish first. A job
  that leaves room beside the Complete is not held back, and nothing
  changes while no Complete waits. A Complete whose request was stopped
  while it waited holds the jobs back for 2 s, once.
  The budget was not raised instead: a Complete and two such post jobs
  hold about 74 MiB, above the 72 MiB that the isolate is sized for, and
  a request budget of 64 MiB would let two 16 MiB bodies in at once on
  every deployment (96 MiB at the weight of a request), whether or not
  it stores large objects.
  Measured in a local workerd (wasm memory of the
  isolate, 1.6 MiB before): 31.1 MiB at the end of a Complete of
  131 072 extents (29.6 MiB more), 25.1 MiB at 65 536 (23.5 MiB more);
  6.8 s and 3.2 s, 43 and 27 catalogue reads, 34 and 18 record puts,
  one publish batch, one queue batch.
  In another run of the 131 072 (6.6 s) the headers of the answer left
  after 2.1 s and the one publish batch took 2.6 s; in a local workerd
  no timer runs during that batch, so a newline that falls due then is
  late there.
- An UploadPart or an abort that arrives while the extents are read
  wins: no head is stored, nothing is published, and the answer is the
  one the upload then deserves (`InvalidPart`, `NoSuchUpload`, or a new
  attempt on the upload as it is).
- Complete sends one batch of at most 100 queue messages. The outbox
  rows are written for every extent in the publish transaction, and the
  dispatcher sends the rest.
- A head names at most 192 segments. With the built-in segment size
  that is far above the limit (131 072 extents are 32 segments).

**Drill settings.** `RECORD_SEGMENT_AFTER` (1 to 10 000),
`RECORD_SEGMENT_EXTENTS` (1 to 4 096) and `PUBLISH_CHUNK_ROWS`
(1 to 25 000) make the segmented path start earlier, with smaller
segments and smaller publish values, so that a drill covers it with a
small object. They only take values at or below the built-in ones. The
Worker refuses to start when `MAX_OBJECT_EXTENTS` in segments of
`RECORD_SEGMENT_EXTENTS` would be more than 192 segments, or in values
of `PUBLISH_CHUNK_ROWS` more than 128 values (a restore asks the
catalogue twice a value in one call): a drill sets a small
`MAX_OBJECT_EXTENTS` with them. Production
and dev set none of them, and a contract test holds them to that.

**The cut drill.** On a drill Worker with `ENVIRONMENT=dev` (never
production), to see that a Complete which the runtime cut gives its
charge back:

1. Set small `RECORD_SEGMENT_AFTER` and `RECORD_SEGMENT_EXTENTS`,
   `DEV_MEMORY_LOG=on`, and `DEV_SEGMENT_PUT_DELAY_MS` so that the
   segments of the drill object take about 90 s together (the delay is
   at most 60 000 ms a put, and is ignored outside dev). Start
   `wrangler tail`.
2. Upload the parts, then send the Complete with `curl --max-time 5`:
   the client leaves while the segments are stored.
3. Wait 60 s (the runtime stops the invocation about 30 s after the
   client left) and then 60 s more for the mark to go quiet. Send any
   request: the tail shows `work table: abandoned work dropped` with
   `budget_in_use_before=33554432` and `budget_in_use=0`, and the
   `memory:` line of that request shows `budget_in_use=0` (plus what
   the request itself holds). All of it has to come from one isolate:
   compare `isolate=` in the lines.
4. Control: the same Complete with a client that stays (no
   `--max-time`). It answers after about 90 s with the result document,
   the object reads back, no `abandoned work` line appears, and
   `budget_in_use` is 0 afterwards.
5. Send the cut Complete again: it publishes or answers from the
   receipt.

**Rollback.** Once one segmented record exists, never roll back to a
version older than the first one that reads segmented records in the
replay, the recovery copy and the intent sweep. The check is on the
stored records: list `SAFETY` for one key under `m/seg/`, and under
`m/x/<tenant>/seg/` for each tenant with `RECORD_LAYOUT = tenant`
(`wrangler r2 object` has no listing; use an S3 client on the bucket
with `--prefix` and `--max-keys 1`). The extent count of a generation in
the catalogue does not answer it: only a multipart Complete writes
segments, so under a drill setting a sliced PutObject above
`RECORD_SEGMENT_AFTER` extents has its record in one document. An older version cannot read a head: its replay stops at it, and
its sweep finds no record for a sliced write and removes the slices a
day later. Setting `MAX_OBJECT_EXTENTS` back to 10 000 stops new
segmented records and does not lower this floor: the ones written stay.
With the limit at 10 000 from the start there is no such record and no
new floor.

## Packed article plans

The article plan of an extent (where its ciphertext is on Usenet) is
either one row per article in `articles`, or one value on the extent's
own row (`extents.plan`, migrations 0016 and 0017). Packed, a 16 MiB
extent keeps under 1 KiB of plan in the catalogue instead of about
11 KiB, and its posting writes two rows instead of three per article.
Every reader takes both forms. The recovery records do not change: the
record of a plan (`m/art/<extent id>`) lists every article in both
cases, so a replay rebuilds either form from it.

To turn it on:

1. Apply the migrations and deploy with `PACKED_PLANS` unset (off).
   This is the first version that reads a packed plan.
2. In a later deploy set `PACKED_PLANS = "on"`. From then on:
   - a new extent's plan is stored packed;
   - a replay stores the plans it restores packed;
   - each cron tick packs up to 50 older plans and deletes their rows.
     Only a plan whose articles are all posted is packed; one that is
     still being posted is packed by a later tick.
3. A large backlog of older plans is packed faster by hand, 1 to 500
   extents a call:

   ```
   curl -sS -X POST -H @<bearer header file> '<base-url>/_admin/pack-plans?limit=500'
   ```

   The answer is `{"looked": n, "packed": n, "end": bool}`. Repeat until
   a call answers `"end": true`: the pass has been over every extent
   that has article rows. Rows that are left belong to plans that are
   not posted in full yet (`SELECT COUNT(*) FROM articles`).

Packing an older plan writes one row for the extent and one per article
row it deletes. The route answers 409 while the switch is off and 503
in restore maintenance. See "Rollback floor" before turning it on.

A packed plan carries a digest of itself and of its extent's id, and a
value that does not match it is never read as a plan: every read of
that extent fails instead. The schema keeps a plan on an extent in
service, so such a value is not dropped by hand. The replay (below)
replaces it: for each extent of a record it reads the stored plan, and
one that cannot be read gives way to the plan in the extent's record.
A plan that reads is left as it is.

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

## A GET above GET_FANOUT_BYTES

One invocation has `cpu_ms` of CPU (300 s), and every byte of a GET is
decrypted in it: a single GET stopped after about 9 GiB read from the
cache, with `exceededCpu`. A GET, whole or ranged, of more plaintext
than `GET_FANOUT_BYTES` (shipped: 1 GiB) is therefore served in
sub-ranges of that size. The invocation that answers the client checks
the signature and the grant and sends the headers, the same as for any
GET; it then asks this Worker for one sub-range after the other through
the `SELF` service binding, and the runtime moves each answer into the
client's response. Each sub-range is an invocation of its own, with its
own `cpu_ms`. A smaller GET is served as before.

- **The binding.** `[[services]] binding = "SELF"` must name this
  Worker (`service` equal to `name`; each environment names its own).
  Without it a GET above the size answers 500 and logs `fanout: no
  service binding or stream`; smaller GETs are not affected.
- **A sub-request** is `GET /_fanout` with one header that carries a
  token: bucket id, generation id, offset, length and an expiry of two
  minutes, under an HMAC keyed from the active KEK. It is refused (403)
  if it carries a header that the edge adds to a request from the
  Internet, or if the token does not verify. Every sub-range of one
  download is read from the generation the first invocation found,
  whatever is written to the key meanwhile.
- **A failure after the first byte** cannot change the status line. The
  response has a `Content-Length`, and the stream is aborted: the client
  sees a broken transfer, never a short one that looks complete. The log
  has `fanout: download aborted (<class>)`. The client asks again with
  `Range: bytes=<received>-` and `If-Match: <the ETag it was sent>`:
  each request reads the object that is live when it arrives, and
  without the condition a key written to meanwhile would give the rest
  of another object (with it: 412). A sub-range after the first that
  answers 503 before its first byte is asked for again, up to three
  times, before the download is given up; a 503 of the first sub-range
  is the answer to the client.
- **Limits.** `GET_FANOUT_BYTES` is from 1 MiB to 2 GiB; a GET of more
  than 8,192 sub-ranges (8 TiB at 1 GiB) is refused with 500 before any
  byte. Sub-requests count against the subrequest limit of the first
  invocation (10,000) and are not billed as requests; their CPU is.
  One download of 100 sub-ranges was read whole on a deployed Worker.
  If the platform ever stops a download at a fixed number of
  sub-requests, the log has `fanout: download aborted (transport)` at
  the same sub-range each time: raise `GET_FANOUT_BYTES`.
- **A sub-range that ends short.** A sub-response is refused unless it
  declares the length asked for. Should its body still end early, the
  download comes out shorter than its `Content-Length` and the close
  fails, which aborts it: a client never takes it for a complete
  response, and must not keep the bytes of a transfer that failed.
- **A deploy during a download.** The next sub-request is answered by
  the new version. A version that does not know the token (from before
  this feature, or with another token format) refuses it, and the
  download aborts as above.
- **Off.** `GET_FANOUT_BYTES = "0"` (or unset) serves every GET in one
  invocation, as a version from before this feature does. Nothing is
  stored for this feature: going back needs nothing else.

Measured on a deployed Worker with an object of 12 GiB (768 extents of
16 MiB), sub-ranges of 1 GiB:

| | wall | CPU per sub-range of 1 GiB | CPU of the first invocation |
|---|---|---|---|
| whole object from the cache | 536 s (22 MiB/s) | 20 to 40 s | under 0.2 s |
| 5 GiB range from the cache | 252 s (20 MiB/s) | 20 to 40 s | under 0.2 s |

A read from Usenet (an extent that is neither in the cache nor a safety
copy) goes extent by extent, over `COLD_SOCKETS` connections at once:

- **Verified, then sent.** The articles of an extent arrive on whichever
  connection is free, each is checked against its hash, the extent
  against its own, and only then is it decrypted and sent. The cache
  write of an extent runs beside the read of the next one and is not
  waited for by the client; a cache write that fails does not fail the
  read.
- **One step ahead, no further.** The Worker reads one extent ahead of
  the client and holds one cache write, all within
  `INFLIGHT_BUDGET_BYTES`. A client that stops reading stops the Worker
  after that extent, and a client that goes away ends the read.
- **A failed article.** An article a provider lacks, or sends wrong, is
  asked for from the next provider that has a connection or a permit. A
  connection that breaks is opened again a bounded number of times,
  and a provider that keeps failing is left for the others. The
  read fails only when no provider can supply an article, and then the
  download breaks as described above: never a short body that looks
  complete.
- **A slow connection.** A connection that takes over three times as
  long per article as the others, and over a second, holds up every
  extent. It is ended and another is opened in its place, at most
  eight times for one set of connections (a download opens a new set
  after it ended one, see the next point); after that the read goes on
  with fewer connections.
- **A client that stalls.** A verified extent waits five seconds for
  the client. Then it is dropped, with its share of the byte budget,
  and the connections are ended; when the client reads again, the
  extent comes from the cache. The connections are also ended when the
  download waits for anything but a provider (room in the byte budget,
  a cache write) for longer than their slots allow: no connection sits
  idle on a slot that ran out. After that the next extents are read
  only when the client asks for them, until it asks for one within
  five seconds of taking the one before; a client slower than about
  3 MiB/s is served that way throughout.
- **Other requests in the same isolate.** A request that waits for
  room in the byte budget, and that the download alone keeps out, goes
  first: the download charges for its next extent after it, so a
  second large request is not kept waiting until the download ends, and
  the two take turns. The download waits for it five seconds at most. A
  request that other requests keep out, or that fits beside the
  download, is not waited for: a small read is not slowed down by a
  large upload that waits. A read that found every provider connection
  taken waits for its room the same way before it tries again, inside
  its forty seconds. A download that has begun waits up to a minute for
  room before it ends short, and no longer once those forty seconds are
  over; a request that has sent nothing waits twenty seconds and
  answers `503 SlowDown`.
- **The log.** Each invocation that read from Usenet writes one line,
  `cold read: extents=64 opened=8 open_ms=70 broken=0 slow=0
  refetched=0 p1=1536/1074007040 warm_ms=... read_ms=... wait_ms=...
  send_ms=... put_ms=...`: connections opened, broken and ended for
  being slow, articles asked for a second time, articles and bytes per
  provider id, and the milliseconds spent asking the cache, reading,
  waiting for room in the byte budget, waiting for the client, and
  writing to the cache. It names no key, bucket, message-id or host.

Measured on a deployed Worker with an object of 6 GiB (384 extents of
16 MiB) that was in neither bucket, one provider reached through a
proxy, `COLD_SOCKETS = "8"`, sub-ranges of 1 GiB:

| | wall | CPU per sub-range of 1 GiB |
|---|---|---|
| 2 GiB range from Usenet, before (one connection) | 812 s (2.5 MiB/s) | 50 to 90 s |
| 2 GiB range from Usenet, eleven runs | 152 to 212 s (10 to 13 MiB/s) in seven, 244 to 298 s (7 to 8 MiB/s) in four | 42 to 60 s in the faster runs, 55 to 89 s in the slower ones |
| whole object from Usenet, six runs | 393 and 400 s (15 MiB/s) in two, 666 to 803 s (8 to 9 MiB/s) in four, some hours later | 34 to 37 s in the faster runs, 56 to 77 s in the slower ones |

The cache write sets the pace: one extent takes one to two seconds to
write, and only one write fits in the byte budget beside the next read.
In a slower run every part is slower by about the same factor, and the
CPU time rises with the wall time (about 0.6 s of CPU per second in
every run), while no article is asked for twice and at most a few slow
connections are replaced. Why one run is slower than the next was not
found.
The earlier drill (an object of 12 GiB, in the first table) read a 2 GiB
range from Usenet at 1.3 MiB/s, and one such GET lost its provider
connection in the second sub-range and broke after 1,152 MiB; a
connection lost now is opened again.

## KEK

The escrow file holds one `VELMORA_KEK_<version>=<base64 of 32 bytes>` line
per version, mode 0600, outside any repository. `ops/kek-restore.sh` sets
each one as a Worker secret through stdin. Nothing else can replace a lost
KEK.

## Naming a wasm frame

The deployed wasm has no `name` section (bundle.sh drops it to stay
under the size budget), so a panic's message is logged as before but
its trace frames read `wasm-function[N]:0xOFF` instead of Rust function
names. To name a frame:

1. Find the deployed version's message, `ci <run id>.<attempt> <sha>`
   (`wrangler deployments list`, or the dashboard).
2. Download the `s3-bridge-symbols` artifact of that CI run (kept 90
   days): `gh run download <run id> -n s3-bridge-symbols`. It holds
   `index_bg.unstripped.wasm`, the same wasm with the names kept.
3. Function `N` is entry `N` of its `name` section. Any wasm tool reads
   it; `wasm-tools print index_bg.unstripped.wasm` prints it as the line
   `(func $<name> (;N;) ...`. Function indices and code offsets are the
   same in both files.

After 90 days, rebuild at `<sha>` with the same toolchain
(`bash bundle.sh`) and use `symbols/index_bg.unstripped.wasm`; a
different rustc may number the functions differently.
