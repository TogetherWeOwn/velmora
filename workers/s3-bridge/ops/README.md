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

`ops/catalog-export.sh` runs `wrangler d1 export`, compresses the SQL with
zstd, and uploads the parts to `velmora-catalog-export` (create it once
with `npx wrangler r2 bucket create velmora-catalog-export`). Run it from
cron, for example daily. D1 does not answer queries while an export runs.

The script prints the **restore point** in milliseconds. Under `d1/<db>/`,
the parts are named `<restore point>.<attempt>.part-000`, `-001`, and so on.
The script uploads `<restore point>.manifest.json` last. The format 2
manifest lists the attempt, its parts and their checksums. Concurrent
exports at the same restore point do not overwrite each other's parts.
The importer also reads format 1 manifests with `.sql.zst.part-NNN` keys.

Install the pinned Wrangler with `npm ci` in `workers/s3-bridge` before
running either script. They require the local Wrangler version from
`package-lock.json`, Python 3.10 or later with SQLite support, and `flock`.
The importer requires SQLite 3.37 or later. On the same host, run these
scripts as the same user with the same `TMPDIR` so they share
locks: exports lock by source database name, imports by resolved target UUID.

The exporter requires a full remote dump with schema and data. Its Wrangler
arguments are limited to configuration options (`--config`/`-c`, `--env`/`-e`,
`--cwd`, `--env-file`, and `--profile`). It has no single-file SQL size limit,
but refuses an export with any SQL statement over 100,000 bytes,
which D1 cannot import. Its summary gives the longest statement and the D1 file
size along with the snapshot sizes. Set `VELMORA_EXPORT_SIZES_LOG` to append
those measurements as JSON lines. The export warns at 60% of either the
statement limit or the paid plan's 10 GB
[database limit](https://developers.cloudflare.com/d1/platform/limits/).
If the D1 size is unavailable, the export warns, records `database_size_bytes`
as `null` in that log, and still publishes the snapshot.

Wrangler uploads each part by default. Splitting keeps each upload under
Wrangler's 300 MiB limit. `VELMORA_EXPORT_PART_BYTES` defaults to 268435456
(256 MiB) and accepts positive integers up to 300000000. At the default, the
1,000-part limit holds over 268 GB of compressed SQL. To use rclone for
uploads and restores, set `VELMORA_EXPORT_RCLONE_REMOTE` to the name of a
configured remote for the R2 S3 endpoint. On failure, the scripts report
where they kept private transfer logs. URL query strings are removed before
logging, and Wrangler's own disk logging is disabled. Staged SQL and parts
are removed locally even on failure.

Take a fresh export after every deploy that applied a migration. An
export carries the schema of its day and the list of the migrations
that were applied (`d1_migrations`), so an older one can still be
loaded and brought up to date (restore, step 2); a fresh one does not
depend on that.

D1 Time Travel (30 days) is the faster tool when the database still
exists: restore it to a timestamp, then replay from that timestamp.

## Restore

Deploy a Worker revision with the incomplete-import replay guard before
using the batched importer. The arming SQL also checks the marker, but an
older Worker cannot enforce it on a direct replay call.

1. Set `MAINTENANCE = "restore"` and deploy. Every write now answers 503,
   and the jobs and the cron do nothing.
2. Bring the database back, one of:
   - Time Travel: `npx wrangler d1 time-travel restore <db> --timestamp <T>`.
     The restore point is `T` in milliseconds.
   - Export: find the newest complete export with
     `rclone lsf <remote>:velmora-catalog-export/d1/<db>/ --include '*.manifest.json' | sort | tail -n 1`.
     An export from before the manifests is one `<restore point>.sql` object
     (`--include '*.sql'`); it loads too, without checksums.
     The number before `.manifest.json` is the restore point. Set
     `VELMORA_D1` to the source database of the export. Create an empty
     database and set `VELMORA_IMPORT_DATABASE_ID` to its UUID from
     `wrangler d1 info <new db> --json` (use the same Wrangler config and
     environment as the import). Export `CLOUDFLARE_ACCOUNT_ID` for the target
     account. Run `ops/catalog-import.sh <new db> <restore point>`.
     The script resolves the supplied name or binding with the operator's
     config and checks the UUID. It then confirms the same UUID and name in
     `CLOUDFLARE_ACCOUNT_ID` and pins every subsequent D1 call to that account
     and UUID with a private config containing no database names or bindings.
     The pinned calls retain the shell credentials and explicit `--profile`
     and `--env-file` (use absolute paths with `--cwd`), not `--env`.
     A production catalogue also requires `VELMORA_IMPORT_PRODUCTION=yes`.
     The export carries the schema and the list of applied migrations, so
     apply migrations after loading it. Do not run against production without
     these confirmations. The script refuses a non-empty database. It caps
     the manifest at 1 MiB, legacy SQL at 5,000,000,000 bytes, and each part at
     its declared size. It stages at most one extra byte to detect overflow
     (which does not limit bytes already in flight). It also bounds
     decompression by the manifest's SQL size and checks every checksum
     before splitting. Legacy single-file exports have no checksums.

     Restore always uses statement-safe batches, even for small exports:
     table schemas first, INSERTs in foreign-key order, then the remaining
     statements (including indexes and triggers). A dependency cycle is
     refused, as are rows for a self-referencing table that cannot fit in
     one batch. `VELMORA_IMPORT_BATCH_BYTES` defaults to 1,000,000,000 bytes
     and cannot exceed D1's 5,000,000,000-byte file import limit. The script
     proves that every original statement is accounted for and rechecks each
     batch's checksum before loading it.

     Reserve local disk for the download and spool (about another SQL dump).
     The importer checks available space before fetching manifest parts (or
     before splitting a legacy download), using about 2.1 times the SQL size
     or the larger decompression/assembly requirement. It discards compressed
     bytes after verification, the SQL after spooling, and spools as used.

     Before batch 0, a single D1 import checks that the target is still
     empty and marks it incomplete. The marker blocks arming and replay.
     If loading stops before all batches are recorded as loaded, delete and
     recreate the target before retrying. The script never deletes databases.

     Verification counts the idle target in indexed pages of at most 5,000
     rows per query. If a verification query fails or is interrupted, rerun
     the same command with the same source, restore point, and target UUID.
     It verifies the counts saved from the dump without downloading or
     reloading any batches. If the counts differ, delete and recreate the
     target; never skip verification of a known mismatch. The opt-out
     (`VELMORA_IMPORT_SKIP_ROW_COUNTS=yes`) is accepted only on a fresh load
     and prints a warning. A retry cannot clear the marker by skipping.
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
   - Replay from the copy's restore point first: its end checks every
     `held` row against the store. Run it again from restore point `0`
     only if it ends with `held_missing_total` above 0. That reads every
     record, so it takes longer; it is always correct. A copy older than
     `SAFETY_MIN_AGE_SECS` is likely to need it, and with the shipped 0 a
     copy of any age can, because a copy may be released minutes after
     its post.
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
  changes where the next record goes, nothing else. It can be changed
  in either direction until a build has written segments (below); from
  then on `flat` is set only under the conditions of "Turning it off
  again" at the end of this section.
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
2. Set `RECORD_LAYOUT = "tenant"` and deploy, alone in its deploy.
   From this deploy on the rollback floor below applies.

In production the variable is not set in `wrangler.toml`, and a value
set by hand in the dashboard or with `wrangler deploy --var` is gone
at the next CI deploy. The deploy job writes it from the variable
`VELMORA_RECORD_LAYOUT` of the `production` environment of the
repository (unset, empty or `flat`: flat; `tenant`; any other value
fails the job before the deploy). Step 2 in production:

1. Let nothing else merge to `main` until step 6 has passed.
2. Check that the version that serves production was deployed by the
   push run of the tip of `main`: its message is `ci <run>.<attempt>
   <commit>`, and the commit is the tip. If the tip was not deployed
   (its deploy failed or was rolled back), stop: the switch would then
   deploy other code together with the variable.
3. Check that this push run is younger than 1 day: the job `deploy
   (production)` takes the bundle the run built, and it is kept for 1
   day. If it is older, wait for the day of the next deploy.
4. Check the other variables of the `production` environment that the
   deploy job writes into the config (every `VELMORA_*` one the step
   "Generate the production wrangler config" reads, among them
   `VELMORA_S3_HOST`, `VELMORA_D1_DATABASE_ID`, `VELMORA_RECOVERY_COPY`,
   `VELMORA_RECOVERY_PREFIX` and `VELMORA_VERIFY_MODE`): the run in
   step 5 deploys their values of now, not those of the serving deploy.
   Compare them with what the serving version carries:
   `wrangler versions view <id> --json` lists its variables and
   bindings in full (without `--json` long values are cut). Put
   any difference right, or confirm it is meant, before going on. Then
   set `VELMORA_RECORD_LAYOUT` to `tenant` in the `production`
   environment.
5. Run the job `deploy (production)` of that push run again, and that
   job only. Running `deploy-build` again builds a new bundle from the
   same commit with the toolchain of that day, which is not the bundle
   that serves. (`workflow_dispatch` does not deploy.)
6. Read the deploy log: the step "Generate the production wrangler
   config" names the layout the generated config carries, `tenant`,
   and the deploy message carries the same commit as the version that
   served before. Then check that the job ended green and that the
   version that serves production carries this run's message. A job
   that fails after the deploy rolls back to the version before it,
   but not always: with no version recorded before the deploy, the
   rollback is skipped; when this run's version is not known and the
   serving one is not the one before, or when a third version serves,
   the step stops with an error and rolls nothing back; and the
   rollback command itself can fail. When this run's version is known
   but the serving one could not be read, it rolls back without that
   check. A failed job sends the deploy alert only where its settings
   are present, and a failed send is only a warning in the log. So
   after a failed job, read which version serves before taking
   production as restored.
   Nothing else changed.

`wrangler secret list` must show no secret named `RECORD_LAYOUT`,
before and after: the Worker reads a secret where the variable is
absent, a deploy keeps secrets, and the deploy job cannot see them.

What to watch after the switch, in the Worker log:

| Line | Meaning |
|---|---|
| `recovery copy: pass=… retry=… records=… copied=… failed=… refused=… source_unreadable=… pending=… extra=… foreign=…` | a copy pass that did not copy everything: `failed`, `refused` and `source_unreadable` count records. A pass without an error logs the line without those three fields |
| `recovery copy: pass=… retry=… stopped: …` | a copy pass that stopped before its end |
| `dispatch: the sweep of unpublished writes was not sent` | the cron could not send the sweep jobs |

and in `GET /_admin/status`: `write_intents.anomalies`, which must not
go up.

Turning it off again (`flat`) is done the same way, with
`VELMORA_RECORD_LAYOUT` set to `flat` or removed. It does not lower the
floor: the tenant records that were written stay. It is safe until a
build has written segments. A segmented upload of a large object writes
segment records for as long as it runs, which can be days, and no
segment may be written under a flat name. So once a build that writes
segments has been deployed with its writer on, the layout is not set
back to `flat`: the writer is turned off first, and `flat` is set only
when no segmented upload is open.

With the recovery copy on, a pass that finds nothing to send costs 6
list calls here and 6 at the other provider (4 and 4 before), in either
setting, because both layouts are listed. Each of the four sweeps (the
tombstones and the generations of each layout) costs one more call on
each side while it holds records of the last hour, so a pass in the
hour after the setting changed, with fresh records in both layouts, can
cost 8 and 8.

The deploy job holds one rule between the layout and segments. A
generation record above 10,000 extents is a segmented one, so a prod
`MAX_OBJECT_EXTENTS` above 10,000 means segments can be written. With
that in the generated config and the layout `flat` (or
`VELMORA_RECORD_LAYOUT` unset), the step "Generate the production
wrangler config" fails and nothing is deployed: no segment is written
under a flat name. A value that is not a plain number
counts as above. `tenant` with any value passes.

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

- **Once deploy 2 of "Shipping the gate" (the `PermitGate` class) has
  been deployed:** never to a version from before it; Cloudflare
  refuses it (code 100402). Before that, a version that knows `PERMITS`
  rolls back like any other. See "Permit gate".

- **Once `RECORD_LAYOUT=tenant` has been deployed:** never to a version
  older than the first one that knows `RECORD_LAYOUT`: the first one
  built from a commit that contains #133 (`tenant-prefixed names for
  new recovery records, behind RECORD_LAYOUT`). From then on a
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
3. Take the latest floor that applies: the merge commit of #133 (the
   one that brought `RECORD_LAYOUT`) once `tenant` has been deployed,
   else the merge commit of #121 (the one that brought `PACKED_PLANS`)
   once that switch has been deployed on, else the merge commit of
   #71. For each version, oldest first,
   check the commit: `git merge-base --is-ancestor <that merge commit>
   <commit>`. The first version for which it succeeds is the floor. A secret-change
   version takes the answer of the version before it. Treat any other
   version without a CI message (an upload by hand) as below the floor.

## More than one S3 host

`S3_HOST` is always in the `legacy` class. Extra hosts can be `legacy` or
`customer`. Both classes admit every key for now, because there is one
tenant; a later change binds tenants to classes. A request is checked
against the host it was sent to: a signature made for one host is refused
on another, and `CompleteMultipartUpload` names the host it was sent to
in `Location`.
A configured host may not be a subdomain of another configured host so
virtual-hosted requests remain refused.
Customer-class hosts return HTTP 404 for `/_admin` routes and HTTP 403
for bearer-token CreateBucket and DeleteBucket requests.

1. Attach the new host to the Worker as a Custom Domain.
2. Set the GitHub Actions variable `VELMORA_S3_HOSTS` to the full list of
   extra hosts, for example `s3.example.io=customer,archive.example.io=legacy`.
   Use up to eight lowercase hostnames without ports or spaces.
3. Let CI deploy. Check the smoke lines for an HTTP 403 with
   `AccessDenied` for each host. Index 1 is the primary host, followed
   by the extra hosts in list order.

To remove a host, remove its entry from `VELMORA_S3_HOSTS`, let CI deploy
successfully, then detach the Custom Domain.

## Client settings

Write with parts of 16 MiB, start multipart at 16 MiB, keep about 16
requests in flight, and give rclone one connection per request:

- rclone, for a tree of files: `--s3-upload-cutoff 16M
  --s3-chunk-size 16M --s3-upload-concurrency 1 --transfers 16
  --s3-disable-http2` (in the remote's section of `rclone.conf`:
  `upload_cutoff = 16M`, `chunk_size = 16M`, `upload_concurrency = 1`,
  `disable_http2 = true`; `transfers` is not a remote key: pass
  `--transfers` on the command line).
  - rclone sends up to `transfers x upload_concurrency` requests at
    once: one PutObject per file below the cutoff, and up to
    `upload_concurrency` parts per file above it. Both are ceilings: a
    multipart transfer pauses between parts to read the next one. `16 x
    1` allows up to 16 requests in flight whatever the file sizes, as
    long as 16 files are being copied.
  - For one large file: `--transfers 1 --s3-upload-concurrency 16`.
  - More than 16 requests at once was not measured.
  - The global `--disable-http2` does the same for every remote of the
    command; `disable_http2` in the remote's section applies to this
    remote only.
- aws-cli, in `~/.aws/config`:

  ```ini
  [default]
  s3 =
    multipart_threshold = 16MB
    multipart_chunksize = 16MB
    max_concurrent_requests = 16
    preferred_transfer_client = classic
  ```

  `classic` keeps these three settings in force: on some instance
  types the default (`auto`) picks the CRT client, which ignores
  `multipart_threshold` and `max_concurrent_requests`.

Why these values:

- **Extents.** One extent holds 16 MiB. A part of 16 MiB is one full
  extent; a smaller part is an extent of its own. With `PACKED_PLANS` on
  (as in production), each extent costs the same catalogue rows and
  queue jobs whatever its size. Usenet articles
  follow the bytes instead (24 for a full 16 MiB extent, one for a tiny
  one), so fewer extents do not cut posts in the same proportion. A
  single PutObject above 16 MiB is stored in slices of 8 MiB (see
  below). With multipart from 16 MiB in 16 MiB parts, a file of 16 to
  95 MiB takes `ceil(size / 16 MiB)` extents. Measured on a test
  deployment, extents per file:

  | File | rclone or aws-cli, these settings | aws-cli defaults (8 MiB) | rclone `--s3-upload-cutoff 95M --s3-chunk-size 16M` |
  |---:|---:|---:|---:|
  | 16 MiB | 1 | 2 | 1 |
  | 17 MiB | 2 | 3 | 3 |
  | 40 MiB | 3 | 5 | 5 |
  | 95 MiB | 6 | 12 | 6 |

  At 95 MiB rclone reaches its cutoff and goes multipart, so that row
  is six parts of 16 MiB, not twelve slices.

- **Concurrency.** One UploadPart of 16 MiB takes 2.0 to 2.3 s through
  the Worker at 4 at once: it is encrypted and stored while it
  arrives. A small PutObject takes about 1.1 s, most of it round trips.
  Both gain from more requests at once. Measured on a test deployment
  from one client host, 256 MiB in 16 MiB parts and 40 PutObjects of
  1 MiB (MiB/s; three deployments for the first and last columns, two
  to seven runs each for the clients):

  | At once | Multipart, S3 test client | aws-cli | rclone `--disable-http2` | rclone default (HTTP/2) | 1 MiB PutObjects |
  |---:|---:|---:|---:|---:|---:|
  | 4 | 15.1 to 18.4 | 17.3, 18.5 | 14.8, 19.3 | 7.1 to 11.0 | 2.6 to 3.1 |
  | 8 | 20.5 to 27.1 | | | 10.7, 16.4 | 4.5 to 5.3 |
  | 16 | 19.6 to 27.8 | 24.0, 28.7 | 32.1, 27.8 | 7.5 to 15.0 | 8.1 to 9.3 |

  No answer was a 5xx, and no client retried. The table is from
  before uploads were stored while they arrive. With that, the S3 test
  client measured on one deployment (three runs each; the other
  columns were not measured again): 24.2 to 29.2 MiB/s at 4 at once
  (1 GiB, five runs), 30.5 to 39.4 at 8, 39.0 to 43.3 at 16, and 3.3
  to 3.7 and 10.2 to 11.3 MiB/s for the 1 MiB PutObjects at 4 and 16.
  - Big parts gain less than small files: the parts in one Worker
    isolate share its CPU, so one part takes about 4.3 s at 16 at
    once. An upload of at most one extent holds a window of a few
    chunks and counts 512 KiB against an isolate's 48 MiB
    `INFLIGHT_BUDGET_BYTES` whatever its length, so the budget does
    not hold such parts back. A slice of a longer upload, a copied
    part and a download count what they hold; one that finds no
    budget waits up to 20 s, then gets 503 `SlowDown`, which clients
    retry. None was refused in these runs.
  - rclone sends all its requests to one host over a single HTTP/2
    connection, and that one connection carries 7 to 16 MiB/s at any
    concurrency. `--disable-http2` gives each request its own
    connection.

A running `rclone rcd` keeps the flags it was started with: a changed
startup command takes effect only when the daemon restarts, and a
restart aborts the copies it runs.

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
  files as multipart uploads. aws-cli does so from 8 MiB in 8 MiB parts,
  rclone from 200 MiB in 5 MiB parts. Use the settings in
  [Client settings](#client-settings) instead: multipart from 16 MiB, in
  parts of 16 MiB. Parts up to 95 MiB work too (`--s3-chunk-size 95M`;
  aws-cli: `multipart_chunksize = 95MB`), within the object size above,
  but they cost more extents: a part above 16 MiB is cut into slices of
  8 MiB, about twice as many extents as parts of 16 MiB.
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
| `waiting_writes`, `oldest_waiting_at` | writes that are due for the sweep: bytes in `SAFETY` that no object uses | the sweep is off, a replay is unfinished, the catalogue is rolled back, the cron could not send the jobs (it logs `dispatch: the sweep of unpublished writes was not sent`), or the jobs fail (each failed job logs `alert: intent sweep: a job failed and is tried again: class=…`, with the class `catalog`, `blob`, `crypto` or `internal`, and is tried again; a job of any kind that did not end or was dropped logs `job table: a job did not end and was given up` or `job table: a running job was dropped`, which does not name the sweep) |
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

## Upload parts that left their upload

Three things take a part out of a multipart upload for good: the part
is uploaded again under its number, the upload is aborted, or
CompleteMultipartUpload leaves the part out of its list. Such a part
was never posted. Its ciphertext stays in `SAFETY` (`x/<extent id>`),
and `GC_MODE` takes it only in a disposable bucket.

`GC_ORPHANS = "on"` (its own switch, in every bucket, whatever
`GC_MODE` says) deletes these copies and nothing else. The copy of an
extent goes when all of this holds in one batch of the catalogue:

1. the extent has an open `delete_safety` row in `gc`. For an extent
   that is still `staged`, only the three writes above queue one, in
   the batch that takes the part out of the upload, dated with that
   moment;
2. that moment is 31 days ago or more;
3. the extent is `staged` and has no generation: no object was ever
   made of it;
4. no `generation_extents` row names it: no object and no server-side
   copy reads it;
5. no part of an open upload names it. An upload in progress keeps
   every part it lists, however old it is;
6. no replay is under way, the catalogue is not behind its rollback
   stamp, and the last replay ended 31 days ago or more ("After a
   restore" below);
7. no key that could still get an object made of the part has a write
   whose outcome is not known (below).

**Why 31 days.** Nothing a request or a job does brings a dropped part
back: its extent id is never issued again, and only an open upload
that lists an extent can publish it. A database taken back to before
the drop does list it. Time Travel reaches 30 days, so a part that was
dropped longer ago is dropped in every state the database can return
to, as long as it was not restored in that time ("After a restore"
below); the 31st day is the margin between the clocks. A database taken
back to before a part was collected still has the part dropped with
its row open, and the collector deletes the absent copy once more.

**A write whose outcome is not known.** CompleteMultipartUpload stores
its recovery record, which names the parts it was given, before its
batch runs. If the batch does not run and the record cannot be removed
either, the request answers 5xx, the upload stays open, and the record
stays: a replay would publish it. The catalogue marks the key before
any such record is stored (`key_floors.unpublished`), and only a write
or a delete of the key that was acknowledged takes the mark away. While
the key of an upload is marked, the collector leaves the parts of that
upload. For a part that was uploaded again, and for the slices after
the first of a part above one extent, the catalogue no longer knows
the upload: those wait until no key of their bucket that an upload was
ever begun on is marked. The catalogue asks that of a bucket once a
day at most and keeps the answer for that day (`scan_cursors`, key
`orphans:bucket:<bucket id>`, value `clean:<time>` or `marked:<time>`
in milliseconds). A key that is marked after a bucket was found clean
holds nothing back that day, and need not: its record was stored then,
from a part list that a part dropped 31 days earlier is not in. The
marked keys:

```
npx wrangler d1 execute <db> --remote --command \
  "SELECT b.name, f.key, f.floor_id FROM key_floors f JOIN buckets b ON b.id = f.bucket_id WHERE f.unpublished <> 0"
```

To let the parts go, settle the key: PUT the object again, or DELETE
the key (a delete of a marked key stores a tombstone also when the key
has no object). The parts of that key's upload go with the pass after
that. The others go with the first pass after the answer about their
bucket is a day old. What holds a bucket's parts back now:

```
npx wrangler d1 execute <db> --remote --command \
  "SELECT k, v FROM scan_cursors WHERE k LIKE 'orphans%'"
```

`orphans:bucket:<bucket id>` = `marked:<time>` means the parts of
unknown uploads in that bucket wait for a marked key, as found at that
time. `orphans` is the position of the scan (`rest:<time>`: the next
pass starts then).

**Before turning it on.**

1. A record stored before the catalogue had `key_floors` (migration
   0007) set no mark. Such a record names only parts that were stored
   before it. This must print 0:

   ```
   npx wrangler d1 execute <db> --remote --command \
     "SELECT COUNT(*) FROM extents WHERE state = 'staged' AND created_at < COALESCE((SELECT CAST(strftime('%s', applied_at) AS INTEGER) * 1000 FROM d1_migrations WHERE name = '0007_key_floors.sql'), 9007199254740991)"
   ```

   A database with no row for that migration in `d1_migrations` (it
   was applied by hand, or the database was imported) counts every
   staged extent: put the time the migration was applied in place of
   the subquery.

   The Worker version that came with that migration is the first one
   that sets the mark. A version from before it may have served for a
   while after the migration was applied, and serves again after a
   Worker rollback: put the time from which only versions with the
   mark have served in place of `applied_at` when it is the later one.

   If it does not, leave the switch off until every key that had an
   upload before that time has been written again: PUT an object
   to it, and DELETE that object after if the key should hold none. A
   DELETE alone is not enough there: such a key carries no mark, and
   on a key with no object and no mark a delete stores nothing, so the
   old record would stay the newest one of the key.
2. Run it on a deployed test environment, with `GC_ORPHANS = "on"`
   and `GC_MODE` off there: with `GC_MODE=disposable` the older
   collector deletes a dropped part in a bucket flagged disposable as
   soon as it is dropped, and the run would show nothing about this
   one. Abort an upload, upload a part twice and keep one upload open.
   Then delete the row `orphans` of `scan_cursors` on that environment
   (the scan rests a day after a pass, and a database used before may
   hold a row from then) and wait until the row is back and reads
   `rest:<ms>`: the collector has then made a pass since the parts
   were dropped (the first cron run of a new deployment can be a
   quarter of an hour away). The copies of the dropped parts are still
   in `SAFETY` (`x/<extent id>`): the grace period holds them. Then
   date the `gc` rows of the dropped parts 31 days back, delete the
   row `orphans` again, and wait for a cron run. Then see both: the
   copies of the dropped parts are gone from `SAFETY` and their
   extents say `deleted` with the `gc` row closed, so the collector
   did run; and the open upload completes and reads back.

**What it costs.** While nothing is due, one row read per cron run. A
pass reads the open `gc` rows in windows of 500, oldest first, and a
job takes at most 100 parts; each part is one delete in `SAFETY` and
three rows written (the extent, the usage counter, the `gc` row), plus
one row per job for the position of the scan. After a pass over every
due row the next one starts a day later. With `GC_MODE` off the rows
of deleted and replaced objects stay open, and every pass reads them
again: one row read for each, plus one for its extent, once a day. The
parts whose upload is no longer known (point 7) need one statement per
bucket that reads every row of `uploads`, about two rows read per
upload ever begun. It runs once a day per bucket, whatever the number
of parts and jobs, and also while a marked key holds such parts back:
those are then refused for the rest of the day without another read of
the uploads. Two jobs that run at the same moment on an answer that is
a day old both ask: the read is then done once for each of them.

**After a restore.** Time Travel cannot reach back past the 31 days on
the history the database is on. It can return to a state of a history
that an earlier restore left, for 30 days after that restore, and such
a state may list in an open upload a part that was dropped, and since
collected, on the history that was kept. So the collector deletes
nothing until 31 days after the last replay ended
(`SELECT state, finished_at FROM restore_state`): a catalogue that was
taken back takes no write before a replay has run to its end, and by
then every state of a history left before it is out of reach.

It cannot see a restore that was undone before the replay after it
ended, or in the minutes after it ended and before the next cron run
raised the rollback stamp: the catalogue that is brought back holds no
trace of the time it was away. So two rules stay as well, for every
Time Travel restore, also one that undoes another, and also one that
the rollback check did not report:

1. set `GC_ORPHANS` to off and leave it off for 31 days;
2. run the replay to its end before the switch goes back on. A restore
   can take away the mark of a write whose outcome is not known while
   its record stays; the replay publishes such a record and takes its
   parts into the object, so they are not collected.

A database loaded from an export file that is older than 31 days can
list, in an open upload, a part whose copy was collected since. The
replay counts such rows in `held_missing_total`; abort the uploads they
belong to. A catalogue rebuilt from the records alone does not know the
parts that were not collected yet: their copies stay in `SAFETY`.

With the switch off nothing is deleted, and the rows stay for a later
run with the switch on.

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

## Permit gate

A provider permit is the right to hold one connection to one provider
account: `max_conns`, `max_ips` and the pool limits are enforced by
handing permits out. `PERMITS` chooses where they are kept:

- `d1` (default, also when unset): slot rows in the catalogue
  (`provider_permits`). Every acquire, renew and release writes a row.
- `do`: in the memory of a Durable Object (`PermitGate`, binding
  `PERMIT_GATE`). A holder (a job, a cold read) opens one WebSocket to
  each object it needs; its first acquire travels with the opening,
  and every renewal, further acquire and release is a message on it.
  Calls a job makes at the same moment travel together. Nothing is
  written for a permit: the permits of a session are kept with its
  socket, the object leaves memory between two messages and finds them
  again when the next one comes. When the socket ends (the job is
  done, its invocation ended or failed) its permits are free at once.
  The object stores one small record: written at the first start after
  a deploy, and every 10 minutes while permits of a class are live.

There is one object per provider account, named
`permits:account.<id>:0`. Accounts that share `pool_max_conns` have one
object for the pool (`permits:pool.<pool>:0`): a limit can only be kept
by an object that sees everything under it. Two optional vars change
that:

- `PERMIT_SHARDS` (1 to 64, default 1) divides each account or pool
  over that many objects, `permits:<unit>:<shard>`. One object answers
  its requests in turn, about 1,000 a second; an account needs a second
  object only when its permit calls come near that. Each object takes
  the slots `n` with `n % shards == shard` and the matching part of
  `max_ips` and of the pool limit. No account gets more objects than
  its smallest limit (`max_conns`, `max_ips`, `pool_max_conns`) less
  the one connection or address that limit keeps back for reads, so
  that every object has a connection and an address to hand out to a
  job. (`max_ips = 2` therefore means one object, whatever
  `PERMIT_SHARDS` says.) A holder asks one object first and the others
  only when that one has nothing left.
- `PERMIT_GATES = "one"` puts every account behind the same objects
  (`permits:all:<shard>`). That is the least duration to pay for (see
  "Cost") and the lowest ceiling on requests.

Change `PERMIT_SHARDS`, `PERMIT_GATES`, which pool an account is in, or
(with more than one shard) a provider's limits only while `PERMITS` is
`d1` and no gate holds rows (the query below is empty). An object
keeps the rows it seized under the old division, and the objects of
the new one wait for them without end: an account moved out of a pool
that still has other members gets no permit, and one moved into
another pool stops that pool too, until a round trip through `d1`.
With three or more shards, a change of `max_conns` while both versions
of a deploy run can also move address shares between objects and pass
`max_ips` for that time.

A permit is a limit on connections, not a guard of data: the lease
token of a job in the catalogue is unchanged and still fences every
write.

### Restarts

The object leaves memory about ten seconds after its last message and
comes back at the next one with every open socket and the permits kept
with it. That is not a restart, costs nothing and makes nobody wait.

A deploy can cut every socket. The object then knows no holder, while
Workers may still hold connections under permits of the old version.
So:

- The first start under a new version that is within the stored
  horizon of the old permits (whether or not a socket is still listed
  as open) waits until
  every one of them has run out: up to 125 s for jobs and 40 s for
  reads (the lease lengths plus 5 s), counted from the first request
  after the deploy (the cron's, at the latest). During the jobs' wait
  a read may use only the connection and the address that are kept
  back for reads. The wait is stored with the version, so later starts
  neither forget it nor begin it again.
- A start with no horizon ahead (nothing was handed out for more than
  10 minutes) hands out at once.
- Permits from before the deploy are neither renewed nor released by
  the new object. A job that cannot renew stops and is retried by the
  queue, as it does when a slot row is lost.

Not covered: an object that is reset without a deploy (it crashed, its
machine was lost) while holders are connected through it. Their sockets
are cut, their permits are free at once, and each of them goes on
until its next renewal fails. A job renews every 20 s and before every
call to the provider, and a call may run for 80 s: up to about 100 s
for a job, 25 s for a read. In
that time the account can be asked for more connections than
`max_conns`; the provider refuses the extra ones and the job that was
refused is retried. Closing this would take two stored rows for every
busy period of every object.

The version comes from the `CF_VERSION_METADATA` binding; without it
the object answers every request with an error.

Every time the object comes into memory it logs one line, `permit gate
started: sessions=… jobs_until=… reads_until=… warm_until=… seized=…`.
`warm_until` in the future is the wait after a deploy.

### Turning it on, and back

Old and new Workers run side by side during a deploy, one side asking
the catalogue and one the gate. The slot rows decide between them, so
the two together never exceed a limit: the gate hands out on a provider
only while it holds every slot row of its part of it under the holder
`do-gate:<gate>`, and every other row of the account (and of every
account of its pool) is held by a gate of the same account or pool. It
takes a row only when the row is free, so the gates start once the
catalogue's callers have let go of the whole account. A gate told to
retire keeps its rows, renamed `do-gate-idle:<gate>`, once none of its
own permits is live; the rows of an account or pool become free
together, when its last gate has retired. With several shards the
address and pool limits are shared out among the gates, so the account
is either all the gates' or all the catalogue's, never part of each.

A gate that comes into memory under the version it last ran as takes
what it stored about the rows. Its first start under a new version
(every change of `PERMITS` is one), the cron (every 5 minutes) and
every return to charge ask the catalogue again. Do not edit `do-gate:`
rows by hand while `PERMITS` is `do`.

1. Ship the class and its binding with `PERMITS = "d1"`, in the three
   deploys of "Shipping the gate" below. Nothing calls the gate yet.
2. In a deploy of its own, set `PERMITS = "do"`. Do not change a
   provider's limits, pools or the provider list in that deploy, and do
   not split its traffic by percentage: both sides must agree on the
   slots. Jobs and cold reads pause until the rows have changed hands:
   at most the length of the permits still held (120 s for jobs, 35 s
   for reads), usually a few seconds.
3. Check:

   ```
   SELECT provider_id, holder, COUNT(*) FROM provider_permits
    WHERE holder IS NOT NULL GROUP BY 1, 2;
   ```

   Every row reads `do-gate:<gate>`. `/_admin/status` shows the permits
   in use as before.

To go back, set `PERMITS = "d1"` in a deploy of its own and keep the
`PERMIT_GATE` binding. The first acquire that finds no free slot (and
the cron, every 5 minutes) tells each gate that still holds rows to
retire; the gates free them once their permits have run out. The query
above is then empty or shows job holders. In `d1` mode a gate that
cannot be reached delays only this hand-back, not the cron's other
work.

`PERMITS = "d1"` is not quite the code from before the gate: the cron
and an acquire that finds no free slot (at most every 30 s) read the
slot rows once more, to find gates to retire, and a job closes its
provider sessions before it frees their slots.

A rollback to a version from before the class (deploy 2 below) is not
possible once deploy 2 is live: Cloudflare refuses it. This includes
the automatic rollback of deploy 2 itself; if that deploy fails, fix
forward (below). `do-gate:` and `do-gate-idle:` rows never run out by
themselves. To clear them by hand, only with no Worker in `do` mode and
after the longest permit has run out (125 s):

```
UPDATE provider_permits SET holder = NULL, lease_until = 0, pool = NULL
 WHERE holder LIKE 'do-gate:%' OR holder LIKE 'do-gate-idle:%';
```

### Shipping the gate

A Worker version that declares a Durable Object class can never be
rolled back past: Cloudflare refuses a rollback, a `versions deploy`
and a traffic split to any version from before the class (code 100402
for a class declared by `exports`; 10210 for the legacy `[[migrations]]`
array). So the class goes out on its own, with the same code that has
already run, and nothing that uses it comes in the same deploy. The
production tables change in three pull requests after the code, each a
deploy of its own, in this order. Production now declares the class
(deploy 2), so the rollback floor it sets is in force, binds it
(deploy 3), and takes its permits from the gate with `PERMITS = "do"`
(deploy 4):

| # | change to the production tables | rollback | merge the next one when |
| - | ------------------------------- | -------- | ----------------------- |
| 1 | none: the code that knows `PERMITS`, with `PERMITS = "d1"` and no class or binding | as for any release | its deploy job is green, it alone serves 100 %, and in a status check after it the outbox `done` count has risen and every provider is healthy |
| 2 | `[exports.PermitGate]` alone | none past it, ever | its deploy job is green |
| 3 | the `PERMIT_GATE` binding and `[version_metadata]` | to deploy 2 | its deploy job is green and the active version has the binding |
| 4 | `PERMITS = "do"` (step 2 above) | `PERMITS = "d1"`, or to deploy 3 | n/a |

Merge each one only when the deploy before it is live and green. The
deploy job ships the tip of main and rolls back to the version it
replaced, so two of these merged close together go out as one deploy:
2 with 3 would put the binding into the one deploy that has no
rollback, and 3 with 4 would
make the job's rollback target a version without the binding, which
strands the gates' slot rows (below).

Deploy 2 adds, at the top level of `wrangler.toml` (never with
`[[migrations]]`: once a class is declared by `exports`, a deploy that
declares it by `[[migrations]]` again is refused, code 100403):

```toml
[exports.PermitGate]
type = "durable-object"
storage = "sqlite"
```

Deploy 3 adds:

```toml
[[durable_objects.bindings]]
name = "PERMIT_GATE"
class_name = "PermitGate"

[version_metadata]
binding = "CF_VERSION_METADATA"
```

Rules for deploy 2:

- It goes out with `wrangler deploy` at 100 %, through the deploy job,
  once deploy 1 meets the condition in the table above. Deploy 1 changes
  the slot path that every post and verify job takes, which runs
  thousands of times in one status interval, so a fault there shows
  before deploy 2. Faults that appear only after hours cannot be ruled
  out this way: after deploy 2 they are fixed forward. A version that
  adds a class cannot be uploaded with `versions upload` together with
  its binding, and cannot share traffic with an older version.
- Every change already shipped has run cleanly before it. Changes that
  ship after it are above the floor it sets and roll back to it or
  later like any other release.
- If its smoke test fails, the deploy job's automatic rollback is
  refused (code 100402) and the job fails at that step. The new version
  keeps serving. Nothing is bound to the class and the code is the code
  of deploy 1, so run the smoke test again; if it still fails, set
  `MAINTENANCE` as needed and ship a fix forward. The class stays.

After deploy 3 a fault is undone in the ordinary way: a rollback to
the deploy 2 version (the job does it). After deploy 4, set
`PERMITS = "d1"` again or roll back to the deploy 3 version, which
keeps the binding, so the gates can hand their slot rows back (see
above). Never roll back to a version without the `PERMIT_GATE` binding
while the query above shows a `do-gate:` or `do-gate-idle:` row: no
Worker could then tell the gates to let go, and those slots stay taken.

Never delete the class to undo it. An unused class with no object
costs nothing. Removing it takes a version without the class in its
code plus a `state = "deleted"` entry under `[exports.PermitGate]` in
one deploy (a deletion is refused while the code still exports the
class), and is a class change of its own, with no rollback. After a
deletion, a rollback to a version that declares the class creates it
again, empty, and a later rollback to the deleting version deletes it
again with whatever it held. Never reuse the name of a deleted class.

### Cost

Measured on a throwaway deployment (three accounts capped at two or
three connections, four gate objects, 11 extents of 16 MiB per mode):

| per 16 MiB extent              | `PERMITS=d1` | `PERMITS=do` |
| ------------------------------ | ------------ | ------------ |
| rows written to the catalogue  | 55.8         | 49.2         |
| of those, slot rows            | about 6      | 0            |
| billed requests to the gates   | 0            | 13 to 31     |
| rows written by the gates      | 0            | about 1.3    |
| gate duration, GB-s            | 0            | 0.12         |

- A job opens one session with each gate it takes a slot at: one
  billed request each, about two per job. The gates were entered 31
  times per extent; 13 is that count with a message as a twentieth
  and the end of a session as nothing, which is how they are priced
  as far as the price list says. Renewals and the release
  are messages on it, billed at a twentieth of a request. An extent is
  about five job runs (the post, its retries and the checks).
- A permit writes nothing. A gate writes its record once per
  10 minutes of use and twice after a deploy (once more for each
  further account or pool it serves), whatever the load.
- A gate is in memory only while it answers: its sessions keep the
  permits while it sleeps. An idle deployment asks each gate once per
  cron run and writes nothing.
- The time a job takes to get its slots was 47 ms at the median
  against 354 ms with slot rows; the first job after a start of a
  gate that has to ask the catalogue for its rows took 3.1 s.

At the list prices of late 2026 that is $3.2 to $3.4 per TB posted in
gate mode against $3.3 with slot rows: about the same bill, with the
slot rows out of the catalogue's write path.

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
  write of an extent normally runs beside the read of the next one. If
  the next extent cannot charge the bytes for a rebuild, the GET waits
  for its own previous cache write, then tries that charge once more
  before giving up on that rebuild attempt. A cache write that fails
  does not fail the read.
- **One step ahead, no further.** The Worker reads one extent ahead of
  the client and holds one cache write, all within
  `INFLIGHT_BUDGET_BYTES`. A client that stops reading stops the Worker
  after that extent, and a client that goes away ends the read.
- **Before deploying with a custom request budget.** Check that it fits
  a cold read and a rebuild from stored parity. With 16 MiB extents,
  `INFLIGHT_BUDGET_BYTES` must be at least 43,658,464 bytes even for one
  cold socket. Raise a lower budget before deploying. `PARITY=off`
  stops writing new parity but does not remove this requirement. The
  shipped 48 MiB budget already fits.
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
  writing to the cache. Time a rebuild spends waiting for this GET's
  previous cache write counts in `read_ms`. The log names no key, bucket,
  message-id or host.

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

## Usage counters and metrics

The catalogue keeps running totals so that the status and dashboard
routes read a handful of rows instead of counting tables: extents by
state, outbox rows by stage, bytes not yet released and bytes pinned,
live objects and bytes per bucket, posts, verifies and releases per
hour, and the failed and dead counts. Triggers (migration 0020) change
a total in the same statement as the row it counts, so a batch that
fails leaves both as they were.

The migration creates empty tables and reads nothing. The counters are
off until the first recount has gone over every row, and a Worker from
before the migration runs on the new schema unchanged.

Switching them on (once, after the migration):

1. `POST /_admin/usage/recount` (admin bearer). It starts a recount and
   does a few bounded steps; no statement reads more than a few
   thousand rows. Optional: `steps` (default 4, at most 16) and `chunk`
   (rows per step, at most 4000).
2. The cron continues it, five steps per run. `GET /_admin/ops-snapshot`
   shows `recount` while it runs and `seeded: true` when it has ended.
   Calling the route again also continues it.
3. From then on the cron recounts once a week and compares. A
   difference is logged as `alert: usage counters differ from the
   tables` and kept in `last_recount`; the counters are replaced only
   by `POST /_admin/usage/recount?adopt=1`. `restart=1` abandons a
   recount that is running and begins again; while a comparison is
   running, `adopt=1` alone only continues it, so send
   `restart=1&adopt=1` to replace the counters.

Rows written: with packed plans, 52 per extent and 23 per object with
the counters on, against 46 and 21 with them off (measured on the local
rig; `rows_written_per_extent` in the slice tests prints both).

Start the first recount only when no Worker older than this one still
serves, and before rolling back to one, send `POST /_admin/usage/off`,
also while a recount is still running (a recount counts changes to the
rows it has passed before the counters are on). It switches the
triggers off and drops a running recount, and the totals are rebuilt
by a recount when the newer Worker returns. The route also files the
hour under way and sets the event totals to zero, so they count from
the next recount on.

The route is refused in maintenance and while a restore is replayed,
which is when a rollback may be needed. This statement does the same
to the triggers, from `wrangler d1 execute`:

```sql
UPDATE usage_global SET all_x = 0, all_o = 0, all_g = 0,
       cur_x = '', cur_o = '', cur_g = '', pass = 0;
```

An older Worker compares the number of rows a statement changed with
one, and a statement that also moved a counter reports two.

Read routes, all `GET` and served without a table scan:

- `/_admin/ops-snapshot[?hours=N]`: the totals, the age of the oldest
  due outbox row per stage, the hourly figures (the last 48 hours that
  had an event unless `hours` says another number, at most 168; each
  names its hour) and the state of the recount.
  Posts, verifies and releases count outbox rows leaving that stage
  in the hour, and dead counts rows given up; failures count errors
  recorded, retries in the same stage included. All are as seen: a
  restore replay that closes a row counts as a verify, and a row
  written late is counted in the hour it was written.
- `/_admin/usage/buckets[?after=&limit=]`: objects and bytes per
  bucket, in pages; `next_after` is the cursor. `seeded: false` says
  that the counters are off and the figures are stale or missing.
- `/_admin/cost`: the JSON at `ops/cost/latest.json` in the cache
  bucket, as the cost job left it (404 when there is none).

`ADMIN_READ_TOKEN` (a secret, at least 32 characters, different from
`ADMIN_TOKEN`) opens these three and `/_admin/status`, with `GET` only;
it opens nothing that changes state. `ADMIN_HOST`, when set, is the
only host name on which `/_admin/` answers at all; on any other host
the routes answer 404. A caller through a service binding is held
to it as well: the host name in the URL it fetches is the one checked. It covers `/_admin/` only: creating and deleting a
bucket with the admin token (`PUT` and `DELETE` of `/<bucket>`) stays
on the S3 host names.

Request metrics go to the Analytics Engine dataset bound as `METRICS`:
one request in `METRICS_SAMPLE` (default 10) and every 5xx the Worker
answers itself. A request the runtime ends (an exception, error 1101,
or a limit) gets no point: those are in the Worker's own invocation
figures, not here. A point has
the method, the status class, `s3` or `admin` (or `sub`: a failed
sub-request of a large GET), and the colo as text,
and the status, latency in ms, request bytes, response bytes and the
sampling weight as numbers; sum the weight to estimate request counts.
A run of reads from Usenet (cache misses) is a point of kind `cold`,
never sampled. One GET can have several such runs and a copy reads
too, so these points show how much is read from Usenet over time; they
are not a hit rate and are not to be subtracted from the GET count. No
bucket, key, query, header, ID, IP address or token is written.

### GET failure stages

Workers Analytics (GraphQL) can show HTTP status counts, including
responses from the runtime. Use the [Analytics Engine SQL API][ae-sql]
to break down Worker-answered GET errors, including range GETs. This
uses the existing request point, with colo still in `blob5`:

- `blob6`: `auth` (authentication, including the key and bucket
  lookups), `lookup` (object, extent or cold-read catalogue), `plan`
  (metadata, range or extent planning), `grant` (fan-out grant creation,
  admission, scope, or a granted generation that no longer exists),
  `subrange_transport` (binding/stream setup or opening the first
  sub-request), `subrange_length` (first sub-range's declared length),
  `subrange_status` (other non-200 first sub-range response), `r2`
  (blob-store failure or warm copies unavailable without a cold plan),
  `nntp` (provider read failed or was interrupted), `slot_wait` (timed
  out waiting for a provider connection slot), `budget` (byte-budget
  exhaustion), `decrypt` (could not open verified cold bytes), or
  `other` (unclassified, including an HTTP response-conversion fallback).
- `blob7`: `le_1gib` or `gt_1gib` for the full object size, including
  for range GETs; `unknown` if it was not available. This does not
  disclose the exact object size or indicate that a range fanned out.

For example, group public S3 GET 500s over the last hour by stage and
size class (`velmora_requests_dev` for dev):

```sql
SELECT blob6 AS stage, blob7 AS size_class,
       SUM(_sample_interval * double5) AS requests
FROM velmora_requests
WHERE timestamp >= NOW() - INTERVAL '1' HOUR
  AND index1 = 'req' AND blob2 = 'GET' AND blob4 = 's3'
  AND double1 = 500 AND blob6 != ''
GROUP BY stage, size_class
ORDER BY requests DESC
```

The empty-stage filter omits older points. To inspect failures inside
sub-requests, query `blob4 = 'sub'` separately (use `blob3 = '5xx'` to
include 503s); do not add these to public counts. The Worker reports
one response point before streaming the body. Failures after that
point, including later sub-range failures on the front request, do
not change its HTTP status or that point.

[ae-sql]: https://developers.cloudflare.com/analytics/analytics-engine/sql-api/

## KEK

The escrow file holds one `VELMORA_KEK_<version>=<base64 of 32 bytes>` line
per version, mode 0600, outside any repository. `ops/kek-restore.sh` sets
each one as a Worker secret through stdin. Nothing else can replace a lost
KEK.

## Naming a wasm frame

The deployed wasm has no `name` section (bundle.sh drops it to keep the
bundle small: about 800 KB, about 8 ms on a request served by a new
isolate), so a panic's message is logged as before but
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
