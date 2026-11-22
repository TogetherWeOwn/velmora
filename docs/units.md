# Units

A **unit** holds the catalogue of one tenant (or of some of its buckets) in
its own SQLite Durable Object, named `<tenant>/<unit number>`. The Worker
stays where keys, R2 and records are; the unit decides S3 requests from its
own tables, one call at a time.

Code: the rules are in `crates/velmora-bridge/src/unit/` (generic over the
database, so they run natively in tests); the Durable Object class, the
`DoSql` adapter, its JavaScript shim and the point-in-time bridge are in
`workers/unit/`. Nothing binds the class yet.

## Rules

1. **Same code.** A unit runs `SqlCatalog<DoSql>`: every operation is the
   catalogue's own code over the unit's database. The Worker calls it with
   coarse calls over `fetch`, as JSON (`unit::call`).
2. **One transaction.** A whole call is one `storage.transactionSync`: all of
   its writes or none. A batch inside it is a nested transaction (a
   savepoint): a batch refused by its guard rolls back only itself.
3. **No key.** A unit never holds an unwrapped key of any kind. Crypto, R2
   access and record writes stay in the Worker. The unit can therefore not
   verify a signature or a seal; rules 6 and 11 say what it checks instead.
4. **No I/O inside a call.** No network, no timer and no queue send inside a
   call, so the object can sleep between calls and its duration cost stays
   near zero. A call is polled once; a call that waits on anything is
   refused and rolled back.
5. **Identity.** Every call carries the tenant and unit it is for. Every
   call but the Worker's own `sync` also carries two chain numbers:
   `state_seq` (the tenant's records) and `keys_seq` (its key records);
   `sync` carries them in the verified record it copies, and `provision`
   carries the caller's `state_seq` for the birth check. The unit compares
   the numbers with its own:
   - another tenant or unit than the object: refused, and the Worker alarms;
   - a number above the unit's: `sync_needed`; the Worker verifies the
     records up to the head and calls `sync` first;
   - a request with a lower number: the unit answers its own numbers and
     does nothing; the Worker refreshes and retries once;
   - a job with a lower number: the unit answers `stale` with its own
     numbers and does nothing; the consumer runs the job once more with
     them (AM-50, "Jobs");
   - a job with no number: refused (`stale_job`); no writer sends one;
   - a fan-out sub-request (a part of a large GET, under a grant made
     earlier) with lower numbers: served only if, in the same transaction,
     the unit's own tables say the tenant may read, the bucket exists, and
     the reader's key is `active` with a grant on that bucket (a public
     read: the bucket is still public). Otherwise it is refused with the
     error the whole request would get.
     Whatever its numbers, a fan-out call names its reader and the
     generation its grant was made for, and reads that generation of that
     key, not the one live now.
   - **The key-chain apply names its base** (`apply(from_seq, entries)`,
     `unit::keys`). `from_seq` is the exclusive base, and the entries,
     one per record, run without a gap from `from_seq + 1`; a gap is
     refused. A base above the unit's `keys_seq` is answered
     `keys_behind` with the unit's numbers, and the caller reads again
     from the unit's seq + 1. Each entry is compared, per subject, with
     that row's `last_seq`: an entry at or below it is skipped, except an
     entry that revokes, and one that opens at the same seq a row held
     closed (the bring-up's second send). `revoked` is final. Each entry
     states its subject as the head holds it, stamped at that record's
     seq. A record that changes no subject (`KeysFrozen`, `KeysThawed`,
     AM-28) comes as a marker item, `{"marker": "keys_frozen" |
     "keys_thawed", "seq": n}` (AM-62): it counts in the gap rule, writes
     no row, is counted as skipped, and `keys_seq` moves past it. The
     golden file pins the form. The apply is the one way `keys_seq`
     moves; `sync` refuses a `keys_seq` above the unit's
     (`keys_not_applied`).
6. **Birth certificate.** A unit is made only by `provision(token)`. The
   token names the tenant, the unit, the jurisdiction, the record seq, the
   schema version, the key scheme and its kind (`birth` or `restore`), and is
   sealed under the control key: the Worker verifies the seal; the unit
   stores the token and checks that the names are its own.
   - The Worker calls `provision` for a birth only when the chain head it has
     just read is the record that first lists the unit, at the token's seq,
     and the unit's born marker is absent. Once the marker exists, the unit
     is made again only by a restore token.
   - A restore token is valid only while the head holds a `restoring` entry
     for this unit at the token's seq. A unit made by it starts closed.
   - The unit refuses a birth token whose seq is below the caller's
     `state_seq`, and a `provision` without the caller's numbers: a lost
     unit is never turned into an empty one with its first token.
7. **Unborn is not empty.** A unit without a certificate answers `unborn` to
   every call but `provision` and writes nothing: no table is made before a
   birth. The Worker answers `503` and pages when a record lists the unit,
   `404` when none does.
11. **Unauthenticated calls are read-only.** A call carries `authenticated`,
    set by the Worker only after SigV4, the service token or a fan-out grant
    verified. Of the callers' operations only two run without it: the
    key-row fetch and the cold read plan (both read-only; a cold read
    returns the key row with the plan, so a cold isolate verifies the
    signature from one call). Their transaction is rolled back and refused
    if it changed a row. The Worker's own calls (`provision`, `sync`, `renew`) are
    not judged by this flag: they carry records the Worker has verified,
    never a caller's input, and a cold isolate needs `sync` before it can
    verify a signature.
12. **Freshness lease** (`unit_lease`). The unit stores `fresh_until`. With
    an expired lease (never issued, closed, or run out) it answers
    `renew_needed` to every call but the Worker's own (`sync`, `renew`, the
    key apply, the import, the gate's and the restore's) and the stamp
    check of a job (`stamp`, `stamp_rolled_back`), and does nothing else.
    The one exception (AM-63): an unauthenticated `key_row` of a request is
    still answered, read-only and marked `lease_expired`. The Worker uses
    that row only to check the signature; a request whose signature
    verifies renews as a signed call and reads `key_row` again, and goes on
    only with the row read after the renewal.
    - **`renew(proof_start, proven, revocations)`.** The Worker proves the
      unit from the safety bucket (`unit_lease::renewal`: the next record of
      each chain is absent, no stamp object after the unit's counter, and
      the listing of `m/rk/<t>/`) and passes what it proved. In one
      transaction the unit applies the listed revocations (a key row is
      revoked; an id it holds no row for is kept in `unit_revoked_ids` and
      revokes a row that arrives for it later), then sets
      `fresh_until = proof_start + T` (T = 10 minutes, est) only if its own
      seqs, stamp counter and revoked count are at least the proven ones,
      every listed id is held as revoked, and `proof_start` is at most 30 s
      behind or 5 s ahead of its clock. A renewal never moves the lease
      back. Refused (with the reason): a `restoring` entry, a recorded
      rollback, a unit without the lease table. The listed revocations are
      kept also when the lease is refused.
    - **The close.** The `sync` that sets a `restoring` entry ends the
      lease; `lease_hi`, the latest `fresh_until` ever held, is kept for the
      restore's wait. A `stamp_rolled_back` that records a rollback ends it
      too.
    - **Every answer** leaves the unit as `UnitReply`: the answer's object
      with `lease_left_ms` (0 for no lease) and, once the unit holds keys or
      listed ids, `revoked` (each id once) beside its fields.
13. **Key scheme.** Tenant 0 holds key scheme 1, every other tenant scheme 2;
    a token with the other scheme is refused.
14. **Jurisdiction.** A token names the jurisdiction of the namespace its
    object is in; a token for another one makes no object.

**Rule 8, one alarm** (`workers/unit/src/alarm.rs`, `unit_lease::alarm`):
the alarm is the only code of a unit that sends to a queue. It sends the
unit's two jobs, format 2 with the tenant and the unit: `stamp_raise`, once
per period (5 minutes, est) after the first write since the last raise
(the stamp's own calls and the cron's bookkeeping do not count), and with an
expired lease one `renew` and nothing else, retried with a doubling wait
(60 s to 30 minutes, est). A raise is handed out only with at least half of
T left (its consumer reaches the unit later); with less, the alarm sends one
`renew` instead, other duties run, and the raise follows the renewal. Work that was due stays due; after a renewal the
alarm is set to now. The alarm is armed only when the wanted time is earlier
than the armed one. A closed unit runs nothing. The day close (W7), the
sweeps and the report to the directory are not built here. Rule 10 (the
unit's outbox to the directory) is not built yet.

**The hand-out** (`unit_lease::handout`, AM-49): under a fresh lease the
alarm also does tenant 0's cron work for the unit. It buries exhausted
outbox rows, then sends the due rows as `extent` jobs (as many as tenant
0's dispatcher sends in one run), one `gc` job while a GC row of a
disposable bucket is due and `GC_MODE` is `disposable`, and one `evict` job
per eviction-check period while the unit's evictable bytes are above
`HOT_CAP_BYTES`, as tenant 0's dispatcher. The object class runs in the
Worker and reads those two variables from its environment; the unit holds
no configuration. The hand-out is due when `Catalog::due` would take a row
(with tenant 0's resend window, as a unit cannot ask the queues for their
backlog; read from a bounded window of each stage, never late), a GC row is
due while GC runs, or the eviction check is due while the cap is set and a
byte is evictable, and never sooner than 60 s (est) after the last
hand-out. A unit with an empty outbox and no cache has nothing due; one
that holds cache wakes once per eviction-check period to take its total. A
tenant that is being shredded hands out nothing (its jobs are refused).
The lift of a `restoring` entry asks for the alarm at once, so what waited
while the unit was closed is handed out after its renewal. Every message
goes through `velmora_bridge::routing`, as tenant 0's: an extent's job to
its shard of the post or verify queues, everything else, the unit's own
`renew` and `stamp_raise` included, to the queue bound as `AUX_Q`, or to
the first verify queue where `AUX_Q` is not bound. The jobs are format 2,
with the tenant, the unit and its numbers. After the sends the rows of the
batches that went through are marked, and the run is recorded only when
every send went through. The write-intent sweep is not handed out: tenant
0's is gated by `INTENT_SWEEP`, which only the Worker's configuration
holds and its consumer does not check.

**What makes the alarm's raise due** (ADR §8.5, AM-48). Every committed S3
or job call that changed a row, and every reservation call that changed one
(a reservation, its drop, a release, a binding, a grant's fence), makes the
raise due: a call that wrote nothing leaves nothing for a rollback to lose.
(AM-48 says "every reservation call"; this narrowing, as built, is with the
design lane.) These do not: the stamp's own calls (`stamp`, `stamp_advance`,
`stamp_rolled_back`), the dispatcher's run time (`record_dispatch`) and the
scan cursors (`set_cursor`). Nor do the Worker's own calls: `renew`, `sync`,
the key-chain apply, `import`, `ImportSeal`, `Recount`, `Export`, the gate
calls and `provision`. A rollback that loses one of these shows as
`SyncNeeded` or an expired lease, or the tool runs it again, and a raise
must not make the next one due. Read stamps (`touch_read`) count. The alarm
sends a raise only while at least T/2 of the lease is left; with less, it
sends `renew` and sends the raise after that renewal. The unit clears its
pending raise only when the stamp call lands, not when the message is sent:
the alarm keeps the hand-out time in `raise_from`, a `stamp_advance` that
moves the counter clears it in its own transaction, and a raise that has not
landed one period after its hand-out is due again. A failed send undoes the
hand-out, and its writes are due from their own time.

**The unit client** (`unit_lease::client`, the Worker's side of rules 5 and
12; AM-50, AM-51). A unit does no I/O, so the Worker reads for it:

- **`renew`.** The unit's numbers, stamp counter and revoked count come
  from one stamp read through the job path (allowed with an expired lease),
  then the proof (`unit_lease::renewal`) and `renew(proof_start, proven,
  revocations)`. A newer record means `sync` first. Stamp objects after
  the counter: the proof holds the newest one's counter, and the unit
  renews only if its own counter has reached it, so a raise in between
  passes; a unit refused `not_proven` (or with a full page of objects
  ahead) is confirmed through its own counter, and with the counter
  unchanged the rollback is recorded, the unit closes and the client pages
  (again at every look while it stays closed). Revocations the unit did not
  hold are applied with the renewal, and the key chain's finisher is told
  once, before the call (SEC-6). More revocations held than listed renews
  nothing and pages. The pages come back with an error too.
- **`sync`.** The tenant chain's verified head and the key-chain records
  after the unit's `keys_seq`: first the key apply (AM-12, in pages of at
  most 100 records, each from the unit's own `keys_seq`), then `sync` at
  both heads, with the head's state, mode and this unit's `restoring` entry.
  A head that clears the entry is not sent as a lift: only the restore
  tool's `sync` carries the lift proof (AM-45); the client reports it and
  changes nothing. A unit the head does not list is not called.
- **The request path** (rule 5): `renew_needed` renews, `sync_needed`
  syncs, a lower request number takes the unit's numbers; each fix runs once
  and the call runs once more. An answer with less than half of T left asks
  for a background renewal (`waitUntil`). Unsigned calls and background
  renewals go through the isolate's spacing: none while one runs, and after
  a failed attempt a backoff from 60 s doubling up to T, cleared by a
  success (rule 11). Signed calls go through the same spacing with the
  backoff capped at 1 s.
- **The `renew` and `stamp_raise` jobs**, which the queue consumer hands to
  the client: a renewal as above; a raise moves the unit's counter, then puts
  its object, renewing first when the lease ran out. A failed call, or a
  unit's `Failed` answer, is handed back with the queue's retry delay; a
  call that is stale twice is acknowledged; `unborn` goes to the consumer's
  `Unborn` rule; a refusal no AM-50 row names goes to the dead-letter queue
  with a page (AM-50). Under `MAINTENANCE = restore` the consumer acknowledges both
  without a call.

**The calls are JSON** (`UnitCall` and `UnitAnswer`, `unit::call`; an
answer leaves the unit as `UnitReply`, rule 12). Until the class is bound
(stage C(b)) the format may change. After it, these types only gain
fields, in two deploys, reader first, and a golden-JSON test pins each
variant.

**What a unit keeps besides the catalogue:** `unit_birth` (the
certificate); `unit_head` (`state_seq`, `keys_seq`, the tenant state and
mode, `restoring_since` and `closed_at`; moved by
`sync`, and `keys_seq` by the key apply); `unit_keys` and
`unit_key_grants` (the key chain); the reservations of capped opening
calls and the fenced creator-grant seqs (`unit_reservations`,
`unit_bucket_fences`); the gate report and its
acknowledgements; the lease and the alarm's counters in
`unit_lease` (`fresh_until`, `lease_hi`, `renew_tries`, `failed_runs`,
`first_write_at`, `raise_from`; migration `u0002`), and revocations listed
for a key the unit does not hold, or for an id that names a principal row,
in `unit_revoked_ids`; and the stamp counter.

**The write mark** (`unit_lease::mark`): the unit's catalogue and every
table of the unit are reached only through `MarkedSql`, which counts every
write of the wake (`wake_id` is random at each wake and kept in memory).
A dump whose pages carry one mark is exact.

## Keys

The unit holds its tenant's key chain as the Worker read and verified it
(`unit_keys`, `unit_key_grants`): every key, app password, principal and
internal key, its status, `made_by`, grants (bucket, access, expiry,
prefix, address list) and the seq of its newest record. A subject is
`held` when the Worker could not open its private part, or the directory
has not acknowledged its opening record: a held subject is never served.

The catalogue's own `access_keys` and `grants`, which the S3 path reads,
are built from these rows in the same call, for every subject the call
touched and every key made under one of them: the **effective grant**. A
key is served only while it is `active`, not held, has its secret, and
every principal up its `made_by` chain is `active` and not held. A grant
is served only on a bucket this unit holds, only without a prefix,
address list or expiry (the catalogue's `grants` cannot state them; such a
grant is not served until the check that can), and only while every
principal up the chain holds such a grant on that bucket; its access is
the lowest along the chain. The internal key is not served from these
rows: it signs presigned URLs only, which they cannot say. A key or an
app password outside tenant 0 must name its principal. Everything else
fails closed. **Milestone 1 serves unlimited grants only:** a key or
principal grant with a prefix, an expiry or an address list is refused
at use, and at its reservation (`grant_limits_not_served`, below).

## Reservations

A capped opening call (create an S3 key, an app password, a principal or
a bucket; a widening grant change) first asks the tenant's root unit for
a reservation (`reserve`, `unit::reserve`), before any intent or record.
The Worker sends SHA-256 of the request's `Idempotency-Key`, the
request's fingerprint, a fresh random 16-byte `rid`, the acting
principal (as `Kofra-Acting-Owner-Ref` named it, or by id) and the
change. In one transaction the unit:

1. refuses a malformed ask, more than 64 grants, and any grant with a
   prefix, an expiry or an address list (`grant_limits_not_served`);
2. resolves the acting principal in its own key rows, by `owner_ref`
   among the principals that are not revoked (an index serves it; two
   such principals for one `owner_ref` are never resolved, and alarm):
   none is `acting_principal_unknown`;
3. reads the row of the scope (the principal's id, or `''` for none; the
   key hash). Another fingerprint is `reused`. An `applied` row answers
   its kept answer. A `reserved` row is asked again: checked again at the
   unit's head for the subject (and a bucket's unit) it holds, not for
   ids the retry drew again, and answered with its own `rid`, `subject`
   and `again`; if the check now fails, the refusal leaves no row (its
   cap slot stays). A bound bucket reservation is answered whatever its
   creator is now;
4. otherwise: a grant change that is a narrowing of the subject's
   current grants (each new grant inside an unlimited current grant on
   the same bucket, access no higher) is answered `narrowing` with the
   unit's `keys_seq`, and takes nothing; its record must be exactly
   `keys_seq + 1` too, so a narrowing judged on a stale key table is
   never recorded on a newer head. A held acting principal may narrow, a
   disabled one may not; the internal key is refused
   (`internal_key_refused`). Then the acting principal must be `active`
   (`acting_principal_inactive`) and not held (`503`); a principal create
   that finds a principal of that `owner_ref` that is not revoked answers
   it (`exists`: the Worker answers `200` when the grant sets are equal,
   `409 principal_exists` otherwise); the id it makes must be new; the
   bucket name must be no bucket's and held by no other open call; the
   `owner_ref` of a principal create held by no other open call; every
   grant on a bucket the unit holds (`404 bucket_not_found` otherwise,
   for a key create, a principal create and a widening alike; AM-61) and
   no wider than the acting principal's effective grant (bucket and
   access; a sign-up principal without an acting principal has none);
   then the caps: 30 capped changes an hour, 50 bucket creates a day, 20
   active S3 keys and 20 app passwords (open reservations count). Then
   the row is kept `reserved`, and its cap slot (`unit_cap_uses`) is
   kept for the cap's window whatever becomes of the row; only an
   explicit release and a cancel (below) give it back.

The answer carries the unit's `keys_seq`: the call's record is exactly
`keys_seq + 1` and carries the `rid` in its door part. The Worker draws
the `rid` (16 bytes from its CSPRNG) and sends it with every ask; the
unit keeps the first one and answers it on every re-ask, ignoring the
re-ask's, and draws no random value itself. A re-ask is checked again at
the head, answers the unit's current `keys_seq`, and the row keeps that
seq. On an `again` or `not_open` answer the Worker reads and verifies
exactly one record, `m/k/<t>/<keys_seq + 1>` (AM-55): one that carries
the `rid` is the finisher's to apply (`409 idempotency_key_in_use`).
Key records are applied in seq order with no gap, so a record of the
call can only sit there. The key-chain apply turns the row
`applied` when it holds a record that carries its `rid` for its subject,
and keeps the answer the Worker passes with it (once; a 2xx status and a
JSON object of at most 16 KiB with no `secret_access_key`, or none is
kept and the Worker builds the answer from the chain). A record that
closes or narrows a principal (any status but `active`, or a grant it
held on a bucket the unit holds that no grant of the record covers; a
grant dropped on a bucket id the unit holds no row for opened nothing,
so it narrows nothing, AM-61) cancels that principal's
other open reservations that are not bound to a creator grant, and
gives their cap slots back (a held principal record counts as a
narrowing: it may come without its private grant parts). Each
entry's reservation turns `applied` before a later entry of the same
call is applied. A bucket reservation is bound to its creator
grant's seq (`bind_bucket`, a compare-and-set; `release_bound`); the
finisher's `bucket_binding` read answers `open`, `created` or `none`, and
`none` fences the seq for good. The apply of the tenant record
`bucket_created` turns the reservation bound to its seq into the bucket
(`reserve::bucket_created`). The unit does not apply tenant-chain bucket
records yet: until that apply exists and calls it in its transaction, a
bucket reservation stays `reserved`, is swept after its hour (its slot
still counts for the day), and a retry after that hour is checked again
as a new ask. `release` drops a `reserved` row. Each ask sweeps first: a
`reserved` row goes after 1 hour, an `applied` one 24 hours after its
apply. `resolve_acting` reads the acting principal of `objects.list` and
`objects.presign` (refused unless active and not held) and writes
nothing. The reservation calls run on an open unit, `authenticated`; an
ask runs in every tenant state but a shred. In a hold or a deletion it
answers only what keeps no reservation (a narrowing, a reused key, a
kept answer, a bound bucket reservation); a re-ask of its own open row
answers `not_open` with the `rid` and `keys_seq` (the Worker reads the
chain for a record of it first, then refuses), and a new ask is refused
as `account_problem`. The Worker answers the contract's code for the
tenant's state (`409 tenant_read_only` or `409 tenant_unavailable`),
never `403`. The other reservation calls run in any state.

## Buckets

A managed tenant's bucket rows come only from its tenant chain (AM-57;
`unit::buckets`). The Worker's `sync` carries, besides the head's numbers
and state, every bucket change of the tenant records it moves past, for
buckets placed on this unit, in seq order: `created{seq, bucket_id,
grant_seq, creator, name, bdk_wrapped, tk_version, written_at}`,
`dropped{seq, bucket_id}` and `unplaced{seq, buckets}`, and the list of
bucket ids the head places on this unit. `name` and `bdk_wrapped` come
from the record's private part. In the `sync`'s transaction the unit:

1. makes each created bucket's row (`created_at` = the record's
   `written_at`; `grant_seq` kept beside it) and turns the reservation
   bound to `grant_seq`, if one is left, `applied` (no answer is kept:
   the Worker builds it from the chain). The keys' grants on the bucket,
   applied before its row existed, are served from then on. A row with
   the same id and name changes nothing; another name for the id, or the
   name for another id, refuses the `sync` (`created_conflict`, alarm). A
   row of the other key scheme is refused by the scheme triggers. Once
   the reservation is gone, `bucket_binding(K)` answers `created` from
   the row kept for K, and never fences a K whose bucket exists (AM-56);
2. drops each dropped bucket's row (its grants first) if it is closing
   and holds nothing. A row that is not closing is marked closing first.
   One that still holds something is kept and renamed
   `~dropped/<bucket_id>`, so that a later `created` can take the name;
   the rest of the `sync` applies, and the answer names it for the
   operator's page (`drop_not_closed`). No object is deleted for it;
2a. on every `sync` (after the changes, before the check) and on the
   gate's last call after §8.6 step 7.4, drops each closing row the head
   does not place once it holds nothing (`buckets::sweep_closing`);
3. for `unplaced`, removes nothing while the unit's `restoring` entry is
   set, and otherwise drops those rows as in 2;
4. checks that its bucket rows, less every closing row the head does not
   place, equal the head's list, only while the `restoring` entry is not
   set and in the `sync` that clears it. A difference refuses the whole
   `sync` (`placements_off`, alarm); the Worker reads the chain again and
   sends it once more, and the same refusal again stops and pages.

The list a `sync` carries is whole, so it is bounded: at most 10,000
(est) ids, and as many changes, `unplaced` ids included. A bucket
create's reservation is refused `cap_reached` once the unit's rows and
its open creates reach that bound, so no tenant outgrows its `sync`.

"Holds nothing" is the catalogue's rule for a bucket delete: no
generation, object, key floor, upload or extent names the bucket. That
is stricter than "no object and no open upload": a bucket whose deleted
objects still wait for the collector stays closing until they are gone,
so no row that names data on the backbone loses its bucket and BDK.

Bucket delete is close, then record, then drop. `bucket_close(bucket_id)`
(a Worker call, in an active tenant) answers `bucket_not_empty` if the
bucket holds anything and `bucket_not_found` if the unit has no such
row; otherwise it marks the bucket closing (once), and every write into
it answers `NoSuchBucket` from then on (`buckets::is_closing`, for the
request path). Then the `DropBucket` record, then `sync`. A closing
bucket whose record never came stays closed and empty, and its name
taken, until a delete retry completes it. The `sync` arm that carries
the changes, and the stamp raise after `bucket_close` (AM-48), are the
Worker's (L2). Until the request path asks `is_closing` before a write
(`RequestCall`, L1 package 5), a write into a closing bucket is not
refused; a drop still keeps every row that holds data. Package 5 also
leaves closing rows out of ListBuckets and HeadBucket: a kept row keeps
its grant rows, and its `~dropped/<id>` name is no S3 name.

## Key scheme

The key scheme follows the tenant (rule 13): tenant 0 is scheme 1, every
other tenant scheme 2, fixed by the birth certificate. A trigger on
insert and on update of every wrap that names a scheme
(`buckets.bdk_wrapped`, `access_keys.secret_wrapped`,
`unit_keys.secret_wrapped`) refuses a value that is not a blob or whose
first byte is not the certificate's scheme (`0x01` or `0x02`), so a
scheme-1 wrap can never sit in a managed tenant's unit and survive its
shred. The call fails whole and answers the failure class `key_scheme`;
the Worker pages. An extent's file key is wrapped under the bucket's
key, with the same byte in both schemes, and is not checked.

## Size guard

A Durable Object's SQLite stops at 10 GB. At 8 GB of database (the
object's `databaseSize`) or 3.4 M extents, a call that adds extents is
refused before it writes (`size`: `database_full` or
`too_many_extents`, with an alarm): the Worker answers `503 SlowDown` and
pages. Reads, deletes and smaller overwrites go on. The extent count is
the usage counters' while they are on (one row read), and the rows the
move's import took while they are off. The move's import batches and the
request calls ("Requests") take the check. Tests run it against a
lowered limit.

Above a hard ceiling of 9 GB (est) no request call that adds a row
runs, deletes (a floor and a tombstone each) and smaller overwrites
included, so the platform's stop is never met; the Worker answers
`503 SlowDown` and pages, and the operator moves a bucket to another
unit. GC, aborts and settles still run. `databaseSize` counts the pages
of the file, freed pages included (not measured on the platform), so
the ceiling may not lift by itself after GC: the bucket move is the way
out. This ceiling is an L1 choice beyond ADR §2.6, for the design
lane to confirm.

## Import

The owner move fills the owner's root unit `<t>/0` from the frozen D1
with `import` batches (`unit::import`). A batch is accepted only while the
unit is the root unit of a tenant other than tenant 0; its own `restoring`
entry is set and the batch names that entry's `since_seq`; tenant 0's
verified head, passed by the Worker, says `moving` with `move.to` = this
tenant and is not older than a head an import was already bound to; and
the caller's numbers equal the unit's (as a job's). That binds the import
to this one move: no other tenant is filled, and no import runs outside a
window.

A batch is one table, its column list (the unit's own, in schema order),
at most 500 rows (est) of values with their type class, the cursor of the
batch it follows and its own. It is applied once and in order; the last
batch sent again changes nothing, so the import resumes by table and
cursor. It fills the data tables only. The keys come by the key apply
(so `keys_seq` and the keys agree). The usage counters `usage_global` and
`usage_buckets` are the unit's own: its triggers count each imported row
while the counters are on, and the recount fills them when they are off.
An `outbox` row must come with its lease cleared, and an extent's
`plan_rev` is bound through `plan_rev::bound`. A cursor may be up to
64 KiB: the copy names the key of the last row it read as typed JSON, and
an object key is bounded only by the S3 request target (8 KiB), which
JSON's escapes can grow sixfold.

**The seal** (`import_seal`, AM-29) ends the import. It is bound and
numbered as a batch, and names every import table once with the rows the
unit took (0 for a table without a batch); a count that is not the
unit's refuses it, so a lost batch is found. It records
`move_ordinal` = tenant 0's `flips + 1` (the head carries `flips`), and
from then on no batch is taken, not even the last one sent again, under
any entry: the refusal is its own code, `sealed`, so a resumed copy knows
the import is done. The seal survives a new `restoring` entry;
`deleteAll()` clears it. While a move's import is not sealed, no lift
passes under any entry, whatever the report.

**The move's record stays** (AM-47): `unit_import` and
`unit_import_move` (the seal, `t0_seq`, `move_ordinal`, `move_lifted`,
`lifted_at`) stay after the move as its record until `deleteAll()`.
`import_progress` answers, read-only, every table's cursor and rows, and
`sealed` (the seal's `move_ordinal`), `t0_seq` (the newest tenant-0 seq a
batch, the seal or a `move` report was bound to), `since_seq` and
`move_lifted`, which are null when no import was ever bound to the unit,
and `lifted_at`, the unit's clock at the lift, null until a `move` report
lifted it (the chain's move floor is raised from it, AM-67). It also answers `schema_tables`, every table the unit holds
(SQLite's and the platform's own left out), for the reverse move's
preflight. A window's copy resumes only an import whose `t0_seq` is at or
above its own first record (AM-53); a second move reads it before step 0
(P12). On an unborn unit, `import_progress` answers `unborn` and makes
nothing; `listed` is as the call says (rule 7). P12 reads both heads
first and sends `listed = false` where they say an unborn unit is
expected (the day-30 `deleteAll()`); every other read keeps the page. Every imported key value must
be of its column's class (text, or integer where declared), so the unit
never holds a key that `export` cannot page after.

In a unit, every `tenant_id` column (such as
`upload_part_extents.tenant_id`) is a legacy default and is not
authoritative: the unit's tenant is its certificate (`unit_birth`), and
no unit code reads that column.

## Export

`export(table, after, limit, mode)` (`unit::export`, AM-26) reads one
table back out, read-only, in primary-key order: the rows after the key
`after`, at most `limit` (1 to 500), in the import's value encoding (the
type class of every value is kept). `mode = hash` answers the page's
count, its last key, whether rows follow, and SHA-256 over the rows
without the table's V1-excluded columns (`buckets.owner`, `bdk_wrapped`
and `kek_version`; the two `hot_*` columns of `extents`; the lease owner
and expiry of `outbox`), as `export::hash_rows` writes it: the move tool
hashes the frozen D1's rows of the same key range with that function.
`mode = rows` answers the rows, also cut at 1 MiB of encoded rows (a
larger row comes alone): the reverse move only. It is refused unless the
unit's `restoring` entry is set. It reads the tables the import writes
and the key tables, and on the key tables only `hash`, over every
column, the wrap included (V6 compares it with `export::chain_key_rows`
of the chain). It never reads the unit's own tables. Wrapped keys
(`bdk_wrapped`, `wrapped_file_key`) leave as stored, still wrapped, to
the move or undo tool in the Worker only, never to a log, a receipt or a
queue message.

## Jobs

Post, verify, release, GC, eviction and the dispatcher run in the Worker,
as today: they hold the NNTP sessions, the blob stores and the keys (rules
3 and 4). What they ask of the catalogue, the tenant's unit answers. Each
catalogue method of the job path is one `job` call (`unit::jobcall`), run
by the unit's own catalogue in one transaction; on the Worker's side,
`TenantCatalog` is a catalogue whose job methods are these calls, so the
job code runs unchanged against a unit. A job call carries the job's
numbers and must match the unit's (rule 5: lower is answered `stale`
with the unit's numbers, missing is refused `stale_job`, higher is
`sync_needed`), and is `authenticated`. A job call carries
`listed = false`: it reaches the unit through its message, not through a
record, so an unborn unit is decided by the consumer from the tenant's
verified head (rule 7). Post, verify, release,
GC and scrub run in `active`, `suspended` (either mode) and `deleting`.
They are refused in `shredding` and `shredded`, and while this unit is
closed (its own `restoring` entry is set, or its lease has expired: rule
12). Provider permits and
provider health are not a unit's: they stay in the shared database, which
every tenant's jobs use. The request path uses request calls instead
("Requests"). A refusal (`sync_needed`, stale, a job with no numbers, closed, unborn)
comes back as a typed error, and the first one is kept
(`TenantCatalog::refusal`). With `stale`, `TenantCatalog::stale_seqs`
holds the unit's numbers, and `latest_seqs` holds the numbers of the
unit's latest `ok` or `stale` answer in the run, for a follow-up job
(never below the job's own).

**What the consumer does with a unit's answer to a job call (AM-50):**

| The unit answers | The consumer |
|---|---|
| `stale{seqs}` | runs the job once more with the unit's `seqs`. They stand for the chain heads, because the unit refuses every job once its lease has expired, so they are at most T old (rule 12). A second `stale` is acknowledged; the outbox row stays. |
| `refused{stale_job}` (no numbers) | DLQ and page: no writer sends a format-2 job without numbers. |
| `closed` (restoring, provisioning) | acknowledges. The row stays in the unit's outbox, and the unit's dispatcher sends it again once the unit opens. |
| `renew_needed` | renews through the unit client (rule 12), then runs the job once more. A failed renewal hands the message back with the queue's `retry_delay`. |
| `sync_needed` | reads and verifies both chains up to their heads, applies the keys and calls `sync`, then runs the job once more. A failure hands the message back, and the DLQ pages once `max_retries` is reached. |
| `unborn` | reads the tenant's verified head. If it lists the unit: DLQ and a "catalogue lost" page (rule 7). If not: acknowledged with a log line and no page. A head read that fails or does not verify hands the message back. |
| `account_problem` while the tenant is `shredding` or `shredded` | acknowledges with a log line and no page. |
| any other refusal | DLQ and page. |

`renew` and `stamp_raise` have no outbox row; the unit keeps a raise
pending until its stamp call lands. A managed tenant's job and request
configs keep `MAINTENANCE` as tenant 0's: under `restore`, a unit job
makes no unit call (an outbox job, `renew` and `stamp_raise` are
acknowledged, with a log line and no page), and the request path refuses
unit writes with `503`. Stamp
calls must name the unit's own stamp id, `<tenant>.<unit>`. Eviction runs
per unit against the configured cap until the directory's global
threshold exists (ADR §5.5): with N managed tenants the cache can hold up
to N times the cap.

The queue consumer runs such a job only when the Worker has the unit
class bound as `UNIT` (no production config binds it; without it the
message is refused as `other_tenant`, as before). The reader
(`jobmsg::admit_for`) admits a format-2 message of a managed tenant that
names its unit, in that tenant's scope (`TenantScope::managed`: blobs
`x/<t>/` and `c/<t>/`). The consumer gives the job a bridge of its own
(`workers/s3-bridge/src/units.rs`): a `TenantCatalog` over the unit
object's `fetch` with the message's numbers; the configuration from
`BridgeConfig::for_unit`, which takes the unit's name and sets the stamp
id `<tenant>.<unit>` (`jobcall::stamp_id`) and the tenant's record layout
`m/x/<t>/` (never the flat layout); a sink whose messages name the same
unit and numbers, always in format 2 (it refuses to send a `v` 1 message,
which would be read as tenant 0's); and the isolate's one byte budget and
permit gate. Garbage collection names the blob it deletes from the row's
extent through the job's scope, not from the catalogue's delete list. The
first refusal decides the delivery (`unit_consumer`): a stale job or a
closed unit is acknowledged (its outbox row stays, for the unit's alarm
dispatcher of W2 to send again; that dispatcher is not built yet, so the
class stays unbound until it is); sync
needed, unborn and any other refusal go to the dead-letter queue with an
alert. Unit jobs (`renew`, `stamp_raise`) are not run yet
(`unit_job_not_run`).

## Requests

The S3 handlers (`service/*`) run in the Worker, as today. What they ask
of the catalogue, the tenant's unit answers (AM-64). Each catalogue method
of the S3 request path, and each of the operator reads of the per-tenant
status, is one `request` call (`unit::request::RequestCall`), run by the
unit's own catalogue in one transaction. The Worker's request catalogue
forwards the handlers' calls as these, so `Bridge::handle` serves a
managed tenant with tenant 0's code: conditional PUT, the publication
batches and their guards, the upload id bound to its bucket and key, and
the delete batches are the catalogue's own.

**The call.** `{"op": "request", "call": {"m": "<method>", ...}}`, with
the method's arguments under the names of `ports.rs`. An upload target is
spelt out as `bucket`, `key` and `upload`. A publication
(`commit_generation`, `commit_sliced`, `copy_generation`,
`complete_upload`) carries the proof of its recovery record as
`record: {generation, key}`. The call has `kind = request`, the Worker's
numbers from the tenant's verified head (rule 5; none is refused
`no_numbers`), `authenticated = true` (rule 11; without it the call is
refused `unauthenticated`: only `key_row` and `read_plan` come before the
signature), and `listed = true`.

**The answer.** `ok` carries the method's return value as JSON. A
publication answers `"applied"`, `"refused"` or `"fenced"`, and the
Worker rebuilds the outcome from the proof it kept
(`Published::outcome`): a refused publication discards the Worker's own
record, never one the unit named. A publication the unit refused for
good before it ran it (`refused`, `closed`, `unborn`, and a `stale`,
`sync_needed` or `renew_needed` that is still the answer after the unit
client's one retry) wrote nothing under its id: the client hands its
proof back (`RequestClient::take_unpublished`), and the Worker discards
that record before it answers. A `failed` answer, or none, keeps the
record, as on tenant 0. The retry is the unit client's
(`UnitClient::call`, AM-71), below this client: it syncs, reads the head
again or renews, and sends the same call once more with the new numbers.
A request body cannot be sent twice, so the retry is the call's, not the
request's.

| The unit answers | The Worker |
|---|---|
| `ok` | the method's value |
| `sync_needed` | syncs, then sends the same call once more; the same answer again is `503` |
| `stale{seqs}` (the head the Worker read is older than the unit's) | reads the head again, then sends the same call once more; the same answer again is `503` |
| `renew_needed` (rule 12) | renews (or waits for its isolate's renewal of the unit, at most 5 s (est)), then sends the same call once more; otherwise `503` (AM-63, AM-71) |
| `closed` | `503` |
| `unborn` | `503`; it pages "catalogue lost" when the route lists the unit (rule 7) |
| `refused{account_problem}` | `403 AccountProblem` |
| `refused{not_found}` (a write into a closing bucket, or one whose row is gone) | `404 NoSuchBucket` |
| `refused{size}` | `503 SlowDown` and a page, or `403 QuotaExceeded` (ADR §2.6) |
| `refused{request: out_of_bounds}` (alarm) | `500` and a page: only a Worker bug sends one |
| `failed{class}` | as on the job path: `guard` is `GuardFailed`; any other class is a catalogue error (`500`) |

**The unit's rules.** The tenant's state decides each call: every call
while `active`; while `suspended` with `read_only`, only the reads, with
a read's own two writes (its read stamp, `touch_read`, and its cache
fill, `record_cache_fill`); none otherwise. While a bucket is closing
(AM-57), `bucket_by_name` answers none for it, `buckets_for` leaves it
out, and a write that adds a row naming it (a generation, extents, a
floor, a tombstone, an upload or a part) is refused `not_found`; so is
such a write into a bucket the unit no longer holds (a `sync` dropped
the row after the request looked it up). A call
that adds extents, or a new object, upload or intent, takes the size
guard first, in its own transaction, and a refusal pages. Reads,
deletes and smaller overwrites go on (ADR §2.6): a publication that
replaces a live generation of at least as many extents passes the
guard. Above a hard ceiling (9 GB, est) no call that adds a row runs,
deletes and overwrites included, so the platform's 10 GB stop is never
met; reads and the calls that only take rows away still run. Each list,
limit and key of a call has a bound: at most 1,000
keys, ids or rows (S3's page and DeleteObjects bound; a listing asks for
one more), 10,001 extents (one object's bound and one more), 1,024 bytes
an object key (the protocol's own bound), and 8 KiB a listing prefix,
delimiter or marker (the request target's bound, as on tenant 0).

**Not request calls.** Bucket create and delete, and the key and grant
writes: a managed tenant's buckets come from its tenant chain and its
keys from its key chain (AM-57, AM-12). The Worker answers S3
CreateBucket and DeleteBucket itself (AM-64). Provider permits and
provider health stay on the shared database. The job methods are job
calls, and the record replay of a restore is tenant 0's.

**`key_row`.** Its answer body is `{key, state, lease_expired}`. With an
expired lease (rule 12), the unit still answers an unauthenticated
`request` call's `key_row`, read-only, with `lease_expired: true`
(`Unit::key_row_expired`, AM-63). The Worker uses that row only to check
the signature, renews as a signed call, and reads `key_row` again before
it serves. On entry point `presigned`, `key_row` also names what the URL
names (`presigned: {principal, bucket, create_only}`, AM-64). `key` is
then the unit's internal key (none for any other key: only the internal
key signs on that entry point), and the answer carries
`presigned: {ok, refusal, bucket_id, access}`, checked in the same
transaction. `ok` needs the internal key `active` and not held, the principal
`active` and not held, an open bucket of that name, and the principal's effective grant on it (`rw` for
a create-only URL). The row is never withheld: the Worker checks SigV4
first, and answers `403 SignatureDoesNotMatch` if it fails, whatever the
check found. A verified request with `ok = false` answers
`403 AccessDenied` and makes no further call. Otherwise the request runs
as that principal, with `access` on `bucket_id`. The internal key has no
`access_keys` or `grants` row, so the Worker answers the request's own
key and grant reads from this answer. A create-only PUT runs as
`If-None-Match: *`.

## Bookmarks

**A bookmark leaves the unit only sealed.** No bookmark is stored or
logged in clear: not in a record, a receipt, a log line, a directory row
or an answer that the Worker keeps. Two leave the unit: the restore's undo
bookmark, and the pre-migration bookmark inside a dump. Both are sealed in
the Worker under `HKDF(TK, catalog-backup/v1)` (tenant 0: a key derived
from the KEK) under `cb/<t>/<unit>/`; the 30-day lifecycle and the shred's
purge delete that prefix. The platform keeps each object's point-in-time
history for 30 days across `deleteAll()`, and the API reaches it only with
a bookmark taken before the delete; with no readable bookmark outside the
unit, the history ends with the platform's retention.

## Tenant state

| State | S3 |
|---|---|
| `provisioning` | `503` |
| `active` | everything the grant allows |
| `suspended`, mode `read_only` | reads only |
| `suspended`, mode `locked`; `deleting`; `shredding`; `shredded` | `403 AccountProblem`, after the signature verifies |
| `restoring` set for the unit | `503` |

A unit decides an authenticated call by the state it holds. An
unauthenticated read gets the state with its answer, and the Worker applies
it after the signature verifies. A missing bucket is answered with the key
row too: a missing bucket and a missing grant both answer `AccessDenied`,
after the signature.

## Restore

A unit is rolled back only by the restore procedure, in two calls
(`unit::restore`), and **it never closes itself for one**: both are
refused unless it is already closed.

1. `restore_prepare(since)` answers the unit's current bookmark, the undo
   bookmark. The tool seals it (see "Bookmarks") before the second call.
2. `restore(token, target, expect_undo)`: the target is a time, which the
   unit turns into a bookmark itself, or an unsealed undo bookmark when an
   earlier restore is undone. The token is a `restore` certificate for
   this unit and entry.

Before anything is armed, the unit checks that its `restoring` entry is
set at the seq named (the token's); that its lease has expired; that its
clock is at least max(`closed_at` + T, `lease_hi`) + 60 s, where
`closed_at` is its own time of the `sync` that set the entry and
`lease_hi` the latest `fresh_until` it ever held; and, for `restore`, that
its current bookmark is still `expect_undo` (it wrote nothing since
`restore_prepare`; on a refusal the tool prepares again). Any failure
refuses and arms nothing. The lease is the latest of `lease_hi` and
`fresh_until`; a unit without a lease table is refused (its lease is not
known), and one with the table but no row never issued a lease. A unit
born from a `restore` token has `closed_at` = its birth and no lease row,
so a gone or unborn unit passes T + 60 s after its birth. The bookmark calls need the object's storage, so the object class
runs them after the unit's own checks; a restore never answers `ok` (the
object restarts), and the tool reads the result from the unit's state. An
answer `failed` of class `pitr_armed` means the restore was armed without
the restart, which applies it: the tool sends the same restore again until
it gets no answer, and runs the gate only once the restart is seen.

**Not before a move's lift, not before the birth** (AM-46, check 5).
While an import exists that no `move` report has lifted
(`unit_import_move` with `move_lifted = 0`), `restore_prepare` is refused
with `move_not_lifted`, so no undo bookmark from before the lift exists;
`restore`, which needs that bookmark, is refused the same way. Once
lifted, `restore` refuses a time target before `lifted_at` + 60 s (est)
with `before_move_lift`. **The floor is also kept in the tenant chain**
(AM-67), where a unit restore cannot take it back: the carried door field
`move_floors: {<unit>: <ms>}`, raised and never lowered or removed, by
three writers: the move's step 8(b1) record `SetMoveFloor{unit,
lifted_at}` (the tool reads `lifted_at` from `ImportProgress`); every
exit that empties a unit with `deleteAll()` (to the Worker's clock after
it answered); and the Worker before every `restore`, when
`ImportProgress` shows a `lifted_at` above the head's. Every `restore`
call carries `floor_ms`, a required field, read from the verified head
for that unit (0 only when the head has none; no `restore` is sent when
the head cannot be read). The unit refuses a time target before max(its
own `lifted_at`, `floor_ms`) + 60 s with `before_move_lift`, also when
its own record is gone. It also refuses a time target before the unit's
own `born_at` + 60 s (est) with `before_birth`: a rebirth (a dump restore
into a gone or unborn unit, or a re-creation after `deleteAll()`)
replaced the unit, and the history before it would bring back the old
incarnation. Both margins cover a recorded time that is its call's clock,
a little before the commit; the S3 drill measures
`getBookmarkForTime`'s offset, and above 30 s the margin becomes twice
it. A bookmark target is not compared: the only bookmarks are the undo
bookmark and the pre-migration bookmark, and neither can be taken before
the lift, with one span open: from the time the owner's unit is closed
with no move record (the move's step-2 sync, or a re-creation with a
`restore` token under the move's entry, AM-53, or under a left entry,
P12) until the first import batch, the unit cannot tell that entry from
a restore's, whatever its birth, so `restore_prepare` there goes on to
checks 1 to 3. Restoring such a bookmark after the lift takes the unit's
own record away; the chain's floor then still refuses a later time
restore into the seal-to-lift span (AM-67; the move's P14 drills it). A unit runs no schema
migration while an import is not lifted
(`schema::migration_allowed`; code reads N - 1 and N, so it serves
without migrating), and the move window runs under the merge freeze.
Every state before the lift is a closed unit in mid-move that never
served a request, so no recovery point is lost. A rollback of the object
by the platform, outside `restore`, is an accepted residual. W4 dumps
leave out `unit_import` and `unit_import_move`, as `export` does, so a
unit born from a dump cannot take a `move` report (`import_not_sealed`);
a dump restore empties the unit first.

A unit born from a `restore` token starts with its usage counters off. The
gate's recount turns them on, and the lift is refused while any is off. A
unit born from a `birth` token starts with them on.

## Restore gate

**The lift is checked inside the unit, against one replay of this
restore** (`unit::lift`). The gate's final replay has a replay id: the
entry's `since_seq` S, the stamp ordinal raised before the restore, and a
nonce from the tool. The unit keeps one report: `gate_open` starts it and
discards a report of any other replay id with its ids and
acknowledgements (such as an old one that a point-in-time restore brought
back); `gate_blockers` adds the ids of each list of the findings in pages
of at most 100, so any number can be reported; `gate_report` stores the
rest (complete, the totals, whether held rows were classified, and per
list the count and hash of its ids) and is the last write, since a page
after it resets it; and `gate_ack` acknowledges blocker ids by name, in
pages of at most 100. Totals count distinct ids, and a stored list that
is not what the summary says (a lost or extra page) keeps the unit
closed. **The `sync` that clears `restoring_since` is
refused unless the check passes:** the report names this entry; its
ordinal equals the unit's stamp counter as the gate levelled it; the lift
decision below opens on its findings, and per class the acknowledged ids
are exactly the ones the decision needs (the same count, and the same
SHA-256 over the sorted ids with duplicates removed, UTF-8, each followed
by `\n`); every usage counter is on; and the `sync` names the lift record's
proof (its replay id and those counts and hashes), equal to the unit's.
`gate_status` answers that proof; the tool builds the lift record's
replay id from its own replay and nonce, and stops if `gate_status` names
another one. Until the replay
runs inside the unit, the Worker sends the replay's findings.

**The move's lift report** (DS1 §3.4 step 8(b), AM-15). The owner move
has no restore: its checks V1 to V8 are its replay. After they pass, the
move tool opens a report of kind `move` (`gate_open_move`) with replay
id (S_move, the unit's current stamp ordinal, a nonce) and closes it
with a complete, empty summary. The unit takes a `move` report only
under this binding: it is the root unit of a managed tenant; the import
is sealed, and the passed tenant-0 head's `flips + 1` is the seal's
`move_ordinal`; S is the unit's current `restoring_since` (not the
import's first S, so a re-entry under a new entry works); tenant 0's
head says `moving` with `move.to` = this tenant at a seq not below the
newest the unit has seen; the call carries the unit's numbers; and the
ordinal is the unit's stamp counter (0 while no stamp was ever raised).
A `move` report takes no blocker page and no acknowledgement, and no
summary but a complete, empty one. The lift check reads the binding the
unit holds again (root unit, seal, stamp counter, empty summary).
The stamp counter is the unit's `rollback_stamp` row, or 0 when no row
exists; only a `move` report takes the 0, and a restore report needs the
row, which the gate's stamp levelling writes. Jobs, the stamp's own
included, are refused while the unit is closed, so the window raises
none. A move into a unit whose stamp prefix `rs/<t>.<u>/` already holds
stamps (a second attempt, or a second move after an undo) must first
level the counter to the newest of them; until W4-gate's levelling
exists, the move's preflight stops before step 0 (AM-44). If a
stamp raise lands between the report and the lift record, the `sync` is
refused by the gate (`refused: gate`); the tool writes a new `restoring`
entry, syncs the unit to it, and opens a new report under it. The lift a
`move` report passes uses the seal up: no other `move` report is taken
after it, so a later entry (a restore of the owner's unit) is lifted only
by the restore gate. So a tool that re-runs 8(b) first reads the unit
(AM-45): if its `restoring_since` is already empty, the lift landed, and
V9 (8(b2)) runs before 8(c). Otherwise: a lost or `failed` answer sends
the same `sync` again; `keys_not_applied` means apply the keys and send
it again, `stale_sync` read the head again, `counters_off` run
`recount`, each once per entry. If the same refusal comes back after
its fix while the owner tenant's chain heads have not moved since the
fix, the window stops; a higher head allows one more fix. Only `not_restoring`, `no_report`,
`stamp_not_levelled` and `proof_mismatch` re-enter, once per window; any
other refusal stops the window. The unit keeps the time of that lift, and refuses a
restore to a time before it, or less than 60 s (est) after it, as the
time is the lift call's clock (`before_move_lift`): a rollback into the
move's window would bring back an unused seal. A restore to an undo
bookmark is not compared (a bookmark names no time); a platform rollback
of the object is outside the unit. The move's import record (the seal,
the tenant-0 seq, the lift) stays until `deleteAll()`. No other kind of
lift exists.

**Recount** (`recount`, `unit::recount`, AM-27). A unit born from a
`restore` token starts with its usage counters off, and the lift is
refused while any is off; jobs are refused while the unit is closed, so
the cron's recount cannot run. `recount{start}` begins a pass of the
catalogue's recount that adopts its figures, and `recount{step}` runs
one bounded chunk, one transaction each; the pass's last step adopts its
figures and turns every counter on. It is accepted only while the
unit's `restoring` entry is set. It is the move's when the import filled
the entry the unit is closed under: then it also needs the seal, tenant
0's verified head moving here, not older than the import's, with `flips
+ 1` equal to the sealed ordinal, and the unit's numbers, as a `move`
report does. Any other `recount` is the restore gate's. It writes, so it
is an `authenticated` Worker call.

A restored unit stays closed until the gate lifts it, and the gate lifts only
on a whole, clean replay (`unit::gate`): no damaged generation, no held row
whose safety copy is gone and that a servable generation names, and no
unreadable, unpublishable, damaged-unpublished, twin or other-bucket record.
While the replay is not whole, every held row without a copy counts as live.
A lift may accept a blocker only by naming each of its ids in the lift
record.

**The stored plan of an extent never changes.** `plan_rev` is 0 or 1;
`tests/plan_rev_contract.rs` holds the list of every statement that writes
it, word for word. `plan_rev::bound` is the one function that turns a
`plan_rev` into a bound value and refuses one above 1, and
`plan_rev::readable` tells a record this code may write from; binding the
catalogue's statements through them, and reporting a record above 1 as
unreadable in the replay, is a separate change to the catalogue's SQL. A
change that would write a higher revision needs its own design first and
lifts that test on purpose.

## The database of a unit

`DoSql` (`workers/unit/src/do_sql.rs`) is the catalogue's `Sql` port over a
Durable Object's SQLite storage. What it does about the runtime, as measured:

- A JS number binds as a SQLite REAL (in a Durable Object and in D1). Both
  adapters write every integer placeholder as `+CAST(?N AS INTEGER)`
  (`velmora_bridge::sql_bind`): the integer a native binding gives, without
  the affinity a bare `CAST` adds. `DoSql` binds the integer as a JS number;
  the D1 adapter binds its decimal text.
- An integer above 2^53 - 1 reads back rounded, silently (Durable Object:
  measured; D1: by its documentation). So the adapters keep three rules:
  (1) every integer is bound and stored as SQLite INTEGER; (2) an integer
  outside ±(2^53 - 1) is refused at bind, before the call, by `DoSql` and
  the D1 adapter alike; (3) a stored value outside that range is never
  read back rounded through them: both refuse it on read. ±(2^53 - 1)
  round-trip exactly with `typeof` integer; ±2^53 and ±(2^53 + 1) are
  refused at bind (2^53 is exact in a double but not safe, because
  2^53 + 1 rounds to it). Readers outside the adapters (the REST API,
  `wrangler --json`, scripts) get rounded values.
- `BEGIN` and `SAVEPOINT` are refused; `transactionSync` nests as a
  savepoint. Rows changed are the difference of `total_changes()` around a
  statement, which counts trigger rows as D1's `meta.changes` does.
- One statement per call (a trigger body is one statement); the comments
  after it are cut, because a script whose last part holds no statement is
  refused.
- A deferred foreign-key violation at the end of the object's implicit
  transaction resets the object.
- Point-in-time recovery keeps 30 days of history, also across
  `deleteAll()`: a bookmark taken before `deleteAll()` brings the data back
  (`workers/unit/src/pitr.rs`). A restore arms and restarts in one step;
  the request that asks for it gets no answer.

`workers/unit-suite/run-suite.sh` runs the whole `velmora-bridge` test suite
with a twin: every native test database gets a fresh Durable Object in
workerd behind `DoSql`, every call runs on both and is compared, and the
tests get the object's answers. Errors are compared by class and keep
SQLite's message. Not compared, by design: calls that meet a state with a
broken foreign key (a test that switched the keys off; they run on SQLite
alone, are counted, and the twin is rebuilt at the next whole state), plain
`EXPLAIN` bytecode (counted as skipped), and `total_changes()` and
`last_insert_rowid()`, which are each connection's own counters. Those two
are answered by SQLite even with the object as primary: the twin sends each
statement as a request of its own, and workerd evicts an object idle for
about 10 s, which restarts its counters (a host stall inside one call was
enough to refuse a read-only call as `wrote_without_authentication`). In
production a call is one `transactionSync` with no await, on one
connection. Rows changed are compared for every statement instead,
`query` included. Then `unit-smoke.py` drives the unit class itself in the
same workerd.
