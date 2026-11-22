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
   - a job with no number, or a lower one: refused;
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
     closed (the bring-up's second send). `revoked` is final. The apply
     is the one way `keys_seq` moves; `sync` refuses a `keys_seq` above
     the unit's (`keys_not_applied`).
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
than the armed one. A closed unit runs nothing. Only the stamp raise is due
on a unit yet: the day close (W7), the sweeps, the hand-out and the report
to the directory are not built here, and the Worker's cron runs a unit's
jobs through `TenantCatalog`. Rules 9 and 10 (jobs that name their tenant,
the unit's outbox to the directory) are not built yet.

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
   grant no wider than the acting principal's effective grant (bucket
   and access; a sign-up principal without an acting principal has none);
   then the caps: 30 capped changes an hour, 50 bucket creates a day, 20
   active S3 keys and 20 app passwords (open reservations count). Then
   the row is kept `reserved`, and its cap slot (`unit_cap_uses`) is
   kept for the cap's window whatever becomes of the row; only an
   explicit release and a cancel (below) give it back.

The answer carries the unit's `keys_seq`: the call's record is exactly
`keys_seq + 1` and carries the `rid` in its door part. On an answer with
`again`, the Worker reads the chain above `keys_seq` for that `rid`: a
record that carries it is the finisher's to apply
(`409 idempotency_key_in_use`). The key-chain apply turns the row
`applied` when it holds a record that carries its `rid` for its subject,
and keeps the answer the Worker passes with it (once; a 2xx status and a
JSON object of at most 16 KiB with no `secret_access_key`, or none is
kept and the Worker builds the answer from the chain). A record that
closes or narrows a principal (any status but `active`, or a grant it
held that no grant of the record covers) cancels that principal's
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
move's import took while they are off. Today the move's import batches
are the calls that add extents to a unit; the request path's write
admission takes the same check when it moves into the unit. Tests run it
against a lowered limit.

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
passes under any entry, whatever the report. Every imported key value must
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
numbers and must match the unit's (rule 5: missing or lower is refused,
higher is `sync_needed`), and is `authenticated`. Post, verify, release,
GC and scrub run in `active`, `suspended` (either mode) and `deleting`.
They are refused in `shredding` and `shredded`, and while this unit is
closed (its own `restoring` entry is set, or its lease has expired: rule
12). Provider permits and
provider health are not a unit's: they stay in the shared database, which
every tenant's jobs use. The request path does not use `TenantCatalog`.
A refusal (`sync_needed`, a stale job, closed, unborn) comes back as a
typed error, and the first one is kept (`TenantCatalog::refusal`) so the
consumer can re-read the heads and run the job again or drop it. Stamp
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
unit, always in format 2 (it refuses to send a `v` 1 message, which
would be read as tenant 0's), with the numbers of the unit's latest
answer in the run, never lower than the message's; and the isolate's one
byte budget and permit gate. Garbage collection names the blob it deletes
from the row's extent through the job's scope, not from the catalogue's
delete list. Job calls carry `listed = false`.

The unit's refusals decide the delivery (`unit_consumer`, ADR §2.4 rule 5
as amended by AM-50): `Stale{seqs}` runs the job once more with the
unit's numbers, and a second `Stale` is acknowledged; `Refused{stale_job}`
(no numbers) goes to the dead-letter queue and pages; `Closed` is
acknowledged (the row stays in the unit's outbox); `renew_needed` and
`SyncNeeded` go through the unit client (renew, or read both chains,
apply the keys and `sync`), then the job runs once more, and a failure
hands the message back with the queue's `retry_delay`; `Unborn` reads the
tenant's verified head (listed: dead-letter queue and a "catalogue lost"
page; not listed: acknowledged; a head that cannot be read: handed back);
`AccountProblem` while the tenant is shredding is acknowledged with no
page; anything else goes to the dead-letter queue and pages. A job runs
once more at most once per delivery, with numbers never below the
message's, and only after the outbox lease its first run claimed is given
back (`TenantCatalog::give_back`; if it cannot be, the message is handed
back). The unit client's other outcomes take the same rows: closed or a
lift pending is acknowledged, unborn reads the head, a unit the head no
longer lists is acknowledged, and every page it returns is logged as an
alert. The unit jobs `renew` and
`stamp_raise` run through the unit client. A unit's job config keeps
tenant 0's `MAINTENANCE`: under `restore` no unit job makes a unit call,
and each is acknowledged with no page. The consumer calls L2's `UnitClient`
through `unit_consumer::ConsumerClient`; until its bodies and a Worker
head reader are wired, the Worker uses `NoClient` and `NoHeads`, so the
arms that need them hand the message back, and `UNIT` stays unbound until
the build that has both and the unit's alarm dispatcher.

A managed tenant's S3 requests reach its units through the request
router (`unit_router`, ADR §2.7), which the management plane uses too.
Only a Worker with `UNIT` bound takes a key route; unbound, every
request takes tenant 0's path with no added read. The claimed access key
id picks the tenant (`KeyRoutes`; tenant 0's keys, unknown keys and a
failed route read keep tenant 0's path, §8.4). The tenant's verified head
(cached per isolate for under 60 s, read again from the seq it knew)
names the unit: the root unit for a call with no bucket, the unit of the
bucket's placement, or the root unit for a bucket with none. The unit
must be listed. A routed call goes through the unit's client (L2's
`UnitClient::call`, which runs rule 5) with the head's `state_seq`, the
highest `keys_seq` a unit of the tenant answered, and `listed`. Under
`MAINTENANCE=restore` every request that writes answers `503` before any
head read or unit call. This build has no S3 request operations on a
unit, and no key routes, head reader or unit client in the Worker, so a
routed request answers `503` and in practice every request takes tenant
0's path. A routed request's `503` comes before its signature is checked:
it tells the caller only that the key id routes to a managed tenant.

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
unit holds again (root unit, seal, stamp counter, empty summary). If a
stamp raise lands between the report and the lift record, the `sync` is
refused by the gate (`refused: gate`); the tool writes a new `restoring`
entry, syncs the unit to it, and opens a new report under it. The lift a
`move` report passes uses the seal up: no other `move` report is taken
after it, so a later entry (a restore of the owner's unit) is lifted only
by the restore gate. So a tool that re-runs 8(b) first reads the unit:
if its `restoring_since` is already empty, the lift landed and 8(c)
follows; a `keys_not_applied` answer means apply the keys and send the
`sync` again, and `stale_sync` means read the head again. Only a gate
refusal re-enters. The unit keeps the time of that lift, and refuses a
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
`last_insert_rowid()`, which are each connection's own counters. Then
`unit-smoke.py` drives the unit class itself in the same workerd.
