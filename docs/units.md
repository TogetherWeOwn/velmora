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
    if it changed a row. The Worker's own calls (`provision`, `sync`) are
    not judged by this flag: they carry records the Worker has verified,
    never a caller's input, and a cold isolate needs `sync` before it can
    verify a signature.
13. **Key scheme.** Tenant 0 holds key scheme 1, every other tenant scheme 2;
    a token with the other scheme is refused.
14. **Jurisdiction.** A token names the jurisdiction of the namespace its
    object is in; a token for another one makes no object.

Rules 8 to 10 and 12 (one alarm, jobs that name their tenant, the unit's
outbox to the directory, the freshness lease) are not built yet. Until the
lease exists, a unit is not bound anywhere: the lease is what closes a unit
that a point-in-time restore took back to an older state.

**The calls are JSON** (`UnitCall` and `UnitAnswer`, `unit::call`). Every
answer is to carry `lease_left_ms`, and an answer of a unit that holds
keys `revoked` (rule 12; with the lease). Until the class is bound
(stage C(b)) the format may change. After it, these types only gain
fields, in two deploys, reader first, and a golden-JSON test pins each
variant.

**What a unit keeps besides the catalogue:** `unit_birth` (the
certificate); `unit_head` (`state_seq`, `keys_seq`, the tenant state and
mode, `restoring_since` and `closed_at`; moved by
`sync`, and `keys_seq` by the key apply); `unit_keys` and
`unit_key_grants` (the key chain); the gate report and its
acknowledgements; the lease and the alarm's counters in
`unit_lease`, and revocations listed for a key the unit does not hold as
tombstones (with the lease); and the stamp counter.

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
fails closed.

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
`plan_rev` is bound through `plan_rev::bound`.

## Jobs

Post, verify, release, GC, eviction and the dispatcher run in the Worker,
as today: they hold the NNTP sessions, the blob stores and the keys (rules
3 and 4). What they ask of the catalogue, the tenant's unit answers. Each
catalogue method of the job path is one `job` call (`unit::jobcall`), run
by the unit's own catalogue in one transaction; on the Worker's side,
`TenantCatalog` is a catalogue whose job methods are these calls, so the
job code runs unchanged against a unit. A job call carries the job's
numbers and must match the unit's (rule 5: missing or lower is refused,
higher is `sync_needed`), is `authenticated`, is refused while the unit is
closed, and is refused for a tenant being shredded. Provider permits and
provider health are not a unit's: they stay in the shared database, which
every tenant's jobs use. The request path does not use `TenantCatalog`.
A refusal (`sync_needed`, a stale job, closed, unborn) comes back as a
typed error, and the first one is kept (`TenantCatalog::refusal`) so the
consumer can re-read the heads and run the job again or drop it. Stamp
calls must name the unit's own stamp id, `<tenant>.<unit>`. Eviction runs
per unit against the configured cap until the directory's global
threshold exists (ADR §5.5): with N managed tenants the cache can hold up
to N times the cap.

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

- A JS number binds as a SQLite REAL (in a Durable Object and in D1). `DoSql`
  writes every integer placeholder as `+CAST(?N AS INTEGER)`: the integer a
  native binding gives, without the affinity a bare `CAST` adds.
- An integer above 2^53 reads back rounded, silently: `DoSql` refuses
  integers outside ±(2^53 - 1) both ways, as the D1 adapter does.
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
