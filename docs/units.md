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
mode, `restoring_since` and, with the restore call, `closed_at`; moved by
`sync`, and `keys_seq` by the key apply); `unit_keys` and
`unit_key_grants` (the key chain); the lease and the alarm's counters in
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
grant is not served until the check that can), and only when every
principal up the chain holds such a grant on that bucket with at least
that access. Everything else fails closed.

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

## Restore gate

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
