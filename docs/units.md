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
5. **Identity.** Every call carries the tenant and unit it is for and two
   chain numbers: `state_seq` (the tenant's records) and `keys_seq` (its key
   records). The unit compares them with its own:
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
    verified. Only two operations run without it: the key-row fetch and the
    cold read plan (both read-only; a cold read returns the key row with the
    plan, so a cold isolate verifies the signature from one call). Their
    transaction is rolled back and refused if it changed a row.
13. **Key scheme.** Tenant 0 holds key scheme 1, every other tenant scheme 2;
    a token with the other scheme is refused.
14. **Jurisdiction.** A token names the jurisdiction of the namespace its
    object is in; a token for another one makes no object.

Rules 8 to 10 and 12 (one alarm, jobs that name their tenant, the unit's
outbox to the directory, the freshness lease) are not built yet. Until the
lease exists, a unit is not bound anywhere: the lease is what closes a unit
that a point-in-time restore took back to an older state.

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
tests get the object's answers. Then `unit-smoke.py` drives the unit class
itself in the same workerd.
