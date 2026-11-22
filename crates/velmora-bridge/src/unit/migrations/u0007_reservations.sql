-- The unit side of the reservation (ADR §2.5 step 0, §6.2, §6.3;
-- amendments AM-18, AM-35, AM-36, AM-38; docs/units.md, "Reservations").
-- Applied at birth, after u0006, in the same transaction.

-- One row per capped opening call (create a key, an app password, a
-- principal or a bucket; a widening grant change), keyed by the
-- `Idempotency-Key`'s scope: the acting principal's id ('' for none) and
-- SHA-256 of the key. The key itself is never stored.
-- - `fingerprint`: SHA-256 of the request (AM-38); the same key with
--   another fingerprint is refused as reused.
-- - `rid`: the reservation's id, given at its first admit and kept by
--   every re-ask; every record of the call carries it in its door part,
--   and the key-chain apply turns the row `applied` by it.
-- - `keys_seq`: the key-chain head the last admit checked at; the record
--   must be exactly `keys_seq + 1`.
-- - `subject`: the key or principal the call makes, or whose grants it
--   widens; `owner_ref`: a principal create holds it (at most one
--   principal per `owner_ref` that is not revoked, AM-35); `name` and
--   `unit`: a bucket create holds the name; `bound`: the creator-grant
--   seq a bucket create bound; `bucket_id`: the bucket it became.
-- - The answer kept once applied: a 2xx status and a JSON body of at
--   most 16 KiB with no secret (the Worker cleans it; the unit checks).
-- A `reserved` row is released after 1 hour; an `applied` one is kept
-- 24 hours after its apply. A refused call leaves no row.
CREATE TABLE unit_reservations (
  scope         TEXT NOT NULL CHECK (length(scope) <= 128),
  key_hash      BLOB NOT NULL CHECK (typeof(key_hash) = 'blob' AND length(key_hash) = 32),
  fingerprint   BLOB NOT NULL CHECK (typeof(fingerprint) = 'blob' AND length(fingerprint) = 32),
  rid           BLOB NOT NULL UNIQUE CHECK (typeof(rid) = 'blob' AND length(rid) = 16),
  class         TEXT NOT NULL CHECK (class IN ('s3', 'app_password', 'principal', 'grants', 'bucket')),
  state         TEXT NOT NULL CHECK (state IN ('reserved', 'applied')),
  keys_seq      INTEGER NOT NULL CHECK (keys_seq >= 0),
  subject       TEXT CHECK (subject IS NULL OR length(subject) BETWEEN 1 AND 128),
  owner_ref     TEXT,
  name          TEXT,
  unit          INTEGER CHECK (unit IS NULL OR unit >= 0),
  bound         INTEGER UNIQUE CHECK (bound IS NULL OR bound >= 1),
  bucket_id     TEXT,
  answer_status INTEGER CHECK (answer_status IS NULL OR answer_status BETWEEN 200 AND 299),
  answer_body   TEXT CHECK (answer_body IS NULL OR length(CAST(answer_body AS BLOB)) <= 16384),
  reserved_at   INTEGER NOT NULL,
  applied_at    INTEGER,
  PRIMARY KEY (scope, key_hash),
  CHECK ((state = 'applied') = (applied_at IS NOT NULL)),
  CHECK ((answer_status IS NULL) = (answer_body IS NULL)),
  CHECK (answer_status IS NULL OR state = 'applied'),
  CHECK ((class = 'bucket') = (name IS NOT NULL)),
  CHECK ((class = 'bucket') = (unit IS NOT NULL)),
  CHECK ((class = 'bucket') = (subject IS NULL)),
  CHECK ((class = 'principal') = (owner_ref IS NOT NULL)),
  CHECK (bound IS NULL OR class = 'bucket'),
  CHECK (bucket_id IS NULL OR (class = 'bucket' AND state = 'applied'))
) WITHOUT ROWID;
CREATE INDEX unit_reservations_by_time ON unit_reservations(state, reserved_at);
CREATE INDEX unit_reservations_by_apply ON unit_reservations(state, applied_at);
CREATE INDEX unit_reservations_by_name ON unit_reservations(name) WHERE name IS NOT NULL;
CREATE INDEX unit_reservations_by_owner_ref ON unit_reservations(owner_ref)
  WHERE owner_ref IS NOT NULL;
CREATE INDEX unit_reservations_by_scope ON unit_reservations(scope, state);

-- Creator-grant seqs that no reservation was bound to when the finisher
-- asked (`bucket_binding` answered none): such a grant is an orphan for
-- good, and no late bind may take it.
CREATE TABLE unit_bucket_fences (
  grant_seq INTEGER PRIMARY KEY CHECK (grant_seq >= 1)
);

-- AM-35: the acting principal is resolved by `owner_ref` in the unit's
-- own key rows.
CREATE INDEX unit_keys_by_owner_ref ON unit_keys(owner_ref) WHERE kind = 'principal';
