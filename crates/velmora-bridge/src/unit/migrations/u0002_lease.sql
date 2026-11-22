-- The freshness lease and the alarm's counters (docs/units.md, rules 8
-- and 12), and the revocations listed for a key the unit does not hold.
-- Applied at birth, after u0001, in the same transaction.

-- One row, made here: a unit that never renewed has it with no lease.
-- `fresh_until`: the lease, the Worker's `proof_start` + T; NULL = none
--   (never issued, or closed by the `sync` that set a `restoring` entry).
-- `lease_hi`: the latest `fresh_until` the unit ever held. Kept across a
--   close: a restore waits for it (AM-2 check 3).
-- `renew_tries`: renew jobs the alarm sent since the last successful
--   renewal (its backoff); set to 0 by one.
-- `failed_runs`: alarm runs in a row in which a duty failed.
-- `first_write_at`: the unit's time of the first write since the last
--   stamp raise the alarm asked for; NULL = no write since.
-- Not moved by `sync` (unit_head is): only `renew`, the close, the alarm
-- and a call that writes.
CREATE TABLE unit_lease (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  fresh_until    INTEGER,
  lease_hi       INTEGER,
  renew_tries    INTEGER NOT NULL DEFAULT 0 CHECK (renew_tries >= 0),
  failed_runs    INTEGER NOT NULL DEFAULT 0 CHECK (failed_runs >= 0),
  first_write_at INTEGER
);

INSERT INTO unit_lease(id) VALUES (1);

-- An access key id that a renewal listed under `m/rk/<t>/` and that the
-- unit holds no key row for: it counts as revoked (ADR §2.4 rule 12,
-- SEC-6), and a key row that arrives for it later is revoked at once (a
-- revocation overrides every key-chain status). Put-only.
CREATE TABLE unit_revoked_ids (
  id         TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  listed_at  INTEGER NOT NULL
) WITHOUT ROWID;
