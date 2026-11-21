-- The unit's own tables (tenancy ADR §2.3, §2.4 rules 5, 6, 7). Applied
-- at birth, after every catalogue migration, in the same transaction.

-- The birth certificate (rule 6): one row, written once by `provision`.
-- `token` is the sealed token as the Worker passed it; the unit cannot
-- open the seal (rule 3) and keeps it for the gate and the recovery copy.
CREATE TABLE unit_birth (
  id             INTEGER PRIMARY KEY CHECK (id = 1),
  tenant         TEXT NOT NULL,
  unit           INTEGER NOT NULL CHECK (unit >= 0),
  jurisdiction   TEXT NOT NULL,
  record_seq     INTEGER NOT NULL CHECK (record_seq >= 0),
  schema_version INTEGER NOT NULL,
  key_scheme     INTEGER NOT NULL CHECK (key_scheme IN (1, 2)),
  kind           TEXT NOT NULL CHECK (kind IN ('birth', 'restore')),
  token          BLOB NOT NULL,
  born_at        INTEGER NOT NULL
);

-- What the unit holds of its tenant's chains (rule 5) and of the door
-- part of the tenant record. One row, moved only by `sync`, which copies
-- verified records. `restoring_since`: the since_seq of this unit's
-- `restoring` entry; NULL when it is not being restored.
CREATE TABLE unit_head (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  state_seq       INTEGER NOT NULL CHECK (state_seq >= 0),
  keys_seq        INTEGER NOT NULL CHECK (keys_seq >= 0),
  tenant_state    TEXT NOT NULL CHECK (tenant_state IN
                    ('provisioning', 'active', 'suspended', 'deleting', 'shredding', 'shredded')),
  tenant_mode     TEXT CHECK (tenant_mode IS NULL OR tenant_mode IN ('read_only', 'locked')),
  restoring_since INTEGER,
  CHECK ((tenant_state = 'suspended') = (tenant_mode IS NOT NULL))
);
