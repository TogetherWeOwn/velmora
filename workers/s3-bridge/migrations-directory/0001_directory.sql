-- The directory: an index of tenants, their units and the routes from an
-- access key id to its tenant. It is its own D1 database, apart from the
-- catalogue, and nothing in it decides: every tenant fact is a copy of the
-- head of the tenant's record chain in R2 (`m/t/<tenant>/<seq>`), and the
-- directory gate rebuilds every row from the records. No service token
-- and no token hash is stored here.
-- Additive only, like the catalogue's migrations.

-- One row per tenant: a copy of its chain head. `door_json` is the head's
-- door part as written; the other columns are taken from it so that they
-- can be queried. `record_seq` only grows (an older head never replaces a
-- newer one). `keys_seq` is the head of the tenant's key chain, written by
-- the key chain's own steps.
CREATE TABLE tenants (
  id            TEXT PRIMARY KEY CHECK (id GLOB 't_[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'),
  record_seq    INTEGER NOT NULL CHECK (record_seq > 0),
  keys_seq      INTEGER NOT NULL DEFAULT 0 CHECK (keys_seq >= 0),
  state         TEXT NOT NULL CHECK (state IN ('provisioning', 'active', 'suspended', 'deleting', 'shredding', 'shredded')),
  hold_mode     TEXT CHECK (hold_mode IN ('read_only', 'locked')),
  shred_due_at  INTEGER,
  tk_version    INTEGER NOT NULL CHECK (tk_version >= 0),
  rotating_to   INTEGER,
  selector      TEXT CHECK (selector IN ('d1', 'moved')),
  synthetic     INTEGER NOT NULL CHECK (synthetic IN (0, 1)),
  jurisdiction  TEXT NOT NULL,
  door_json     TEXT NOT NULL,
  updated_at    INTEGER NOT NULL
);

CREATE INDEX tenants_shred_due ON tenants (shred_due_at) WHERE shred_due_at IS NOT NULL;

-- One row per unit of a tenant's unit list. `restoring_since` is the
-- `since_seq` of the unit's `restoring` entry, NULL when none. The size
-- and counter columns are what the unit last reported, never a record.
CREATE TABLE units (
  tenant           TEXT NOT NULL REFERENCES tenants (id),
  unit             INTEGER NOT NULL CHECK (unit >= 0),
  restoring_since  INTEGER,
  schema_version   INTEGER,
  size_bytes       INTEGER,
  extent_count     INTEGER,
  counters_json    TEXT,
  reported_at      INTEGER,
  PRIMARY KEY (tenant, unit)
);

-- Access key id to tenant. A route never changes, so it is cached without
-- a time limit; the unit decides the key's status. `kind` is `s3`,
-- `app_password`, `internal` or `principal`.
CREATE TABLE key_routes (
  akid        TEXT PRIMARY KEY,
  tenant      TEXT NOT NULL REFERENCES tenants (id),
  kind        TEXT NOT NULL CHECK (kind IN ('s3', 'app_password', 'internal', 'principal')),
  owner_ref   TEXT,
  created_at  INTEGER NOT NULL
);

CREATE INDEX key_routes_tenant ON key_routes (tenant);

-- Public bucket label to tenant and bucket id. Rebuilt from the newest
-- bucket configuration record of every bucket.
CREATE TABLE bucket_index (
  label      TEXT PRIMARY KEY,
  tenant     TEXT NOT NULL REFERENCES tenants (id),
  bucket_id  TEXT NOT NULL
);

-- The closed set of tenant key locations: a copy of the head of the
-- key-location chain `m/kl/<seq>`.
CREATE TABLE key_locations (
  location  TEXT PRIMARY KEY,
  status    TEXT NOT NULL,
  kl_seq    INTEGER NOT NULL CHECK (kl_seq > 0)
);

-- A control change that is not yet applied everywhere: the visible copy
-- of its queue message, for the pending sweep and its age alarm.
-- `chain` is `t` (tenant chain) or `k` (key chain).
CREATE TABLE pending_ops (
  tenant      TEXT NOT NULL,
  chain       TEXT NOT NULL CHECK (chain IN ('t', 'k')),
  seq         INTEGER NOT NULL CHECK (seq > 0),
  kind        TEXT NOT NULL,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (tenant, chain, seq)
);

CREATE INDEX pending_ops_created ON pending_ops (created_at);

-- The reserved slots of the shred brake, by day.
CREATE TABLE shred_slots (
  day     INTEGER NOT NULL,
  tenant  TEXT NOT NULL,
  seq     INTEGER NOT NULL,
  PRIMARY KEY (day, tenant)
);

-- A copy of the head of the registry chain `m/reg/<seq>`.
CREATE TABLE registry (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  reg_seq    INTEGER NOT NULL CHECK (reg_seq > 0),
  body_json  TEXT NOT NULL
);

-- The directory gate. While `closed` is 1 the management plane answers
-- 503 but for the closing calls that need no directory row. The epoch
-- grows by one at every closing; the event feed starts a new one with it.
-- No row = closed at epoch 0: a directory that no rebuild has filled
-- serves nothing to the management plane.
CREATE TABLE directory_gate (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  closed     INTEGER NOT NULL CHECK (closed IN (0, 1)),
  epoch      INTEGER NOT NULL CHECK (epoch >= 0),
  reason     TEXT,
  closed_at  INTEGER,
  opened_at  INTEGER
);
