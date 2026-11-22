-- The unit's copy of its tenant's key chain, and the progress of an
-- import (docs/units.md, "Keys" and "Import"). Applied at birth, after
-- u0001, in the same transaction.

-- One row per subject of the key chain (an access key, an app password,
-- a principal or the internal key), as the Worker read and verified it
-- (`apply`, AM-12). The catalogue's own `access_keys` and `grants` are
-- built from these rows (the effective grant), never written by a caller.
-- `held`: the store holds the subject closed (its private part did not
-- open, or the directory has not acknowledged its opening record);
-- a held subject is never served. `revoked` is final.
CREATE TABLE unit_keys (
  id                 TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  kind               TEXT NOT NULL CHECK (kind IN ('s3', 'app_password', 'principal', 'internal')),
  status             TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'revoked')),
  held               INTEGER NOT NULL CHECK (held IN (0, 1)),
  made_by            TEXT,
  created_at         INTEGER NOT NULL CHECK (created_at >= 0),
  secret_wrapped     BLOB,
  secret_kek_version INTEGER,
  owner_ref          TEXT,
  last_seq           INTEGER NOT NULL CHECK (last_seq >= 1),
  CHECK (kind <> 'principal' OR (secret_wrapped IS NULL AND secret_kek_version IS NULL)),
  CHECK ((secret_wrapped IS NULL) = (secret_kek_version IS NULL))
) WITHOUT ROWID;
CREATE INDEX unit_keys_by_made_by ON unit_keys(made_by) WHERE made_by IS NOT NULL;

-- The grants of a subject, door and private part joined, in record order.
CREATE TABLE unit_key_grants (
  subject_id  TEXT NOT NULL REFERENCES unit_keys(id),
  idx         INTEGER NOT NULL CHECK (idx >= 0),
  bucket_id   TEXT NOT NULL,
  access      TEXT NOT NULL CHECK (access IN ('ro', 'rw')),
  expires_at  INTEGER,
  prefix      TEXT,
  ip_list     TEXT NOT NULL DEFAULT '[]',
  PRIMARY KEY (subject_id, idx)
) WITHOUT ROWID;
CREATE INDEX unit_key_grants_by_bucket ON unit_key_grants(bucket_id);

-- The import of the owner move (DS1 §2.3): per table, the cursor of the
-- last batch applied and the rows it has taken. A batch names the cursor
-- it follows, so a batch is applied once, in order, and a lost answer is
-- resumed by sending the same batch again.
CREATE TABLE unit_import (
  tbl     TEXT PRIMARY KEY,
  cursor  TEXT NOT NULL,
  rows    INTEGER NOT NULL CHECK (rows >= 0)
) WITHOUT ROWID;

-- The newest tenant-0 head an import was bound to (its seq only goes up),
-- and the restore entry the import fills.
CREATE TABLE unit_import_move (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  t0_seq     INTEGER NOT NULL CHECK (t0_seq >= 0),
  since_seq  INTEGER NOT NULL CHECK (since_seq >= 0)
);
