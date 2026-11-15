-- The slices of a write that stores its body as several extents, known
-- to the catalogue before the first of them is stored. A PutObject above
-- one extent inserts one row per slice, then stores the slices; the
-- batch that publishes the object deletes the rows. Rows that stay name
-- safety blobs no catalogue row refers to: the sweep deletes those blobs,
-- unless a recovery record of the write exists.
--   open       the request can still be running
--   abandoned  the request gave up and published nothing
--   sweeping   the sweep took the write; no publication of it can commit
--   kept       the sweep found a recovery record and left the blobs
-- `generation_id` is stored before the recovery record of that id is
-- written, so a record of the write can always be found from its rows.
-- A replay of the recovery records removes the rows when it starts, all
-- but the `kept` rows whose record it does not read.
-- Additive only.

CREATE TABLE write_intents (
  extent_id     TEXT PRIMARY KEY,                 -- minted before the slice is stored
  write_id      TEXT NOT NULL,                    -- w_<32 hex>, one per request
  tenant_id     TEXT NOT NULL DEFAULT 't_0000000000000000',  -- the default tenant
  generation_id TEXT,                             -- NULL until a recovery record is about to be written
  state         TEXT NOT NULL CHECK (state IN ('open','abandoned','sweeping','kept')),
  created_at    INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX write_intents_by_write ON write_intents(write_id);
CREATE INDEX write_intents_due ON write_intents(created_at);
