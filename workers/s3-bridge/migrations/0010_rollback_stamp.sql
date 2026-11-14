-- The rollback stamp: a counter that only grows, with one small object
-- in the safety bucket per value it has reached. A restore of this
-- database to an earlier point (Time Travel, an import) takes the
-- counter back; the objects stay. A counter behind its newest object
-- therefore means the catalogue was rolled back.
-- No row = the counter was never raised on this database.
-- `rolled_back_at` is set when that was found; from then until a replay
-- of the recovery records has ended, every write is refused and no
-- background job runs.
-- `catalogue_id` is the id the stamp objects of this database are keyed
-- by, written with the row. A Worker that is configured with another id
-- would look for them in the wrong place: it refuses to use the stamp.
-- Additive only.

CREATE TABLE rollback_stamp (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  counter         INTEGER NOT NULL CHECK (counter >= 0),
  catalogue_id    TEXT NOT NULL,
  rolled_back_at  INTEGER
);
