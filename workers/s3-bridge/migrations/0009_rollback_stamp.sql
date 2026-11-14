-- The rollback stamp: a counter that only grows, with one empty object
-- in the safety bucket per value it has reached. A restore of this
-- database to an earlier point (Time Travel, an import) takes the
-- counter back; the objects stay. A counter behind its newest object
-- therefore means the catalogue was rolled back.
-- No row = the counter was never raised on this database.
-- `rolled_back_at` is set when that was found; from then until a replay
-- of the recovery records has ended, every write is refused and no
-- background job runs.
-- Additive only.

CREATE TABLE rollback_stamp (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  counter         INTEGER NOT NULL CHECK (counter >= 0),
  rolled_back_at  INTEGER
);
