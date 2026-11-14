-- Whether a replay of the recovery records is under way. The restore
-- route sets `replaying` when a replay starts and `complete` when it
-- ends. While the row says `replaying`, every write is refused, also
-- after maintenance was switched off: a catalogue that holds only a part
-- of the records must not take new writes.
-- No row = no replay was ever started on this database.
-- `reached_*` is the place the next step of the replay starts from
-- (NULL = no step has finished). The restore route takes no cursor that
-- is ahead of it, so that no part of the records can be skipped.
-- Additive only.

CREATE TABLE restore_state (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  state        TEXT NOT NULL CHECK (state IN ('replaying', 'complete')),
  since_ms     INTEGER NOT NULL,
  started_at   INTEGER NOT NULL,
  finished_at  INTEGER,
  reached_phase   INTEGER,
  reached_after   TEXT,
  reached_extent  INTEGER
);
