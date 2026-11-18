-- The light check of the verify stage (`VERIFY_MODE=light`).
--
-- `verifications.mode` says more about a row than `kind` does:
--   NULL      = a row as before: a full read (`kind = 'body'`) or a
--               `STAT` pass (`kind = 'stat'`);
--   'sampled' = a full read (`kind = 'body'`) made because the extent
--               fell in the sample, or because its backbone is read in
--               full for a while after a failed read;
--   'size'    = presence and the size of every article as the
--               provider counted it (`kind = 'stat'`). A size that came
--               with the article is checked too, but leaves `mode` NULL.
-- `kind` keeps its two values, so a Worker from before this column
-- reads a 'sampled' row as the full read it is and a 'size' row as the
-- presence check it also is, and its own inserts leave `mode` NULL: it
-- can run on this schema.
-- Additive only.

ALTER TABLE verifications ADD COLUMN mode TEXT
  CHECK (mode IS NULL OR mode IN ('size','sampled'));

-- A backbone that is read in full for every extent until `until`,
-- because a full read of a sampled extent failed there. One row per
-- backbone (its label, trimmed and lower case). It covers every extent
-- stored before `until` (`extents.created_at`), whenever that extent is
-- verified or released; it says nothing about an extent stored later.
-- `extent_id` and `result` name the read that raised it last.
CREATE TABLE verify_escalations (
  backbone   TEXT PRIMARY KEY,
  until      INTEGER NOT NULL,
  raised_at  INTEGER NOT NULL,
  extent_id  TEXT NOT NULL,
  result     TEXT NOT NULL CHECK (result IN ('missing','corrupt','error'))
) WITHOUT ROWID;
