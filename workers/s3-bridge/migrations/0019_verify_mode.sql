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
--               with the article is checked too: where it fits the row
--               keeps `mode` NULL (presence is all it proves), where it
--               does not the row is 'size' with `result = 'corrupt'`.
-- `kind` keeps its two values, so a Worker from before this column
-- reads a 'sampled' row as the full read it is and a 'size' row as the
-- presence check it also is, and its own inserts leave `mode` NULL: it
-- can run on this schema.
-- Additive only.

-- No CHECK on the column: adding one makes SQLite test it against every
-- row the table has, and this must not read the table. The Worker
-- writes only NULL, 'size' or 'sampled', and reads a value it does not
-- know as what `kind` says.
ALTER TABLE verifications ADD COLUMN mode TEXT;

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

-- An extent has raised a backbone for a plan: it does so once. Written
-- with the row above, in one batch. A failed read of the same plan found
-- again by a retry says nothing new about the backbone; a new plan of
-- the extent (`plan_rev`) or another extent does.
CREATE TABLE verify_raises (
  extent_id  TEXT NOT NULL,
  backbone   TEXT NOT NULL,
  plan_rev   INTEGER NOT NULL,
  raised_at  INTEGER NOT NULL,
  PRIMARY KEY (extent_id, backbone, plan_rev)
) WITHOUT ROWID;
