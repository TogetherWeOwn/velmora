-- Extents whose safety copy is still held: the working set of the
-- re-drive of under-verified extents, small once copies are released.
-- Additive only.

CREATE INDEX extents_held ON extents(id) WHERE safety_state = 'held';

-- Where a periodic scan resumes, so each run reads a bounded window.
-- 'redrive': the last extent id the re-drive looked at ('' = start).
CREATE TABLE scan_cursors (
  k              TEXT PRIMARY KEY,
  v              TEXT NOT NULL
) WITHOUT ROWID;
