-- Scrub: a background read-back of released extents from Usenet alone,
-- and the repair of what it finds lost (crate::scrub).
--
-- `last_scrubbed_at`: when the last check that read the extent ended.
-- `scrub_result`: what it found: 'ok', 'suspect' (a loss seen once, to be
--   looked at again), 'repairing' (re-pinned: the safety copy is back and
--   the verify stage posts what a backbone lacks), 'stalled' (still
--   re-pinned when the repair should have ended), 'unrecoverable' (no
--   intact copy anywhere). NULL = never checked.
-- `scrub_next_at`: when the extent is due again. NULL = never checked: the
--   first check is due 30 days after the last verification (H6: every
--   extent at least every 30 days; the verification before the release
--   is the first check).
--
-- A Worker from before these columns neither reads nor writes them. One
-- that releases a re-pinned extent leaves `scrub_next_at` as it is, and
-- the scrub checks the extent when it is due. Additive only.

ALTER TABLE extents ADD COLUMN last_scrubbed_at INTEGER;
ALTER TABLE extents ADD COLUMN scrub_result TEXT;
ALTER TABLE extents ADD COLUMN scrub_next_at INTEGER;

-- The extents the scrub looks at, by when they are due, oldest first.
-- Released extents, and any the scrub has put a due time on (a re-pinned
-- one is `held`). The expression and the condition are those of the
-- statements in `sql/scrub.rs`, word for word: the planner takes a
-- partial or expression index only then. 2592000000 ms = 30 days.
CREATE INDEX extents_scrub_due
  ON extents(COALESCE(scrub_next_at,
                      COALESCE(last_verified_at, released_at, created_at) + 2592000000))
  WHERE safety_state = 'released' OR scrub_next_at IS NOT NULL;

-- One row: the scrub's lease (one run at a time) and its running totals.
CREATE TABLE scrub_state (
  id                    INTEGER PRIMARY KEY CHECK (id = 1),
  lease_token           INTEGER NOT NULL DEFAULT 0,  -- +1 on every take; fences a run's writes
  lease_until           INTEGER,
  runs                  INTEGER NOT NULL DEFAULT 0,
  checked               INTEGER NOT NULL DEFAULT 0,
  ok                    INTEGER NOT NULL DEFAULT 0,
  suspect               INTEGER NOT NULL DEFAULT 0,
  repaired              INTEGER NOT NULL DEFAULT 0,
  unrecoverable         INTEGER NOT NULL DEFAULT 0,
  stalled               INTEGER NOT NULL DEFAULT 0,
  incidents             INTEGER NOT NULL DEFAULT 0,
  bytes_read            INTEGER NOT NULL DEFAULT 0,
  last_run_at           INTEGER,
  last_unrecoverable_at INTEGER,
  last_incident_at      INTEGER,
  last_incident         TEXT                        -- backbone label and counts; no host or id
);
INSERT INTO scrub_state(id) VALUES (1);
