-- SQLite twin of pg/0005_scrub.sql and pg/0006_scrub_indexes.sql, for local
-- development and tests. Never applied to the frozen D1 catalogue.

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
  last_incident         TEXT,                       -- JSON array of the backbones under an incident; NULL = none
  incident_clean        INTEGER NOT NULL DEFAULT 0  -- checks in a row since the last trip that found nothing lacking on a blocked backbone
);
INSERT INTO scrub_state(id) VALUES (1);

-- Separate existence and integrity schedules for each counting backbone.
-- The old extent result remains a summary; its due time is for repair watches.
ALTER TABLE extents ADD COLUMN scrub_enrolled INTEGER NOT NULL DEFAULT 0;
CREATE INDEX extents_scrub_pending ON extents(id)
  WHERE safety_state = 'released' AND scrub_enrolled = 0;
CREATE INDEX extents_scrub_enrolled ON extents(id)
  WHERE scrub_enrolled = 1 AND safety_state <> 'deleted';
CREATE INDEX extents_scrub_watch ON extents(scrub_next_at, id) WHERE scrub_next_at IS NOT NULL;

CREATE TABLE scrub_copies (
  extent_id TEXT NOT NULL REFERENCES extents(id) ON DELETE CASCADE,
  backbone TEXT NOT NULL,
  stat_at INTEGER NOT NULL,
  full_at INTEGER NOT NULL,
  stat_phase_at INTEGER NOT NULL,
  full_phase_at INTEGER NOT NULL,
  stat_loss_at INTEGER,
  full_loss_at INTEGER,
  PRIMARY KEY (extent_id, backbone)
) WITHOUT ROWID;
CREATE INDEX scrub_copies_due ON scrub_copies(backbone, MIN(stat_at, full_at), extent_id);

-- A change in the set of counting backbones starts a bounded keyset pass
-- over enrolled extents, including temporarily held repairs. Previously
-- unenrolled releases enter through pending, regardless of cursor order.
ALTER TABLE scrub_state ADD COLUMN cadence_backbones TEXT;
ALTER TABLE scrub_state ADD COLUMN cadence_after TEXT;
ALTER TABLE scrub_state ADD COLUMN cadence_epoch INTEGER;
ALTER TABLE scrub_state ADD COLUMN incident_clean_by TEXT;
ALTER TABLE scrub_state ADD COLUMN incident_body_by TEXT;
-- Legacy incidents did not distinguish STAT from BODY. Require BODY evidence.
UPDATE scrub_state SET incident_body_by = last_incident WHERE id = 1;
