-- Separate existence and integrity schedules for each counting backbone.
-- The old extent result remains a summary; its due time is for repair watches.
-- Creating each index reads its table once. Apply in a quiet window.
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
