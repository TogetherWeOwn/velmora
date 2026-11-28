-- SQLite twin of pg/0006_scrub_indexes.sql, for local development and tests.
-- Never applied to the frozen D1 catalogue.
CREATE INDEX extents_scrub_pending ON extents(id)
  WHERE safety_state = 'released' AND scrub_enrolled = 0;
CREATE INDEX extents_scrub_enrolled ON extents(id)
  WHERE scrub_enrolled = 1 AND safety_state <> 'deleted';
CREATE INDEX extents_scrub_watch ON extents(scrub_next_at, id) WHERE scrub_next_at IS NOT NULL;
