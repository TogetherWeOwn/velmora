-- velmora: no-transaction
-- These indexes scan the existing extents table. Build without holding W1.
CREATE INDEX CONCURRENTLY IF NOT EXISTS extents_scrub_pending ON extents(id)
    WHERE safety_state = 'released' AND scrub_enrolled = 0;
CREATE INDEX CONCURRENTLY IF NOT EXISTS extents_scrub_enrolled ON extents(id)
    WHERE scrub_enrolled = 1 AND safety_state <> 'deleted';
CREATE INDEX CONCURRENTLY IF NOT EXISTS extents_scrub_watch ON extents(scrub_next_at, id)
    WHERE scrub_next_at IS NOT NULL;
