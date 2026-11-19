-- Two indexes for periodic work on the ingest path. Additive only: a
-- Worker from before this migration neither names nor needs them, and
-- runs on this schema unchanged.
--
-- Creating each index reads its table once. Apply in a quiet window.

-- The rows the cron buries: out of attempts and still at a working
-- stage. A row enters when its 51st claim is counted and leaves when it
-- is buried, so the index is empty in normal work and an insert or a
-- claim writes no entry for it. The bury reads this index and nothing
-- else; before, it walked every post, verify and release row.
-- The literal 50 is `MAX_ATTEMPTS`: the statement must spell the same
-- condition for the planner to use the index.
CREATE INDEX outbox_exhausted
  ON outbox(extent_id)
  WHERE attempts > 50 AND stage IN ('post', 'verify', 'release');

-- The pinned set (safety copy held or being released) in id order, with
-- the size of each copy. One index for every periodic read of it:
--   - the re-drive of under-verified extents walks the held ones in id
--     order (was `extents_held`);
--   - the status total sums `cipher_size` over all of it (was
--     `extents_pinned`);
--   - the recovery check of safety copies walks all of it in id order
--     (was the primary key, over every extent).
-- Each is answered from this index alone. `id` leads so that the walks
-- need no sort.
--
-- Expand, then contract: `extents_held` and `extents_pinned` stay until
-- no Worker that names or needs them can run (an older Worker names
-- `extents_held` in its statements, and fails without it). While old and
-- new exist side by side an extent pays one index entry more at its
-- insert and one more when its release starts; after the drops, two
-- less at its insert than before this migration. `extents_by_generation`
-- goes with them (one more off every insert and every adopted part):
-- from this release on no statement filters `extents` by generation.
-- The drops are `migrations-next/0022_drop_superseded_indexes.sql`,
-- moved into this directory by the release after this one.
CREATE INDEX extents_safety
  ON extents(id, cipher_size, safety_state)
  WHERE safety_state IN ('held', 'releasing');
