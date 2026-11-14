-- Closes a catalogue that was just brought back (restore, step 2): from
-- here until a replay has run to its end, every write answers 503, also
-- with MAINTENANCE off.
--   npx wrangler d1 execute <db> --remote --file ops/restore-arm.sql
-- A replay that was under way on this database is made void: its
-- cursors are of an earlier mark. Running this twice is harmless.
-- `since_ms` -1 = closed by this file, no replay started: the replay
-- may start from any restore point. The restore point of a replay that
-- had not ended on this database is kept: the next one must start
-- there or earlier.
INSERT INTO restore_state(id, state, since_ms, started_at)
VALUES (1, 'replaying', -1, 0)
ON CONFLICT(id) DO UPDATE SET
  since_ms = CASE WHEN state = 'complete' THEN -1 ELSE since_ms END,
  state = 'replaying',
  started_at = started_at + 1,
  finished_at = NULL,
  reached_phase = NULL,
  reached_after = NULL,
  reached_extent = NULL;
