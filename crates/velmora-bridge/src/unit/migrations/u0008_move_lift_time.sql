-- The time of the owner move's lift (docs/units.md, "Restore"). Applied
-- at birth, after u0007, in the same transaction.

-- The unit's clock at the `sync` that a `move` report lifted. A restore
-- to a time before it is refused: it would bring back the move's window
-- (a sealed import whose seal is not used up yet), under which a stale
-- tenant-0 head could open a `move` report for the restore's own entry.
ALTER TABLE unit_import_move ADD COLUMN lifted_at INTEGER;
