-- The owner move's lift (docs/units.md, "Import" and "Restore gate";
-- DS1 §3.4 step 8(b), AM-15, AM-29). Applied at birth, after u0004, in
-- the same transaction.

-- The seal of the import (`import_seal`): every import table's row count
-- was named and equal to `unit_import`, so no batch is missing. `final`
-- = 1 from then on, and no batch is taken. `move_ordinal`: tenant 0's
-- `flips + 1` at the seal, the window this import belongs to; a `move`
-- report and a move's recount are taken only for it. Survives a new
-- `restoring` entry (AM-15's re-entry); `deleteAll()` clears it.
ALTER TABLE unit_import_move ADD COLUMN final INTEGER NOT NULL DEFAULT 0
  CHECK (final IN (0, 1));
ALTER TABLE unit_import_move ADD COLUMN move_ordinal INTEGER
  CHECK (move_ordinal IS NULL OR move_ordinal >= 1);
-- A `move` report lifted this unit: the seal is used up, and no other
-- `move` report is taken (only `deleteAll()` and a new move start again).
ALTER TABLE unit_import_move ADD COLUMN move_lifted INTEGER NOT NULL DEFAULT 0
  CHECK (move_lifted IN (0, 1));

-- What the stored gate report is: the final replay of a restore, or the
-- move's lift report (complete, with no blocker, opened only under the
-- binding of DS1 §3.4 step 8(b)).
ALTER TABLE unit_gate_report ADD COLUMN kind TEXT NOT NULL DEFAULT 'restore'
  CHECK (kind IN ('restore', 'move'));
