-- The first open of the directory gate (AM-83b) empties `pending_ops`
-- exactly once: in the batch that moves the gate row from closed at
-- epoch 0 (or no row) to closed at epoch 1, and never after an open.
-- `pending_cleared` says that this batch has run at epoch 1; the open
-- at epoch 1 requires it. Additive only, like 0001 to 0003.
ALTER TABLE directory_gate ADD COLUMN pending_cleared INTEGER NOT NULL DEFAULT 0 CHECK (pending_cleared IN (0, 1));
