-- The restore calls and the lift checked in the unit (docs/units.md,
-- "Restore" and "Restore gate"). Applied at birth, after u0003, in the
-- same transaction.

-- The unit's own time of the `sync` that set its `restoring` entry (a
-- unit born from a `restore` token: its birth). Kept while the entry is
-- set; cleared with it.
ALTER TABLE unit_head ADD COLUMN closed_at INTEGER;

-- The one gate report: the replay it belongs to (`since_seq`, the stamp
-- ordinal, the tool's nonce) and what that replay found (JSON, the gate's
-- findings). A report of another replay is discarded when the gate opens.
CREATE TABLE unit_gate_report (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  since_seq  INTEGER NOT NULL CHECK (since_seq >= 0),
  ordinal    INTEGER NOT NULL CHECK (ordinal >= 0),
  nonce      TEXT NOT NULL CHECK (length(nonce) BETWEEN 1 AND 64),
  findings   TEXT NOT NULL
);

-- Blocker ids acknowledged by name for the stored report.
CREATE TABLE unit_gate_acks (
  class  TEXT NOT NULL CHECK (class IN ('damaged', 'held_missing', 'unreadable',
           'unpublishable', 'damaged_unpublished', 'twins', 'other_bucket')),
  id     TEXT NOT NULL,
  PRIMARY KEY (class, id)
) WITHOUT ROWID;
