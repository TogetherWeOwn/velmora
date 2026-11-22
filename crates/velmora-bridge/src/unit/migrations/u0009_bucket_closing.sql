-- Bucket delete is close, then record, then drop (docs/units.md,
-- "Buckets"; ADR §6.2, AM-57). Applied at birth, after u0008, in the
-- same transaction.

-- A bucket row the unit holds `closing`: `bucket_close` found it empty
-- and marked it, or a `dropped` (or `unplaced`) record reached a row
-- that was not closing. Every write into a closing bucket answers
-- `NoSuchBucket`; its name stays taken until the row is dropped.
-- `dropped_seq`: the seq of the record that dropped (or unplaced) it,
-- set when the row had to be kept because it still held a row of the
-- bucket's data (paged `drop_not_closed`); the placement check leaves
-- such a row out, as the head no longer places it.
CREATE TABLE unit_bucket_closing (
  bucket_id   TEXT PRIMARY KEY REFERENCES buckets(id) ON DELETE CASCADE,
  closed_at   INTEGER NOT NULL,
  dropped_seq INTEGER
) WITHOUT ROWID;
