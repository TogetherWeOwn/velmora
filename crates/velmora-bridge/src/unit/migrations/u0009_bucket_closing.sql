-- Bucket delete is close, then record, then drop (docs/units.md,
-- "Buckets"; ADR §6.2, AM-56, AM-57). Applied at birth, after u0008, in
-- the same transaction.

-- A bucket row the unit holds `closing`: `bucket_close` found it empty
-- and marked it, or a `dropped` (or `unplaced`) record reached a row
-- that was not closing. Every write into a closing bucket answers
-- `NoSuchBucket`. A closing row the head does not place is dropped once
-- it holds nothing (AM-57 step 2a).
CREATE TABLE unit_bucket_closing (
  bucket_id   TEXT PRIMARY KEY REFERENCES buckets(id) ON DELETE CASCADE,
  closed_at   INTEGER NOT NULL
) WITHOUT ROWID;

-- The creator grant's seq K of each bucket row made from a
-- `bucket_created` record (AM-57 step 1): the finisher's
-- `bucket_binding(K)` answers `created` from it after the reservation
-- is gone (AM-56), and never fences a K whose bucket exists.
CREATE TABLE unit_bucket_grant (
  bucket_id   TEXT PRIMARY KEY REFERENCES buckets(id) ON DELETE CASCADE,
  grant_seq   INTEGER NOT NULL UNIQUE
) WITHOUT ROWID;
