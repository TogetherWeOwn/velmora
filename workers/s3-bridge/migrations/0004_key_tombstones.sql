-- The newest tombstone of each key that was ever deleted. A publication
-- must carry an id above it (and above the live generation), so that the
-- order of ids on one key is the order of commits, which is the order a
-- replay of the recovery records uses.
-- Additive only.

CREATE TABLE key_tombstones (
  bucket_id      TEXT NOT NULL REFERENCES buckets(id),
  key            TEXT NOT NULL,
  tombstone_id   TEXT NOT NULL,
  PRIMARY KEY (bucket_id, key)
) WITHOUT ROWID;
