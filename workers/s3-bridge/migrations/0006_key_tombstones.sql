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

-- Deletes made before this table existed left their tombstone ids only in
-- the recovery records. Every key that was ever deleted gets a boundary
-- above all of them (the time of this migration plus five minutes, with
-- the highest suffix), so that the next publication of such a key sorts
-- after its old tombstones, also from a clock that runs behind.
INSERT INTO key_tombstones(bucket_id, key, tombstone_id)
SELECT bucket_id, key,
       printf('g_%013x', CAST(strftime('%s', 'now') AS INTEGER) * 1000 + 300000)
         || 'ffffffffffffffff'
  FROM generations
 WHERE state = 'deleted'
 GROUP BY bucket_id, key;
