-- The newest tombstone of each key that was ever deleted, or an upper
-- bound of it. A publication must carry an id above it (and above the
-- live generation), so that the order of ids on one key is the order of
-- commits, which is the order a replay of the recovery records uses.
-- Additive only.

CREATE TABLE key_tombstones (
  bucket_id      TEXT NOT NULL REFERENCES buckets(id),
  key            TEXT NOT NULL,
  tombstone_id   TEXT NOT NULL,
  PRIMARY KEY (bucket_id, key)
) WITHOUT ROWID;

-- A tombstone id is minted in the millisecond of the delete or one
-- millisecond after the id of the generation it deletes, whichever is
-- later. The row of the deleted generation holds both: `retired_at` and
-- its id, whose characters 3 to 15 are the milliseconds in hex. The same
-- millisecond with the highest suffix is therefore at or above the
-- tombstone, whatever the clocks that minted the two said.

-- Deletes made before this table existed left their tombstone ids only in
-- the recovery records. Every key that was ever deleted gets a boundary
-- above all of them: the bound above, and at least the time of this
-- migration plus five minutes for a key whose deleted rows are gone.
INSERT INTO key_tombstones(bucket_id, key, tombstone_id)
SELECT bucket_id, key,
       printf('g_%013x', max(
         CAST(strftime('%s', 'now') AS INTEGER) * 1000 + 300000,
         max(COALESCE(retired_at, 0)),
         max(((instr('0123456789abcdef', substr(id, 3, 1)) - 1) * 281474976710656
          + (instr('0123456789abcdef', substr(id, 4, 1)) - 1) * 17592186044416
          + (instr('0123456789abcdef', substr(id, 5, 1)) - 1) * 1099511627776
          + (instr('0123456789abcdef', substr(id, 6, 1)) - 1) * 68719476736
          + (instr('0123456789abcdef', substr(id, 7, 1)) - 1) * 4294967296
          + (instr('0123456789abcdef', substr(id, 8, 1)) - 1) * 268435456
          + (instr('0123456789abcdef', substr(id, 9, 1)) - 1) * 16777216
          + (instr('0123456789abcdef', substr(id, 10, 1)) - 1) * 1048576
          + (instr('0123456789abcdef', substr(id, 11, 1)) - 1) * 65536
          + (instr('0123456789abcdef', substr(id, 12, 1)) - 1) * 4096
          + (instr('0123456789abcdef', substr(id, 13, 1)) - 1) * 256
          + (instr('0123456789abcdef', substr(id, 14, 1)) - 1) * 16
          + (instr('0123456789abcdef', substr(id, 15, 1)) - 1) * 1)) + 1))
         || 'ffffffffffffffff'
  FROM generations
 WHERE state = 'deleted'
 GROUP BY bucket_id, key;

-- A Worker from before this table deletes without writing a row here,
-- and it keeps serving between this migration and its replacement (and
-- after a rollback). This trigger writes the bound for every delete, so
-- such a delete is fenced too. Current code writes the exact tombstone
-- in the same batch; the bound is in the same millisecond or later.
CREATE TRIGGER key_tombstones_on_delete AFTER UPDATE OF state ON generations
WHEN NEW.state = 'deleted' AND OLD.state <> 'deleted'
BEGIN
  INSERT INTO key_tombstones(bucket_id, key, tombstone_id)
  VALUES (NEW.bucket_id, NEW.key,
          printf('g_%013x', max(
            COALESCE(NEW.retired_at, 0),
            ((instr('0123456789abcdef', substr(NEW.id, 3, 1)) - 1) * 281474976710656
          + (instr('0123456789abcdef', substr(NEW.id, 4, 1)) - 1) * 17592186044416
          + (instr('0123456789abcdef', substr(NEW.id, 5, 1)) - 1) * 1099511627776
          + (instr('0123456789abcdef', substr(NEW.id, 6, 1)) - 1) * 68719476736
          + (instr('0123456789abcdef', substr(NEW.id, 7, 1)) - 1) * 4294967296
          + (instr('0123456789abcdef', substr(NEW.id, 8, 1)) - 1) * 268435456
          + (instr('0123456789abcdef', substr(NEW.id, 9, 1)) - 1) * 16777216
          + (instr('0123456789abcdef', substr(NEW.id, 10, 1)) - 1) * 1048576
          + (instr('0123456789abcdef', substr(NEW.id, 11, 1)) - 1) * 65536
          + (instr('0123456789abcdef', substr(NEW.id, 12, 1)) - 1) * 4096
          + (instr('0123456789abcdef', substr(NEW.id, 13, 1)) - 1) * 256
          + (instr('0123456789abcdef', substr(NEW.id, 14, 1)) - 1) * 16
          + (instr('0123456789abcdef', substr(NEW.id, 15, 1)) - 1) * 1) + 1))
            || 'ffffffffffffffff')
  ON CONFLICT(bucket_id, key) DO UPDATE SET
    tombstone_id = max(tombstone_id, excluded.tombstone_id);
END;
