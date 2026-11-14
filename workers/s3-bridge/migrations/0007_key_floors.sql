-- The floor of a key: the highest id a recovery record of the key was
-- stored under while no live generation carries it. That is the
-- tombstone of a delete (also of one that found nothing left to delete),
-- or the record of a write that was not published: its batch failed, or
-- it was refused and its record could not be removed. The Worker raises
-- the floor in a statement of its own before it stores a record, and a
-- publication must carry an id above the live generation and not below
-- the floor. The order of ids on one key is then the order of its
-- records, which is the order a replay of them uses. A publication
-- removes the floor it stands on: the live generation holds the line
-- from there.
-- `unpublished` = a generation record was stored under this floor or
-- below it since the last tombstone of the key. It may never have been
-- published, and then a replay would publish it. A DeleteObject that
-- finds nothing live writes a tombstone all the same while this is set,
-- and a tombstone at or above the floor clears it.
-- Additive only.

CREATE TABLE key_floors (
  bucket_id      TEXT NOT NULL REFERENCES buckets(id),
  key            TEXT NOT NULL,
  floor_id       TEXT NOT NULL,
  unpublished    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket_id, key)
) WITHOUT ROWID;

-- A Worker from before this table minted a tombstone id in the
-- millisecond of the delete or one millisecond after the id of the
-- generation it deleted, whichever was later. The row of the deleted generation holds both: `retired_at` and
-- its id, whose characters 3 to 15 are the milliseconds in hex. The same
-- millisecond with the highest suffix is therefore at or above the
-- tombstone, whatever the clocks that minted the two said.

-- Deletes made before this table existed left their tombstone ids only in
-- the recovery records. Every key that has a deleted generation row gets
-- a floor above all of its tombstones: the bound above, and at least the
-- time of this migration plus five minutes, for a Worker whose clock is
-- ahead of the database's. Nothing removes generation rows today; a key
-- without one gets no floor here. Records of writes that failed before
-- this migration get none either.
INSERT INTO key_floors(bucket_id, key, floor_id)
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
-- such a delete is fenced too. Current code raises the floor to the
-- exact tombstone before the delete; the row keeps the higher of the two.
CREATE TRIGGER key_floors_on_delete AFTER UPDATE OF state ON generations
WHEN NEW.state = 'deleted' AND OLD.state <> 'deleted'
BEGIN
  INSERT INTO key_floors(bucket_id, key, floor_id)
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
    floor_id = max(floor_id, excluded.floor_id);
END;
