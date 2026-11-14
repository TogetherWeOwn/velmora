-- Which extents make up a generation, in order. A copy is a new
-- generation that references the extents of its source, so one extent
-- can belong to several generations and is in service while any of
-- them is live. Additive only.
--
-- `extents.generation_id`, `seq` and `plain_offset` stay as written: they
-- name the generation the extent was first published in, and the outbox
-- row keeps that id. Reads and garbage collection go through this table.

CREATE TABLE generation_extents (
  generation_id  TEXT NOT NULL REFERENCES generations(id),
  seq            INTEGER NOT NULL,                -- order within the generation
  extent_id      TEXT NOT NULL REFERENCES extents(id),
  plain_offset   INTEGER NOT NULL,                -- where the extent starts in the object
  PRIMARY KEY (generation_id, seq)
) WITHOUT ROWID;
CREATE INDEX generation_extents_by_extent ON generation_extents(extent_id);

-- "Does an open upload name this extent" is asked for every extent of a
-- retired generation and by every garbage-collection step.
CREATE INDEX upload_parts_by_extent ON upload_parts(extent_id);

-- Every extent already published, under the generation it was written for.
INSERT OR IGNORE INTO generation_extents(generation_id, seq, extent_id, plain_offset)
SELECT generation_id, seq, id, plain_offset FROM extents
 WHERE generation_id IS NOT NULL AND seq IS NOT NULL AND plain_offset IS NOT NULL;

-- A Worker version from before this migration publishes through the
-- `extents` columns alone. It can run while this migration is applied
-- and again after a rollback, so the database records the reference for
-- it: once when a committed extent is inserted (single PUT), once when a
-- staged part is adopted (multipart Complete). Current code writes the
-- same row itself; `OR IGNORE` makes the two agree.
--
-- That covers what an older Worker writes. It does not make a copy
-- readable by one: an older Worker sees a copy as a generation without
-- extents and treats the source's extents as the source's alone. Copies
-- are therefore not created until `SERVER_SIDE_COPY` is turned on, in a
-- release after the one that ships this migration.
CREATE TRIGGER generation_extents_on_insert AFTER INSERT ON extents
WHEN NEW.generation_id IS NOT NULL AND NEW.seq IS NOT NULL AND NEW.plain_offset IS NOT NULL
BEGIN
  INSERT OR IGNORE INTO generation_extents(generation_id, seq, extent_id, plain_offset)
  VALUES (NEW.generation_id, NEW.seq, NEW.id, NEW.plain_offset);
END;

CREATE TRIGGER generation_extents_on_adopt AFTER UPDATE OF generation_id ON extents
WHEN OLD.generation_id IS NULL AND NEW.generation_id IS NOT NULL
  AND NEW.seq IS NOT NULL AND NEW.plain_offset IS NOT NULL
BEGIN
  INSERT OR IGNORE INTO generation_extents(generation_id, seq, extent_id, plain_offset)
  VALUES (NEW.generation_id, NEW.seq, NEW.id, NEW.plain_offset);
END;
