-- Which extents make up a generation, in order. A copy is a new
-- generation that references the extents of its source, so one extent
-- can belong to several generations and is in service while any of
-- them is live. Additive only.
--
-- `extents.generation_id`, `seq` and `plain_offset` stay as written: they
-- name the generation the extent was first published in, and the outbox
-- row keeps that id. Reads and garbage collection go through this table.

-- First, and before anything is created: every live generation must have
-- exactly the extents it says it has, in distinct positions. The backfill
-- below would otherwise leave such an object short without a word. A row
-- of 0 violates the CHECK on `tx_guard` and stops the migration here.
INSERT INTO tx_guard(ok)
SELECT 0 FROM generations g
 WHERE g.state = 'live'
   AND g.extent_count <> (SELECT COUNT(DISTINCT e.seq) FROM extents e
                           WHERE e.generation_id = g.id
                             AND e.seq IS NOT NULL AND e.plain_offset IS NOT NULL);

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

-- The same older Worker retires a generation by looking only at the
-- extents first written for it. Once a copy exists that is wrong: the
-- copy still reads them. These triggers make the statements that would
-- take such an extent out of service fail instead, so the older Worker
-- answers an error and nothing is lost. Current code never reaches them:
-- it asks the same question before it writes.

-- Retiring a generation after queueing collection, or cancelling the
-- posting, of an extent another live generation references.
CREATE TRIGGER generations_keep_shared_extents BEFORE UPDATE OF state ON generations
WHEN OLD.state = 'live' AND NEW.state <> 'live' AND EXISTS (
  SELECT 1 FROM generation_extents mine
   WHERE mine.generation_id = OLD.id
     AND EXISTS (SELECT 1 FROM generation_extents other
                   JOIN generations og ON og.id = other.generation_id
                  WHERE other.extent_id = mine.extent_id
                    AND og.state = 'live' AND og.id <> OLD.id)
     AND (EXISTS (SELECT 1 FROM gc q
                   WHERE q.extent_id = mine.extent_id AND q.done_at IS NULL)
          OR EXISTS (SELECT 1 FROM outbox o
                      WHERE o.extent_id = mine.extent_id AND o.stage = 'cancelled')))
BEGIN
  SELECT RAISE(ABORT, 'extent is referenced by another live generation');
END;
CREATE INDEX gc_open_by_extent ON gc(extent_id) WHERE done_at IS NULL;

-- Shredding the key of an extent that is in service.
CREATE TRIGGER extents_keep_key_in_service BEFORE UPDATE OF wrapped_file_key ON extents
WHEN OLD.wrapped_file_key IS NOT NULL AND NEW.wrapped_file_key IS NULL AND (
  EXISTS (SELECT 1 FROM generation_extents r JOIN generations g ON g.id = r.generation_id
           WHERE r.extent_id = OLD.id AND g.state = 'live')
  OR EXISTS (SELECT 1 FROM upload_parts p JOIN uploads u ON u.id = p.upload_id
              WHERE p.extent_id = OLD.id AND u.state = 'open'))
BEGIN
  SELECT RAISE(ABORT, 'extent is in service');
END;

-- Dropping the article list of an extent that is in service.
CREATE TRIGGER articles_keep_in_service BEFORE DELETE ON articles
WHEN EXISTS (SELECT 1 FROM generation_extents r JOIN generations g ON g.id = r.generation_id
              WHERE r.extent_id = OLD.extent_id AND g.state = 'live')
  OR EXISTS (SELECT 1 FROM upload_parts p JOIN uploads u ON u.id = p.upload_id
              WHERE p.extent_id = OLD.extent_id AND u.state = 'open')
BEGIN
  SELECT RAISE(ABORT, 'extent is in service');
END;

-- Every extent already published, under the generation it was written for.
-- After the triggers, so nothing published while this runs is missed.
INSERT OR IGNORE INTO generation_extents(generation_id, seq, extent_id, plain_offset)
SELECT generation_id, seq, id, plain_offset FROM extents
 WHERE generation_id IS NOT NULL AND seq IS NOT NULL AND plain_offset IS NOT NULL;
