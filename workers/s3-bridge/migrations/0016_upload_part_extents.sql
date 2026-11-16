-- A part of a multipart upload stored as several extents. A part body
-- above one extent is cut into slices, each its own staged extent.
-- `upload_parts` keeps one row per part: the size and the ETag of the
-- whole part, and in `extent_id` the first slice. The slices after the
-- first are named here, in body order. A part of one extent has no row
-- in this table, so nothing changes for it.
--
-- Rollback: a build older than this table sees only the first slice of
-- such a part. Its Complete is refused by its own size guard, and its
-- Abort leaves the other slices staged. Before deploying an older build,
-- complete or abort the uploads this query lists:
--   SELECT DISTINCT u.id, u.bucket_id, u.key FROM upload_part_extents x
--     JOIN uploads u ON u.id = x.upload_id WHERE u.state = 'open';
-- Additive only.

CREATE TABLE upload_part_extents (
  upload_id   TEXT NOT NULL REFERENCES uploads(id),
  part_number INTEGER NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
  piece       INTEGER NOT NULL CHECK (piece >= 1),  -- order within the part; 0 is upload_parts.extent_id
  tenant_id   TEXT NOT NULL DEFAULT 't_0000000000000000',  -- the default tenant
  extent_id   TEXT NOT NULL REFERENCES extents(id),
  PRIMARY KEY (upload_id, part_number, piece)
) WITHOUT ROWID;
CREATE INDEX upload_part_extents_by_extent ON upload_part_extents(extent_id);

-- The two triggers of 0005 that keep an extent of an open upload in
-- service, extended to the slices named above.

DROP TRIGGER extents_keep_key_in_service;
CREATE TRIGGER extents_keep_key_in_service BEFORE UPDATE OF wrapped_file_key ON extents
WHEN OLD.wrapped_file_key IS NOT NULL AND NEW.wrapped_file_key IS NULL AND (
  EXISTS (SELECT 1 FROM generation_extents r JOIN generations g ON g.id = r.generation_id
           WHERE r.extent_id = OLD.id AND g.state = 'live')
  OR EXISTS (SELECT 1 FROM upload_parts p JOIN uploads u ON u.id = p.upload_id
              WHERE p.extent_id = OLD.id AND u.state = 'open')
  OR EXISTS (SELECT 1 FROM upload_part_extents p JOIN uploads u ON u.id = p.upload_id
              WHERE p.extent_id = OLD.id AND u.state = 'open'))
BEGIN
  SELECT RAISE(ABORT, 'extent is in service');
END;

DROP TRIGGER articles_keep_in_service;
CREATE TRIGGER articles_keep_in_service BEFORE DELETE ON articles
WHEN EXISTS (SELECT 1 FROM generation_extents r JOIN generations g ON g.id = r.generation_id
              WHERE r.extent_id = OLD.extent_id AND g.state = 'live')
  OR EXISTS (SELECT 1 FROM upload_parts p JOIN uploads u ON u.id = p.upload_id
              WHERE p.extent_id = OLD.extent_id AND u.state = 'open')
  OR EXISTS (SELECT 1 FROM upload_part_extents p JOIN uploads u ON u.id = p.upload_id
              WHERE p.extent_id = OLD.extent_id AND u.state = 'open')
BEGIN
  SELECT RAISE(ABORT, 'extent is in service');
END;
