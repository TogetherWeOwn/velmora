-- Replaces the trigger of migration 0005 that keeps the article rows of
-- an extent in service.
--
-- The article rows of an extent in service may go once its plan is
-- packed: they are a copy of what the extent's row holds.
DROP TRIGGER articles_keep_in_service;
CREATE TRIGGER articles_keep_in_service BEFORE DELETE ON articles
WHEN (SELECT plan FROM extents WHERE id = OLD.extent_id) IS NULL
 AND (EXISTS (SELECT 1 FROM generation_extents r JOIN generations g ON g.id = r.generation_id
               WHERE r.extent_id = OLD.extent_id AND g.state = 'live')
   OR EXISTS (SELECT 1 FROM upload_parts p JOIN uploads u ON u.id = p.upload_id
               WHERE p.extent_id = OLD.extent_id AND u.state = 'open'))
BEGIN
  SELECT RAISE(ABORT, 'extent is in service');
END;
