-- Replaces the trigger of migration 0005 that keeps the article rows of
-- an extent in service.
--
-- The article rows of an extent in service may go once its plan is
-- packed: they are a copy of what the extent's row holds. For an extent
-- whose plan is not packed the rule is the one of migration 0005, word
-- for word, so a Worker from before this migration (it packs nothing)
-- finds what it found.
--
-- A trigger cannot be altered, and no second trigger can let through
-- what the first one aborts, so the old one is dropped. It is dropped
-- after its replacement exists, under another name: the rows are
-- covered after every statement of this file, however it is applied.
CREATE TRIGGER articles_keep_unpacked_in_service BEFORE DELETE ON articles
WHEN (SELECT plan FROM extents WHERE id = OLD.extent_id) IS NULL
 AND (EXISTS (SELECT 1 FROM generation_extents r JOIN generations g ON g.id = r.generation_id
               WHERE r.extent_id = OLD.extent_id AND g.state = 'live')
   OR EXISTS (SELECT 1 FROM upload_parts p JOIN uploads u ON u.id = p.upload_id
               WHERE p.extent_id = OLD.extent_id AND u.state = 'open'))
BEGIN
  SELECT RAISE(ABORT, 'extent is in service');
END;
DROP TRIGGER articles_keep_in_service;

-- The packed plan of an extent in service stays, as its key does and as
-- its article rows did: without it the articles cannot be found.
CREATE TRIGGER extents_keep_plan_in_service BEFORE UPDATE OF plan ON extents
WHEN OLD.plan IS NOT NULL AND NEW.plan IS NULL
 AND (EXISTS (SELECT 1 FROM generation_extents r JOIN generations g ON g.id = r.generation_id
               WHERE r.extent_id = OLD.id AND g.state = 'live')
   OR EXISTS (SELECT 1 FROM upload_parts p JOIN uploads u ON u.id = p.upload_id
               WHERE p.extent_id = OLD.id AND u.state = 'open'))
BEGIN
  SELECT RAISE(ABORT, 'extent is in service');
END;

-- `articles.message_id` is UNIQUE over the rows only: no constraint
-- compares the message-ids of packed plans. They are drawn from 128
-- random bits per article (a seeded plan: from a 128-bit seed), as they
-- always were, and nothing reads a plan by message-id.
