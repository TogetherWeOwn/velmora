-- Standalone yEnc articles: each article's own random yEnc name.
-- Additive only.

-- Set when a plan is made: the article is posted as one single-part
-- yEnc file under this name, with `size=` and `crc32=` of its own
-- payload and no part numbers, so nothing on the wire ties the articles
-- of one extent together or shows the extent's size.
-- NULL: a row planned before this migration. It keeps the multi-part
-- form it was posted in (part numbers, the extent size, the name taken
-- from the message-id), so a repost of it stays byte-identical.
-- A Worker from before this migration neither writes nor reads the
-- column: after a rollback to one, its new plans are NULL rows in the
-- old form, and it would repost a non-NULL row in the old form. The
-- payload bytes, and so every read and verify, are the same either way.
ALTER TABLE articles ADD COLUMN yenc_name TEXT
  CHECK (yenc_name IS NULL OR (length(yenc_name) BETWEEN 1 AND 64 AND yenc_name NOT GLOB '*[^0-9a-z]*'));
