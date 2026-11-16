-- The article plan of an extent as one value on its row, instead of one
-- `articles` row per article.
--
-- `plan`: the packed plan. NULL = the extent has no plan, or its plan is
-- still rows in `articles`. Once it is set it is the plan: rows of the
-- extent that are still in `articles` are not read.
-- `posted_at`: when the last article of a packed plan was posted, in ms.
-- A packed plan is posted as a whole: NULL = not posted, 0 = posted at a
-- time nobody knows (a catalogue restored for an extent whose pinned copy
-- is gone).
-- `reposted_at`: when an article of a packed plan was last posted again
-- (a repost to a backbone that lacked it), in ms. NULL = never. As with
-- `articles.reposted_at`, the minimum age of the safety copy counts from
-- the newer of the two.
--
-- A Worker from before these columns neither reads nor writes them: it
-- can run on this schema as long as no plan was packed. It cannot read a
-- packed plan, so plans are packed only once every Worker reads them.
-- Additive only.

ALTER TABLE extents ADD COLUMN plan BLOB;
ALTER TABLE extents ADD COLUMN posted_at INTEGER;
ALTER TABLE extents ADD COLUMN reposted_at INTEGER;
