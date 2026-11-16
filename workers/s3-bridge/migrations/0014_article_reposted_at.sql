-- When an article was last posted again after its first post (a repost
-- to a backbone that lacked it), in ms. NULL = never posted again.
-- `posted_at` stays the time of the first post: the retention of the
-- provider that took it counts from there.
-- The minimum age of a safety copy counts from the newest of the two
-- over all the articles of its extent, so a release never follows a
-- post, or a repost, by less than the minimum age.
-- A Worker from before this column neither reads nor writes it: it can
-- run on this schema.
-- Additive only.

ALTER TABLE articles ADD COLUMN reposted_at INTEGER;
