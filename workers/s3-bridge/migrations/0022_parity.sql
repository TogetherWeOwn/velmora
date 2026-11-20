-- Repair parity of an extent: a few extra articles, computed over the
-- extent's own articles, from which lost articles can be rebuilt.
--
-- `parity`: the parity addendum, beside the packed plan (`plan`), which
-- it does not change: the row numbers and payload hashes of the parity
-- articles and the seed their identifiers are derived from. NULL = the
-- extent has no parity. Only an extent with a packed plan has one. No
-- row is written per parity article.
-- `parity_count`: how many parity articles the addendum plans. NULL = no
-- parity. A plan with parity is posted as a whole: `posted_at` is stamped
-- by a write that lists `article_count + parity_count` articles.
--
-- A Worker from before these columns neither reads nor writes them, and
-- reads every plan as before. If it posts or releases an extent that has
-- an addendum it leaves the parity articles out, and a recovery record
-- it writes for the extent has the plan without the addendum; the
-- addendum stays on the row. Verification with these columns reads the
-- data articles only: it does not find a parity article that is missing,
-- and nothing posts one again. An extent whose parity articles were
-- never posted keeps its addendum: reads find no parity for it. Its
-- data is as safe as without parity. Additive only.

ALTER TABLE extents ADD COLUMN parity BLOB;
ALTER TABLE extents ADD COLUMN parity_count INTEGER;
