-- NOT APPLIED YET. The deploy applies `migrations/` only. Move this file
-- there in the release after the one that ships
-- `0021_ingest_indexes.sql`, once no Worker from before that release can
-- run or be rolled back to: such a Worker names `extents_held` in its
-- statements and filters `extents` by generation.
-- Its number is the next free one when it moves, after every file then
-- in `migrations/` (0023 held a place behind 0020-0022 and is taken there
-- since; the name of this file is not its number).
--
-- Contract: the indexes `extents_safety` replaced, and the one nothing
-- reads any more. Each drop takes one index entry off every extent
-- written (`extents_by_generation`: one more off every adopted part).
-- The tests run the catalogue on this schema as well.

-- Duplicated by `generation_extents`; no statement filters `extents` by
-- generation.
DROP INDEX IF EXISTS extents_by_generation;
-- Both served by `extents_safety`.
DROP INDEX IF EXISTS extents_held;
DROP INDEX IF EXISTS extents_pinned;
