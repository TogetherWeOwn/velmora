-- How a verification row checked the articles: `body` = every article was
-- read back and its payload hash compared (the full check); `stat` = the
-- provider only said that it has them. A release needs a `body` pass on
-- one backbone; `stat` passes complete the count on the others and are
-- never the full check.
-- Every row from before this column was a `BODY` read, hence the default.
-- A Worker from before this column writes only `BODY` reads, and its
-- inserts take the default: it can run on this schema.
-- Additive only.

ALTER TABLE verifications ADD COLUMN kind TEXT NOT NULL DEFAULT 'body'
  CHECK (kind IN ('body','stat'));
