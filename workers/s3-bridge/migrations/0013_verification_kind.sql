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

-- The articles a `stat` row found present. A `stat` row keeps
-- `articles_ok` at 0 and counts here instead, so a reader from before
-- this migration, which takes `articles_ok = articles_total` for a full
-- read-back, never takes a `stat` pass for one (after a rollback of the
-- Worker, for example). A `body` row keeps this at 0.
ALTER TABLE verifications ADD COLUMN articles_present INTEGER NOT NULL DEFAULT 0;
