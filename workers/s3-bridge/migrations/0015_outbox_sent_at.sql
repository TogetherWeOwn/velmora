-- When the cron dispatcher last sent a queue job for this outbox row, in
-- ms. NULL = it has not, or a job has claimed the row since.
-- The dispatcher sends a due row once and marks it here; it sends the
-- row again only when a job claimed it meanwhile (the claim clears the
-- mark), when the row was given a later due time than the mark, or when
-- the mark is older than the resend timeout (the message was lost).
-- The mark is a hint for the dispatcher alone. It gates no claim and no
-- release: a row with a mark is claimed like any other.
-- Not indexed: an update of the mark writes one row.
-- A Worker from before this column neither reads nor writes it: it can
-- run on this schema.
-- Additive only.

ALTER TABLE outbox ADD COLUMN sent_at INTEGER;
