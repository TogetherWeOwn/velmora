-- The claim a verification row was recorded under.
--
-- `lease_token`: `outbox.lease_token` of the lease the row was written
-- with. A claim bumps the token and nothing ever lowers it, so it names
-- one claim of the extent's row. The release guard counts a pass as
-- presence only when it carries the token of the lease that releases:
-- a pass of an earlier claim recorded in the same millisecond as this
-- claim was made is not this claim's. When a result at the same instant
-- replaces a row, the token is replaced with it.
--
-- NULL = a row from before this column, or from a Worker from before
-- it. Such a row is never presence for a release; it still stands as
-- the full check on record (a `body` pass), which is not bound to a
-- claim. A release whose presence a Worker from before wrote is refused
-- and asked again by the next claim. Additive only: a column, no index,
-- no row rewritten.

ALTER TABLE verifications ADD COLUMN lease_token INTEGER;
