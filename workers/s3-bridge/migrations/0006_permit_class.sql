-- Provider permits: which held slots belong to background jobs.
-- Additive only.

-- Set on every acquire: 1 = taken by a background job (post, verify,
-- repost, drill), 0 = taken by a read. A provider with an address limit
-- counts its background holders apart, so that reads in flight do not
-- use up the addresses left to jobs. Slots held when this is applied
-- count as reads until they are released or expire.
ALTER TABLE provider_permits ADD COLUMN background INTEGER NOT NULL DEFAULT 0;
