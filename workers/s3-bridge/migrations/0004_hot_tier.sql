-- Hot tier: R2 is a cache in front of Usenet. A release no longer deletes
-- the safety copy; it makes the copy evictable. A bounded job evicts the
-- least recently read evictable extents when their total exceeds the cap.
-- Additive only.

-- Bytes of this extent that R2 holds and that may be evicted:
--   hot_safety_bytes  the released safety copy (set by the release)
--   hot_cache_bytes   the cache fill (set by a cold read, or by a read
--                     served from a fill that was not counted)
-- The safety copy of a pinned extent (safety_state 'held' or 'releasing')
-- is never evicted, whatever these say. A cache fill is always evictable:
-- it only ever comes from a verified read from Usenet.
-- Rows released before this migration had their safety copy deleted by
-- the release, so 0 is right for them. Cache fills from before this
-- migration start uncounted; a read served from one counts it.
ALTER TABLE extents ADD COLUMN hot_safety_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE extents ADD COLUMN hot_cache_bytes INTEGER NOT NULL DEFAULT 0;
-- Last GET that used the extent, written at most once an hour per extent.
-- A release starts it at the upload time.
ALTER TABLE extents ADD COLUMN last_read_at INTEGER;
-- Fencing token of an eviction: +1 whenever an eviction starts or ends,
-- whenever a hot copy is written or forgotten, and whenever safety_state
-- changes.
ALTER TABLE extents ADD COLUMN evict_seq INTEGER NOT NULL DEFAULT 0;

-- The extents with evictable bytes, in eviction order. It covers what the
-- total and the candidate list read, so both use the index alone.
CREATE INDEX extents_evictable
  ON extents(last_read_at, id, hot_safety_bytes, hot_cache_bytes, evict_seq, safety_state)
  WHERE (hot_cache_bytes > 0
         OR (hot_safety_bytes > 0 AND safety_state NOT IN ('held', 'releasing')));

-- The pinned set, covering what the status total needs.
CREATE INDEX extents_pinned
  ON extents(cipher_size, safety_state)
  WHERE safety_state IN ('held', 'releasing');
