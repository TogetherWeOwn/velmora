-- Hot tier: R2 is a cache in front of Usenet. A release no longer deletes
-- the safety copy; it makes the copy evictable. A bounded job evicts the
-- least recently read evictable extents when their total exceeds the cap.
-- Additive only.

-- Bytes of this extent that R2 holds and that may be evicted:
--   hot_safety_bytes  the released safety copy (set by the release)
--   hot_cache_bytes   the cache fill (set by a cold read)
-- A pinned extent (safety_state 'held' or 'releasing') is never evicted,
-- whatever these say. Rows released before this migration had their safety
-- copy deleted by the release, so 0 is right for them.
ALTER TABLE extents ADD COLUMN hot_safety_bytes INTEGER NOT NULL DEFAULT 0;
ALTER TABLE extents ADD COLUMN hot_cache_bytes INTEGER NOT NULL DEFAULT 0;
-- Last GET that used the extent, written at most once an hour per extent.
-- A release starts it at the upload time.
ALTER TABLE extents ADD COLUMN last_read_at INTEGER;
-- Fencing token of an eviction: +1 whenever an eviction starts or ends and
-- whenever a hot copy is written or forgotten.
ALTER TABLE extents ADD COLUMN evict_seq INTEGER NOT NULL DEFAULT 0;

-- The evictable set in eviction order. It covers the byte columns, so the
-- total and the candidates are read from the index alone.
CREATE INDEX extents_evictable
  ON extents(last_read_at, id, hot_safety_bytes, hot_cache_bytes, evict_seq, safety_state)
  WHERE hot_safety_bytes + hot_cache_bytes > 0
    AND safety_state NOT IN ('held', 'releasing');

-- The pinned set, covering what the status total needs.
CREATE INDEX extents_pinned
  ON extents(cipher_size, hot_cache_bytes, safety_state)
  WHERE safety_state IN ('held', 'releasing');
