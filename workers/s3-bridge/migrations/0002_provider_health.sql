-- Provider pool: health with cooldown and pool-shared connection limits.
-- Additive only.

CREATE TABLE provider_health (                    -- one row per provider that ever failed
  provider_id     TEXT PRIMARY KEY,
  failures        INTEGER NOT NULL DEFAULT 0,     -- failed sessions in a row; 0 after a good one or a cooldown
  cooldowns       INTEGER NOT NULL DEFAULT 0,     -- cooldowns in a row; each doubles the next
  cooldown_until  INTEGER NOT NULL DEFAULT 0,     -- skipped until then; 0 = not cooling
  last_failure_at INTEGER,
  last_ok_at      INTEGER
) WITHOUT ROWID;

-- The pool a held slot counts against (set on every acquire; NULL = none).
ALTER TABLE provider_permits ADD COLUMN pool TEXT;
