-- Usage counters: what the status page and the dashboard read instead of
-- scanning `extents`, `outbox` and `generations`.
--
-- Additive only: four new tables and ten triggers. Nothing here reads
-- or rewrites an existing table, so the migration costs the same on an
-- empty catalogue and on a full one.
--
-- How the counters stay right
--   Every counter is moved by a trigger, in the same statement as the
--   row change it counts. A batch that rolls back takes the counter
--   change with it, and two concurrent batches cannot interleave inside
--   a statement, so the counters cannot drift from the tables by a lost
--   or a doubled update.
--
-- Coverage (why the migration needs no backfill)
--   `usage_global` has two rows: 1 is the live counters, 2 is the
--   shadow of a recount in progress. Each row covers a table either
--   wholly (`all_*` = 1) or up to a cursor (`cur_*`, ids at or below
--   it). A trigger moves a row only for an id that row covers.
--   As migrated, both rows cover nothing: every trigger's statement
--   matches zero rows and writes nothing, and the number of rows a
--   statement reports as changed is what it was before this migration.
--   An older Worker therefore runs on this schema unchanged.
--   The counters are switched on by a recount (a paged job, driven by
--   `POST /_admin/usage/recount` and the cron): it counts the tables in
--   id order into row 2, a bounded chunk per statement, while the
--   triggers keep the part already counted current; when all three
--   tables are counted, row 2 is copied to row 1 in one batch.
--   Later recounts compare row 2 with row 1 and record the difference
--   in `usage_recounts`; they change row 1 only when asked to.
--
-- Rolling back past this migration once the counters are on
--   A trigger that writes adds to the changed-row count of its
--   statement. A Worker older than this migration checks some of those
--   counts for exactly one row. Before deploying such a Worker, switch
--   the counters off (`POST /_admin/usage/off`, or the statement
--   below); the triggers then write nothing again.
--     UPDATE usage_global SET all_x = 0, all_o = 0, all_g = 0,
--            cur_x = '', cur_o = '', cur_g = '', pass = 0;
--
-- No CHECK (>= 0) on any counter: a counter must never refuse a write
-- of the data path. A wrong counter is found by the recount.

CREATE TABLE usage_global (
  id             INTEGER PRIMARY KEY CHECK (id IN (1, 2)),  -- 1 live, 2 recount
  -- coverage
  cur_x          TEXT NOT NULL DEFAULT '',     -- extents counted up to this id
  all_x          INTEGER NOT NULL DEFAULT 0,
  cur_o          TEXT NOT NULL DEFAULT '',     -- outbox, by extent_id
  all_o          INTEGER NOT NULL DEFAULT 0,
  cur_g          TEXT NOT NULL DEFAULT '',     -- generations
  all_g          INTEGER NOT NULL DEFAULT 0,
  -- extents by safety state; unreleased = held or releasing (pinned)
  x_unreleased   INTEGER NOT NULL DEFAULT 0,
  unreleased_bytes INTEGER NOT NULL DEFAULT 0, -- SUM(cipher_size)
  x_released     INTEGER NOT NULL DEFAULT 0,
  released_bytes INTEGER NOT NULL DEFAULT 0,
  x_deleted      INTEGER NOT NULL DEFAULT 0,
  -- outbox rows by stage
  ob_post        INTEGER NOT NULL DEFAULT 0,
  ob_verify      INTEGER NOT NULL DEFAULT 0,
  ob_release     INTEGER NOT NULL DEFAULT 0,
  ob_done        INTEGER NOT NULL DEFAULT 0,
  ob_cancelled   INTEGER NOT NULL DEFAULT 0,
  ob_dead        INTEGER NOT NULL DEFAULT 0,
  -- events since the counters were switched on (row 1 only is read)
  posts_total    INTEGER NOT NULL DEFAULT 0,
  verifies_total INTEGER NOT NULL DEFAULT 0,
  releases_total INTEGER NOT NULL DEFAULT 0,
  dead_total     INTEGER NOT NULL DEFAULT 0,
  failures_total INTEGER NOT NULL DEFAULT 0,
  -- events of the current hour (hour = UnixMs / 3600000)
  hour           INTEGER NOT NULL DEFAULT 0,
  h_posts        INTEGER NOT NULL DEFAULT 0,
  h_verifies     INTEGER NOT NULL DEFAULT 0,
  h_releases     INTEGER NOT NULL DEFAULT 0,
  h_dead         INTEGER NOT NULL DEFAULT 0,
  h_failures     INTEGER NOT NULL DEFAULT 0,
  -- the recount in progress (row 2 only)
  pass           INTEGER NOT NULL DEFAULT 0,   -- 1 while a recount runs
  started_at     INTEGER NOT NULL DEFAULT 0,
  rows_seen      INTEGER NOT NULL DEFAULT 0,
  adopt          INTEGER NOT NULL DEFAULT 0    -- 1 = copy to row 1 at the end
);
INSERT INTO usage_global (id) VALUES (1), (2);

-- Completed hours, one row each, written when the first event of a later
-- hour arrives.
CREATE TABLE usage_hours (
  hour           INTEGER PRIMARY KEY,          -- UnixMs / 3600000
  posts          INTEGER NOT NULL,
  verifies       INTEGER NOT NULL,
  releases       INTEGER NOT NULL,
  dead           INTEGER NOT NULL,
  failures       INTEGER NOT NULL
);

-- Live objects and their plaintext bytes per bucket. kind 1 = live
-- counters, kind 2 = the recount in progress. No foreign key: a counter
-- row must never stop a bucket from being dropped.
CREATE TABLE usage_buckets (
  kind           INTEGER NOT NULL,
  bucket_id      TEXT NOT NULL,
  live_objects   INTEGER NOT NULL DEFAULT 0,
  live_bytes     INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (kind, bucket_id)
) WITHOUT ROWID;

-- One row per finished recount: what it found against the live counters.
CREATE TABLE usage_recounts (
  id             INTEGER PRIMARY KEY,
  started_at     INTEGER NOT NULL,
  finished_at    INTEGER NOT NULL,
  rows           INTEGER NOT NULL,             -- table rows counted
  adopted        INTEGER NOT NULL,             -- 1 = row 1 was replaced
  drift          INTEGER NOT NULL,             -- counters that differed
  detail         TEXT                          -- JSON, live and recount values
);

-- extents -------------------------------------------------------------

CREATE TRIGGER usage_extents_insert AFTER INSERT ON extents
BEGIN
  UPDATE usage_global SET
    x_unreleased = x_unreleased + (NEW.safety_state IN ('held', 'releasing')),
    unreleased_bytes = unreleased_bytes
      + CASE WHEN NEW.safety_state IN ('held', 'releasing') THEN NEW.cipher_size ELSE 0 END,
    x_released = x_released + (NEW.safety_state = 'released'),
    released_bytes = released_bytes
      + CASE WHEN NEW.safety_state = 'released' THEN NEW.cipher_size ELSE 0 END,
    x_deleted = x_deleted + (NEW.safety_state = 'deleted')
  WHERE all_x = 1 OR NEW.id <= cur_x;
END;

-- held <-> releasing stays inside one counter and writes nothing.
CREATE TRIGGER usage_extents_update AFTER UPDATE OF safety_state, cipher_size ON extents
WHEN (NEW.safety_state IN ('held', 'releasing')) <> (OLD.safety_state IN ('held', 'releasing'))
  OR (NEW.safety_state = 'released') <> (OLD.safety_state = 'released')
  OR NEW.cipher_size <> OLD.cipher_size
BEGIN
  UPDATE usage_global SET
    x_unreleased = x_unreleased
      + (NEW.safety_state IN ('held', 'releasing')) - (OLD.safety_state IN ('held', 'releasing')),
    unreleased_bytes = unreleased_bytes
      + CASE WHEN NEW.safety_state IN ('held', 'releasing') THEN NEW.cipher_size ELSE 0 END
      - CASE WHEN OLD.safety_state IN ('held', 'releasing') THEN OLD.cipher_size ELSE 0 END,
    x_released = x_released + (NEW.safety_state = 'released') - (OLD.safety_state = 'released'),
    released_bytes = released_bytes
      + CASE WHEN NEW.safety_state = 'released' THEN NEW.cipher_size ELSE 0 END
      - CASE WHEN OLD.safety_state = 'released' THEN OLD.cipher_size ELSE 0 END,
    x_deleted = x_deleted + (NEW.safety_state = 'deleted') - (OLD.safety_state = 'deleted')
  WHERE all_x = 1 OR NEW.id <= cur_x;
END;

CREATE TRIGGER usage_extents_delete AFTER DELETE ON extents
BEGIN
  UPDATE usage_global SET
    x_unreleased = x_unreleased - (OLD.safety_state IN ('held', 'releasing')),
    unreleased_bytes = unreleased_bytes
      - CASE WHEN OLD.safety_state IN ('held', 'releasing') THEN OLD.cipher_size ELSE 0 END,
    x_released = x_released - (OLD.safety_state = 'released'),
    released_bytes = released_bytes
      - CASE WHEN OLD.safety_state = 'released' THEN OLD.cipher_size ELSE 0 END,
    x_deleted = x_deleted - (OLD.safety_state = 'deleted')
  WHERE all_x = 1 OR OLD.id <= cur_x;
END;

-- outbox --------------------------------------------------------------

CREATE TRIGGER usage_outbox_insert AFTER INSERT ON outbox
BEGIN
  UPDATE usage_global SET
    ob_post = ob_post + (NEW.stage = 'post'),
    ob_verify = ob_verify + (NEW.stage = 'verify'),
    ob_release = ob_release + (NEW.stage = 'release'),
    ob_done = ob_done + (NEW.stage = 'done'),
    ob_cancelled = ob_cancelled + (NEW.stage = 'cancelled'),
    ob_dead = ob_dead + (NEW.stage = 'dead')
  WHERE all_o = 1 OR NEW.extent_id <= cur_o;
END;

-- A stage change moves the row between two stage counters and may be an
-- event: post -> verify is a post, verify -> release or done a verify,
-- release -> done a release, anything -> dead a burial. The first event
-- of a new hour files the hour that ended.
CREATE TRIGGER usage_outbox_stage AFTER UPDATE OF stage ON outbox
WHEN NEW.stage <> OLD.stage
BEGIN
  INSERT OR IGNORE INTO usage_hours (hour, posts, verifies, releases, dead, failures)
    SELECT hour, h_posts, h_verifies, h_releases, h_dead, h_failures FROM usage_global
     WHERE id = 1 AND all_o = 1 AND hour > 0 AND NEW.updated_at / 3600000 > hour
       AND h_posts + h_verifies + h_releases + h_dead + h_failures > 0;
  UPDATE usage_global SET
    ob_post = ob_post + (NEW.stage = 'post') - (OLD.stage = 'post'),
    ob_verify = ob_verify + (NEW.stage = 'verify') - (OLD.stage = 'verify'),
    ob_release = ob_release + (NEW.stage = 'release') - (OLD.stage = 'release'),
    ob_done = ob_done + (NEW.stage = 'done') - (OLD.stage = 'done'),
    ob_cancelled = ob_cancelled + (NEW.stage = 'cancelled') - (OLD.stage = 'cancelled'),
    ob_dead = ob_dead + (NEW.stage = 'dead') - (OLD.stage = 'dead'),
    posts_total = posts_total + (OLD.stage = 'post' AND NEW.stage = 'verify'),
    verifies_total = verifies_total
      + (OLD.stage = 'verify' AND NEW.stage IN ('release', 'done')),
    releases_total = releases_total + (OLD.stage = 'release' AND NEW.stage = 'done'),
    dead_total = dead_total + (NEW.stage = 'dead'),
    h_posts = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_posts END
      + (OLD.stage = 'post' AND NEW.stage = 'verify'),
    h_verifies = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_verifies END
      + (OLD.stage = 'verify' AND NEW.stage IN ('release', 'done')),
    h_releases = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_releases END
      + (OLD.stage = 'release' AND NEW.stage = 'done'),
    h_dead = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_dead END
      + (NEW.stage = 'dead'),
    h_failures = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_failures END,
    hour = MAX(hour, NEW.updated_at / 3600000)
  WHERE all_o = 1 OR NEW.extent_id <= cur_o;
END;

-- A failed attempt: `last_error` is set and the stage stays.
CREATE TRIGGER usage_outbox_failure AFTER UPDATE OF last_error ON outbox
WHEN NEW.last_error IS NOT NULL AND NEW.stage = OLD.stage
BEGIN
  INSERT OR IGNORE INTO usage_hours (hour, posts, verifies, releases, dead, failures)
    SELECT hour, h_posts, h_verifies, h_releases, h_dead, h_failures FROM usage_global
     WHERE id = 1 AND all_o = 1 AND hour > 0 AND NEW.updated_at / 3600000 > hour
       AND h_posts + h_verifies + h_releases + h_dead + h_failures > 0;
  UPDATE usage_global SET
    failures_total = failures_total + 1,
    h_posts = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_posts END,
    h_verifies = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_verifies END,
    h_releases = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_releases END,
    h_dead = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_dead END,
    h_failures = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_failures END + 1,
    hour = MAX(hour, NEW.updated_at / 3600000)
  WHERE all_o = 1 OR NEW.extent_id <= cur_o;
END;

CREATE TRIGGER usage_outbox_delete AFTER DELETE ON outbox
BEGIN
  UPDATE usage_global SET
    ob_post = ob_post - (OLD.stage = 'post'),
    ob_verify = ob_verify - (OLD.stage = 'verify'),
    ob_release = ob_release - (OLD.stage = 'release'),
    ob_done = ob_done - (OLD.stage = 'done'),
    ob_cancelled = ob_cancelled - (OLD.stage = 'cancelled'),
    ob_dead = ob_dead - (OLD.stage = 'dead')
  WHERE all_o = 1 OR OLD.extent_id <= cur_o;
END;

-- generations ---------------------------------------------------------
-- One upsert per covering row of `usage_global` (its id is the kind).

CREATE TRIGGER usage_generations_insert AFTER INSERT ON generations
WHEN NEW.state = 'live'
BEGIN
  INSERT INTO usage_buckets (kind, bucket_id, live_objects, live_bytes)
    SELECT u.id, NEW.bucket_id, 1, NEW.size FROM usage_global u
     WHERE u.all_g = 1 OR NEW.id <= u.cur_g
  ON CONFLICT (kind, bucket_id) DO UPDATE SET
    live_objects = live_objects + excluded.live_objects,
    live_bytes = live_bytes + excluded.live_bytes;
END;

CREATE TRIGGER usage_generations_update AFTER UPDATE OF state, size, bucket_id ON generations
WHEN (NEW.state = 'live') <> (OLD.state = 'live')
  OR (NEW.state = 'live' AND (NEW.size <> OLD.size OR NEW.bucket_id <> OLD.bucket_id))
BEGIN
  INSERT INTO usage_buckets (kind, bucket_id, live_objects, live_bytes)
    SELECT u.id, OLD.bucket_id, -1, -OLD.size FROM usage_global u
     WHERE OLD.state = 'live' AND (u.all_g = 1 OR OLD.id <= u.cur_g)
  ON CONFLICT (kind, bucket_id) DO UPDATE SET
    live_objects = live_objects + excluded.live_objects,
    live_bytes = live_bytes + excluded.live_bytes;
  INSERT INTO usage_buckets (kind, bucket_id, live_objects, live_bytes)
    SELECT u.id, NEW.bucket_id, 1, NEW.size FROM usage_global u
     WHERE NEW.state = 'live' AND (u.all_g = 1 OR NEW.id <= u.cur_g)
  ON CONFLICT (kind, bucket_id) DO UPDATE SET
    live_objects = live_objects + excluded.live_objects,
    live_bytes = live_bytes + excluded.live_bytes;
END;

CREATE TRIGGER usage_generations_delete AFTER DELETE ON generations
WHEN OLD.state = 'live'
BEGIN
  INSERT INTO usage_buckets (kind, bucket_id, live_objects, live_bytes)
    SELECT u.id, OLD.bucket_id, -1, -OLD.size FROM usage_global u
     WHERE u.all_g = 1 OR OLD.id <= u.cur_g
  ON CONFLICT (kind, bucket_id) DO UPDATE SET
    live_objects = live_objects + excluded.live_objects,
    live_bytes = live_bytes + excluded.live_bytes;
END;
