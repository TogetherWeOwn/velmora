-- A release by the verify job that has just checked the extent
-- (`RELEASE_AT_VERIFY`) takes the row from `verify` to `done` in the
-- batch that releases the copy. It is a verify and a release: the
-- trigger of 0020 counted it as a verify only, so the release totals
-- (`releases_total`, the hourly `releases`) would stop counting once
-- verify jobs release.
--
-- `usage_outbox_stage` again, word for word but for the two lines that
-- count a release: now also verify -> done where the same batch set the
-- extent `released` at the row's `updated_at`. A row that goes from
-- `verify` to `done` with its copy still held (too few backbones count)
-- is a verify only, as before, and so is one whose copy was released at
-- another time.
--
-- A trigger cannot be altered, so it is dropped and created. Both
-- statements are in this one file. Rows, tables and the other triggers
-- are untouched. A Worker from before this file writes what it wrote:
-- it never moves a row from `verify` to `done` with the copy released
-- at that instant.

DROP TRIGGER usage_outbox_stage;

CREATE TRIGGER usage_outbox_stage AFTER UPDATE OF stage ON outbox
WHEN NEW.stage <> OLD.stage
BEGIN
  INSERT INTO usage_hours (hour, posts, verifies, releases, dead, failures)
    SELECT hour, h_posts, h_verifies, h_releases, h_dead, h_failures FROM usage_global
     WHERE id = 1 AND all_o = 1 AND hour > 0 AND NEW.updated_at / 3600000 > hour
       AND h_posts + h_verifies + h_releases + h_dead + h_failures > 0
    ON CONFLICT (hour) DO UPDATE SET
       posts = posts + excluded.posts, verifies = verifies + excluded.verifies,
       releases = releases + excluded.releases, dead = dead + excluded.dead,
       failures = failures + excluded.failures;
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
    releases_total = releases_total
      + ((OLD.stage = 'release' AND NEW.stage = 'done')
         OR (OLD.stage = 'verify' AND NEW.stage = 'done'
             AND EXISTS (SELECT 1 FROM extents e WHERE e.id = NEW.extent_id
                          AND e.safety_state = 'released' AND e.released_at = NEW.updated_at))),
    dead_total = dead_total + (NEW.stage = 'dead'),
    h_posts = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_posts END
      + (OLD.stage = 'post' AND NEW.stage = 'verify'),
    h_verifies = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_verifies END
      + (OLD.stage = 'verify' AND NEW.stage IN ('release', 'done')),
    h_releases = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_releases END
      + ((OLD.stage = 'release' AND NEW.stage = 'done')
         OR (OLD.stage = 'verify' AND NEW.stage = 'done'
             AND EXISTS (SELECT 1 FROM extents e WHERE e.id = NEW.extent_id
                          AND e.safety_state = 'released' AND e.released_at = NEW.updated_at))),
    h_dead = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_dead END
      + (NEW.stage = 'dead'),
    h_failures = CASE WHEN NEW.updated_at / 3600000 > hour THEN 0 ELSE h_failures END,
    hour = MAX(hour, NEW.updated_at / 3600000)
  WHERE all_o = 1 OR NEW.extent_id <= cur_o;
END;
