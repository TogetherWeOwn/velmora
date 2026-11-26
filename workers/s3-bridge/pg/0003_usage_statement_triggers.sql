-- PostgreSQL only: the usage counters (D1 migrations 0020 and 0025) move
-- once per statement instead of once per changed row.
--
-- PostgreSQL writes a new version of a row for every UPDATE, and a
-- transaction cannot prune the versions it created itself. A per-row
-- counter trigger therefore walks about i versions of the same counter row
-- on its i-th firing: N changed rows in one transaction cost O(N^2). These
-- statement triggers aggregate the changed rows once (transition tables)
-- and write each counter row at most once per statement.
--
-- Contract: after every statement the counters equal the D1 per-row
-- triggers' values. Within one statement, outbox events are applied in
-- ascending hour order (failures and stage changes alike). Every app
-- statement uses a single hour; for a statement that mixes hours, row
-- order is undefined in both engines and this rule makes the result
-- unique. Zero-row statements and rows outside the counters' coverage
-- write and lock nothing.

DROP TRIGGER usage_extents_insert ON extents;
DROP TRIGGER usage_extents_update ON extents;
DROP TRIGGER usage_extents_delete ON extents;
DROP TRIGGER usage_generations_insert ON generations;
DROP TRIGGER usage_generations_update ON generations;
DROP TRIGGER usage_generations_delete ON generations;
DROP TRIGGER usage_outbox_insert ON outbox;
DROP TRIGGER usage_outbox_delete ON outbox;
DROP TRIGGER usage_outbox_failure ON outbox;
DROP TRIGGER usage_outbox_stage ON outbox;
DROP FUNCTION trg_usage_extents_insert();
DROP FUNCTION trg_usage_extents_update();
DROP FUNCTION trg_usage_extents_delete();
DROP FUNCTION trg_usage_generations();
DROP FUNCTION trg_usage_outbox_insert();
DROP FUNCTION trg_usage_outbox_delete();
DROP FUNCTION trg_usage_outbox_update();

-- Plans: no query here joins new_rows to old_rows. PostgreSQL has no
-- statistics for transition tables, so a join of the two is planned blind:
-- PL/pgSQL may cache it with the first firing's size (usually one row) and
-- run it as a nested loop, O(N^2); and any join estimates about N*M/200
-- rows, which inflates the cost past the JIT thresholds (about 0.2 s of
-- compilation per query) and turns per-row index probes into full scans.
-- Instead, per-row deltas are summed over new_rows UNION ALL old_rows, and
-- rows are paired by key with GROUP BY over the same UNION ALL (one side
-- per table, as the key is unique). Both are linear in the rows changed
-- whatever plan is chosen, and their estimates grow with N, not N^2.
--
-- Coverage: usage row u counts changed row r when u.all_* = 1 or r's key
-- <= u.cur_* (byte order: every key column and variable is COLLATE "C").
-- A row covers some changed row exactly when it covers the smallest one,
-- so first_id selects the rows to write. Every usage_global write names
-- its primary key.

CREATE FUNCTION trg_usage_extents_insert_stmt() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    first_id TEXT COLLATE "C";
BEGIN
    SELECT min(n.id) INTO first_id FROM new_rows n;
    IF first_id IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE usage_global u SET
        (x_unreleased, unreleased_bytes, x_released, released_bytes, x_deleted) = (
            SELECT u.x_unreleased + count(*) FILTER (WHERE n.safety_state IN ('held', 'releasing')),
                   u.unreleased_bytes
                       + COALESCE(sum(n.cipher_size) FILTER (WHERE n.safety_state IN ('held', 'releasing')), 0),
                   u.x_released + count(*) FILTER (WHERE n.safety_state = 'released'),
                   u.released_bytes + COALESCE(sum(n.cipher_size) FILTER (WHERE n.safety_state = 'released'), 0),
                   u.x_deleted + count(*) FILTER (WHERE n.safety_state = 'deleted')
              FROM new_rows n
             WHERE u.all_x = 1 OR n.id <= u.cur_x)
     WHERE u.id IN (1, 2) AND (u.all_x = 1 OR u.cur_x >= first_id);
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_extents_insert AFTER INSERT ON extents
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT
    EXECUTE FUNCTION trg_usage_extents_insert_stmt();

CREATE FUNCTION trg_usage_extents_delete_stmt() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    first_id TEXT COLLATE "C";
BEGIN
    SELECT min(o.id) INTO first_id FROM old_rows o;
    IF first_id IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE usage_global u SET
        (x_unreleased, unreleased_bytes, x_released, released_bytes, x_deleted) = (
            SELECT u.x_unreleased - count(*) FILTER (WHERE o.safety_state IN ('held', 'releasing')),
                   u.unreleased_bytes
                       - COALESCE(sum(o.cipher_size) FILTER (WHERE o.safety_state IN ('held', 'releasing')), 0),
                   u.x_released - count(*) FILTER (WHERE o.safety_state = 'released'),
                   u.released_bytes - COALESCE(sum(o.cipher_size) FILTER (WHERE o.safety_state = 'released'), 0),
                   u.x_deleted - count(*) FILTER (WHERE o.safety_state = 'deleted')
              FROM old_rows o
             WHERE u.all_x = 1 OR o.id <= u.cur_x)
     WHERE u.id IN (1, 2) AND (u.all_x = 1 OR u.cur_x >= first_id);
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_extents_delete AFTER DELETE ON extents
    REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT
    EXECUTE FUNCTION trg_usage_extents_delete_stmt();

-- UPDATE pairs OLD and NEW rows by primary key. PostgreSQL checks the
-- primary key per row, so an UPDATE cannot permute keys: the key sets
-- differ exactly when some row's key changed, which no statement does and
-- which this refuses (VL002) rather than count against the wrong row.
-- Only pairs that satisfy the D1 trigger's WHEN clause count.
CREATE FUNCTION trg_usage_extents_update_stmt() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    first_id TEXT COLLATE "C";
    unpaired BOOLEAN;
BEGIN
    SELECT min(g.id) FILTER (WHERE g.n_rows = 1 AND g.o_rows = 1
               AND (g.n_pinned <> g.o_pinned OR g.n_released <> g.o_released OR g.n_size <> g.o_size)),
           bool_or(g.n_rows <> 1 OR g.o_rows <> 1)
      INTO first_id, unpaired
      FROM (SELECT d.id,
                   count(*) FILTER (WHERE d.side = 1) AS n_rows,
                   count(*) FILTER (WHERE d.side = -1) AS o_rows,
                   bool_or(d.pinned) FILTER (WHERE d.side = 1) AS n_pinned,
                   bool_or(d.pinned) FILTER (WHERE d.side = -1) AS o_pinned,
                   bool_or(d.released) FILTER (WHERE d.side = 1) AS n_released,
                   bool_or(d.released) FILTER (WHERE d.side = -1) AS o_released,
                   max(d.cipher_size) FILTER (WHERE d.side = 1) AS n_size,
                   max(d.cipher_size) FILTER (WHERE d.side = -1) AS o_size
              FROM (SELECT n.id, 1 AS side, n.safety_state IN ('held', 'releasing') AS pinned,
                           n.safety_state = 'released' AS released, n.cipher_size
                      FROM new_rows n
                    UNION ALL
                    SELECT o.id, -1, o.safety_state IN ('held', 'releasing'),
                           o.safety_state = 'released', o.cipher_size
                      FROM old_rows o) d
             GROUP BY d.id) g;
    IF unpaired THEN
        RAISE EXCEPTION 'usage counters require a stable extents.id' USING ERRCODE = 'VL002';
    END IF;
    IF first_id IS NULL THEN
        RETURN NULL;
    END IF;
    -- NEW minus OLD over every row, without pairing: a pair outside the WHEN
    -- has the same class and cipher_size on both sides, so it adds zero, and
    -- both sides of a pair have the same key, so the same coverage.
    -- The byte products are numeric: -1 * a BIGINT-minimum size must not
    -- overflow before the unchanged pair cancels; the bigint column
    -- assignment still errors on a real overflow.
    UPDATE usage_global u SET
        (x_unreleased, unreleased_bytes, x_released, released_bytes, x_deleted) = (
            SELECT u.x_unreleased + sum(d.sign * (d.safety_state IN ('held', 'releasing'))::int),
                   u.unreleased_bytes + sum(d.sign::numeric * CASE WHEN d.safety_state IN ('held', 'releasing')
                                                          THEN d.cipher_size ELSE 0 END),
                   u.x_released + sum(d.sign * (d.safety_state = 'released')::int),
                   u.released_bytes + sum(d.sign::numeric * CASE WHEN d.safety_state = 'released'
                                                        THEN d.cipher_size ELSE 0 END),
                   u.x_deleted + sum(d.sign * (d.safety_state = 'deleted')::int)
              FROM (SELECT n.id, n.safety_state, n.cipher_size, 1 AS sign FROM new_rows n
                    UNION ALL
                    SELECT o.id, o.safety_state, o.cipher_size, -1 FROM old_rows o) d
             WHERE u.all_x = 1 OR d.id <= u.cur_x)
     WHERE u.id IN (1, 2) AND (u.all_x = 1 OR u.cur_x >= first_id);
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_extents_update AFTER UPDATE ON extents
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT
    EXECUTE FUNCTION trg_usage_extents_update_stmt();

-- generations: one additive upsert per touched (kind, bucket_id). A bucket
-- with at least one counted row gets a row even if its net change is zero,
-- as with the per-row upserts.
CREATE FUNCTION trg_usage_generations_insert_stmt() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    INSERT INTO usage_buckets (kind, bucket_id, live_objects, live_bytes)
    SELECT u.id, n.bucket_id, count(*), sum(n.size)
      FROM new_rows n JOIN usage_global u ON u.id IN (1, 2) AND (u.all_g = 1 OR n.id <= u.cur_g)
     WHERE n.state = 'live'
     GROUP BY u.id, n.bucket_id
    ON CONFLICT (kind, bucket_id) DO UPDATE SET
        live_objects = usage_buckets.live_objects + EXCLUDED.live_objects,
        live_bytes = usage_buckets.live_bytes + EXCLUDED.live_bytes;
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_generations_insert AFTER INSERT ON generations
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT
    EXECUTE FUNCTION trg_usage_generations_insert_stmt();

CREATE FUNCTION trg_usage_generations_delete_stmt() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    INSERT INTO usage_buckets (kind, bucket_id, live_objects, live_bytes)
    SELECT u.id, o.bucket_id, -count(*), -sum(o.size)
      FROM old_rows o JOIN usage_global u ON u.id IN (1, 2) AND (u.all_g = 1 OR o.id <= u.cur_g)
     WHERE o.state = 'live'
     GROUP BY u.id, o.bucket_id
    ON CONFLICT (kind, bucket_id) DO UPDATE SET
        live_objects = usage_buckets.live_objects + EXCLUDED.live_objects,
        live_bytes = usage_buckets.live_bytes + EXCLUDED.live_bytes;
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_generations_delete AFTER DELETE ON generations
    REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT
    EXECUTE FUNCTION trg_usage_generations_delete_stmt();

CREATE FUNCTION trg_usage_generations_update_stmt() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    unpaired BOOLEAN;
BEGIN
    SELECT bool_or(g.n_rows <> 1 OR g.o_rows <> 1) INTO unpaired
      FROM (SELECT d.id, count(*) FILTER (WHERE d.side = 1) AS n_rows,
                   count(*) FILTER (WHERE d.side = -1) AS o_rows
              FROM (SELECT n.id, 1 AS side FROM new_rows n
                    UNION ALL
                    SELECT o.id, -1 FROM old_rows o) d
             GROUP BY d.id) g;
    IF unpaired THEN
        RAISE EXCEPTION 'usage counters require a stable generations.id' USING ERRCODE = 'VL002';
    END IF;
    -- Which buckets a pair touches depends on the pair (the D1 WHEN).
    WITH p AS (
        SELECT d.id,
               max(d.bucket_id) FILTER (WHERE d.side = -1) AS o_bucket,
               max(d.size) FILTER (WHERE d.side = -1) AS o_size,
               bool_or(d.live) FILTER (WHERE d.side = -1) AS o_live,
               max(d.bucket_id) FILTER (WHERE d.side = 1) AS n_bucket,
               max(d.size) FILTER (WHERE d.side = 1) AS n_size,
               bool_or(d.live) FILTER (WHERE d.side = 1) AS n_live
          FROM (SELECT n.id, 1 AS side, n.bucket_id, n.size, n.state = 'live' AS live FROM new_rows n
                UNION ALL
                SELECT o.id, -1, o.bucket_id, o.size, o.state = 'live' FROM old_rows o) d
         GROUP BY d.id
    ), e AS (
        SELECT u.id AS kind, p.o_bucket AS bucket_id, -1 AS objects, -p.o_size AS bytes
          FROM p JOIN usage_global u ON u.id IN (1, 2) AND (u.all_g = 1 OR p.id <= u.cur_g)
         WHERE p.o_live
           AND (p.n_live <> p.o_live OR (p.n_live AND (p.n_size <> p.o_size OR p.n_bucket <> p.o_bucket)))
        UNION ALL
        SELECT u.id, p.n_bucket, 1, p.n_size
          FROM p JOIN usage_global u ON u.id IN (1, 2) AND (u.all_g = 1 OR p.id <= u.cur_g)
         WHERE p.n_live
           AND (p.n_live <> p.o_live OR (p.n_live AND (p.n_size <> p.o_size OR p.n_bucket <> p.o_bucket)))
    )
    INSERT INTO usage_buckets (kind, bucket_id, live_objects, live_bytes)
    SELECT e.kind, e.bucket_id, sum(e.objects), sum(e.bytes)
      FROM e
     GROUP BY e.kind, e.bucket_id
    ON CONFLICT (kind, bucket_id) DO UPDATE SET
        live_objects = usage_buckets.live_objects + EXCLUDED.live_objects,
        live_bytes = usage_buckets.live_bytes + EXCLUDED.live_bytes;
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_generations_update AFTER UPDATE ON generations
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT
    EXECUTE FUNCTION trg_usage_generations_update_stmt();

-- outbox ------------------------------------------------------------------
CREATE FUNCTION trg_usage_outbox_insert_stmt() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    first_id TEXT COLLATE "C";
BEGIN
    SELECT min(n.extent_id) INTO first_id FROM new_rows n;
    IF first_id IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE usage_global u SET
        (ob_post, ob_verify, ob_release, ob_done, ob_cancelled, ob_dead) = (
            SELECT u.ob_post + count(*) FILTER (WHERE n.stage = 'post'),
                   u.ob_verify + count(*) FILTER (WHERE n.stage = 'verify'),
                   u.ob_release + count(*) FILTER (WHERE n.stage = 'release'),
                   u.ob_done + count(*) FILTER (WHERE n.stage = 'done'),
                   u.ob_cancelled + count(*) FILTER (WHERE n.stage = 'cancelled'),
                   u.ob_dead + count(*) FILTER (WHERE n.stage = 'dead')
              FROM new_rows n
             WHERE u.all_o = 1 OR n.extent_id <= u.cur_o)
     WHERE u.id IN (1, 2) AND (u.all_o = 1 OR u.cur_o >= first_id);
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_outbox_insert AFTER INSERT ON outbox
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT
    EXECUTE FUNCTION trg_usage_outbox_insert_stmt();

CREATE FUNCTION trg_usage_outbox_delete_stmt() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    first_id TEXT COLLATE "C";
BEGIN
    SELECT min(o.extent_id) INTO first_id FROM old_rows o;
    IF first_id IS NULL THEN
        RETURN NULL;
    END IF;
    UPDATE usage_global u SET
        (ob_post, ob_verify, ob_release, ob_done, ob_cancelled, ob_dead) = (
            SELECT u.ob_post - count(*) FILTER (WHERE o.stage = 'post'),
                   u.ob_verify - count(*) FILTER (WHERE o.stage = 'verify'),
                   u.ob_release - count(*) FILTER (WHERE o.stage = 'release'),
                   u.ob_done - count(*) FILTER (WHERE o.stage = 'done'),
                   u.ob_cancelled - count(*) FILTER (WHERE o.stage = 'cancelled'),
                   u.ob_dead - count(*) FILTER (WHERE o.stage = 'dead')
              FROM old_rows o
             WHERE u.all_o = 1 OR o.extent_id <= u.cur_o)
     WHERE u.id IN (1, 2) AND (u.all_o = 1 OR u.cur_o >= first_id);
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_outbox_delete AFTER DELETE ON outbox
    REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT
    EXECUTE FUNCTION trg_usage_outbox_delete_stmt();

-- A failure is a row whose stage is unchanged and whose last_error is a
-- SET target with a non-NULL value, even when the text is unchanged. Only
-- a trigger with a column list sees SET targets, and PostgreSQL gives such
-- a trigger no transition tables. The SET list is the same for every row of
-- a statement, so this statement trigger records "last_error is a target"
-- for the statement in a transaction-local setting. usage_outbox_stage
-- fires next for the same statement (statement triggers fire in name
-- order), clears the setting and folds failures and stage changes together
-- in ascending hour order. A rolled-back statement or savepoint also rolls
-- back the setting.
CREATE FUNCTION trg_usage_outbox_failure_stmt() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    PERFORM set_config('velmora.usage_last_error_set', 'on', true);
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_outbox_failure AFTER UPDATE OF last_error ON outbox FOR EACH STATEMENT
    EXECUTE FUNCTION trg_usage_outbox_failure_stmt();

-- Events, as in D1 0025: post->verify is a post; verify->release and
-- verify->done are a verify; release->done is a release, and so is
-- verify->done when the extent is released at this update; any->dead is
-- dead. hour = updated_at / 3600000. Before an event of a later hour, row 1
-- files its h_* into usage_hours (only when all_o = 1, hour > 0 and the
-- h_* sum is > 0); h_* then reset and hour becomes the event's hour. An
-- earlier-hour event joins the current bucket. Row 2 resets the same way
-- but never files.
CREATE FUNCTION trg_usage_outbox_stage_stmt() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    failures BOOLEAN := COALESCE(current_setting('velmora.usage_last_error_set', true), '') = 'on';
    first_id TEXT COLLATE "C";
    cur TEXT COLLATE "C";
    unpaired BOOLEAN;
    u RECORD;
    g RECORD;
    hr BIGINT; hp BIGINT; hv BIGINT; hl BIGINT; hd BIGINT; hf BIGINT;
    a_post BIGINT; a_verify BIGINT; a_release BIGINT; a_done BIGINT; a_cancelled BIGINT; a_dead BIGINT;
    t_posts BIGINT; t_verifies BIGINT; t_releases BIGINT; t_dead BIGINT; t_failures BIGINT;
BEGIN
    SELECT min(k.extent_id) FILTER (WHERE k.n_rows = 1 AND k.o_rows = 1
               AND (k.ns <> k.os OR (failures AND k.last_error IS NOT NULL))),
           bool_or(k.n_rows <> 1 OR k.o_rows <> 1)
      INTO first_id, unpaired
      FROM (SELECT d.extent_id,
                   count(*) FILTER (WHERE d.side = 1) AS n_rows,
                   count(*) FILTER (WHERE d.side = -1) AS o_rows,
                   max(d.stage) FILTER (WHERE d.side = 1) AS ns,
                   max(d.stage) FILTER (WHERE d.side = -1) AS os,
                   max(d.last_error) FILTER (WHERE d.side = 1) AS last_error
              FROM (SELECT n.extent_id, 1 AS side, n.stage, n.last_error FROM new_rows n
                    UNION ALL
                    SELECT o.extent_id, -1, o.stage, NULL FROM old_rows o) d
             GROUP BY d.extent_id) k;
    IF unpaired THEN
        RAISE EXCEPTION 'usage counters require a stable outbox.extent_id' USING ERRCODE = 'VL002';
    END IF;
    IF failures THEN
        PERFORM set_config('velmora.usage_last_error_set', '', true);
    END IF;
    IF first_id IS NULL THEN
        RETURN NULL;
    END IF;
    -- Read and write each covering row once; the lock makes the
    -- read-modify-write of hour and h_* safe without relying on W1.
    FOR u IN SELECT id, all_o, cur_o, hour, h_posts, h_verifies, h_releases, h_dead, h_failures
               FROM usage_global
              WHERE id IN (1, 2) AND (all_o = 1 OR cur_o >= first_id)
              ORDER BY id FOR NO KEY UPDATE
    LOOP
        cur := u.cur_o;
        hr := u.hour; hp := u.h_posts; hv := u.h_verifies; hl := u.h_releases;
        hd := u.h_dead; hf := u.h_failures;
        a_post := 0; a_verify := 0; a_release := 0; a_done := 0; a_cancelled := 0; a_dead := 0;
        t_posts := 0; t_verifies := 0; t_releases := 0; t_dead := 0; t_failures := 0;
        FOR g IN
            SELECT e.event_hour,
                   count(*) FILTER (WHERE e.ns = 'post') - count(*) FILTER (WHERE e.os = 'post') AS ob_post,
                   count(*) FILTER (WHERE e.ns = 'verify') - count(*) FILTER (WHERE e.os = 'verify') AS ob_verify,
                   count(*) FILTER (WHERE e.ns = 'release') - count(*) FILTER (WHERE e.os = 'release') AS ob_release,
                   count(*) FILTER (WHERE e.ns = 'done') - count(*) FILTER (WHERE e.os = 'done') AS ob_done,
                   count(*) FILTER (WHERE e.ns = 'cancelled') - count(*) FILTER (WHERE e.os = 'cancelled')
                       AS ob_cancelled,
                   count(*) FILTER (WHERE e.ns = 'dead') - count(*) FILTER (WHERE e.os = 'dead') AS ob_dead,
                   count(*) FILTER (WHERE e.os = 'post' AND e.ns = 'verify') AS posts,
                   count(*) FILTER (WHERE e.os = 'verify' AND e.ns IN ('release', 'done')) AS verifies,
                   count(*) FILTER (WHERE (e.os = 'release' AND e.ns = 'done') OR e.released) AS releases,
                   count(*) FILTER (WHERE e.ns = 'dead' AND e.os <> 'dead') AS dead,
                   count(*) FILTER (WHERE e.ns = e.os) AS failed
              FROM (WITH p AS (
                        -- Events are per pair: paired by key (see the top).
                        SELECT d.extent_id,
                               max(d.updated_at) FILTER (WHERE d.side = 1) AS updated_at,
                               max(d.stage) FILTER (WHERE d.side = 1) AS ns,
                               max(d.stage) FILTER (WHERE d.side = -1) AS os,
                               max(d.last_error) FILTER (WHERE d.side = 1) AS last_error
                          FROM (SELECT n.extent_id, 1 AS side, n.updated_at, n.stage, n.last_error
                                  FROM new_rows n
                                UNION ALL
                                SELECT o.extent_id, -1, NULL, o.stage, NULL FROM old_rows o) d
                         GROUP BY d.extent_id)
                    SELECT p.updated_at / 3600000 AS event_hour, p.ns, p.os,
                           CASE WHEN p.os = 'verify' AND p.ns = 'done'
                                THEN EXISTS (SELECT 1 FROM extents x WHERE x.id = p.extent_id
                                              AND x.safety_state = 'released' AND x.released_at = p.updated_at)
                                ELSE false END AS released
                      FROM p
                     WHERE (p.ns <> p.os OR (failures AND p.last_error IS NOT NULL))
                       AND (u.all_o = 1 OR p.extent_id <= cur)) e
             GROUP BY e.event_hour
             ORDER BY e.event_hour
        LOOP
            IF g.event_hour > hr THEN
                IF u.id = 1 AND u.all_o = 1 AND hr > 0 AND hp + hv + hl + hd + hf > 0 THEN
                    INSERT INTO usage_hours (hour, posts, verifies, releases, dead, failures)
                    VALUES (hr, hp, hv, hl, hd, hf)
                    ON CONFLICT (hour) DO UPDATE SET
                        posts = usage_hours.posts + EXCLUDED.posts,
                        verifies = usage_hours.verifies + EXCLUDED.verifies,
                        releases = usage_hours.releases + EXCLUDED.releases,
                        dead = usage_hours.dead + EXCLUDED.dead,
                        failures = usage_hours.failures + EXCLUDED.failures;
                END IF;
                hp := 0; hv := 0; hl := 0; hd := 0; hf := 0;
                hr := g.event_hour;
            END IF;
            hp := hp + g.posts; hv := hv + g.verifies; hl := hl + g.releases;
            hd := hd + g.dead; hf := hf + g.failed;
            a_post := a_post + g.ob_post; a_verify := a_verify + g.ob_verify;
            a_release := a_release + g.ob_release; a_done := a_done + g.ob_done;
            a_cancelled := a_cancelled + g.ob_cancelled; a_dead := a_dead + g.ob_dead;
            t_posts := t_posts + g.posts; t_verifies := t_verifies + g.verifies;
            t_releases := t_releases + g.releases; t_dead := t_dead + g.dead;
            t_failures := t_failures + g.failed;
        END LOOP;
        UPDATE usage_global SET
            ob_post = ob_post + a_post, ob_verify = ob_verify + a_verify,
            ob_release = ob_release + a_release, ob_done = ob_done + a_done,
            ob_cancelled = ob_cancelled + a_cancelled, ob_dead = ob_dead + a_dead,
            posts_total = posts_total + t_posts, verifies_total = verifies_total + t_verifies,
            releases_total = releases_total + t_releases, dead_total = dead_total + t_dead,
            failures_total = failures_total + t_failures,
            hour = hr, h_posts = hp, h_verifies = hv, h_releases = hl, h_dead = hd, h_failures = hf
         WHERE id = u.id;
    END LOOP;
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_outbox_stage AFTER UPDATE ON outbox
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT
    EXECUTE FUNCTION trg_usage_outbox_stage_stmt();
