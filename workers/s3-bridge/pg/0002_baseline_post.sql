-- Apply after bulk COPY: imported reference rows and usage counters are authoritative.
CREATE INDEX extents_by_generation ON extents(generation_id, seq);
CREATE INDEX extents_evictable ON extents(last_read_at ASC NULLS FIRST, id,
    hot_safety_bytes, hot_cache_bytes, evict_seq, safety_state)
    WHERE hot_cache_bytes > 0 OR (hot_safety_bytes > 0 AND safety_state NOT IN ('held', 'releasing'));
CREATE INDEX extents_held ON extents(id) WHERE safety_state = 'held';
CREATE INDEX extents_pinned ON extents(cipher_size, safety_state) WHERE safety_state IN ('held', 'releasing');
CREATE INDEX extents_safety ON extents(id, cipher_size, safety_state) WHERE safety_state IN ('held', 'releasing');
CREATE INDEX gc_due ON gc(due_at, id) WHERE done_at IS NULL;
CREATE INDEX generation_extents_by_extent ON generation_extents(extent_id);
CREATE INDEX generations_by_key ON generations(bucket_id, key, created_at);
CREATE INDEX outbox_due ON outbox(stage, next_at, seq);
CREATE INDEX outbox_exhausted ON outbox(extent_id) WHERE attempts > 50 AND stage IN ('post', 'verify', 'release');
CREATE INDEX recovery_copy_log_kind_at ON recovery_copy_log(kind, at);
CREATE INDEX recovery_copy_log_problem_at ON recovery_copy_log(at DESC, pass) WHERE kind = 'job' AND problems > 0;
CREATE INDEX recovery_copy_log_swept_at ON recovery_copy_log(at DESC) WHERE kind = 'job' AND swept = 1;
CREATE INDEX upload_part_extents_by_extent ON upload_part_extents(extent_id);
CREATE INDEX upload_parts_by_extent ON upload_parts(extent_id);
CREATE INDEX uploads_open ON uploads(bucket_id, key) WHERE state = 'open';
CREATE INDEX write_intents_by_write ON write_intents(write_id);
CREATE INDEX write_intents_due ON write_intents(created_at);

-- Bind all trigger functions to the catalogue's creation-time search path.
-- The migration runner places pg_temp last to prevent shadowing.
CREATE FUNCTION trg_generation_extents_on_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    INSERT INTO generation_extents(generation_id, seq, extent_id, plain_offset)
    VALUES (NEW.generation_id, NEW.seq, NEW.id, NEW.plain_offset)
    ON CONFLICT (generation_id, seq) DO NOTHING;
    RETURN NULL;
END;
$$;
CREATE TRIGGER generation_extents_on_insert AFTER INSERT ON extents FOR EACH ROW
    WHEN (NEW.generation_id IS NOT NULL AND NEW.seq IS NOT NULL AND NEW.plain_offset IS NOT NULL)
    EXECUTE FUNCTION trg_generation_extents_on_insert();
CREATE TRIGGER generation_extents_on_adopt AFTER UPDATE OF generation_id ON extents FOR EACH ROW
    WHEN (OLD.generation_id IS NULL AND NEW.generation_id IS NOT NULL
          AND NEW.seq IS NOT NULL AND NEW.plain_offset IS NOT NULL)
    EXECUTE FUNCTION trg_generation_extents_on_insert();

CREATE FUNCTION trg_gc_keep_shared_extents() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM extents e JOIN generations og ON og.id = e.generation_id
        WHERE e.id = NEW.extent_id AND og.state = 'live'
          AND EXISTS (SELECT 1 FROM generation_extents r JOIN generations g ON g.id = r.generation_id
                      WHERE r.extent_id = e.id AND g.state = 'live' AND g.id <> e.generation_id)
    ) THEN
        RAISE EXCEPTION 'extent is referenced by another live generation' USING ERRCODE = 'VL001';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER gc_keep_shared_extents BEFORE INSERT ON gc FOR EACH ROW
    EXECUTE FUNCTION trg_gc_keep_shared_extents();

CREATE FUNCTION trg_outbox_keep_shared_extents() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM generations og
        WHERE og.id = OLD.generation_id AND og.state = 'live'
          AND EXISTS (SELECT 1 FROM generation_extents r JOIN generations g ON g.id = r.generation_id
                      WHERE r.extent_id = OLD.extent_id AND g.state = 'live' AND g.id <> OLD.generation_id)
    ) THEN
        RAISE EXCEPTION 'extent is referenced by another live generation' USING ERRCODE = 'VL001';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER outbox_keep_shared_extents BEFORE UPDATE OF stage ON outbox FOR EACH ROW
    WHEN (NEW.stage = 'cancelled' AND OLD.stage <> 'cancelled')
    EXECUTE FUNCTION trg_outbox_keep_shared_extents();

CREATE FUNCTION trg_extents_keep_in_service() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM generation_extents r JOIN generations g ON g.id = r.generation_id
               WHERE r.extent_id = OLD.id AND g.state = 'live')
       OR EXISTS (SELECT 1 FROM upload_parts p JOIN uploads u ON u.id = p.upload_id
                  WHERE p.extent_id = OLD.id AND u.state = 'open') THEN
        RAISE EXCEPTION 'extent is in service' USING ERRCODE = 'VL001';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER extents_keep_key_in_service BEFORE UPDATE OF wrapped_file_key ON extents FOR EACH ROW
    WHEN (OLD.wrapped_file_key IS NOT NULL AND NEW.wrapped_file_key IS NULL)
    EXECUTE FUNCTION trg_extents_keep_in_service();
CREATE TRIGGER extents_keep_plan_in_service BEFORE UPDATE OF plan ON extents FOR EACH ROW
    WHEN (OLD.plan IS NOT NULL AND NEW.plan IS NULL)
    EXECUTE FUNCTION trg_extents_keep_in_service();

CREATE FUNCTION trg_extents_keep_of_slices() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM upload_part_extents p JOIN uploads u ON u.id = p.upload_id
               WHERE p.extent_id = OLD.id AND u.state = 'open') THEN
        RAISE EXCEPTION 'extent is in service' USING ERRCODE = 'VL001';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER extents_keep_key_of_slices BEFORE UPDATE OF wrapped_file_key ON extents FOR EACH ROW
    WHEN (OLD.wrapped_file_key IS NOT NULL AND NEW.wrapped_file_key IS NULL)
    EXECUTE FUNCTION trg_extents_keep_of_slices();
CREATE TRIGGER extents_keep_plan_of_slices BEFORE UPDATE OF plan ON extents FOR EACH ROW
    WHEN (OLD.plan IS NOT NULL AND NEW.plan IS NULL)
    EXECUTE FUNCTION trg_extents_keep_of_slices();

CREATE FUNCTION trg_articles_keep_unpacked_in_service() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (SELECT plan FROM extents WHERE id = OLD.extent_id) IS NULL
       AND (EXISTS (SELECT 1 FROM generation_extents r JOIN generations g ON g.id = r.generation_id
                    WHERE r.extent_id = OLD.extent_id AND g.state = 'live')
            OR EXISTS (SELECT 1 FROM upload_parts p JOIN uploads u ON u.id = p.upload_id
                       WHERE p.extent_id = OLD.extent_id AND u.state = 'open')) THEN
        RAISE EXCEPTION 'extent is in service' USING ERRCODE = 'VL001';
    END IF;
    RETURN OLD;
END;
$$;
CREATE TRIGGER articles_keep_unpacked_in_service BEFORE DELETE ON articles FOR EACH ROW
    EXECUTE FUNCTION trg_articles_keep_unpacked_in_service();

CREATE FUNCTION trg_articles_keep_unpacked_of_slices() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF (SELECT plan FROM extents WHERE id = OLD.extent_id) IS NULL
       AND EXISTS (SELECT 1 FROM upload_part_extents p JOIN uploads u ON u.id = p.upload_id
                   WHERE p.extent_id = OLD.extent_id AND u.state = 'open') THEN
        RAISE EXCEPTION 'extent is in service' USING ERRCODE = 'VL001';
    END IF;
    RETURN OLD;
END;
$$;
CREATE TRIGGER articles_keep_unpacked_of_slices BEFORE DELETE ON articles FOR EACH ROW
    EXECUTE FUNCTION trg_articles_keep_unpacked_of_slices();

CREATE FUNCTION trg_key_floors_on_delete() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    id_ms BIGINT := 0;
    ms_hex TEXT;
BEGIN
    -- Match SQLite instr() - 1 even for legacy IDs without 13 hex digits.
    FOR pos IN 3..15 LOOP
        id_ms := id_ms * 16 + strpos('0123456789abcdef', substr(NEW.id, pos, 1)) - 1;
    END LOOP;
    ms_hex := to_hex(GREATEST(COALESCE(NEW.retired_at, 0), id_ms + 1));
    INSERT INTO key_floors(bucket_id, key, floor_id)
    VALUES (NEW.bucket_id, NEW.key, 'g_' || lpad(ms_hex, GREATEST(13, length(ms_hex)), '0') || 'ffffffffffffffff')
    ON CONFLICT (bucket_id, key) DO UPDATE SET
        floor_id = GREATEST(key_floors.floor_id, EXCLUDED.floor_id);
    RETURN NULL;
END;
$$;
CREATE TRIGGER key_floors_on_delete AFTER UPDATE OF state ON generations FOR EACH ROW
    WHEN (NEW.state = 'deleted' AND OLD.state <> 'deleted')
    EXECUTE FUNCTION trg_key_floors_on_delete();

CREATE FUNCTION trg_usage_extents_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    UPDATE usage_global SET
        x_unreleased = x_unreleased + (NEW.safety_state IN ('held', 'releasing'))::int,
        unreleased_bytes = unreleased_bytes
            + CASE WHEN NEW.safety_state IN ('held', 'releasing') THEN NEW.cipher_size ELSE 0 END,
        x_released = x_released + (NEW.safety_state = 'released')::int,
        released_bytes = released_bytes + CASE WHEN NEW.safety_state = 'released' THEN NEW.cipher_size ELSE 0 END,
        x_deleted = x_deleted + (NEW.safety_state = 'deleted')::int
    WHERE all_x = 1 OR NEW.id <= cur_x;
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_extents_insert AFTER INSERT ON extents FOR EACH ROW EXECUTE FUNCTION trg_usage_extents_insert();

CREATE FUNCTION trg_usage_extents_update() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    UPDATE usage_global SET
        x_unreleased = x_unreleased
            + (NEW.safety_state IN ('held', 'releasing'))::int - (OLD.safety_state IN ('held', 'releasing'))::int,
        unreleased_bytes = unreleased_bytes
            + CASE WHEN NEW.safety_state IN ('held', 'releasing') THEN NEW.cipher_size ELSE 0 END
            - CASE WHEN OLD.safety_state IN ('held', 'releasing') THEN OLD.cipher_size ELSE 0 END,
        x_released = x_released + (NEW.safety_state = 'released')::int - (OLD.safety_state = 'released')::int,
        released_bytes = released_bytes
            + CASE WHEN NEW.safety_state = 'released' THEN NEW.cipher_size ELSE 0 END
            - CASE WHEN OLD.safety_state = 'released' THEN OLD.cipher_size ELSE 0 END,
        x_deleted = x_deleted + (NEW.safety_state = 'deleted')::int - (OLD.safety_state = 'deleted')::int
    WHERE all_x = 1 OR NEW.id <= cur_x;
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_extents_update AFTER UPDATE OF safety_state, cipher_size ON extents FOR EACH ROW
    WHEN ((NEW.safety_state IN ('held', 'releasing')) <> (OLD.safety_state IN ('held', 'releasing'))
          OR (NEW.safety_state = 'released') <> (OLD.safety_state = 'released') OR NEW.cipher_size <> OLD.cipher_size)
    EXECUTE FUNCTION trg_usage_extents_update();

CREATE FUNCTION trg_usage_extents_delete() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    UPDATE usage_global SET
        x_unreleased = x_unreleased - (OLD.safety_state IN ('held', 'releasing'))::int,
        unreleased_bytes = unreleased_bytes
            - CASE WHEN OLD.safety_state IN ('held', 'releasing') THEN OLD.cipher_size ELSE 0 END,
        x_released = x_released - (OLD.safety_state = 'released')::int,
        released_bytes = released_bytes - CASE WHEN OLD.safety_state = 'released' THEN OLD.cipher_size ELSE 0 END,
        x_deleted = x_deleted - (OLD.safety_state = 'deleted')::int
    WHERE all_x = 1 OR OLD.id <= cur_x;
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_extents_delete AFTER DELETE ON extents FOR EACH ROW EXECUTE FUNCTION trg_usage_extents_delete();

CREATE FUNCTION trg_usage_generations() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    IF TG_OP <> 'INSERT' THEN
        INSERT INTO usage_buckets (kind, bucket_id, live_objects, live_bytes)
        SELECT u.id, OLD.bucket_id, -1, -OLD.size FROM usage_global u
        WHERE OLD.state = 'live' AND (u.all_g = 1 OR OLD.id <= u.cur_g)
        ON CONFLICT (kind, bucket_id) DO UPDATE SET
            live_objects = usage_buckets.live_objects + EXCLUDED.live_objects,
            live_bytes = usage_buckets.live_bytes + EXCLUDED.live_bytes;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        INSERT INTO usage_buckets (kind, bucket_id, live_objects, live_bytes)
        SELECT u.id, NEW.bucket_id, 1, NEW.size FROM usage_global u
        WHERE NEW.state = 'live' AND (u.all_g = 1 OR NEW.id <= u.cur_g)
        ON CONFLICT (kind, bucket_id) DO UPDATE SET
            live_objects = usage_buckets.live_objects + EXCLUDED.live_objects,
            live_bytes = usage_buckets.live_bytes + EXCLUDED.live_bytes;
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_generations_insert AFTER INSERT ON generations FOR EACH ROW
    WHEN (NEW.state = 'live') EXECUTE FUNCTION trg_usage_generations();
CREATE TRIGGER usage_generations_update AFTER UPDATE OF state, size, bucket_id ON generations FOR EACH ROW
    WHEN ((NEW.state = 'live') <> (OLD.state = 'live')
          OR (NEW.state = 'live' AND (NEW.size <> OLD.size OR NEW.bucket_id <> OLD.bucket_id)))
    EXECUTE FUNCTION trg_usage_generations();
CREATE TRIGGER usage_generations_delete AFTER DELETE ON generations FOR EACH ROW
    WHEN (OLD.state = 'live') EXECUTE FUNCTION trg_usage_generations();

CREATE FUNCTION trg_usage_outbox_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    UPDATE usage_global SET
        ob_post = ob_post + (NEW.stage = 'post')::int,
        ob_verify = ob_verify + (NEW.stage = 'verify')::int,
        ob_release = ob_release + (NEW.stage = 'release')::int,
        ob_done = ob_done + (NEW.stage = 'done')::int,
        ob_cancelled = ob_cancelled + (NEW.stage = 'cancelled')::int,
        ob_dead = ob_dead + (NEW.stage = 'dead')::int
    WHERE all_o = 1 OR NEW.extent_id <= cur_o;
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_outbox_insert AFTER INSERT ON outbox FOR EACH ROW EXECUTE FUNCTION trg_usage_outbox_insert();

CREATE FUNCTION trg_usage_outbox_delete() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
    UPDATE usage_global SET
        ob_post = ob_post - (OLD.stage = 'post')::int,
        ob_verify = ob_verify - (OLD.stage = 'verify')::int,
        ob_release = ob_release - (OLD.stage = 'release')::int,
        ob_done = ob_done - (OLD.stage = 'done')::int,
        ob_cancelled = ob_cancelled - (OLD.stage = 'cancelled')::int,
        ob_dead = ob_dead - (OLD.stage = 'dead')::int
    WHERE all_o = 1 OR OLD.extent_id <= cur_o;
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_outbox_delete AFTER DELETE ON outbox FOR EACH ROW EXECUTE FUNCTION trg_usage_outbox_delete();

CREATE FUNCTION trg_usage_outbox_update() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
    next_hour BIGINT := NEW.updated_at / 3600000;
    d_post INT;
    d_verify INT;
    d_release INT;
    d_dead INT;
BEGIN
    INSERT INTO usage_hours (hour, posts, verifies, releases, dead, failures)
    SELECT hour, h_posts, h_verifies, h_releases, h_dead, h_failures FROM usage_global
    WHERE id = 1 AND all_o = 1 AND hour > 0 AND next_hour > hour
      AND h_posts + h_verifies + h_releases + h_dead + h_failures > 0
    ON CONFLICT (hour) DO UPDATE SET
        posts = usage_hours.posts + EXCLUDED.posts,
        verifies = usage_hours.verifies + EXCLUDED.verifies,
        releases = usage_hours.releases + EXCLUDED.releases,
        dead = usage_hours.dead + EXCLUDED.dead,
        failures = usage_hours.failures + EXCLUDED.failures;

    IF NEW.stage = OLD.stage THEN
        UPDATE usage_global SET
            failures_total = failures_total + 1,
            h_posts = CASE WHEN next_hour > hour THEN 0 ELSE h_posts END,
            h_verifies = CASE WHEN next_hour > hour THEN 0 ELSE h_verifies END,
            h_releases = CASE WHEN next_hour > hour THEN 0 ELSE h_releases END,
            h_dead = CASE WHEN next_hour > hour THEN 0 ELSE h_dead END,
            h_failures = CASE WHEN next_hour > hour THEN 0 ELSE h_failures END + 1,
            hour = GREATEST(hour, next_hour)
        WHERE all_o = 1 OR NEW.extent_id <= cur_o;
    ELSE
        d_post := (OLD.stage = 'post' AND NEW.stage = 'verify')::int;
        d_verify := (OLD.stage = 'verify' AND NEW.stage IN ('release', 'done'))::int;
        d_release := ((OLD.stage = 'release' AND NEW.stage = 'done')
            OR (OLD.stage = 'verify' AND NEW.stage = 'done'
                AND EXISTS (SELECT 1 FROM extents e WHERE e.id = NEW.extent_id
                            AND e.safety_state = 'released' AND e.released_at = NEW.updated_at)))::int;
        d_dead := (NEW.stage = 'dead')::int;
        UPDATE usage_global SET
            ob_post = ob_post + (NEW.stage = 'post')::int - (OLD.stage = 'post')::int,
            ob_verify = ob_verify + (NEW.stage = 'verify')::int - (OLD.stage = 'verify')::int,
            ob_release = ob_release + (NEW.stage = 'release')::int - (OLD.stage = 'release')::int,
            ob_done = ob_done + (NEW.stage = 'done')::int - (OLD.stage = 'done')::int,
            ob_cancelled = ob_cancelled + (NEW.stage = 'cancelled')::int - (OLD.stage = 'cancelled')::int,
            ob_dead = ob_dead + (NEW.stage = 'dead')::int - (OLD.stage = 'dead')::int,
            posts_total = posts_total + d_post,
            verifies_total = verifies_total + d_verify,
            releases_total = releases_total + d_release,
            dead_total = dead_total + d_dead,
            h_posts = CASE WHEN next_hour > hour THEN 0 ELSE h_posts END + d_post,
            h_verifies = CASE WHEN next_hour > hour THEN 0 ELSE h_verifies END + d_verify,
            h_releases = CASE WHEN next_hour > hour THEN 0 ELSE h_releases END + d_release,
            h_dead = CASE WHEN next_hour > hour THEN 0 ELSE h_dead END + d_dead,
            h_failures = CASE WHEN next_hour > hour THEN 0 ELSE h_failures END,
            hour = GREATEST(hour, next_hour)
        WHERE all_o = 1 OR NEW.extent_id <= cur_o;
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER usage_outbox_failure AFTER UPDATE OF last_error ON outbox FOR EACH ROW
    WHEN (NEW.last_error IS NOT NULL AND NEW.stage = OLD.stage) EXECUTE FUNCTION trg_usage_outbox_update();
CREATE TRIGGER usage_outbox_stage AFTER UPDATE OF stage ON outbox FOR EACH ROW
    WHEN (NEW.stage <> OLD.stage) EXECUTE FUNCTION trg_usage_outbox_update();
