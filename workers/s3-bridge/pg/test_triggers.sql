-- Run only on a fresh test database, inside a transaction that the caller rolls back.
-- Explicit identity values keep even the nontransactional sequence state unchanged.
CREATE TEMP TABLE wp2_usage_trace (step TEXT, target TEXT, values_ TEXT) ON COMMIT DROP;

-- BEGIN SHARED FIXTURE
-- pg-migrate also runs these statements on SQLite and compares each checkpoint.
INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,created_at) VALUES
    ('wp2_a','wp2_a','wp2',decode('','hex'),1,0), ('wp2_b','wp2_b','wp2',decode('','hex'),1,0);
UPDATE usage_global SET all_x=1,all_o=1,all_g=1 WHERE id=1;
UPDATE usage_global SET cur_x='wp2_m',cur_o='wp2_m',cur_g='g_m' WHERE id=2;

INSERT INTO generations(id,bucket_id,key,state,size,etag,content_json,user_meta_json,extent_count,created_at) VALUES
    ('g_00000000000ff0000000000000000','wp2_a','floor','live',10,'e','{}','{}',0,0),
    ('g_z','wp2_a','move','live',20,'e','{}','{}',0,0);
INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,
                    cipher_sha256,safety_state,created_at) VALUES
    ('wp2_a','wp2_a','staged',10,11,decode('','hex'),decode('','hex'),decode('','hex'),decode('','hex'),'held',0),
    ('wp2_z','wp2_a','staged',20,22,decode('','hex'),decode('','hex'),decode('','hex'),decode('','hex'),'held',0);
INSERT INTO outbox(extent_id,generation_id,stage,next_at,updated_at,seq) VALUES
    ('wp2_a','g_z','post',0,3600000,-10), ('wp2_z','g_z','post',0,3600000,-11);
INSERT INTO wp2_usage_trace SELECT 'a-insert', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'a-insert', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;

UPDATE generations SET size=15 WHERE key='floor';
UPDATE generations SET bucket_id='wp2_b',size=25 WHERE id='g_z';
UPDATE generations SET state='superseded' WHERE id='g_z';
UPDATE generations SET state='live' WHERE id='g_z';
UPDATE generations SET state='deleted',retired_at=1 WHERE key='floor';
INSERT INTO wp2_usage_trace SELECT 'b-update', 'floor', floor_id FROM key_floors WHERE key='floor';
UPDATE generations SET state='live' WHERE key='floor';
UPDATE generations SET state='deleted',retired_at=4503599627370496 WHERE key='floor';
INSERT INTO wp2_usage_trace SELECT 'b-wide-floor', 'floor', floor_id FROM key_floors WHERE key='floor';
UPDATE generations SET state='live' WHERE key='floor';
UPDATE generations SET state='deleted',retired_at=2 WHERE key='floor';
INSERT INTO wp2_usage_trace SELECT 'b-floor-no-regression', 'floor', floor_id FROM key_floors WHERE key='floor';
UPDATE extents SET safety_state='releasing' WHERE id='wp2_a';
UPDATE outbox SET stage='verify' WHERE extent_id IN ('wp2_a','wp2_z');
UPDATE outbox SET last_error='fixture failure' WHERE extent_id='wp2_a';
UPDATE extents SET safety_state='released',released_at=7200000,cipher_size=12 WHERE id='wp2_a';
UPDATE outbox SET stage='done',last_error='not a failure',updated_at=7200000 WHERE extent_id='wp2_a';
UPDATE outbox SET stage='release',updated_at=7200000 WHERE extent_id='wp2_z';
UPDATE outbox SET stage='done',updated_at=7200000 WHERE extent_id='wp2_z';
UPDATE outbox SET stage='dead',updated_at=10800000 WHERE extent_id='wp2_z';
UPDATE outbox SET stage='cancelled',updated_at=10800000 WHERE extent_id='wp2_z';
INSERT INTO wp2_usage_trace SELECT 'c-stage', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'c-stage', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'c-stage', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;

UPDATE extents SET safety_state='deleted' WHERE id='wp2_a';
INSERT INTO wp2_usage_trace SELECT 'd-deleted', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted FROM usage_global;
DELETE FROM outbox WHERE extent_id IN ('wp2_a','wp2_z');
DELETE FROM extents WHERE id IN ('wp2_a','wp2_z');
DELETE FROM generations WHERE key IN ('floor','move') AND bucket_id IN ('wp2_a','wp2_b');
INSERT INTO wp2_usage_trace SELECT 'e-delete', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'e-delete', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
-- END SHARED FIXTURE

DO $$
DECLARE refusal text;
BEGIN
    INSERT INTO generations(id,bucket_id,key,state,size,etag,content_json,user_meta_json,extent_count,created_at) VALUES
        ('wp2_gen','wp2_a','guard','live',10,'e','{}','{}',2,0),
        ('wp2_shared','wp2_a','share','live',10,'e','{}','{}',1,0);
    INSERT INTO extents(id,bucket_id,generation_id,seq,plain_offset,state,plain_size,cipher_size,media_header,
                        plain_md5,plain_sha256,cipher_sha256,safety_state,created_at,wrapped_file_key,plan) VALUES
        ('wp2_live','wp2_a','wp2_gen',1,0,'committed',10,11,'','','','','held',0,'',''),
        ('wp2_duplicate','wp2_a','wp2_gen',1,90,'committed',10,11,'','','','','held',0,'',''),
        ('wp2_adopt','wp2_a',NULL,2,10,'staged',10,11,'','','','','held',0,'',NULL),
        ('wp2_adopt_dup','wp2_a',NULL,2,99,'staged',10,11,'','','','','held',0,'',NULL),
        ('wp2_slice','wp2_a',NULL,NULL,NULL,'staged',10,11,'','','','','held',0,'',''),
        ('wp2_slice_plain','wp2_a',NULL,NULL,NULL,'staged',10,11,'','','','','held',0,'',NULL),
        ('wp2_legacy','wp2_a',NULL,NULL,NULL,'staged',10,11,'','','','','held',0,'','');
    UPDATE extents SET generation_id='wp2_gen' WHERE id='wp2_adopt';
    UPDATE extents SET generation_id='wp2_gen' WHERE id='wp2_adopt_dup';
    IF (SELECT count(*) FROM generation_extents WHERE generation_id='wp2_gen') <> 2
       OR NOT EXISTS (SELECT FROM generation_extents WHERE generation_id='wp2_gen' AND seq=1
                      AND extent_id='wp2_live' AND plain_offset=0)
       OR NOT EXISTS (SELECT FROM generation_extents WHERE generation_id='wp2_gen' AND seq=2
                      AND extent_id='wp2_adopt' AND plain_offset=10)
    THEN RAISE EXCEPTION 'insert/adopt did not retain exactly the two original references'; END IF;

    INSERT INTO generation_extents VALUES ('wp2_shared',1,'wp2_live',0);
    INSERT INTO outbox(extent_id,generation_id,stage,next_at,updated_at,seq)
        VALUES ('wp2_live','wp2_gen','post',0,0,-20);
    INSERT INTO uploads(id,bucket_id,key,content_json,user_meta_json,state,initiated_at)
        VALUES ('wp2_upload','wp2_a','multipart','{}','{}','open',0);
    INSERT INTO upload_part_extents(upload_id,part_number,piece,extent_id) VALUES
        ('wp2_upload',1,1,'wp2_slice'), ('wp2_upload',1,2,'wp2_slice_plain');
    INSERT INTO upload_parts(upload_id,part_number,extent_id,size,etag,uploaded_at)
        VALUES ('wp2_upload',2,'wp2_legacy',10,'e',0);
    INSERT INTO articles(extent_id,idx,message_id,newsgroup,headers,cipher_offset,cipher_len,payload_sha256,state)
        VALUES ('wp2_adopt',1,'wp2-msg1','fixture','',0,11,'','planned'),
               ('wp2_slice_plain',1,'wp2-msg2','fixture','',0,11,'','planned'),
               ('wp2_live',1,'wp2-msg3','fixture','',0,11,'','planned');

    -- Each entry isolates a refusal trigger. Verify a prior statement rolls
    -- back too, rather than accepting silently skipped writes as refusals.
    FOREACH refusal IN ARRAY ARRAY[
        $q$INSERT INTO gc(id,extent_id,action,due_at) VALUES (-10,'wp2_live','shred_key',0)$q$,
        $q$UPDATE outbox SET stage='cancelled' WHERE extent_id='wp2_live'$q$,
        $q$UPDATE extents SET wrapped_file_key=NULL WHERE id='wp2_live'$q$,
        $q$UPDATE extents SET plan=NULL WHERE id='wp2_legacy'$q$,
        $q$UPDATE extents SET wrapped_file_key=NULL WHERE id='wp2_slice'$q$,
        $q$UPDATE extents SET plan=NULL WHERE id='wp2_slice'$q$,
        $q$DELETE FROM articles WHERE extent_id='wp2_adopt'$q$,
        $q$DELETE FROM articles WHERE extent_id='wp2_slice_plain'$q$
    ] LOOP
        BEGIN
            INSERT INTO meta VALUES ('wp2_must_rollback',1);
            EXECUTE refusal;
            RAISE EXCEPTION 'statement should have raised VL001: %', refusal;
        EXCEPTION WHEN SQLSTATE 'VL001' THEN
            IF EXISTS (SELECT FROM meta WHERE k='wp2_must_rollback') THEN
                RAISE EXCEPTION 'refusal did not roll back earlier work';
            END IF;
        END;
    END LOOP;

    DELETE FROM articles WHERE extent_id='wp2_live'; -- packed, still in service
    IF FOUND IS FALSE THEN RAISE EXCEPTION 'packed article was not deletable'; END IF;
    UPDATE uploads SET state='aborted' WHERE id='wp2_upload';
    UPDATE extents SET wrapped_file_key=NULL,plan=NULL WHERE id IN ('wp2_slice','wp2_legacy');
    IF EXISTS (SELECT FROM extents WHERE id IN ('wp2_slice','wp2_legacy')
               AND (wrapped_file_key IS NOT NULL OR plan IS NOT NULL))
    THEN RAISE EXCEPTION 'aborted upload still held its extents'; END IF;
    UPDATE generations SET state='superseded' WHERE id='wp2_shared';
    INSERT INTO gc(id,extent_id,action,due_at) VALUES (-10,'wp2_live','shred_key',0);
    UPDATE outbox SET stage='cancelled' WHERE extent_id='wp2_live';
    IF NOT FOUND THEN RAISE EXCEPTION 'non-shared outbox row was not cancellable'; END IF;
END;
$$;
SELECT json_agg(json_build_array(step,target,values_) ORDER BY step,target) FROM wp2_usage_trace;
