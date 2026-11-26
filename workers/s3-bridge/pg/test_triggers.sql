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
-- Multi-row statements (one hour each), with row 2 covering part of each
-- table. Its cursor 'wp2_m' covers 'wp2_B', 'wp2_M', 'wp2_N' and 'wp2_c'
-- only in byte (C) order; a linguistic collation would order them around it.
INSERT INTO buckets(id,name,owner,bdk_wrapped,kek_version,created_at) VALUES
    ('wp2_c','wp2_c','wp2',decode('','hex'),1,0), ('wp2_d','wp2_d','wp2',decode('','hex'),1,0),
    ('wp2_e','wp2_e','wp2',decode('','hex'),1,0);
INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,
                    cipher_sha256,safety_state,created_at) VALUES
    ('wp2_B','wp2_a','staged',1,100,decode('','hex'),decode('','hex'),decode('','hex'),decode('','hex'),'held',0), ('wp2_M','wp2_a','staged',1,200,decode('','hex'),decode('','hex'),decode('','hex'),decode('','hex'),'releasing',0), ('wp2_N','wp2_a','staged',1,400,decode('','hex'),decode('','hex'),decode('','hex'),decode('','hex'),'released',0),
    ('wp2_c','wp2_a','staged',1,800,decode('','hex'),decode('','hex'),decode('','hex'),decode('','hex'),'deleted',0), ('wp2_n','wp2_a','staged',1,1600,decode('','hex'),decode('','hex'),decode('','hex'),decode('','hex'),'held',0), ('wp2_y','wp2_a','staged',1,3200,decode('','hex'),decode('','hex'),decode('','hex'),decode('','hex'),'released',0);
INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,
                    cipher_sha256,safety_state,created_at)
    SELECT id || '_none',bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,
           cipher_sha256,safety_state,created_at FROM extents WHERE id = 'wp2_none';
INSERT INTO wp2_usage_trace SELECT 'f1-extents-insert', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'f1-extents-insert', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'f1-extents-insert', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;

UPDATE extents SET
    safety_state = CASE id WHEN 'wp2_B' THEN 'releasing' WHEN 'wp2_M' THEN 'released'
                           WHEN 'wp2_N' THEN 'deleted' WHEN 'wp2_n' THEN 'released' ELSE safety_state END,
    cipher_size = CASE id WHEN 'wp2_c' THEN 801 WHEN 'wp2_y' THEN 3201 ELSE cipher_size END
 WHERE id IN ('wp2_B','wp2_M','wp2_N','wp2_c','wp2_n','wp2_y');
UPDATE extents SET safety_state = 'deleted' WHERE id IN ('wp2_c','wp2_N');
UPDATE extents SET safety_state = 'held' WHERE id = 'wp2_B';
UPDATE extents SET cipher_size = 150 WHERE id = 'wp2_B';
UPDATE extents SET released_at = 14400000 WHERE id IN ('wp2_M','wp2_y');
UPDATE extents SET safety_state = 'held' WHERE id = 'wp2_none';
DELETE FROM extents WHERE id = 'wp2_none';
INSERT INTO wp2_usage_trace SELECT 'f2-extents-update', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'f2-extents-update', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'f2-extents-update', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;

INSERT INTO outbox(extent_id,generation_id,stage,next_at,updated_at,seq) VALUES
    ('wp2_B','g_f','post',0,0,-101), ('wp2_M','g_f','verify',0,0,-102), ('wp2_N','g_f','release',0,0,-103),
    ('wp2_c','g_f','done',0,0,-104), ('wp2_n','g_f','post',0,0,-105);
INSERT INTO outbox(extent_id,generation_id,stage,next_at,updated_at,seq) VALUES
    ('wp2_B','g_f','dead',0,0,-107), ('wp2_y','g_f','dead',0,0,-106)
    ON CONFLICT DO NOTHING;
INSERT INTO outbox(extent_id,generation_id,stage,next_at,updated_at,seq)
    SELECT extent_id,generation_id,stage,next_at,updated_at,seq - 1000 FROM outbox WHERE extent_id = 'wp2_none';
INSERT INTO wp2_usage_trace SELECT 'f3-outbox-insert', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'f3-outbox-insert', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'f3-outbox-insert', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;

-- Hour 4 (current hour 3): row 1 files hour 3 first.
UPDATE outbox SET
    stage = CASE extent_id WHEN 'wp2_B' THEN 'verify' WHEN 'wp2_M' THEN 'done' WHEN 'wp2_N' THEN 'done'
                           WHEN 'wp2_n' THEN 'verify' WHEN 'wp2_y' THEN 'dead' ELSE stage END,
    updated_at = 14400000
 WHERE extent_id IN ('wp2_B','wp2_M','wp2_N','wp2_c','wp2_n','wp2_y');
UPDATE outbox SET stage = 'verify', updated_at = 14400000 WHERE extent_id = 'wp2_c';
-- verify->done: extent deleted (wp2_c), released with released_at NULL (wp2_n).
UPDATE outbox SET stage = 'done', updated_at = 14400000 WHERE extent_id IN ('wp2_c','wp2_n');
UPDATE outbox SET stage = CASE extent_id WHEN 'wp2_B' THEN 'dead' ELSE 'cancelled' END, updated_at = 14400000
 WHERE extent_id IN ('wp2_B','wp2_M');
UPDATE outbox SET stage = 'post', updated_at = 14400000 WHERE extent_id IN ('wp2_B','wp2_M','wp2_n');
UPDATE outbox SET stage = 'verify', updated_at = 14400000 WHERE extent_id = 'wp2_none';
INSERT INTO wp2_usage_trace SELECT 'f4-outbox-stage', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'f4-outbox-stage', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'f4-outbox-stage', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;

UPDATE outbox SET last_error = 'same', updated_at = 14400000 WHERE extent_id IN ('wp2_B','wp2_M','wp2_n');
UPDATE outbox SET last_error = 'same', updated_at = 14400000 WHERE extent_id IN ('wp2_B','wp2_M','wp2_n');
UPDATE outbox SET last_error = NULL, updated_at = 14400000 WHERE extent_id = 'wp2_B';
UPDATE outbox SET last_error = CASE extent_id WHEN 'wp2_M' THEN 'x' ELSE NULL END, updated_at = 14400000
 WHERE extent_id IN ('wp2_M','wp2_n');
UPDATE outbox SET updated_at = 14400000 WHERE extent_id IN ('wp2_M','wp2_n');
UPDATE outbox SET stage = CASE extent_id WHEN 'wp2_B' THEN 'verify' ELSE stage END, last_error = 'e',
                  updated_at = 14400000
 WHERE extent_id IN ('wp2_B','wp2_M');
UPDATE outbox SET last_error = 'none', updated_at = 14400000 WHERE extent_id = 'wp2_none';
INSERT INTO wp2_usage_trace SELECT 'f5-outbox-failure', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'f5-outbox-failure', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'f5-outbox-failure', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;

-- Hour 5 files hour 4; a later statement of hour 4 joins the hour-5 bucket.
UPDATE outbox SET stage = 'done', updated_at = 18000000 WHERE extent_id IN ('wp2_B','wp2_M');
UPDATE outbox SET last_error = 'late', updated_at = 14400000 WHERE extent_id = 'wp2_n';
UPDATE outbox SET stage = 'verify', updated_at = 14400000 WHERE extent_id = 'wp2_B';
-- Filing into an hour already filed adds to it.
UPDATE usage_global SET hour = 4 WHERE id = 1;
UPDATE outbox SET stage = 'done', updated_at = 18000000 WHERE extent_id = 'wp2_B';
INSERT INTO wp2_usage_trace SELECT 'f6-hour-filing', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'f6-hour-filing', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'f6-hour-filing', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;

-- At hour 0 a roll drops the counts.
UPDATE usage_global SET hour = 0 WHERE id IN (1, 2);
UPDATE outbox SET stage = 'verify', last_error = NULL, updated_at = 21600000 WHERE extent_id IN ('wp2_B','wp2_M');
INSERT INTO wp2_usage_trace SELECT 'f7-hour-zero', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'f7-hour-zero', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'f7-hour-zero', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;

-- Mixed hours in one statement apply in ascending hour order. Key, rowid
-- and hour order agree here, so SQLite's per-row order is the same.
-- velmora: sqlite-key-order
UPDATE outbox SET stage = 'done',
                  updated_at = CASE extent_id WHEN 'wp2_B' THEN 25200000 WHEN 'wp2_M' THEN 28800000 ELSE 32400000 END
 WHERE extent_id IN ('wp2_B','wp2_M','wp2_n');
UPDATE outbox SET stage = 'post', updated_at = 32400000 WHERE extent_id = 'wp2_M';
-- A stage change of hour 10 and a failure of hour 11 in one statement:
-- the post is filed in hour 10.
-- velmora: sqlite-key-order
UPDATE outbox SET stage = CASE extent_id WHEN 'wp2_M' THEN 'verify' ELSE stage END,
                  last_error = CASE extent_id WHEN 'wp2_n' THEN 'late' ELSE last_error END,
                  updated_at = CASE extent_id WHEN 'wp2_M' THEN 36000000 ELSE 39600000 END
 WHERE extent_id IN ('wp2_M','wp2_n');
UPDATE outbox SET stage = 'dead', updated_at = 43200000 WHERE extent_id = 'wp2_M';
INSERT INTO wp2_usage_trace SELECT 'f8-mixed-hours', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'f8-mixed-hours', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'f8-mixed-hours', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;

DELETE FROM outbox WHERE extent_id IN ('wp2_B','wp2_M','wp2_N','wp2_c','wp2_n','wp2_y','wp2_none');
DELETE FROM extents WHERE id IN ('wp2_B','wp2_M','wp2_N','wp2_c','wp2_n','wp2_y');
INSERT INTO wp2_usage_trace SELECT 'f9-delete', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'f9-delete', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'f9-delete', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;

-- generations: cursor 'g_m' covers 'g_B' and 'g_a' only in byte order.
INSERT INTO generations(id,bucket_id,key,state,size,etag,content_json,user_meta_json,extent_count,created_at) VALUES
    ('g_B','wp2_a','f1','live',1,'e','{}','{}',0,0), ('g_a','wp2_b','f2','live',2,'e','{}','{}',0,0),
    ('g_n','wp2_c','f3','live',4,'e','{}','{}',0,0), ('g_s','wp2_e','f4','superseded',8,'e','{}','{}',0,0),
    ('g_x1','wp2_c','f5','live',5,'e','{}','{}',0,0), ('g_x2','wp2_d','f6','live',5,'e','{}','{}',0,0);
INSERT INTO generations(id,bucket_id,key,state,size,etag,content_json,user_meta_json,extent_count,created_at)
    SELECT id,bucket_id,key,state,size,etag,content_json,user_meta_json,extent_count,created_at
      FROM generations WHERE id = 'g_none';
INSERT INTO wp2_usage_trace SELECT 'g1-generations-insert', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'g1-generations-insert', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'g1-generations-insert', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;

UPDATE generations SET
    state = CASE id WHEN 'g_B' THEN 'superseded' WHEN 'g_s' THEN 'live' ELSE state END,
    size = CASE id WHEN 'g_a' THEN 3 ELSE size END,
    bucket_id = CASE id WHEN 'g_n' THEN 'wp2_a' ELSE bucket_id END
 WHERE id IN ('g_B','g_a','g_n','g_s');
UPDATE generations SET size = size, bucket_id = bucket_id WHERE id IN ('g_a','g_n');
UPDATE generations SET state = 'deleted', retired_at = 1 WHERE id = 'g_B';
UPDATE generations SET state = 'live' WHERE id = 'g_none';
-- Two covered generations swap buckets: no net change, rows are created.
UPDATE usage_global SET cur_g = 'g_y' WHERE id = 2;
UPDATE generations SET bucket_id = CASE id WHEN 'g_x1' THEN 'wp2_d' ELSE 'wp2_c' END WHERE id IN ('g_x1','g_x2');
INSERT INTO wp2_usage_trace SELECT 'g2-generations-update', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'g2-generations-update', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'g2-generations-update', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;

DELETE FROM generations WHERE id IN ('g_B','g_a','g_n','g_s','g_x1','g_x2','g_none');
UPDATE usage_global SET cur_g = 'g_m' WHERE id = 2;
INSERT INTO wp2_usage_trace SELECT 'g3-generations-delete', 'global-' || id,
    x_unreleased || ',' || unreleased_bytes || ',' || x_released || ',' || released_bytes || ',' || x_deleted
    || ',' || ob_post || ',' || ob_verify || ',' || ob_release || ',' || ob_done || ',' || ob_cancelled || ',' || ob_dead
    || ',' || posts_total || ',' || verifies_total || ',' || releases_total || ',' || dead_total || ',' || failures_total
    || ',' || hour || ',' || h_posts || ',' || h_verifies || ',' || h_releases || ',' || h_dead || ',' || h_failures
    FROM usage_global;
INSERT INTO wp2_usage_trace SELECT 'g3-generations-delete', 'bucket-' || kind || '-' || bucket_id,
    live_objects || ',' || live_bytes FROM usage_buckets;
INSERT INTO wp2_usage_trace SELECT 'g3-generations-delete', 'hour-' || hour,
    posts || ',' || verifies || ',' || releases || ',' || dead || ',' || failures FROM usage_hours;
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
-- PostgreSQL only (SQLite applies rows in key order): one statement whose
-- lower-key row fails in a later hour than its higher-key row's stage
-- change must equal the same changes as separate statements in ascending
-- hour order. Each variant runs in a block that is rolled back.
DO $$
DECLARE
    combined text;
    separate text;
    filed bigint;
BEGIN
    INSERT INTO extents(id,bucket_id,state,plain_size,cipher_size,media_header,plain_md5,plain_sha256,
                        cipher_sha256,safety_state,created_at) VALUES
        ('wp2_pa','wp2_a','staged',1,1,'','','','','held',0), ('wp2_pb','wp2_a','staged',1,1,'','','','','held',0);
    INSERT INTO outbox(extent_id,generation_id,stage,next_at,updated_at,seq) VALUES
        ('wp2_pa','g_p','verify',0,0,-201), ('wp2_pb','g_p','post',0,0,-202);
    BEGIN
        UPDATE outbox SET stage = CASE extent_id WHEN 'wp2_pb' THEN 'verify' ELSE stage END,
                          last_error = CASE extent_id WHEN 'wp2_pa' THEN 'late' ELSE last_error END,
                          updated_at = CASE extent_id WHEN 'wp2_pa' THEN 75600000 ELSE 72000000 END
         WHERE extent_id IN ('wp2_pa','wp2_pb');
        SELECT (SELECT string_agg(g::text, ';' ORDER BY g.id) FROM usage_global g) || '|'
               || COALESCE((SELECT string_agg(h::text, ';' ORDER BY h.hour) FROM usage_hours h), '') INTO combined;
        SELECT posts INTO filed FROM usage_hours WHERE hour = 20;
        RAISE EXCEPTION USING ERRCODE = 'VL990';
    EXCEPTION WHEN SQLSTATE 'VL990' THEN NULL;
    END;
    BEGIN
        UPDATE outbox SET stage = 'verify', updated_at = 72000000 WHERE extent_id = 'wp2_pb';
        UPDATE outbox SET last_error = 'late', updated_at = 75600000 WHERE extent_id = 'wp2_pa';
        SELECT (SELECT string_agg(g::text, ';' ORDER BY g.id) FROM usage_global g) || '|'
               || COALESCE((SELECT string_agg(h::text, ';' ORDER BY h.hour) FROM usage_hours h), '') INTO separate;
        RAISE EXCEPTION USING ERRCODE = 'VL990';
    EXCEPTION WHEN SQLSTATE 'VL990' THEN NULL;
    END;
    IF combined IS NULL OR combined IS DISTINCT FROM separate THEN
        RAISE EXCEPTION 'mixed-hour statement differs from ascending separate statements: % / %', combined, separate;
    END IF;
    IF filed IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'the hour-20 post was not filed in hour 20 (posts %)', filed;
    END IF;
END;
$$;
SELECT json_agg(json_build_array(step,target,values_) ORDER BY step,target) FROM wp2_usage_trace;
