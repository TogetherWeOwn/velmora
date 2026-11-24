-- Final D1 schema through 0027; apply before copying any rows.
-- velmora: d1-baseline 0001-0022,0025-0027 f8de1bfa9f219f30a2f955a1b8d9be6cdba66cf51edd6add1df1653b48f79218
-- The six rowid-table text PKs are NOT NULL in PostgreSQL; the copy
-- census must reject NULLs in those source columns. No history is replayed.
CREATE TABLE tx_guard (
    ok BIGINT NOT NULL CONSTRAINT tx_guard_ok CHECK (ok = 1)
);

CREATE TABLE buckets (
    id TEXT COLLATE "C" PRIMARY KEY,
    name TEXT COLLATE "C" NOT NULL UNIQUE,
    owner TEXT COLLATE "C" NOT NULL,
    bdk_wrapped BYTEA NOT NULL,
    kek_version BIGINT NOT NULL,
    disposable BIGINT NOT NULL DEFAULT 0,
    created_at BIGINT NOT NULL
);

CREATE TABLE access_keys (
    access_key_id TEXT COLLATE "C" PRIMARY KEY,
    principal TEXT COLLATE "C" NOT NULL,
    secret_wrapped BYTEA NOT NULL,
    kek_version BIGINT NOT NULL,
    status TEXT COLLATE "C" NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at BIGINT NOT NULL
);

CREATE TABLE grants (
    access_key_id TEXT COLLATE "C" NOT NULL REFERENCES access_keys(access_key_id),
    bucket_id TEXT COLLATE "C" NOT NULL REFERENCES buckets(id),
    perm TEXT COLLATE "C" NOT NULL CHECK (perm IN ('rw', 'ro')),
    PRIMARY KEY (access_key_id, bucket_id)
);

CREATE TABLE generations (
    id TEXT COLLATE "C" PRIMARY KEY,
    bucket_id TEXT COLLATE "C" NOT NULL REFERENCES buckets(id),
    key TEXT COLLATE "C" NOT NULL,
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('live', 'superseded', 'deleted')),
    size BIGINT NOT NULL,
    etag TEXT COLLATE "C" NOT NULL,
    checksum_json TEXT COLLATE "C",
    content_json TEXT COLLATE "C" NOT NULL,
    user_meta_json TEXT COLLATE "C" NOT NULL,
    extent_count BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    retired_at BIGINT
);

CREATE TABLE objects (
    bucket_id TEXT COLLATE "C" NOT NULL,
    key TEXT COLLATE "C" NOT NULL,
    generation_id TEXT COLLATE "C" NOT NULL REFERENCES generations(id),
    PRIMARY KEY (bucket_id, key)
);

CREATE TABLE extents (
    id TEXT COLLATE "C" PRIMARY KEY,
    bucket_id TEXT COLLATE "C" NOT NULL REFERENCES buckets(id),
    generation_id TEXT COLLATE "C" REFERENCES generations(id),
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('staged', 'committed')),
    seq BIGINT,
    plain_offset BIGINT,
    plain_size BIGINT NOT NULL,
    cipher_size BIGINT NOT NULL,
    media_header BYTEA NOT NULL,
    key_mode BIGINT NOT NULL DEFAULT 1,
    wrapped_file_key BYTEA,
    plain_md5 BYTEA NOT NULL,
    plain_sha256 BYTEA NOT NULL,
    cipher_sha256 BYTEA NOT NULL,
    safety_state TEXT COLLATE "C" NOT NULL CHECK (safety_state IN ('held', 'releasing', 'released', 'deleted')),
    article_count BIGINT,
    plan_rev BIGINT NOT NULL DEFAULT 0,
    last_verified_at BIGINT,
    release_evidence TEXT COLLATE "C",
    released_at BIGINT,
    created_at BIGINT NOT NULL,
    hot_safety_bytes BIGINT NOT NULL DEFAULT 0,
    hot_cache_bytes BIGINT NOT NULL DEFAULT 0,
    last_read_at BIGINT,
    evict_seq BIGINT NOT NULL DEFAULT 0,
    plan BYTEA,
    posted_at BIGINT,
    reposted_at BIGINT,
    parity BYTEA,
    parity_count BIGINT
);

CREATE TABLE articles (
    extent_id TEXT COLLATE "C" NOT NULL REFERENCES extents(id),
    idx BIGINT NOT NULL,
    message_id TEXT COLLATE "C" NOT NULL UNIQUE,
    newsgroup TEXT COLLATE "C" NOT NULL,
    headers BYTEA NOT NULL,
    cipher_offset BIGINT NOT NULL,
    cipher_len BIGINT NOT NULL,
    payload_sha256 BYTEA NOT NULL,
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('planned', 'posted')),
    provider_id TEXT COLLATE "C",
    posted_at BIGINT,
    yenc_name TEXT COLLATE "C" CHECK (yenc_name IS NULL OR
        (length(yenc_name) BETWEEN 1 AND 64 AND yenc_name !~ '[^0-9a-z]')),
    reposted_at BIGINT,
    PRIMARY KEY (extent_id, idx)
);

CREATE TABLE verifications (
    extent_id TEXT COLLATE "C" NOT NULL REFERENCES extents(id),
    backbone TEXT COLLATE "C" NOT NULL,
    provider_id TEXT COLLATE "C" NOT NULL,
    verified_at BIGINT NOT NULL,
    plan_rev BIGINT NOT NULL,
    articles_ok BIGINT NOT NULL,
    articles_total BIGINT NOT NULL,
    result TEXT COLLATE "C" NOT NULL CHECK (result IN ('ok', 'missing', 'corrupt', 'error')),
    kind TEXT COLLATE "C" NOT NULL DEFAULT 'body' CHECK (kind IN ('body', 'stat')),
    articles_present BIGINT NOT NULL DEFAULT 0,
    mode TEXT COLLATE "C",
    lease_token BIGINT,
    PRIMARY KEY (extent_id, backbone, verified_at)
);

CREATE TABLE outbox (
    extent_id TEXT COLLATE "C" PRIMARY KEY REFERENCES extents(id),
    generation_id TEXT COLLATE "C" NOT NULL,
    stage TEXT COLLATE "C" NOT NULL CHECK (stage IN ('post', 'verify', 'release', 'done', 'cancelled', 'dead')),
    attempts BIGINT NOT NULL DEFAULT 0,
    next_at BIGINT NOT NULL,
    lease_token BIGINT NOT NULL DEFAULT 0,
    lease_owner TEXT COLLATE "C",
    lease_until BIGINT,
    cursor BIGINT NOT NULL DEFAULT 0,
    last_error TEXT COLLATE "C",
    updated_at BIGINT NOT NULL,
    sent_at BIGINT,
    -- Preserve the D1 rowid tie-break and revive cursor without exposing ctid.
    seq BIGINT GENERATED BY DEFAULT AS IDENTITY UNIQUE
);

CREATE TABLE uploads (
    id TEXT COLLATE "C" PRIMARY KEY,
    bucket_id TEXT COLLATE "C" NOT NULL REFERENCES buckets(id),
    key TEXT COLLATE "C" NOT NULL,
    content_json TEXT COLLATE "C" NOT NULL,
    user_meta_json TEXT COLLATE "C" NOT NULL,
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('open', 'completed', 'aborted')),
    revision BIGINT NOT NULL DEFAULT 0,
    completed_generation_id TEXT COLLATE "C",
    complete_digest BYTEA,
    result_etag TEXT COLLATE "C",
    initiated_at BIGINT NOT NULL
);

CREATE TABLE upload_parts (
    upload_id TEXT COLLATE "C" NOT NULL REFERENCES uploads(id),
    part_number BIGINT NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
    extent_id TEXT COLLATE "C" NOT NULL REFERENCES extents(id),
    size BIGINT NOT NULL,
    etag TEXT COLLATE "C" NOT NULL,
    uploaded_at BIGINT NOT NULL,
    PRIMARY KEY (upload_id, part_number)
);

CREATE TABLE gc (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    extent_id TEXT COLLATE "C" NOT NULL,
    action TEXT COLLATE "C" NOT NULL CHECK (action IN ('delete_cache', 'delete_safety', 'shred_key', 'drop_articles_meta')),
    due_at BIGINT NOT NULL,
    done_at BIGINT
);

CREATE TABLE provider_permits (
    provider_id TEXT COLLATE "C" NOT NULL,
    slot BIGINT NOT NULL,
    token BIGINT NOT NULL DEFAULT 0,
    holder TEXT COLLATE "C",
    lease_until BIGINT NOT NULL DEFAULT 0,
    pool TEXT COLLATE "C",
    background BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (provider_id, slot)
);

CREATE TABLE meta (k TEXT COLLATE "C" PRIMARY KEY, v BIGINT NOT NULL);

CREATE TABLE provider_health (
    provider_id TEXT COLLATE "C" PRIMARY KEY,
    failures BIGINT NOT NULL DEFAULT 0,
    cooldowns BIGINT NOT NULL DEFAULT 0,
    cooldown_until BIGINT NOT NULL DEFAULT 0,
    last_failure_at BIGINT,
    last_ok_at BIGINT,
    last_failure_reason TEXT COLLATE "C"
);

CREATE TABLE scan_cursors (k TEXT COLLATE "C" PRIMARY KEY, v TEXT COLLATE "C" NOT NULL);

CREATE TABLE generation_extents (
    generation_id TEXT COLLATE "C" NOT NULL REFERENCES generations(id),
    seq BIGINT NOT NULL,
    extent_id TEXT COLLATE "C" NOT NULL REFERENCES extents(id),
    plain_offset BIGINT NOT NULL,
    PRIMARY KEY (generation_id, seq)
);

CREATE TABLE key_floors (
    bucket_id TEXT COLLATE "C" NOT NULL REFERENCES buckets(id),
    key TEXT COLLATE "C" NOT NULL,
    floor_id TEXT COLLATE "C" NOT NULL,
    unpublished BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_id, key)
);

CREATE TABLE restore_state (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('replaying', 'complete')),
    since_ms BIGINT NOT NULL,
    started_at BIGINT NOT NULL,
    finished_at BIGINT,
    reached_phase BIGINT,
    reached_after TEXT COLLATE "C",
    reached_extent BIGINT
);

CREATE TABLE rollback_stamp (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    counter BIGINT NOT NULL CHECK (counter >= 0),
    catalogue_id TEXT COLLATE "C" NOT NULL,
    rolled_back_at BIGINT
);

CREATE TABLE write_intents (
    extent_id TEXT COLLATE "C" PRIMARY KEY,
    write_id TEXT COLLATE "C" NOT NULL,
    tenant_id TEXT COLLATE "C" NOT NULL DEFAULT 't_0000000000000000',
    generation_id TEXT COLLATE "C",
    state TEXT COLLATE "C" NOT NULL CHECK (state IN ('open', 'abandoned', 'sweeping', 'kept')),
    created_at BIGINT NOT NULL
);

CREATE TABLE upload_part_extents (
    upload_id TEXT COLLATE "C" NOT NULL REFERENCES uploads(id),
    part_number BIGINT NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
    piece BIGINT NOT NULL CHECK (piece >= 1),
    tenant_id TEXT COLLATE "C" NOT NULL DEFAULT 't_0000000000000000',
    extent_id TEXT COLLATE "C" NOT NULL REFERENCES extents(id),
    PRIMARY KEY (upload_id, part_number, piece)
);

CREATE TABLE verify_escalations (
    backbone TEXT COLLATE "C" PRIMARY KEY,
    until BIGINT NOT NULL,
    raised_at BIGINT NOT NULL,
    extent_id TEXT COLLATE "C" NOT NULL,
    result TEXT COLLATE "C" NOT NULL CHECK (result IN ('missing', 'corrupt', 'error'))
);

CREATE TABLE verify_raises (
    extent_id TEXT COLLATE "C" NOT NULL,
    backbone TEXT COLLATE "C" NOT NULL,
    plan_rev BIGINT NOT NULL,
    raised_at BIGINT NOT NULL,
    PRIMARY KEY (extent_id, backbone, plan_rev)
);

CREATE TABLE usage_global (
    id BIGINT PRIMARY KEY CHECK (id IN (1, 2)),
    cur_x TEXT COLLATE "C" NOT NULL DEFAULT '',
    all_x BIGINT NOT NULL DEFAULT 0,
    cur_o TEXT COLLATE "C" NOT NULL DEFAULT '',
    all_o BIGINT NOT NULL DEFAULT 0,
    cur_g TEXT COLLATE "C" NOT NULL DEFAULT '',
    all_g BIGINT NOT NULL DEFAULT 0,
    x_unreleased BIGINT NOT NULL DEFAULT 0,
    unreleased_bytes BIGINT NOT NULL DEFAULT 0,
    x_released BIGINT NOT NULL DEFAULT 0,
    released_bytes BIGINT NOT NULL DEFAULT 0,
    x_deleted BIGINT NOT NULL DEFAULT 0,
    ob_post BIGINT NOT NULL DEFAULT 0,
    ob_verify BIGINT NOT NULL DEFAULT 0,
    ob_release BIGINT NOT NULL DEFAULT 0,
    ob_done BIGINT NOT NULL DEFAULT 0,
    ob_cancelled BIGINT NOT NULL DEFAULT 0,
    ob_dead BIGINT NOT NULL DEFAULT 0,
    posts_total BIGINT NOT NULL DEFAULT 0,
    verifies_total BIGINT NOT NULL DEFAULT 0,
    releases_total BIGINT NOT NULL DEFAULT 0,
    dead_total BIGINT NOT NULL DEFAULT 0,
    failures_total BIGINT NOT NULL DEFAULT 0,
    hour BIGINT NOT NULL DEFAULT 0,
    h_posts BIGINT NOT NULL DEFAULT 0,
    h_verifies BIGINT NOT NULL DEFAULT 0,
    h_releases BIGINT NOT NULL DEFAULT 0,
    h_dead BIGINT NOT NULL DEFAULT 0,
    h_failures BIGINT NOT NULL DEFAULT 0,
    pass BIGINT NOT NULL DEFAULT 0,
    started_at BIGINT NOT NULL DEFAULT 0,
    rows_seen BIGINT NOT NULL DEFAULT 0,
    adopt BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE usage_hours (
    hour BIGINT PRIMARY KEY,
    posts BIGINT NOT NULL,
    verifies BIGINT NOT NULL,
    releases BIGINT NOT NULL,
    dead BIGINT NOT NULL,
    failures BIGINT NOT NULL
);

CREATE TABLE usage_buckets (
    kind BIGINT NOT NULL,
    bucket_id TEXT COLLATE "C" NOT NULL,
    live_objects BIGINT NOT NULL DEFAULT 0,
    live_bytes BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (kind, bucket_id)
);

CREATE TABLE usage_recounts (
    id BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
    started_at BIGINT NOT NULL,
    finished_at BIGINT NOT NULL,
    rows BIGINT NOT NULL,
    adopted BIGINT NOT NULL,
    drift BIGINT NOT NULL,
    detail TEXT COLLATE "C"
);

CREATE TABLE recovery_copy_log (
    at BIGINT NOT NULL,
    kind TEXT COLLATE "C" NOT NULL CHECK (kind IN ('job', 'walk', 'audit')),
    pass BIGINT NOT NULL,
    swept BIGINT NOT NULL DEFAULT 0,
    problems BIGINT NOT NULL DEFAULT 0,
    checked BIGINT NOT NULL DEFAULT 0,
    detail TEXT COLLATE "C"
);
