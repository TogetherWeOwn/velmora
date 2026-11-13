-- velmora S3 bridge catalogue, schema version 1 (D1 / SQLite).
-- Every *_at and *_until column is Unix milliseconds.
-- Frozen: schema changes are new migration files, never edits to this one.

PRAGMA foreign_keys = ON;

-- Guard row for atomic batches: first statement of a guarded batch is
--   INSERT INTO tx_guard(ok) SELECT 0 WHERE NOT EXISTS (<guard predicate>);
-- A failed guard violates the CHECK, the statement errors, and D1 rolls back the whole batch.
CREATE TABLE tx_guard (ok INTEGER NOT NULL CHECK (ok = 1));

CREATE TABLE buckets (
  id            TEXT PRIMARY KEY,                 -- b_<16 hex>
  name          TEXT NOT NULL UNIQUE,             -- S3 bucket name (3..63, lowercase)
  owner         TEXT NOT NULL,                    -- principal
  bdk_wrapped   BLOB NOT NULL,                    -- WrappedKey (73 B)
  kek_version   INTEGER NOT NULL,
  disposable    INTEGER NOT NULL DEFAULT 0,       -- allows safety evict (drills)
  created_at    INTEGER NOT NULL
);

CREATE TABLE access_keys (
  access_key_id TEXT PRIMARY KEY,
  principal     TEXT NOT NULL,
  secret_wrapped BLOB NOT NULL,
  kek_version   INTEGER NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('active','disabled')),
  created_at    INTEGER NOT NULL
);

CREATE TABLE grants (
  access_key_id TEXT NOT NULL REFERENCES access_keys(access_key_id),
  bucket_id     TEXT NOT NULL REFERENCES buckets(id),
  perm          TEXT NOT NULL CHECK (perm IN ('rw','ro')),
  PRIMARY KEY (access_key_id, bucket_id)
) WITHOUT ROWID;

CREATE TABLE generations (
  id            TEXT PRIMARY KEY,                 -- g_<13 hex ms><16 hex>
  bucket_id     TEXT NOT NULL REFERENCES buckets(id),
  key           TEXT NOT NULL,
  state         TEXT NOT NULL CHECK (state IN ('live','superseded','deleted')),
  size          INTEGER NOT NULL,                 -- plaintext bytes
  etag          TEXT NOT NULL,                    -- quoted S3 ETag
  checksum_json TEXT,                             -- x-amz-checksum-* stored values
  content_json  TEXT NOT NULL,                    -- content-type/-disposition/-encoding/cache-control/expires
  user_meta_json TEXT NOT NULL,                   -- x-amz-meta-*
  extent_count  INTEGER NOT NULL,
  created_at    INTEGER NOT NULL,                 -- Last-Modified (ms)
  retired_at    INTEGER
);
CREATE INDEX generations_by_key ON generations(bucket_id, key, created_at);

CREATE TABLE objects (                            -- live pointer; absent = 404
  bucket_id     TEXT NOT NULL,
  key           TEXT NOT NULL,
  generation_id TEXT NOT NULL REFERENCES generations(id),
  PRIMARY KEY (bucket_id, key)
) WITHOUT ROWID;

CREATE TABLE extents (
  id             TEXT PRIMARY KEY,                -- x_<26 hex>
  bucket_id      TEXT NOT NULL REFERENCES buckets(id),
  generation_id  TEXT REFERENCES generations(id), -- NULL while only an upload part
  state          TEXT NOT NULL CHECK (state IN ('staged','committed')),  -- staged = upload part
  seq            INTEGER,                         -- order within generation
  plain_offset   INTEGER,
  plain_size     INTEGER NOT NULL,
  cipher_size    INTEGER NOT NULL,                -- media::ciphertext_size(plain_size)
  media_header   BLOB NOT NULL,                   -- 48 B media.v1 header
  key_mode       INTEGER NOT NULL DEFAULT 1,      -- KeyMode::Random
  wrapped_file_key BLOB,                          -- NULL = shredded
  plain_md5      BLOB NOT NULL,
  plain_sha256   BLOB NOT NULL,
  cipher_sha256  BLOB NOT NULL,
  safety_state   TEXT NOT NULL CHECK (safety_state IN ('held','releasing','released','deleted')),
  article_count  INTEGER,                         -- set by plan_articles; verification must match it
  plan_rev       INTEGER NOT NULL DEFAULT 0,      -- bumped when the article plan changes (repost, H4)
  last_verified_at INTEGER,                       -- health: newest full-ok verification
  release_evidence TEXT,                          -- JSON rows that authorized the release
  released_at    INTEGER,
  created_at     INTEGER NOT NULL
);
CREATE INDEX extents_by_generation ON extents(generation_id, seq);

CREATE TABLE articles (
  extent_id      TEXT NOT NULL REFERENCES extents(id),
  idx            INTEGER NOT NULL,
  message_id     TEXT NOT NULL UNIQUE,            -- bare, no <>
  newsgroup      TEXT NOT NULL,
  headers        BLOB NOT NULL,                   -- rendered obfuscated headers (repost = identical)
  cipher_offset  INTEGER NOT NULL,
  cipher_len     INTEGER NOT NULL,
  payload_sha256 BLOB NOT NULL,                   -- sha256 of decoded article payload
  state          TEXT NOT NULL CHECK (state IN ('planned','posted')),
  provider_id    TEXT,
  posted_at      INTEGER,
  PRIMARY KEY (extent_id, idx)
) WITHOUT ROWID;

CREATE TABLE verifications (
  extent_id      TEXT NOT NULL REFERENCES extents(id),
  backbone       TEXT NOT NULL,
  provider_id    TEXT NOT NULL,
  verified_at    INTEGER NOT NULL,
  plan_rev       INTEGER NOT NULL,
  articles_ok    INTEGER NOT NULL,
  articles_total INTEGER NOT NULL,
  result         TEXT NOT NULL CHECK (result IN ('ok','missing','corrupt','error')),
  PRIMARY KEY (extent_id, backbone, verified_at)
) WITHOUT ROWID;

CREATE TABLE outbox (
  extent_id      TEXT PRIMARY KEY REFERENCES extents(id),
  generation_id  TEXT NOT NULL,
  stage          TEXT NOT NULL CHECK (stage IN ('post','verify','release','done','cancelled','dead')),
  attempts       INTEGER NOT NULL DEFAULT 0,
  next_at        INTEGER NOT NULL,
  lease_token    INTEGER NOT NULL DEFAULT 0,      -- fencing token; +1 on every claim
  lease_owner    TEXT,
  lease_until    INTEGER,
  cursor         INTEGER NOT NULL DEFAULT 0,      -- resume point (verify/release: backbone index)
  last_error     TEXT,                            -- class only, never provider text with creds
  updated_at     INTEGER NOT NULL
);
CREATE INDEX outbox_due ON outbox(stage, next_at);

CREATE TABLE uploads (
  id             TEXT PRIMARY KEY,
  bucket_id      TEXT NOT NULL REFERENCES buckets(id),
  key            TEXT NOT NULL,
  content_json   TEXT NOT NULL,
  user_meta_json TEXT NOT NULL,
  state          TEXT NOT NULL CHECK (state IN ('open','completed','aborted')),
  revision       INTEGER NOT NULL DEFAULT 0,      -- +1 on every UploadPart / Abort / Complete
  completed_generation_id TEXT,                   -- completion receipt
  complete_digest BLOB,                           -- sha256 of the canonical (part_number, etag) list
  result_etag    TEXT,
  initiated_at   INTEGER NOT NULL
);
CREATE INDEX uploads_open ON uploads(bucket_id, key) WHERE state = 'open';

CREATE TABLE upload_parts (
  upload_id      TEXT NOT NULL REFERENCES uploads(id),
  part_number    INTEGER NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
  extent_id      TEXT NOT NULL REFERENCES extents(id),
  size           INTEGER NOT NULL,
  etag           TEXT NOT NULL,
  uploaded_at    INTEGER NOT NULL,
  PRIMARY KEY (upload_id, part_number)
) WITHOUT ROWID;

CREATE TABLE gc (
  id             INTEGER PRIMARY KEY,
  extent_id      TEXT NOT NULL,
  action         TEXT NOT NULL CHECK (action IN ('delete_cache','delete_safety','shred_key','drop_articles_meta')),
  due_at         INTEGER NOT NULL,
  done_at        INTEGER
);
CREATE INDEX gc_due ON gc(due_at) WHERE done_at IS NULL;

CREATE TABLE provider_permits (                   -- one row per allowed NNTP connection (§A.7)
  provider_id    TEXT NOT NULL,
  slot           INTEGER NOT NULL,
  token          INTEGER NOT NULL DEFAULT 0,      -- fencing token; +1 on every acquire
  holder         TEXT,
  lease_until    INTEGER NOT NULL DEFAULT 0,      -- 0 = free
  PRIMARY KEY (provider_id, slot)
) WITHOUT ROWID;

CREATE TABLE meta (                               -- small operational values
  k              TEXT PRIMARY KEY,                -- 'last_dispatch_at' (UnixMs) | 'guard_selftest_marker'
  v              INTEGER NOT NULL
) WITHOUT ROWID;
