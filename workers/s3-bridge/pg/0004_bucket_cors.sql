-- The matching SQLite stage is in migrations-local, outside D1 migrations.
-- Bucket deletion removes its CORS row in the same guarded write batch.
CREATE TABLE IF NOT EXISTS bucket_cors (
    bucket_id TEXT COLLATE "C" NOT NULL PRIMARY KEY,
    doc TEXT COLLATE "C" NOT NULL,
    doc_sha256 TEXT COLLATE "C" NOT NULL,
    rules INTEGER NOT NULL,
    updated_at_ms BIGINT NOT NULL
);
