-- SQLite twin for local development and tests. Do not apply to frozen D1.
CREATE TABLE IF NOT EXISTS bucket_cors (
    bucket_id TEXT NOT NULL PRIMARY KEY,
    doc TEXT NOT NULL,
    doc_sha256 TEXT NOT NULL,
    rules INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);
