-- SQLite test twin of PostgreSQL stage 0007.
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT NOT NULL PRIMARY KEY,
    external_ref TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL DEFAULT 'active',
    suspension_mode TEXT,
    display_name TEXT,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mgmt_tokens_disabled (
    token_sha256 TEXT NOT NULL PRIMARY KEY,
    token_class TEXT NOT NULL,
    disabled_at_ms INTEGER NOT NULL,
    reason TEXT NOT NULL
);
