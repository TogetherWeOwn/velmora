-- Add the account catalogue without rewriting existing bucket or key rows.
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT COLLATE "C" NOT NULL PRIMARY KEY,
    external_ref TEXT COLLATE "C" NOT NULL UNIQUE,
    state TEXT COLLATE "C" NOT NULL DEFAULT 'active',
    suspension_mode TEXT COLLATE "C",
    display_name TEXT COLLATE "C",
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

-- Store only the digest of a disabled management token, never the token.
CREATE TABLE IF NOT EXISTS mgmt_tokens_disabled (
    token_sha256 TEXT COLLATE "C" NOT NULL PRIMARY KEY,
    token_class TEXT COLLATE "C" NOT NULL,
    disabled_at_ms BIGINT NOT NULL,
    reason TEXT COLLATE "C" NOT NULL
);
