-- SQLite test twin of PostgreSQL stage 0008.
CREATE INDEX IF NOT EXISTS buckets_owner_name ON buckets (owner, name);
CREATE INDEX IF NOT EXISTS access_keys_principal ON access_keys (principal);
