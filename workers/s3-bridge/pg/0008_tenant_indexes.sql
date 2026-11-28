-- velmora: no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS buckets_owner_name ON buckets (owner, name);
CREATE INDEX CONCURRENTLY IF NOT EXISTS access_keys_principal ON access_keys (principal);
