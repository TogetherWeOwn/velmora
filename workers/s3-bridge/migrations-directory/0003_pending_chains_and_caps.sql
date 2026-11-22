-- The pending sweep steps from chain to chain on the primary key of
-- `pending_ops` and takes each chain's oldest row from this index, so a
-- pass reads O(chains) rows whatever the rows' ages (AM-75).
-- Additive only, like 0001 and 0002.
CREATE INDEX pending_ops_chain_created ON pending_ops (tenant, chain, created_at);

-- The global backstops per service token (ADR §6.3): one row per window,
-- token and action, counted up to the cap in one statement. `token` names
-- the service token (never its secret or hash); `action` is a fixed code
-- (`tenant_create`). The key starts with the window, so the prune of old
-- windows is one range of it.
CREATE TABLE token_caps (
  window_start  INTEGER NOT NULL,
  token         TEXT NOT NULL,
  action        TEXT NOT NULL,
  count         INTEGER NOT NULL CHECK (count > 0),
  PRIMARY KEY (window_start, token, action)
);
