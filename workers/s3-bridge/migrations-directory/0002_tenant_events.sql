-- The event feed of the management plane: control changes and unit
-- events, one row each, in one feed for every tenant. `GET /v1/events`
-- reads it in `seq` order, and `GET /v1/tenants/{t}/events` reads one
-- tenant's part of it through the (tenant, seq) index. A position is
-- `e<epoch>.<seq>`. Additive only, like 0001.
--
-- `seq` is never used twice, also after the prune empties the table
-- (AUTOINCREMENT), so a position never names two events. `epoch` is the
-- feed's epoch when the row was written (`feed_epoch`). `source` names
-- what the event is of (a chain record, an hour), so a writer that
-- repeats itself after a lost answer writes one row. `data_json` names
-- ids and names only, never a secret or a URL.
CREATE TABLE tenant_events (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  epoch      INTEGER NOT NULL CHECK (epoch >= 0),
  tenant     TEXT NOT NULL,
  type       TEXT NOT NULL,
  source     TEXT NOT NULL,
  at         INTEGER NOT NULL,
  data_json  TEXT NOT NULL
);

CREATE INDEX tenant_events_tenant ON tenant_events (tenant, seq);
CREATE UNIQUE INDEX tenant_events_source ON tenant_events (tenant, source);

-- The feed's current epoch. A gate run starts a new one at its step 8
-- (the gate's epoch), and every row up to `base_seq` belongs to an older
-- epoch: a position of an older epoch answers `409 feed_reset`, and the
-- rows of an older epoch are not served again. No row = epoch 0, base 0.
CREATE TABLE feed_epoch (
  id        INTEGER PRIMARY KEY CHECK (id = 1),
  epoch     INTEGER NOT NULL CHECK (epoch >= 0),
  base_seq  INTEGER NOT NULL CHECK (base_seq >= 0)
);

-- Per tenant, the newest seq that the 30-day prune removed of that
-- tenant's events. A tenant position below it answers `409 feed_reset`,
-- so a poller never skips events silently, and a tenant whose own events
-- were not pruned never sees a false reset.
CREATE TABLE tenant_feed_pruned (
  tenant  TEXT PRIMARY KEY,
  seq     INTEGER NOT NULL CHECK (seq > 0)
);
