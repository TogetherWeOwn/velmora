-- State of the alerts Worker (its own small D1, not the catalogue).

-- One row per alert key.
CREATE TABLE alerts (
  key            TEXT PRIMARY KEY,              -- cron: <check>[:<id>]; host:<key>; ci:<key>
  source         TEXT NOT NULL,                 -- cron | host | ci | test
  severity       TEXT NOT NULL,                 -- page (email) | info (digest only)
  title          TEXT NOT NULL,
  detail         TEXT NOT NULL,
  active         INTEGER NOT NULL DEFAULT 0,    -- 1 while the condition holds
  active_since   INTEGER,                       -- ms; start of the current active run
  last_seen_at   INTEGER NOT NULL,              -- ms; last tick or report that saw it
  last_sent_at   INTEGER,                       -- ms; last email for this key
  seen_unsent    INTEGER NOT NULL DEFAULT 0,    -- reports since the last email
  sent_in_run    INTEGER NOT NULL DEFAULT 0,    -- emails in the current active run (reminder backoff)
  resolved_at    INTEGER                        -- ms; when it last stopped holding
) WITHOUT ROWID;

-- Every email sent (for the daily cap and the digest). Pruned after 8 days.
CREATE TABLE sends (
  id    INTEGER PRIMARY KEY,
  at    INTEGER NOT NULL,
  key   TEXT NOT NULL,
  kind  TEXT NOT NULL                           -- alert | digest
);
CREATE INDEX sends_at ON sends(at);

-- One row per dead-letter batch received. Pruned after 30 days.
CREATE TABLE dlq (
  id      INTEGER PRIMARY KEY,
  at      INTEGER NOT NULL,
  queue   TEXT NOT NULL,
  count   INTEGER NOT NULL,
  sample  TEXT                                  -- first message body, cut to 300 chars
);
CREATE INDEX dlq_at ON dlq(at);

-- Small values: last digest, previous post head, last export reading.
CREATE TABLE meta (
  k  TEXT PRIMARY KEY,
  v  TEXT NOT NULL
) WITHOUT ROWID;
