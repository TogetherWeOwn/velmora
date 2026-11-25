-- velmora: d1-twin 0028_scrub.sql b460d12979f09579602c23023cd18f48b5e006d4d8dcfb3d085f3e1090024b58
-- No extent rewrite: all new summary columns are nullable.
ALTER TABLE extents
    ADD COLUMN last_scrubbed_at BIGINT,
    ADD COLUMN scrub_result TEXT COLLATE "C",
    ADD COLUMN scrub_next_at BIGINT;

CREATE TABLE scrub_state (
    id BIGINT PRIMARY KEY CHECK (id = 1),
    lease_token BIGINT NOT NULL DEFAULT 0,
    lease_until BIGINT,
    runs BIGINT NOT NULL DEFAULT 0,
    checked BIGINT NOT NULL DEFAULT 0,
    ok BIGINT NOT NULL DEFAULT 0,
    suspect BIGINT NOT NULL DEFAULT 0,
    repaired BIGINT NOT NULL DEFAULT 0,
    unrecoverable BIGINT NOT NULL DEFAULT 0,
    stalled BIGINT NOT NULL DEFAULT 0,
    incidents BIGINT NOT NULL DEFAULT 0,
    bytes_read BIGINT NOT NULL DEFAULT 0,
    last_run_at BIGINT,
    last_unrecoverable_at BIGINT,
    last_incident_at BIGINT,
    last_incident TEXT COLLATE "C",
    incident_clean BIGINT NOT NULL DEFAULT 0
);
INSERT INTO scrub_state(id) VALUES (1);
