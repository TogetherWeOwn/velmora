-- velmora: sqlite-twin 0005_scrub.sql f21390558eec06dbe551e2841f2f8a1df0bb117b2f3588d56f2e2c12081d2290
-- Additive only. The extents indexes follow in 0006, built concurrently.
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

-- The constant default does not rewrite extents in PostgreSQL.
ALTER TABLE extents ADD COLUMN scrub_enrolled BIGINT NOT NULL DEFAULT 0;

CREATE TABLE scrub_copies (
    extent_id TEXT COLLATE "C" NOT NULL REFERENCES extents(id) ON DELETE CASCADE,
    backbone TEXT COLLATE "C" NOT NULL,
    stat_at BIGINT NOT NULL,
    full_at BIGINT NOT NULL,
    stat_phase_at BIGINT NOT NULL,
    full_phase_at BIGINT NOT NULL,
    stat_loss_at BIGINT,
    full_loss_at BIGINT,
    PRIMARY KEY (extent_id, backbone)
);
-- This table is empty when created, so its index is built here.
CREATE INDEX scrub_copies_due ON scrub_copies(backbone, LEAST(stat_at, full_at), extent_id);

ALTER TABLE scrub_state
    ADD COLUMN cadence_backbones TEXT COLLATE "C",
    ADD COLUMN cadence_after TEXT COLLATE "C",
    ADD COLUMN cadence_epoch BIGINT,
    ADD COLUMN incident_clean_by TEXT COLLATE "C",
    ADD COLUMN incident_body_by TEXT COLLATE "C";
UPDATE scrub_state SET incident_body_by = last_incident WHERE id = 1;
