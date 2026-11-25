-- velmora: d1-twin 0029_scrub_cadence.sql 91b30f7d931eaab2e0f06dee5008224498afc44f8c0ab304cf80d3bb3fed63c0
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
-- This table is empty when created; the populated extents indexes follow in 0005.
CREATE INDEX scrub_copies_due ON scrub_copies(backbone, LEAST(stat_at, full_at), extent_id);

ALTER TABLE scrub_state
    ADD COLUMN cadence_backbones TEXT COLLATE "C",
    ADD COLUMN cadence_after TEXT COLLATE "C",
    ADD COLUMN cadence_epoch BIGINT,
    ADD COLUMN incident_clean_by TEXT COLLATE "C",
    ADD COLUMN incident_body_by TEXT COLLATE "C";
UPDATE scrub_state SET incident_body_by = last_incident WHERE id = 1;
