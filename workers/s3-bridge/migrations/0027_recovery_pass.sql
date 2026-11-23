-- Scheduled recovery-copy telemetry only. One bounded, retry-idempotent
-- sequence per pass. No catalogue object names or provider response text.
CREATE TABLE recovery_pass_job (
    pass_id           INTEGER NOT NULL,
    job_seq           INTEGER NOT NULL CHECK (job_seq BETWEEN 0 AND 255),
    cursor_tag        TEXT NOT NULL,
    next_tag          TEXT,
    copied            INTEGER NOT NULL,
    failed            INTEGER NOT NULL,
    pending           INTEGER NOT NULL,
    source_unreadable INTEGER NOT NULL,
    refused_put       INTEGER NOT NULL,
    put_status        INTEGER,
    put_code          TEXT,
    refused_verify    INTEGER NOT NULL,
    verify_status     INTEGER,
    verify_code       TEXT,
    refused_plan      INTEGER NOT NULL,
    plan_status       INTEGER,
    plan_code         TEXT,
    unsignable        INTEGER NOT NULL,
    skipped_sweep     INTEGER NOT NULL CHECK (skipped_sweep IN (0, 1)),
    final             INTEGER NOT NULL CHECK (final IN (0, 1)),
    at                INTEGER NOT NULL,
    PRIMARY KEY (pass_id, job_seq)
) WITHOUT ROWID;

CREATE UNIQUE INDEX recovery_pass_final ON recovery_pass_job (pass_id) WHERE final = 1;
CREATE INDEX recovery_pass_age ON recovery_pass_job (at);
CREATE INDEX recovery_pass_verified ON recovery_pass_job (at) WHERE copied > 0;
