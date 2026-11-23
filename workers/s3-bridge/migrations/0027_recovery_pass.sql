-- Scheduled copy telemetry, not part of the catalogue's recovery data.
CREATE TABLE recovery_pass_job (
    pass_id           INTEGER NOT NULL,
    message_id        TEXT NOT NULL,
    copied            INTEGER NOT NULL,
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
    verified_write    INTEGER NOT NULL CHECK (verified_write IN (0, 1)),
    at                INTEGER NOT NULL,
    PRIMARY KEY (pass_id, message_id)
) WITHOUT ROWID;
CREATE INDEX recovery_pass_age ON recovery_pass_job (at);

-- Written even if a job verified a PUT but failed to enqueue its successor.
CREATE TABLE recovery_alarm_state (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    last_job_at             INTEGER NOT NULL,
    last_refused_at         INTEGER NOT NULL,
    last_verified_write_at  INTEGER NOT NULL,
    opened_at               INTEGER NOT NULL,
    last_refused_pass       INTEGER NOT NULL
);
