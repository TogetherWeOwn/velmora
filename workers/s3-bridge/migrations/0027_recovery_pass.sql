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

CREATE TABLE recovery_alarm_state (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),
    last_problem_at         INTEGER NOT NULL,
    problem_destination     TEXT,
    problem_operation       TEXT,
    problem_kind            TEXT,
    problem_status          INTEGER,
    problem_code            TEXT,
    problem_counts          TEXT,
    opened_at               INTEGER NOT NULL,
    last_clean_sweep_at     INTEGER NOT NULL,
    last_clean_fresh_pass   INTEGER NOT NULL DEFAULT 0,
    last_clean_fresh_dest   TEXT,
    last_clean_walk_start   INTEGER NOT NULL,
    last_clean_walk_dest    TEXT,
    last_verified_write_at  INTEGER NOT NULL
);

-- One telemetry frontier, independent of the copy cursor and queue wire.
-- Missing observations leave a gap, which cannot certify a clean walk.
CREATE TABLE recovery_walk_frontier (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    began_at     INTEGER NOT NULL,
    destination  TEXT NOT NULL,
    next_tag     TEXT,
    last_from    TEXT NOT NULL,
    last_message TEXT NOT NULL,
    completed_by TEXT
);
