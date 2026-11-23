-- Best-effort, short-lived telemetry. This table is not a copy checkpoint.
CREATE TABLE recovery_copy_log (
    at       INTEGER NOT NULL,
    kind     TEXT    NOT NULL CHECK (kind IN ('job', 'walk', 'audit')),
    pass     INTEGER NOT NULL,
    swept    INTEGER NOT NULL DEFAULT 0,
    problems INTEGER NOT NULL DEFAULT 0,
    checked  INTEGER NOT NULL DEFAULT 0,
    detail   TEXT
);
CREATE INDEX recovery_copy_log_kind_at ON recovery_copy_log (kind, at);
CREATE INDEX recovery_copy_log_problem_at ON recovery_copy_log (at DESC, pass)
    WHERE kind = 'job' AND problems > 0;
CREATE INDEX recovery_copy_log_swept_at ON recovery_copy_log (at DESC)
    WHERE kind = 'job' AND swept = 1;
