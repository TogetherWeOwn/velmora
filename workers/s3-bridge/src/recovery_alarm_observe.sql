-- Values are event times, not delivery times. An out-of-order delivery
-- cannot replace a newer event or reopen an already verified incident.
INSERT INTO recovery_alarm_state (
    id, last_job_at, last_refused_at, last_verified_write_at, opened_at, last_refused_pass
)
VALUES (1, ?1, ?2, ?3, CASE WHEN ?2 > ?3 THEN ?2 ELSE 0 END, CASE WHEN ?2 > 0 THEN ?4 ELSE 0 END)
ON CONFLICT (id) DO UPDATE SET
    last_job_at = max(last_job_at, excluded.last_job_at),
    last_refused_pass = CASE WHEN excluded.last_refused_at > last_refused_at
        THEN excluded.last_refused_pass ELSE last_refused_pass END,
    opened_at = CASE
        WHEN max(last_refused_at, excluded.last_refused_at) <= max(last_verified_write_at, excluded.last_verified_write_at) THEN 0
        WHEN opened_at > max(last_verified_write_at, excluded.last_verified_write_at) THEN
            CASE WHEN excluded.last_refused_at > max(last_verified_write_at, excluded.last_verified_write_at)
                THEN min(opened_at, excluded.last_refused_at) ELSE opened_at END
        ELSE max(last_refused_at, excluded.last_refused_at)
    END,
    last_refused_at = max(last_refused_at, excluded.last_refused_at),
    last_verified_write_at = max(last_verified_write_at, excluded.last_verified_write_at)
