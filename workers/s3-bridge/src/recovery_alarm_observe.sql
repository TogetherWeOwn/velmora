-- Destination outcome time, not signing or delivery time. A delayed
-- observation inside the most recent proved walk invalidates the proof.
INSERT INTO recovery_alarm_state (
    id, last_problem_at, problem_operation, problem_kind, problem_status, problem_code,
    problem_counts, opened_at, last_clean_sweep_at, last_clean_walk_start, last_verified_write_at, problem_destination
)
VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?1, 0, 0, ?7, CASE WHEN ?1 > 0 THEN ?8 END)
ON CONFLICT (id) DO UPDATE SET
    opened_at = CASE
        WHEN max(last_problem_at, excluded.last_problem_at) < last_clean_walk_start AND last_clean_walk_dest =
          CASE WHEN excluded.last_problem_at >= max(1, last_problem_at) THEN excluded.problem_destination ELSE problem_destination END
          THEN 0
        WHEN opened_at = 0 THEN max(last_problem_at, excluded.last_problem_at)
        WHEN excluded.last_problem_at >= max(1, last_clean_walk_start) THEN min(opened_at, excluded.last_problem_at)
        ELSE opened_at
    END,
    problem_destination = CASE WHEN excluded.last_problem_at >= max(1, last_problem_at) THEN excluded.problem_destination ELSE problem_destination END,
    problem_operation = CASE WHEN excluded.last_problem_at >= max(1, last_problem_at) THEN excluded.problem_operation ELSE problem_operation END,
    problem_kind = CASE WHEN excluded.last_problem_at >= max(1, last_problem_at) THEN excluded.problem_kind ELSE problem_kind END,
    problem_status = CASE WHEN excluded.last_problem_at >= max(1, last_problem_at) THEN excluded.problem_status ELSE problem_status END,
    problem_code = CASE WHEN excluded.last_problem_at >= max(1, last_problem_at) THEN excluded.problem_code ELSE problem_code END,
    problem_counts = CASE WHEN excluded.last_problem_at >= max(1, last_problem_at) THEN excluded.problem_counts ELSE problem_counts END,
    last_problem_at = max(last_problem_at, excluded.last_problem_at),
    last_verified_write_at = max(last_verified_write_at, excluded.last_verified_write_at)
