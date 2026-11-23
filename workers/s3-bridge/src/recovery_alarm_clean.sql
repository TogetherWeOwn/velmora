-- A sweep that finishes while healthy refreshes the stale clock. Only a
-- proved full walk beginning after the latest problem closes an incident.
UPDATE recovery_alarm_state SET
    last_clean_sweep_at = max(last_clean_sweep_at, ?1),
    last_clean_walk_start = CASE WHEN ?3 > max(last_problem_at, last_clean_walk_start) AND EXISTS (
        SELECT 1 FROM recovery_walk_frontier WHERE id = 1 AND began_at = ?3 AND completed_by = ?4 AND next_tag IS NULL
    ) THEN ?3 ELSE last_clean_walk_start END,
    opened_at = 0
WHERE id = 1 AND (
    (?2 = 1 AND opened_at = 0)
    OR (?3 > max(last_problem_at, last_clean_walk_start) AND EXISTS (
        SELECT 1 FROM recovery_walk_frontier WHERE id = 1 AND began_at = ?3 AND completed_by = ?4 AND next_tag IS NULL
    ))
)
