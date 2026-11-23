-- Only an unexpired, destination-bound full walk with fresh sweeps in
-- its starting and finishing passes can clear a problem.
UPDATE recovery_alarm_state SET
    last_clean_sweep_at = CASE WHEN ?2 = 1 THEN max(last_clean_sweep_at, ?1) ELSE last_clean_sweep_at END,
    last_clean_walk_start = ?3,
    last_clean_walk_dest = ?7,
    opened_at = 0
WHERE id = 1 AND opened_at > 0 AND ?1 < ?6 AND problem_destination = ?7
  AND last_clean_fresh_pass = ?5 AND last_clean_fresh_dest = ?7
  AND ?3 > max(last_problem_at, last_clean_walk_start)
  AND EXISTS (
      SELECT 1 FROM recovery_walk_frontier WHERE id = 1 AND began_at = ?3
        AND destination = ?7 AND completed_by = ?4 AND next_tag IS NULL
  )
