-- Refresh freshness only on a completed fresh sweep, and only when
-- healthy. Also remember its pass so a finishing walk can prove both
-- the fresh and older portions of the keyspace.
UPDATE recovery_alarm_state SET
    last_clean_fresh_pass = ?1,
    last_clean_fresh_dest = ?4,
    last_clean_sweep_at = CASE WHEN opened_at = 0 THEN max(last_clean_sweep_at, ?2) ELSE last_clean_sweep_at END
WHERE id = 1 AND ?1 >= last_clean_fresh_pass AND ?1 > last_problem_at AND ?2 < ?3
