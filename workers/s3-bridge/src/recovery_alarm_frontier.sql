-- Only the start of a new walk or the matching continuation moves this
-- frontier. A redelivery can replace its most recent nonterminal link.
INSERT INTO recovery_walk_frontier (id, began_at, destination, next_tag, last_from, last_message, completed_by)
SELECT 1, ?1, ?6, ?3, ?2, ?5, CASE WHEN ?3 IS NULL THEN ?5 ELSE NULL END
WHERE ?7 < ?8 AND ((?4 = 1 AND EXISTS (
    SELECT 1 FROM recovery_alarm_state WHERE id = 1 AND last_clean_fresh_pass = ?1 AND last_clean_fresh_dest = ?6
)) OR EXISTS (
    SELECT 1 FROM recovery_walk_frontier WHERE id = 1 AND began_at = ?1 AND destination = ?6
      AND (next_tag = ?2 OR (next_tag IS NOT NULL AND last_from = ?2 AND last_message = ?5))
))
ON CONFLICT (id) DO UPDATE SET
    began_at = excluded.began_at, destination = excluded.destination, next_tag = excluded.next_tag,
    last_from = excluded.last_from, last_message = excluded.last_message, completed_by = excluded.completed_by
WHERE (?4 = 1 AND excluded.began_at > recovery_walk_frontier.began_at)
   OR (excluded.began_at = recovery_walk_frontier.began_at AND excluded.destination = recovery_walk_frontier.destination
       AND (recovery_walk_frontier.next_tag = ?2 OR (recovery_walk_frontier.next_tag IS NOT NULL
            AND recovery_walk_frontier.last_from = ?2 AND recovery_walk_frontier.last_message = ?5)))
