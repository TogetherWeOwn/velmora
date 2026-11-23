-- Only the start of a new walk or the matching continuation moves this
-- frontier. There is no retry/deploy requirement on the copy itself.
INSERT INTO recovery_walk_frontier (id, began_at, next_tag, completed_by)
SELECT 1, ?1, ?3, CASE WHEN ?3 IS NULL THEN ?5 ELSE NULL END
WHERE ?4 = 1 OR EXISTS (
    SELECT 1 FROM recovery_walk_frontier WHERE id = 1 AND began_at = ?1 AND next_tag = ?2
)
ON CONFLICT (id) DO UPDATE SET
    began_at = excluded.began_at,
    next_tag = excluded.next_tag,
    completed_by = excluded.completed_by
WHERE (?4 = 1 AND excluded.began_at > recovery_walk_frontier.began_at)
   OR (excluded.began_at = recovery_walk_frontier.began_at AND recovery_walk_frontier.next_tag = ?2)
