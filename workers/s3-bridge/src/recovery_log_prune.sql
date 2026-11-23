DELETE FROM recovery_copy_log
WHERE rowid IN (
    SELECT rowid FROM recovery_copy_log INDEXED BY recovery_copy_log_kind_at
    WHERE kind IN ('job', 'walk', 'audit') AND at < ?1
    ORDER BY kind, at LIMIT 1000
)
