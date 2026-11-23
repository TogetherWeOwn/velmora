-- Queue message IDs are stable on redelivery. Keep one diagnostic row
-- per job and bound the number of rows retained for a single pass.
INSERT OR IGNORE INTO recovery_pass_job (
    pass_id, message_id, copied, pending, source_unreadable,
    refused_put, put_status, put_code, refused_verify, verify_status, verify_code,
    refused_plan, plan_status, plan_code, unsignable, verified_write, at
)
SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
WHERE (SELECT count(*) FROM (
    SELECT 1 FROM recovery_pass_job WHERE pass_id = ?1 LIMIT 256
)) < 256
