-- A redelivery can supply newer evidence, but never adds another job.
INSERT INTO recovery_pass_job (
    pass_id, message_id, copied, pending, source_unreadable,
    refused_put, put_status, put_code, refused_verify, verify_status, verify_code,
    refused_plan, plan_status, plan_code, unsignable, verified_write, at
)
SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17
WHERE EXISTS (SELECT 1 FROM recovery_pass_job WHERE pass_id = ?1 AND message_id = ?2)
   OR (SELECT count(*) FROM (SELECT 1 FROM recovery_pass_job WHERE pass_id = ?1 LIMIT 256)) < 256
ON CONFLICT (pass_id, message_id) DO UPDATE SET
    copied = excluded.copied, pending = excluded.pending, source_unreadable = excluded.source_unreadable,
    refused_put = excluded.refused_put, put_status = excluded.put_status, put_code = excluded.put_code,
    refused_verify = excluded.refused_verify, verify_status = excluded.verify_status, verify_code = excluded.verify_code,
    refused_plan = excluded.refused_plan, plan_status = excluded.plan_status, plan_code = excluded.plan_code,
    unsignable = excluded.unsignable, verified_write = excluded.verified_write, at = excluded.at
WHERE excluded.at >= recovery_pass_job.at
