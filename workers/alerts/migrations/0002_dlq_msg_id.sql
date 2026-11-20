-- The id of a dead-letter batch's first message, so that a batch the
-- queue delivers again (at-least-once) is counted once.
ALTER TABLE dlq ADD COLUMN msg_id TEXT;
CREATE UNIQUE INDEX dlq_msg_id ON dlq(msg_id);
