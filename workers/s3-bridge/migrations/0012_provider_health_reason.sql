-- Why a provider's last failed session failed: a short neutral code
-- (`connect_refused`, `login_refused`, `session_failed`), never the provider's own text.
-- Set with every strike, cleared by a good session. NULL = no strike on
-- record (or one from before this column).
-- Additive only.

ALTER TABLE provider_health ADD COLUMN last_failure_reason TEXT;
