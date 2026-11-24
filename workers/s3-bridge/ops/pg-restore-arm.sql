-- Close new and old writer invocations before replay on Postgres.
-- Run via psql -X -v ON_ERROR_STOP=1 -f with the migrate role, after enabling
-- maintenance. Set search_path and velmora.lock_key explicitly for a test schema.
BEGIN ISOLATION LEVEL READ COMMITTED;
SET LOCAL lock_timeout = '3s';

DO $arm$
DECLARE
  catalogue_schema text := current_schema();
  scoped_key bigint := nullif(current_setting('velmora.lock_key', true), '')::bigint;
BEGIN
  IF catalogue_schema = 'public' THEN
    IF scoped_key IS NOT NULL AND scoped_key <> 7413000001 THEN
      RAISE EXCEPTION 'wrong catalogue lock for the public schema';
    END IF;
    scoped_key := 7413000001;
  ELSIF catalogue_schema IS NULL OR scoped_key IS NULL THEN
    RAISE EXCEPTION 'an explicit catalogue schema and velmora.lock_key are required';
  END IF;
  PERFORM pg_catalog.pg_advisory_xact_lock(scoped_key);
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = catalogue_schema AND c.relname = '_velmora_import_incomplete'
  ) THEN
    RAISE EXCEPTION 'catalogue import incomplete';
  END IF;
  -- Qualify the target even if a session's search_path contains other schemas.
  EXECUTE format($sql$
    INSERT INTO %I.restore_state AS r (id, state, since_ms, started_at)
    VALUES (1, 'replaying', -1, 0)
    ON CONFLICT (id) DO UPDATE SET
      since_ms = CASE WHEN r.state = 'complete' THEN -1 ELSE r.since_ms END,
      state = 'replaying',
      started_at = r.started_at + 1,
      finished_at = NULL,
      reached_phase = NULL,
      reached_after = NULL,
      reached_extent = NULL
  $sql$, catalogue_schema);
END
$arm$;

COMMIT;
