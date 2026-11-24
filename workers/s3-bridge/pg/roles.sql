-- Run as the database administrator after provisioning the three login roles.
-- Roles/passwords are provisioned out of band; this file contains no credentials.
-- Usage: psql -X -v ON_ERROR_STOP=1 [-v schema=public] -f roles.sql
\set ON_ERROR_STOP on
\if :{?schema}
\else
    \set schema public
\endif
BEGIN;
-- Refuse a role bootstrap after the explicit activation grant. Revoking
-- that grant on a rerun would silently close access to a live catalogue.
SELECT EXISTS (SELECT FROM pg_namespace n, LATERAL aclexplode(n.nspacl) a
               WHERE n.nspname = :'schema' AND a.grantee = 'kofra_app'::regrole
                 AND a.privilege_type = 'USAGE') AS app_activated \gset
\if :app_activated
    DO $$ BEGIN RAISE EXCEPTION 'role bootstrap refused: app schema USAGE already granted'; END $$;
\endif
ALTER SCHEMA :"schema" OWNER TO kofra_migrate;
REVOKE ALL ON SCHEMA :"schema" FROM PUBLIC;
REVOKE ALL ON SCHEMA :"schema" FROM kofra_app;
SELECT has_schema_privilege('kofra_app', :'schema', 'USAGE,CREATE') AS app_has_schema_access \gset
\if :app_has_schema_access
    DO $$ BEGIN RAISE EXCEPTION 'role bootstrap refused: app inherits schema privileges'; END $$;
\endif
GRANT pg_read_all_data TO kofra_ro;

-- If the proxy drops BEGIN, following statements must not autocommit writes.
-- The adapter must opt into READ WRITE before taking W1.
ALTER ROLE kofra_app SET default_transaction_read_only = on;
ALTER ROLE kofra_app SET idle_in_transaction_session_timeout = '5s';
SELECT current_setting('server_version_num')::int >= 170000 AS pg17 \gset
\if :pg17
    ALTER ROLE kofra_app SET transaction_timeout = '30s';
\endif

ALTER DEFAULT PRIVILEGES FOR ROLE kofra_migrate IN SCHEMA :"schema"
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO kofra_app;
ALTER DEFAULT PRIVILEGES FOR ROLE kofra_migrate IN SCHEMA :"schema"
    GRANT USAGE, SELECT ON SEQUENCES TO kofra_app;
-- An IN SCHEMA revoke cannot remove PostgreSQL's global default EXECUTE.
ALTER DEFAULT PRIVILEGES FOR ROLE kofra_migrate REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE kofra_migrate IN SCHEMA :"schema"
    GRANT EXECUTE ON FUNCTIONS TO kofra_app;
ALTER DEFAULT PRIVILEGES FOR ROLE kofra_migrate IN SCHEMA :"schema"
    GRANT SELECT ON TABLES TO kofra_ro;
COMMIT;
