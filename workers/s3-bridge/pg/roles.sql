-- Run as the database administrator after provisioning the three login roles.
-- Roles/passwords are provisioned out of band; this file contains no credentials.
-- Usage: psql -X -v ON_ERROR_STOP=1 [-v schema=public] -f roles.sql
\if :{?schema}
\else
    \set schema public
\endif
BEGIN;
ALTER SCHEMA :"schema" OWNER TO kofra_migrate;
REVOKE ALL ON SCHEMA :"schema" FROM PUBLIC;
-- Bootstrapping never opens the app path. This file is for an unactivated schema.
REVOKE ALL ON SCHEMA :"schema" FROM kofra_app;
GRANT pg_read_all_data TO kofra_ro;

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
