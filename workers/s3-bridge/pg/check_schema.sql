-- Read-only PostgreSQL manifest. The migration runner compares this JSON with
-- an in-memory SQLite database built from the shipped D1 migrations.
WITH ns AS (
    SELECT * FROM pg_namespace WHERE nspname = current_schema()
), tbl AS (
    SELECT c.* FROM pg_class c JOIN ns ON ns.oid = c.relnamespace
    WHERE c.relkind IN ('r', 'p')
      AND c.relname NOT IN ('schema_migrations', '_velmora_import_incomplete')
), defaults AS (
    SELECT d.defaclobjtype, d.defaclnamespace, a.grantee, a.privilege_type, a.is_grantable
    FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a
    WHERE d.defaclrole = 'kofra_migrate'::regrole
      AND d.defaclnamespace IN (0, (SELECT oid FROM ns))
), app AS (
    SELECT * FROM pg_roles WHERE rolname = 'kofra_app'
)
SELECT json_build_object(
    'tables', (SELECT json_agg(t.relname) FROM tbl t),
    'inherited_tables', (SELECT json_agg(DISTINCT parent.relname)
        FROM pg_inherits i JOIN tbl parent ON i.inhparent = parent.oid),
    'columns', (SELECT json_agg(json_build_array(t.relname, a.attname,
        format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attidentity,
        co.collname, pg_get_expr(d.adbin, d.adrelid)))
        FROM tbl t JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum > 0 AND NOT a.attisdropped
        LEFT JOIN pg_attrdef d ON d.adrelid = t.oid AND d.adnum = a.attnum
        LEFT JOIN pg_collation co ON co.oid = a.attcollation),
    'indexes', (SELECT json_agg(json_build_array(t.relname, idx.relname, i.indisprimary,
        i.indisunique, i.indisvalid AND i.indisready, m.amname,
        (SELECT json_agg(json_build_array(a.attname, (i.indoption[k.ord - 1] & 1) <> 0,
                    (i.indoption[k.ord - 1] & 2) <> 0) ORDER BY k.ord)
         FROM unnest(i.indkey) WITH ORDINALITY k(attnum, ord)
         LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum),
        pg_get_expr(i.indpred, i.indrelid)))
        FROM tbl t JOIN pg_index i ON i.indrelid = t.oid
        JOIN pg_class idx ON idx.oid = i.indexrelid JOIN pg_am m ON m.oid = idx.relam),
    'foreign_keys', (SELECT json_agg(json_build_array(t.relname, r.relname,
        (SELECT json_agg(a.attname ORDER BY k.ord) FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ord)
         JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum),
        (SELECT json_agg(a.attname ORDER BY k.ord) FROM unnest(c.confkey) WITH ORDINALITY k(attnum, ord)
         JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum = k.attnum),
        c.confupdtype, c.confdeltype, c.confmatchtype,
        c.convalidated AND NOT c.condeferrable AND r.relnamespace = t.relnamespace))
        FROM tbl t JOIN pg_constraint c ON c.conrelid = t.oid AND c.contype = 'f'
        JOIN pg_class r ON r.oid = c.confrelid),
    'checks', (SELECT json_agg(json_build_array(t.relname, pg_get_expr(c.conbin, c.conrelid), c.convalidated))
        FROM tbl t JOIN pg_constraint c ON c.conrelid = t.oid AND c.contype = 'c'),
    'identities_ready', (SELECT bool_and(next_value > max_key AND next_value <= 9223372036854775807)
        FROM (
            SELECT last_value::numeric + is_called::int AS next_value, (SELECT coalesce(max(id), 0) FROM gc) AS max_key
            FROM gc_id_seq
            UNION ALL
            SELECT last_value::numeric + is_called::int, (SELECT coalesce(max(id), 0) FROM usage_recounts)
            FROM usage_recounts_id_seq
            UNION ALL
            SELECT last_value::numeric + is_called::int, (SELECT coalesce(max(seq), 0) FROM outbox)
            FROM outbox_seq_seq
        ) s),
    'triggers', (SELECT json_agg(json_build_array(r.relname, t.tgname, t.tgenabled,
        t.tgtype, ARRAY(SELECT a.attname FROM unnest(t.tgattr) WITH ORDINALITY k(attnum, ord)
                        JOIN pg_attribute a ON a.attrelid = r.oid AND a.attnum = k.attnum ORDER BY k.ord),
        p.proname, encode(sha256(convert_to(p.prosrc, 'UTF8')), 'hex'), pg_get_triggerdef(t.oid),
        p.pronamespace = r.relnamespace, t.tgoldtable, t.tgnewtable))
        FROM tbl r JOIN pg_trigger t ON t.tgrelid = r.oid AND NOT t.tgisinternal
        JOIN pg_proc p ON p.oid = t.tgfoid),
    'tx_guard', EXISTS (SELECT FROM tbl t JOIN pg_constraint c ON c.conrelid = t.oid
        WHERE t.relname = 'tx_guard' AND c.conname = 'tx_guard_ok'
          AND c.contype = 'c' AND c.convalidated AND pg_get_expr(c.conbin, c.conrelid) = '(ok = 1)'),
    'privileges', json_build_object(
        'catalogue owner', (SELECT nspowner = 'kofra_migrate'::regrole FROM ns)
            AND NOT EXISTS (SELECT FROM tbl WHERE relowner <> 'kofra_migrate'::regrole),
        'no PUBLIC schema privileges', NOT EXISTS (SELECT FROM ns,
            LATERAL aclexplode(coalesce(nspacl, acldefault('n', nspowner))) a WHERE a.grantee = 0),
        'app login without schema CREATE or owner rights', (SELECT rolcanlogin AND NOT rolsuper
            AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolbypassrls AND NOT rolreplication FROM app)
            AND NOT has_schema_privilege('kofra_app', current_schema(), 'CREATE')
            AND NOT pg_has_role('kofra_app', 'kofra_migrate', 'MEMBER'),
        'import marker blocks app', NOT has_schema_privilege('kofra_app', current_schema(), 'USAGE')
            OR to_regclass(format('%I._velmora_import_incomplete', current_schema())) IS NULL,
        'app transactions default read only', (SELECT 'default_transaction_read_only=on' = ANY(rolconfig)
            AND NOT EXISTS (SELECT FROM pg_db_role_setting s JOIN pg_database d ON d.oid = s.setdatabase,
                LATERAL unnest(s.setconfig) AS c(setting)
                WHERE s.setrole = app.oid AND d.datname = current_database()
                  AND split_part(c.setting, '=', 1) = 'default_transaction_read_only'
                  AND c.setting <> 'default_transaction_read_only=on') FROM app),
        'app role timeouts', (SELECT 'idle_in_transaction_session_timeout=5s' = ANY(rolconfig)
            AND (current_setting('server_version_num')::int < 170000
                 OR 'transaction_timeout=30s' = ANY(rolconfig)) FROM app),
        -- Write binds stay out of the server logs: no setting may log
        -- statements with their parameters for an app session. Effective
        -- value per setting: database and role, role, database, all roles,
        -- then the server value as this session sees it (an override of
        -- this session fails the check). An extension setting that this
        -- session has only as a placeholder is read with current_setting
        -- (empty once a configured value was removed again).
        'app sessions log no bind values', NOT EXISTS (
            WITH wanted(name, ok) AS (VALUES
                ('log_statement', ARRAY['none']),
                ('log_min_duration_statement', ARRAY['-1']),
                ('log_min_duration_sample', ARRAY['-1']),
                ('log_transaction_sample_rate', ARRAY['0']),
                ('log_parameter_max_length_on_error', ARRAY['0']),
                ('auto_explain.log_min_duration', ARRAY['-1', '', '<absent>']),
                ('pginsights.raw_queries', ARRAY['off', '', '<absent>'])
            ), setting AS (
                SELECT 1 AS rank, c.setting FROM pg_db_role_setting s
                    JOIN pg_database d ON d.oid = s.setdatabase, LATERAL unnest(s.setconfig) AS c(setting)
                    WHERE s.setrole = (SELECT oid FROM app) AND d.datname = current_database()
                UNION ALL SELECT 2, c.setting FROM app, LATERAL unnest(app.rolconfig) AS c(setting)
                UNION ALL SELECT 3, c.setting FROM pg_db_role_setting s
                    JOIN pg_database d ON d.oid = s.setdatabase, LATERAL unnest(s.setconfig) AS c(setting)
                    WHERE s.setrole = 0 AND d.datname = current_database()
                UNION ALL SELECT 4, c.setting FROM pg_db_role_setting s, LATERAL unnest(s.setconfig) AS c(setting)
                    WHERE s.setrole = 0 AND s.setdatabase = 0
            ), effective AS (
                SELECT rank, split_part(setting, '=', 1) AS name,
                       substr(setting, strpos(setting, '=') + 1) AS v FROM setting
                UNION ALL SELECT 5, w.name, CASE
                        WHEN p.name IS NULL THEN coalesce(current_setting(w.name, true), '<absent>')
                        WHEN p.source IN ('default', 'configuration file', 'command line',
                            'environment variable') THEN p.reset_val
                        ELSE '<session override>' END
                    FROM wanted w LEFT JOIN pg_settings p ON p.name = w.name
            )
            SELECT FROM wanted w
            WHERE NOT (SELECT e.v FROM effective e WHERE e.name = w.name
                       ORDER BY e.rank LIMIT 1) = ANY (w.ok)
            UNION ALL SELECT FROM effective WHERE name LIKE 'pgaudit.%'
            UNION ALL SELECT FROM pg_settings WHERE name LIKE 'pgaudit.%'
            -- A configured pgaudit.log this session sees as a placeholder
            -- (empty once removed again, 'none' when off).
            UNION ALL SELECT WHERE coalesce(current_setting('pgaudit.log', true), '') NOT IN ('', 'none')
        ),
        'read-only role membership', pg_has_role('kofra_ro', 'pg_read_all_data', 'USAGE')
            AND NOT pg_has_role('kofra_ro', 'pg_write_all_data', 'MEMBER')
            AND NOT pg_has_role('kofra_ro', 'kofra_migrate', 'MEMBER')
            AND NOT pg_has_role('kofra_ro', 'kofra_app', 'MEMBER'),
        'app DML on all catalogue tables', NOT EXISTS (SELECT FROM tbl t WHERE NOT (
            has_table_privilege('kofra_app', t.oid, 'SELECT')
            AND has_table_privilege('kofra_app', t.oid, 'INSERT')
            AND has_table_privilege('kofra_app', t.oid, 'UPDATE')
            AND has_table_privilege('kofra_app', t.oid, 'DELETE'))
            OR has_table_privilege('kofra_app', t.oid, 'TRUNCATE,TRIGGER,REFERENCES')
            OR has_table_privilege('kofra_ro', t.oid, 'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES')),
        'migration ledger not app writable', NOT has_table_privilege('kofra_app', 'schema_migrations',
            'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES'),
        'app sequence privileges', NOT EXISTS (SELECT FROM pg_class s JOIN ns ON ns.oid = s.relnamespace
            WHERE s.relkind = 'S' AND (s.relowner <> 'kofra_migrate'::regrole
              OR NOT has_sequence_privilege('kofra_app', s.oid, 'USAGE')
              OR NOT has_sequence_privilege('kofra_app', s.oid, 'SELECT')
              OR has_sequence_privilege('kofra_app', s.oid, 'UPDATE'))),
        'app-only trigger function EXECUTE', NOT EXISTS (SELECT FROM pg_proc p JOIN ns ON ns.oid = p.pronamespace
            WHERE p.prorettype = 'trigger'::regtype AND (p.proowner <> 'kofra_migrate'::regrole
              OR p.prosecdef OR NOT has_function_privilege('kofra_app', p.oid, 'EXECUTE')
              OR p.proconfig IS DISTINCT FROM ARRAY[format('search_path=%I, pg_temp', current_schema())]
              OR EXISTS (SELECT FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
                         WHERE a.grantee = 0))),
        'explicit default privileges', (SELECT array_agg(DISTINCT privilege_type ORDER BY privilege_type) FROM defaults
            WHERE defaclobjtype = 'r' AND defaclnamespace <> 0
              AND grantee = 'kofra_app'::regrole AND NOT is_grantable) = ARRAY['DELETE','INSERT','SELECT','UPDATE']
            AND (SELECT array_agg(DISTINCT privilege_type ORDER BY privilege_type) FROM defaults
                 WHERE defaclobjtype = 'S' AND defaclnamespace <> 0
                   AND grantee = 'kofra_app'::regrole AND NOT is_grantable) = ARRAY['SELECT','USAGE']
            AND EXISTS (SELECT FROM defaults WHERE defaclobjtype = 'f' AND defaclnamespace <> 0
                AND grantee = 'kofra_app'::regrole AND privilege_type = 'EXECUTE' AND NOT is_grantable)
            AND EXISTS (SELECT FROM pg_default_acl d WHERE d.defaclrole = 'kofra_migrate'::regrole
                AND d.defaclnamespace = 0 AND d.defaclobjtype = 'f')
            AND NOT EXISTS (SELECT FROM defaults WHERE grantee = 0 AND defaclobjtype = 'f')
            AND EXISTS (SELECT FROM defaults WHERE defaclobjtype = 'r' AND defaclnamespace <> 0
                AND grantee = 'kofra_ro'::regrole AND privilege_type = 'SELECT' AND NOT is_grantable)
    )
);
