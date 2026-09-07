BEGIN;

-- Standard PostgreSQL counterpart of the Supabase runtime-role migrations.
-- Never use this group role as the migration owner or give it LOGIN.
DO $migration$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'vchs_runtime') THEN
        CREATE ROLE vchs_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOREPLICATION NOBYPASSRLS;
    END IF;
END
$migration$;

REVOKE ALL ON SCHEMA app_private FROM vchs_runtime;
REVOKE ALL ON ALL TABLES IN SCHEMA app_private FROM vchs_runtime;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA app_private FROM vchs_runtime;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA app_private FROM vchs_runtime;
GRANT USAGE ON SCHEMA app_private TO vchs_runtime;
GRANT SELECT ON app_private.devices TO vchs_runtime;
GRANT SELECT, INSERT, UPDATE ON app_private.vpn_accesses TO vchs_runtime;
GRANT INSERT ON app_private.admin_audit_events TO vchs_runtime;
GRANT SELECT, INSERT, DELETE ON app_private.pilot_test_results TO vchs_runtime;

COMMIT;
