begin;

do $migration$
begin
    if not exists (select 1 from pg_roles where rolname = 'vchs_runtime') then
        create role vchs_runtime
            nologin
            nosuperuser
            nocreatedb
            nocreaterole
            noreplication
            nobypassrls;
    end if;
end
$migration$;

alter role vchs_runtime set search_path = 'pg_catalog';
alter role vchs_runtime set statement_timeout = '5s';
alter role vchs_runtime set lock_timeout = '2s';
alter role vchs_runtime set idle_in_transaction_session_timeout = '5s';

revoke all on schema public from vchs_runtime;
revoke all on schema app_private from vchs_runtime;
revoke all on all tables in schema app_private from vchs_runtime;
revoke all on all sequences in schema app_private from vchs_runtime;
revoke execute on all functions in schema app_private from vchs_runtime;

grant usage on schema app_private to vchs_runtime;
grant select on app_private.devices to vchs_runtime;
grant select, insert, update on app_private.vpn_accesses to vchs_runtime;
grant insert on app_private.admin_audit_events to vchs_runtime;
grant select, insert on app_private.pilot_test_results to vchs_runtime;

commit;
