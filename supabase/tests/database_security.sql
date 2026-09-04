begin;

do $test$
declare
    exposed_count integer;
begin
    if has_schema_privilege('anon', 'app_private', 'usage') then
        raise exception 'anon unexpectedly has USAGE on app_private';
    end if;
    if has_schema_privilege('authenticated', 'app_private', 'usage') then
        raise exception 'authenticated unexpectedly has USAGE on app_private';
    end if;
    if not has_schema_privilege('vchs_runtime', 'app_private', 'usage') then
        raise exception 'vchs_runtime is missing USAGE on app_private';
    end if;

    select count(*)
    into exposed_count
    from information_schema.role_table_grants
    where table_schema = 'app_private'
      and grantee in ('PUBLIC', 'anon', 'authenticated');
    if exposed_count <> 0 then
        raise exception 'Data API roles have % app_private table grants', exposed_count;
    end if;
    if not has_table_privilege('vchs_runtime', 'app_private.vpn_accesses', 'select,insert,update')
        or has_table_privilege('vchs_runtime', 'app_private.vpn_accesses', 'delete')
        or not has_table_privilege('vchs_runtime', 'app_private.admin_audit_events', 'insert')
        or has_table_privilege('vchs_runtime', 'app_private.admin_audit_events', 'select')
        or not has_table_privilege('vchs_runtime', 'app_private.pilot_test_results', 'select,insert,delete')
        or has_table_privilege('vchs_runtime', 'app_private.pilot_test_results', 'update') then
        raise exception 'vchs_runtime privileges do not match the least-privilege contract';
    end if;

    if exists (
        select 1 from pg_roles
        where rolname = 'vchs_runtime'
          and (rolcanlogin or rolsuper or rolcreaterole or rolcreatedb or rolreplication or rolbypassrls)
    ) then
        raise exception 'vchs_runtime has a forbidden role attribute';
    end if;

    if to_regprocedure('app_private.rls_auto_enable()') is not null then
        if has_function_privilege('anon', 'app_private.rls_auto_enable()', 'execute')
            or has_function_privilege('authenticated', 'app_private.rls_auto_enable()', 'execute')
            or has_function_privilege('public', 'app_private.rls_auto_enable()', 'execute') then
            raise exception 'RLS event trigger function is executable by a Data API role';
        end if;
    end if;

    if exists (
        select 1
        from pg_class relation
        join pg_namespace namespace on namespace.oid = relation.relnamespace
        where namespace.nspname = 'public'
          and relation.relname in (
              'accounts', 'devices', 'nodes', 'manifest_revisions',
              'admin_audit_events', 'vpn_accesses', 'pilot_test_results'
          )
    ) then
        raise exception 'control-plane table leaked into the public schema';
    end if;
end
$test$;

do $test$
begin
    begin
        insert into app_private.admin_audit_events (
            id, actor, action, object_type, object_id, metadata
        ) values (
            '00000000-0000-4000-8000-000000000001',
            'test', 'oversized_metadata', 'test', 'test',
            jsonb_build_object('payload', repeat('x', 9000))
        );
        raise exception 'oversized audit metadata was accepted';
    exception
        when check_violation then null;
    end;

    begin
        insert into app_private.accounts (id, status)
        values ('00000000-0000-4000-8000-000000000002', 'active');
        insert into app_private.devices (
            id, account_id, label, identity_public_key, status
        ) values (
            '00000000-0000-4000-8000-000000000003',
            '00000000-0000-4000-8000-000000000002',
            'test', repeat('k', 32), 'active'
        );
        insert into app_private.pilot_test_results (
            id, device_id, client_platform, transport, occurred_at, success,
            connection_time_bucket, recorded_at
        ) values (
            '00000000-0000-4000-8000-000000000004',
            '00000000-0000-4000-8000-000000000003',
            'linux', 'amneziawg', current_timestamp - interval '31 days',
            true, 'lt_3s', current_timestamp
        );
        raise exception 'out-of-retention telemetry was accepted';
    exception
        when check_violation then null;
    end;
end
$test$;

insert into app_private.accounts (id, status)
values ('00000000-0000-4000-8000-000000000010', 'active');
insert into app_private.devices (
    id, account_id, label, identity_public_key, status
) values (
    '00000000-0000-4000-8000-000000000011',
    '00000000-0000-4000-8000-000000000010',
    'retention-test', repeat('r', 32), 'active'
);
insert into app_private.pilot_test_results (
    id, device_id, client_platform, transport, occurred_at, success,
    connection_time_bucket, recorded_at
) values (
    '00000000-0000-4000-8000-000000000012',
    '00000000-0000-4000-8000-000000000011',
    'linux', 'amneziawg', current_timestamp - interval '31 days',
    true, 'lt_3s', current_timestamp - interval '31 days'
);

delete from app_private.pilot_test_results
where id in (
    select id
    from app_private.pilot_test_results
    where occurred_at < current_timestamp - interval '30 days'
    order by occurred_at
    limit 1000
);

do $test$
begin
    if exists (
        select 1 from app_private.pilot_test_results
        where id = '00000000-0000-4000-8000-000000000012'
    ) then
        raise exception 'expired telemetry was not physically deleted';
    end if;
end
$test$;

rollback;
