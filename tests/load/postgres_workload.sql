begin;
set local statement_timeout = '30s';
set local lock_timeout = '2s';

insert into app_private.accounts (id, status)
select (
    lpad(to_hex(series), 8, '0') || '-0000-4000-8000-' ||
    lpad(to_hex(series), 12, '0')
)::uuid, 'active'
from generate_series(1, 1000) as series;

insert into app_private.nodes (
    id, region, country_code, provider, status
) values ('load-node', 'eu-west', 'DE', 'load-test', 'active');

insert into app_private.devices (
    id, account_id, label, identity_public_key, status
)
select (
    lpad(to_hex(series + 1000), 8, '0') || '-0000-4000-8000-' ||
    lpad(to_hex(series + 1000), 12, '0')
)::uuid,
(
    lpad(to_hex(series), 8, '0') || '-0000-4000-8000-' ||
    lpad(to_hex(series), 12, '0')
)::uuid,
'load-' || series,
repeat('k', 32) || series,
'active'
from generate_series(1, 1000) as series;

insert into app_private.vpn_accesses (
    id, device_id, node_id, transport, external_reference,
    created_at, expires_at, status
)
select (
    lpad(to_hex(series + 2000), 8, '0') || '-0000-4000-8000-' ||
    lpad(to_hex(series + 2000), 12, '0')
)::uuid,
(
    lpad(to_hex(series + 1000), 8, '0') || '-0000-4000-8000-' ||
    lpad(to_hex(series + 1000), 12, '0')
)::uuid,
'load-node',
case when series % 2 = 0 then 'amneziawg' else 'xray_reality' end,
'load-' || series,
current_timestamp - interval '1 day',
current_timestamp + interval '30 days',
'active'
from generate_series(1, 1000) as series;

insert into app_private.pilot_test_results (
    id, device_id, client_platform, isp, transport, occurred_at, success,
    failure_stage, connection_time_bucket, throughput_bucket, recorded_at
)
select gen_random_uuid(),
(
    lpad(to_hex(1001 + series % 1000), 8, '0') || '-0000-4000-8000-' ||
    lpad(to_hex(1001 + series % 1000), 12, '0')
)::uuid,
'linux',
'ISP-' || series % 20,
case when series % 2 = 0 then 'amneziawg' else 'xray_reality' end,
current_timestamp - ((series % 43200) || ' seconds')::interval,
series % 10 <> 0,
case when series % 10 = 0 then 'dns' else null end,
'3_10s',
'10_50_mbps',
current_timestamp
from generate_series(1, 50000) as series;

create function pg_temp.explain_json(query_text text)
returns jsonb
language plpgsql
as $function$
declare
    result jsonb;
begin
    execute 'explain (analyze, buffers, format json) ' || query_text into result;
    return result;
end
$function$;

select workload,
       (plan -> 0 ->> 'Planning Time')::numeric as planning_ms,
       (plan -> 0 ->> 'Execution Time')::numeric as execution_ms,
       plan -> 0 -> 'Plan' ->> 'Node Type' as root_node
from (
    values
    (
        'transport_aggregate',
        pg_temp.explain_json($query$
            select transport, count(*)::bigint,
                   count(*) filter (where success)::bigint
            from app_private.pilot_test_results
            where occurred_at >= current_timestamp - interval '30 days'
            group by transport
            order by transport
        $query$)
    ),
    (
        'failed_isp_aggregate',
        pg_temp.explain_json($query$
            select isp, count(*)::bigint
            from app_private.pilot_test_results
            where success = false
              and isp is not null
              and occurred_at >= current_timestamp - interval '30 days'
            group by isp
            having count(*) >= 2
            order by count(*) desc, isp
            limit 100
        $query$)
    ),
    (
        'active_access_counts',
        pg_temp.explain_json($query$
            select count(distinct access.device_id)::bigint,
                   count(distinct device.account_id)::bigint
            from app_private.vpn_accesses as access
            join app_private.devices as device on device.id = access.device_id
            where access.status = 'active'
              and access.expires_at > current_timestamp
        $query$)
    )
) as plans(workload, plan)
order by workload;

rollback;
