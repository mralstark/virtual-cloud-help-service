begin;

create schema if not exists app_private;
revoke all on schema app_private from public, anon, authenticated;

alter default privileges for role postgres in schema public
    revoke all on tables from anon, authenticated;
alter default privileges for role postgres in schema public
    revoke all on sequences from anon, authenticated;
alter default privileges for role postgres in schema public
    revoke execute on functions from anon, authenticated;
alter default privileges for role postgres in schema app_private
    revoke all on tables from public, anon, authenticated;
alter default privileges for role postgres in schema app_private
    revoke all on sequences from public, anon, authenticated;
alter default privileges for role postgres in schema app_private
    revoke execute on functions from public, anon, authenticated;

do $migration$
begin
    if to_regprocedure('public.rls_auto_enable()') is not null then
        execute 'revoke all on function public.rls_auto_enable() from public, anon, authenticated';
        execute 'alter function public.rls_auto_enable() set schema app_private';
        execute 'revoke all on function app_private.rls_auto_enable() from public, anon, authenticated';
    end if;
end
$migration$;

create table app_private.accounts (
    id uuid primary key,
    status text not null check (status in ('active', 'suspended', 'closed')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    check (updated_at >= created_at)
);

create table app_private.devices (
    id uuid primary key,
    account_id uuid not null references app_private.accounts(id) on delete cascade,
    label text not null check (
        char_length(label) between 1 and 100 and octet_length(label) <= 400
    ),
    identity_public_key text not null unique check (
        char_length(identity_public_key) between 32 and 512
        and identity_public_key !~ '[[:space:]]'
    ),
    status text not null check (status in ('pending', 'active', 'revoked')),
    created_at timestamptz not null default now(),
    revoked_at timestamptz,
    check ((status = 'revoked') = (revoked_at is not null))
);

create index devices_account_id_idx on app_private.devices(account_id);

create table app_private.nodes (
    id text primary key check (id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    region text not null check (char_length(region) between 1 and 100),
    country_code char(2) not null check (country_code ~ '^[A-Z]{2}$'),
    provider text not null check (char_length(provider) between 1 and 100),
    autonomous_system_number bigint check (autonomous_system_number > 0),
    status text not null check (status in ('provisioning', 'active', 'draining', 'retired')),
    created_at timestamptz not null default now(),
    retired_at timestamptz,
    check (retired_at is null or retired_at >= created_at)
);

create table app_private.manifest_revisions (
    version bigint primary key check (version > 0),
    payload_sha256 bytea not null check (octet_length(payload_sha256) = 32),
    created_at timestamptz not null default now(),
    created_by text not null check (char_length(created_by) between 1 and 128)
);

create table app_private.admin_audit_events (
    id uuid primary key,
    actor text not null check (char_length(actor) between 1 and 128),
    action text not null check (char_length(action) between 1 and 128),
    object_type text not null check (char_length(object_type) between 1 and 128),
    object_id text not null check (char_length(object_id) between 1 and 256),
    occurred_at timestamptz not null default now(),
    metadata jsonb not null default '{}'::jsonb check (
        jsonb_typeof(metadata) = 'object' and octet_length(metadata::text) <= 8192
    )
);

create index admin_audit_events_occurred_at_idx
    on app_private.admin_audit_events(occurred_at desc);

create table app_private.vpn_accesses (
    id uuid primary key,
    device_id uuid not null references app_private.devices(id) on delete cascade,
    node_id text not null references app_private.nodes(id) on delete restrict,
    transport text not null check (transport in ('amneziawg', 'xray_reality')),
    external_reference text not null check (char_length(external_reference) between 1 and 256),
    created_at timestamptz not null,
    expires_at timestamptz not null,
    revoked_at timestamptz,
    status text not null check (status in ('active', 'revoked')),
    check (expires_at > created_at and expires_at <= created_at + interval '90 days'),
    check (revoked_at is null or revoked_at >= created_at),
    check ((status = 'revoked') = (revoked_at is not null)),
    unique (node_id, transport, external_reference)
);

create index vpn_accesses_device_id_idx on app_private.vpn_accesses(device_id);
create index vpn_accesses_node_status_idx on app_private.vpn_accesses(node_id, status);
create index vpn_accesses_expires_at_idx
    on app_private.vpn_accesses(expires_at)
    where status = 'active';

create table app_private.pilot_test_results (
    id uuid primary key,
    device_id uuid not null references app_private.devices(id) on delete cascade,
    client_platform text not null check (
        client_platform in ('android', 'ios', 'linux', 'macos', 'windows')
    ),
    isp text check (
        isp is null or (
            char_length(isp) between 1 and 100
            and octet_length(isp) <= 400
            and isp = btrim(isp)
            and isp !~ '[[:cntrl:]]'
        )
    ),
    transport text not null check (transport in ('amneziawg', 'xray_reality')),
    occurred_at timestamptz not null,
    success boolean not null,
    failure_stage text check (
        failure_stage is null or failure_stage in (
            'server_health', 'public_ip', 'transport', 'port', 'server_outbound',
            'tunnel', 'dns', 'https', 'ipv4_leak', 'ipv6_leak', 'upload',
            'download', 'reconnect'
        )
    ),
    connection_time_bucket text not null check (
        connection_time_bucket in ('lt_3s', '3_10s', '10_30s', 'gt_30s', 'unknown')
    ),
    throughput_bucket text check (
        throughput_bucket is null or throughput_bucket in (
            'lt_1_mbps', '1_10_mbps', '10_50_mbps', 'gte_50_mbps'
        )
    ),
    recorded_at timestamptz not null default now(),
    check (success = (failure_stage is null)),
    check (
        occurred_at >= recorded_at - interval '30 days'
        and occurred_at <= recorded_at + interval '5 minutes'
    )
);

create index pilot_test_results_device_time_idx
    on app_private.pilot_test_results(device_id, occurred_at desc);
create index pilot_test_results_transport_time_idx
    on app_private.pilot_test_results(transport, occurred_at desc);
create index pilot_test_results_failures_idx
    on app_private.pilot_test_results(failure_stage, occurred_at desc)
    where success = false;
create index pilot_test_results_failed_isp_idx
    on app_private.pilot_test_results(isp, occurred_at desc)
    where success = false and isp is not null;
create index pilot_test_results_retention_idx
    on app_private.pilot_test_results(occurred_at);

comment on table app_private.admin_audit_events is
    'Administrative changes only. Never store browsing destinations, DNS queries, packet data, or full client IP addresses.';
comment on table app_private.vpn_accesses is
    'Operational references to access issued manually through official AmneziaVPN. Never store client private keys or connection profiles.';
comment on column app_private.vpn_accesses.external_reference is
    'Opaque operator-visible identifier from Amnezia; it must not contain a private key or complete connection profile.';
comment on table app_private.pilot_test_results is
    'Privacy-preserving pilot outcomes. Never store URLs, destination domains, DNS history, packet contents, or client public IP addresses.';
comment on column app_private.pilot_test_results.isp is
    'Optional tester-provided ISP label. It must not contain an IP address or subscriber identifier.';

revoke all on all tables in schema app_private from public, anon, authenticated;
revoke all on all sequences in schema app_private from public, anon, authenticated;
revoke execute on all functions in schema app_private from public, anon, authenticated;

commit;
