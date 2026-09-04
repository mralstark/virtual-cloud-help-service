# Database security and load audit — 2026-09-02

Scope: the Go control-plane PostgreSQL stores, migrations, and the connected
Supabase project fywtgmrdjctrocalkwiw. The review intentionally excludes VPN
payload traffic and client browsing data, which the service must never collect.

## Confirmed findings and remediation

1. **Data API exposure risk.** The original migrations created unqualified
   tables in public, where legacy Supabase projects can grant broad default
   privileges to anon and authenticated. All application tables now live in
   app_private; schema, table, sequence, and function access is revoked from
   Data API roles.
2. **Callable privileged function.** public.rls_auto_enable() was a
   SECURITY DEFINER event-trigger function executable by PUBLIC, anon, and
   authenticated. It was moved to app_private and all public execution
   privileges were revoked. The event trigger remains enabled.
3. **Search-path substitution.** Store queries used unqualified relation names.
   Every application query is now schema-qualified, and connections force
   search_path=pg_catalog.
4. **Overprivileged runtime identity.** The administrative Supabase role has
   CREATEROLE, CREATEDB, and BYPASSRLS. The migration creates a NOLOGIN,
   NOBYPASSRLS group role named vchs_runtime with only the exact SELECT, INSERT,
   UPDATE, and telemetry-retention DELETE privileges used by the service.
   Startup now rejects superuser, role-creator, database-creator, and RLS-bypass
   identities.
5. **Unbounded database values.** Length and shape constraints were added for
   device labels and keys, provider metadata, audit fields, and JSON audit
   metadata. Telemetry rejects control characters and records outside its
   30-day/5-minute time window at the database boundary.
6. **Unbounded retention/query horizon.** Pilot aggregates now read only the
   last 30 days. Each accepted telemetry write also deletes at most 1,000 rows
   older than 30 days using the retention index, avoiding an unbounded delete
   lock while eventually enforcing physical retention during an active pilot.
7. **Missing workload indexes.** Partial ISP-failure and retention indexes were
   added. Existing foreign-key and active-access indexes were retained.
8. **Database resource exhaustion.** The client enforces server-side
   statement_timeout=5s, lock_timeout=2s, and
   idle_in_transaction_session_timeout=5s, in addition to request contexts and
   a five-connection pool.
9. **Repeated revoke audit events.** Revocation now updates only active access
   rows, preventing repeated calls from generating misleading duplicate audit
   events.

## Verification

- Supabase Security Advisor: zero findings after migration.
- SQL negative tests: Data API roles cannot use app_private; no application
  table exists in public; oversized audit JSON and out-of-window telemetry are
  rejected; the event-trigger function is not publicly executable.
- Least-privilege tests: vchs_runtime cannot log in, bypass RLS, create roles,
  create databases, delete access rows, or read audit events.
- Go unit tests, go vet, gosec, govulncheck, module verification, and formatting
  are release gates.

## Load result

The rollback-only workload inserted 1,000 accounts/devices/accesses and 50,000
telemetry rows in one transaction. On Supabase PostgreSQL 17.6:

- transport aggregate: 20.539–20.680 ms execution;
- failed-ISP aggregate: 3.152–3.187 ms execution;
- active device/user count: 1.975–1.983 ms execution;
- complete remote call including seed, plans, and rollback: 4.175–5.585 seconds.

Post-test row counts were all zero, confirming rollback. This is a query-plan and
schema load test, not a substitute for concurrent HTTP testing from the final
Timeweb host.

## Deployment boundary

The application must not use the Supabase postgres, service_role, or another
RLS-bypass identity. Create a dedicated login outside version control, grant it
membership in vchs_runtime, store its password in the deployment secret manager,
and use a certificate-verified PostgreSQL URL. The service will fail closed if
that login is privileged or lacks the required table grants.

RLS is intentionally not enabled automatically on the private tables. Supabase
list_tables emits a generic RLS-disabled advisory, but the project Security
Advisor reports no exposure: app_private is not an exposed Data API schema and
anon/authenticated have neither schema usage nor table grants. If a future
architecture exposes this schema, define and test operation-specific RLS
policies before enabling it.

References:

- https://supabase.com/docs/guides/api/securing-your-api
- https://supabase.com/docs/guides/database/postgres/row-level-security
- https://supabase.com/docs/guides/database/database-advisors
