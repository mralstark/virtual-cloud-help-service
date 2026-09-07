#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${TEST_DATABASE_URL:?Set TEST_DATABASE_URL to an empty disposable vchs_test database}"
# Keep credentials out of process arguments. These variables are inherited by
# child processes only; do not enable shell tracing for this script.
export PGDATABASE="$TEST_DATABASE_URL"
[[ $(psql -X -Atqc 'select current_database()') == vchs_test ]] || { echo 'Database must be named vchs_test.' >&2; exit 1; }
[[ $(psql -X -Atqc "select count(*) from pg_namespace where nspname='app_private'") == 0 ]] || { echo 'Use a fresh vchs_test database; existing schemas are never reset.' >&2; exit 1; }
for migration in migrations/*.sql; do psql -X -v ON_ERROR_STOP=1 -f "$migration"; done
go test -race -count=1 ./cmd/control-plane -run '^TestDatabaseIntegration$' -v
