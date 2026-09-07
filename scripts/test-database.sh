#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
: "${TEST_DATABASE_URL:?Set TEST_DATABASE_URL to an empty disposable vchs_test database}"
# --dbname parses a URI explicitly. Use disposable credentials only; never
# point this migration/test runner at a shared or production database.
psql_test() { psql -X --dbname="$TEST_DATABASE_URL" -v ON_ERROR_STOP=1 "$@"; }
[[ $(psql_test -Atqc 'select current_database()') == vchs_test ]] || { echo 'Database must be named vchs_test.' >&2; exit 1; }
[[ $(psql_test -Atqc "select count(*) from pg_namespace where nspname='app_private'") == 0 ]] || { echo 'Use a fresh vchs_test database; existing schemas are never reset.' >&2; exit 1; }
for migration in migrations/*.sql; do psql_test -f "$migration"; done
go test -race -count=1 ./cmd/control-plane -run '^TestDatabaseIntegration$' -v
