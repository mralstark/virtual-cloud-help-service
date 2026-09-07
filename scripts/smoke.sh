#!/usr/bin/env bash
# Run in a fresh Linux checkout; never overwrite development keys.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ ! -e .local ]] || { echo 'Smoke test needs a fresh checkout without .local.' >&2; exit 1; }
make init build
if bash scripts/dev.sh init; then
  echo 'Initialization unexpectedly overwrote existing state.' >&2
  exit 1
fi
export LISTEN_ADDRESS=127.0.0.1:18080
unset DATABASE_URL PILOT_ADMIN_TOKEN
pid=''
cleanup() {
  if [[ -n $pid ]]; then kill "$pid" 2>/dev/null || true; wait "$pid" || true; fi
}
trap cleanup EXIT
start() {
  bash scripts/dev.sh run >.local/smoke.log 2>&1 &
  pid=$!
  for ((attempt=0; attempt<100; attempt++)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      cat .local/smoke.log >&2
      return 1
    fi
    if curl --fail --silent --max-time 2 http://127.0.0.1:18080/readyz >/dev/null; then return; fi
    sleep 0.1
  done
  echo 'Service did not become ready.' >&2
  return 1
}
version() {
  curl --fail --silent --max-time 5 http://127.0.0.1:18080/v1/manifest |
    jq -er '.payload | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | .version'
}
start
curl --fail --silent --max-time 5 http://127.0.0.1:18080/healthz
first=$(version)
kill -TERM "$pid"
wait "$pid"
pid=''
start
second=$(version)
[[ $second -gt $first ]] || { echo 'Manifest version did not advance after restart.' >&2; exit 1; }
echo 'Startup, readiness, graceful restart and persistent version checks passed.'
