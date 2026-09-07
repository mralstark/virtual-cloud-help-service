#!/usr/bin/env bash
# Local Linux development only; production uses separate offline-root custody.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux ]] || { echo 'Use Linux or WSL (a Linux filesystem).' >&2; exit 1; }
umask 077

case "${1:-}" in
  init)
    [[ ! -e .local ]] || { echo '.local already exists; initialization never overwrites keys or issuer state.' >&2; exit 1; }
    mkdir .local
    go run ./cmd/manifest-keygen -private-out .local/manifest-root.key -public-out .local/manifest-root.pub
    go run ./cmd/manifest-keygen -private-out .local/manifest-signing.key -public-out .local/manifest-signing.pub
    go run ./cmd/manifest-key-policy -root-private .local/manifest-root.key -grants config/key-grants.example.json -policy-version 1 -out .local/manifest-key-policy.json
    cp config/nodes.example.json .local/nodes.json
    echo 'Development initialized. Run make run; this sample does not establish a VPN tunnel.'
    ;;
  run)
    export MANIFEST_SIGNING_KEY_PATH=.local/manifest-signing.key
    export MANIFEST_ROOT_PUBLIC_KEY_PATH=.local/manifest-root.pub
    export MANIFEST_KEY_POLICY_PATH=.local/manifest-key-policy.json
    export MANIFEST_STATE_PATH=.local/issuer-state.json
    export MANIFEST_CATALOG_PATH="${MANIFEST_CATALOG_PATH:-.local/nodes.json}"
    export LISTEN_ADDRESS="${LISTEN_ADDRESS:-127.0.0.1:8080}"
    mkdir -p bin
    go build -o bin/control-plane ./cmd/control-plane
    exec ./bin/control-plane
    ;;
  *) echo 'Usage: bash scripts/dev.sh init|run' >&2; exit 2 ;;
esac
