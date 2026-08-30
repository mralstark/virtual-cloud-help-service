# Virtual Cloud Help Service

Privacy-first control plane and deployment tooling for a small, censorship-resilient
VPN service. The project is at the bootstrap stage: it does **not** yet provision a
production VPN node or provide an end-user client.

The implemented bootstrap component publishes a short-lived, Ed25519-signed
endpoint and discovery manifest. It persists a monotonic issuer sequence so a
restart cannot silently roll clients back. The repository also contains reusable
client-side verification, bounded mirror discovery, and endpoint planning packages.

## Current scope

- signed endpoint and discovery manifests with durable issuer versions;
- strict size, schema, signature, expiry, rollback, and equivocation checks;
- sequential discovery fallback with pinned signing keys and bounded downloads;
- a transport-aware endpoint planner with cooldown and provider/ASN diversity;
- liveness, readiness, and manifest HTTP endpoints;
- cached issuance plus bounded concurrent HTTP work;
- no request/access logging in the application;
- a PostgreSQL schema for accounts, devices, nodes, and manifest revisions;
- threat model, architecture decision records, and an incremental roadmap;
- CI for tests, race detection, vetting, and reproducible builds.

The planned data plane uses maintained upstream cryptography rather than custom
cryptography: an AmneziaWG-family UDP path plus an independent Xray REALITY TCP
fallback. Neither is integrated yet. See [ADR 0001](docs/adr/0001-transport-strategy.md)
and the [resilience research](docs/censorship-resilience.md).

## Run locally

Prerequisites: Linux (or WSL for development) and Go 1.27.0 or newer. Key loading
fails closed outside Linux because the file-permission and process-locking model has
only been implemented and reviewed for Linux.

```bash
go run ./cmd/manifest-keygen \
  -private-out .local/manifest-signing.key \
  -public-out .local/manifest-signing.pub

MANIFEST_SIGNING_KEY_PATH=.local/manifest-signing.key \
MANIFEST_STATE_PATH=.local/issuer-state.json \
MANIFEST_CATALOG_PATH=config/nodes.example.json \
go run ./cmd/control-plane
```

The example endpoints are documentation-only addresses and will not carry traffic.
Increase the catalog `revision` whenever discovery, node, or endpoint content
changes. Reusing a revision with different content is intentionally rejected.

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/readyz
curl http://127.0.0.1:8080/v1/manifest
```

## Verify

```bash
go test ./...
go test -race ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
go build -trimpath ./cmd/control-plane ./cmd/manifest-keygen
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `LISTEN_ADDRESS` | `127.0.0.1:8080` | HTTP listen address |
| `MANIFEST_CATALOG_PATH` | `config/nodes.json` | Unsigned public node catalog |
| `MANIFEST_SIGNING_KEY_PATH` | required | Mounted Ed25519 private key file |
| `MANIFEST_STATE_PATH` | required | Durable monotonic issuer state file |
| `MANIFEST_TTL` | `15m` | Signed manifest lifetime, 1–60 minutes |
| `MANIFEST_CACHE_TTL` | `30s` | Cached envelope and catalog reload interval |
| `MAX_IN_FLIGHT` | `64` | Concurrent readiness/manifest request limit |
| `SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown deadline |

The service should normally listen on a private interface behind a hardened HTTPS
reverse proxy. The private signing key must be mounted read-only as a secret and
must never be committed, copied into an image, or passed in a URL. The issuer state
must be on persistent storage owned by the service user (`0600` file in a `0700`
directory), backed up atomically with the signing key, and never restored to an
older snapshot. Losing it requires a controlled signing-key rotation; starting from
version one with the same key is unsafe. The file-backed issuer is deliberately
single-active on Linux. Do not place its lock/state files on NFS or run multiple
replicas; HA requires a transactional compare-and-swap state-store implementation.

## Project status

Read [the roadmap](docs/roadmap.md), [threat model](docs/threat-model.md), and
[architecture overview](docs/architecture.md) before deploying anything. A true
network allowlist can make an ordinary foreign VPS unreachable; this project does
not claim to be unblockable or production-ready. Current research is recorded with
an explicit evidence cutoff of 2026-08-30 rather than claiming knowledge from the
future.

## License

[GNU Affero General Public License v3.0](LICENSE).
