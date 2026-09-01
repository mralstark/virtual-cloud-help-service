# Virtual Cloud Help Service

Privacy-first control plane and deployment tooling for a small, censorship-resilient
VPN service. The project is at the bootstrap stage: it does **not** yet provision a
production VPN node or provide an end-user client.

The implemented bootstrap component publishes a short-lived, Ed25519-signed
endpoint and discovery manifest. It persists a monotonic issuer sequence so a
restart cannot silently roll clients back. The repository also contains reusable
client-side verification, bounded mirror discovery, and endpoint planning packages.

An offline Ed25519 root signs a versioned key policy. The policy assigns contiguous,
non-overlapping manifest-version ranges to online signing keys, so a retired online
key cannot sign a later version and a policy rollback is rejected.

## Current scope

- signed endpoint and discovery manifests with durable issuer versions;
- strict size, schema, offline-root policy, signature, expiry, rollback, and
  equivocation checks;
- sequential discovery fallback with pinned signing keys and bounded downloads;
- a transport-aware endpoint planner with cooldown and provider/ASN diversity;
- a fail-closed downloader for size-bounded, SHA-256-pinned pilot artifacts;
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
  -private-out .local/manifest-root.key \
  -public-out .local/manifest-root.pub

go run ./cmd/manifest-keygen \
  -private-out .local/manifest-signing.key \
  -public-out .local/manifest-signing.pub

go run ./cmd/manifest-key-policy \
  -root-private .local/manifest-root.key \
  -grants config/key-grants.example.json \
  -policy-version 1 \
  -out .local/manifest-key-policy.json

MANIFEST_SIGNING_KEY_PATH=.local/manifest-signing.key \
MANIFEST_ROOT_PUBLIC_KEY_PATH=.local/manifest-root.pub \
MANIFEST_KEY_POLICY_PATH=.local/manifest-key-policy.json \
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
go build -trimpath ./cmd/artifact-fetch ./cmd/control-plane ./cmd/manifest-keygen ./cmd/manifest-key-policy
```

Data-plane versions in `deploy/data-plane/artifacts.lock.json` are laboratory
candidates only. `cmd/artifact-fetch` verifies exact bytes but never executes or
installs them. See [ADR 0004](docs/adr/0004-pinned-pilot-data-plane.md).

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `LISTEN_ADDRESS` | `127.0.0.1:8080` | HTTP listen address |
| `MANIFEST_CATALOG_PATH` | `config/nodes.json` | Unsigned public node catalog |
| `MANIFEST_SIGNING_KEY_PATH` | required | Mounted Ed25519 private key file |
| `MANIFEST_ROOT_PUBLIC_KEY_PATH` | required | Pinned offline-root public key |
| `MANIFEST_KEY_POLICY_PATH` | required | Offline-root-signed online key policy |
| `MANIFEST_STATE_PATH` | required | Durable monotonic issuer state file |
| `MANIFEST_TTL` | `15m` | Signed manifest lifetime, 1–60 minutes |
| `MANIFEST_CACHE_TTL` | `30s` | Cached envelope and catalog reload interval |
| `MAX_IN_FLIGHT` | `64` | Concurrent readiness/manifest request limit |
| `SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown deadline |
| `DATABASE_URL` | disabled | PostgreSQL connection for pilot access metadata |
| `PILOT_ADMIN_TOKEN` | disabled | 32–512 byte bearer token for the loopback/private pilot admin API |

`DATABASE_URL` and `PILOT_ADMIN_TOKEN` must be set together. Apply
all migrations in numeric order through `migrations/000003_pilot_test_results.sql`
before enabling them. The service then verifies the schema at startup and exposes:

- `POST /admin/pilot/access` to record metadata for access created manually in
  official AmneziaVPN;
- `POST /admin/pilot/access/{id}/revoke` to mark that record revoked.
- `POST /admin/pilot/test-results` to record a coarse, privacy-safe acceptance result;
- `GET /admin/pilot/report` to export transport success rates, failure stages,
  optional ISP failure counts, active users/devices, and optional current server
  metrics.

Keep these routes on loopback or an authenticated private edge. The API accepts an
opaque external reference, not a connection profile or private client key. Use
`.env.example` only as a variable-name template; never commit real values.
Test results intentionally have no fields for URLs, destination domains, DNS
history, traffic contents, or client public IP addresses.
When pilot access is enabled, startup rejects wildcard, hostname, and public-IP
`LISTEN_ADDRESS` values. Remote PostgreSQL endpoints must use TLS with no plaintext
fallback; loopback and Unix-socket database connections may be plaintext.
Access registration/revocation and their `admin_audit_events` rows commit in one
transaction, so an unavailable audit sink fails the mutation closed.
Generate the admin token with a cryptographic RNG (for example,
`openssl rand -base64 32`). For a remote database use `sslmode=verify-full` and an
approved CA; `sslmode=require` is rejected because it encrypts without proving the
server identity.

The service should normally listen on a private interface behind a hardened HTTPS
reverse proxy. The private signing key must be mounted read-only as a secret and
must never be committed, copied into an image, or passed in a URL. The issuer state
must be on persistent storage owned by the service user (`0600` file in a `0700`
directory), backed up atomically with the signing key, and never restored to an
older snapshot. Losing it is not recoverable by deleting the file or rotating only
the online key; restore a verified atomic backup. The file-backed issuer is deliberately
single-active on Linux. Do not place its lock/state files on NFS or run multiple
replicas; HA requires a transactional compare-and-swap state-store implementation.

The root private key must never be mounted on the control plane. Keep it offline and
use it only to create a new policy file during a reviewed signing-key rotation. See
the [signing-key rotation runbook](docs/runbooks/signing-key-rotation.md).

## Project status

Read [the roadmap](docs/roadmap.md), [threat model](docs/threat-model.md), and
[production-readiness gate](docs/production-readiness.md) before deploying anything.
The [architecture overview](docs/architecture.md) describes current boundaries. A true
network allowlist can make an ordinary foreign VPS unreachable; this project does
not claim to be unblockable or production-ready. Current research is recorded with
an explicit evidence cutoff of 2026-08-30 rather than claiming knowledge from the
future.

## License

[GNU Affero General Public License v3.0](LICENSE).
