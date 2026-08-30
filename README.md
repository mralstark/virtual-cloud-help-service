# Virtual Cloud Help Service

Privacy-first control plane and deployment tooling for a small, censorship-resilient
VPN service. The project is at the bootstrap stage: it does **not** yet provision a
production VPN node or provide an end-user client.

The first implemented component is a minimal Go service that publishes a
short-lived, Ed25519-signed endpoint manifest. A future client orchestrator can use
that manifest to rotate nodes and choose between independent transports without
trusting the delivery channel.

## Current scope

- signed, versioned endpoint manifests;
- strict manifest validation and tamper/expiry verification;
- liveness, readiness, and manifest HTTP endpoints;
- no request/access logging in the application;
- a PostgreSQL schema for accounts, devices, nodes, and manifest revisions;
- threat model, architecture decision records, and an incremental roadmap;
- CI for tests, race detection, vetting, and reproducible builds.

The planned data plane uses maintained open-source transports rather than custom
cryptography: an AmneziaWG-family UDP path plus an independent Xray REALITY TCP
fallback. Neither is integrated yet. See [ADR 0001](docs/adr/0001-transport-strategy.md).

## Run locally

Prerequisites: Go 1.27 or newer.

```bash
go run ./cmd/manifest-keygen \
  -private-out .local/manifest-signing.key \
  -public-out .local/manifest-signing.pub

MANIFEST_SIGNING_KEY_PATH=.local/manifest-signing.key \
MANIFEST_CATALOG_PATH=config/nodes.example.json \
go run ./cmd/control-plane
```

PowerShell:

```powershell
go run ./cmd/manifest-keygen `
  -private-out .local/manifest-signing.key `
  -public-out .local/manifest-signing.pub

$env:MANIFEST_SIGNING_KEY_PATH = ".local/manifest-signing.key"
$env:MANIFEST_CATALOG_PATH = "config/nodes.example.json"
go run ./cmd/control-plane
```

The example endpoints are documentation-only addresses and will not carry traffic.

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
go build ./cmd/control-plane ./cmd/manifest-keygen
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `LISTEN_ADDRESS` | `127.0.0.1:8080` | HTTP listen address |
| `MANIFEST_CATALOG_PATH` | `config/nodes.json` | Unsigned public node catalog |
| `MANIFEST_SIGNING_KEY_PATH` | required | Mounted Ed25519 private key file |
| `MANIFEST_TTL` | `15m` | Signed manifest lifetime, 1–60 minutes |
| `SHUTDOWN_TIMEOUT` | `10s` | Graceful shutdown deadline |

The service should normally listen on a private interface behind a hardened HTTPS
reverse proxy. The private signing key must be mounted as a secret and must never be
committed, copied into an image, or passed in a URL.

## Project status

Read [the roadmap](docs/roadmap.md), [threat model](docs/threat-model.md), and
[architecture overview](docs/architecture.md) before deploying anything. A true
network allowlist can make an ordinary foreign VPS unreachable; this project does
not claim to be unblockable.

## License

[GNU Affero General Public License v3.0](LICENSE).
