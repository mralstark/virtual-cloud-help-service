# Virtual Cloud Help Service

A small Go control plane for a single-server Timeweb/Amnezia VPN pilot.
It publishes signed server catalogs, records manually issued access references,
and produces privacy-preserving reports. Official AmneziaVPN installs the VPN
protocols and manages client profiles.

**Start here:** [Pilot setup](docs/quickstart.md) ·
[Configuration](docs/configuration.md) · [Documentation index](docs/README.md)

## What works

- Ed25519-signed catalogs with an offline trust root and persistent protection
  against rollback, equivocation and concurrent issuers.
- Bounded discovery fallback and endpoint selection across transports/providers.
- Private authenticated API for access metadata, audit events and test results.
- PostgreSQL/Supabase private schema, minimum runtime permissions, verified TLS,
  bounded connections/queries and 30-day reporting.
- Read-only Timeweb server preflight, Linux service unit and infrastructure templates.
- Unit, race, security and real PostgreSQL integration tests in CI.

The control plane does not install a VPN or issue/revoke client credentials.
Recording revocation in this database **does not disconnect a client**: revoke it
in Amnezia first. The pilot uses AmneziaWG for UDP and Xray REALITY for TCP fallback.
Field tests determine which works on a given network; a foreign VPS cannot
guarantee reachability through a strict destination allowlist.

## Local development

Use Linux or WSL on a Linux filesystem, Go 1.27.1+, Bash and Make. Key loading and
issuer locks are Linux-only. On Windows use a WSL directory such as
`~/src/virtual-cloud-help-service`, rather than a Windows-mounted directory.

```sh
make init
make run
```

In a second terminal:

```sh
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
curl --fail http://127.0.0.1:8080/v1/manifest
```

Initialization refuses to overwrite `.local`. Generated keys and the sample
catalog are for development; example endpoints do not carry VPN traffic.
Restart with `make run`, preserving issuer state. Never recover by deleting it.

## Connect an existing Timeweb server

Set `TWC_TOKEN` in the environment, then run:

```sh
go run ./cmd/pilot-check -server-id 123456 -zone fra-1
```

This checks running state, zone and public IP assignment. It reads only the chosen
server, never changes billing/networking, and excludes provider passwords from
output. VPN setup also needs SSH access and a client profile. Follow the
[setup guide](docs/quickstart.md).

## Checks

```sh
make check
make build
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
go run github.com/securego/gosec/v2/cmd/gosec@v2.29.0 -quiet ./...
```

Set `TEST_DATABASE_URL` for a fresh disposable database named `vchs_test`, then
run `make integration`. It applies standard migrations and exercises actual pgx
writes, reports, concurrent revocation and denied privileges. It never resets an
existing schema. CI runs this separately from mocked tests using PostgreSQL 17.

## Repository map

- `cmd/` — control plane, key tools, artifact downloader, server preflight.
- `internal/` — application logic and adapters.
- `migrations/` — fresh standard PostgreSQL schema and runtime grants.
- `supabase/` — equivalent managed migrations and security SQL checks.
- `deploy/` — Linux service configuration and laboratory artifact candidates.
- `infra/timeweb/` — separately reviewed billable host provisioning.
- `docs/` — setup, operations, architecture and dated research.

See [production readiness](docs/production-readiness.md) for remaining product
release gates and [the September review](docs/reviews/2026-09-07.md) for decisions.

## License

[GNU Affero General Public License v3.0](LICENSE).
