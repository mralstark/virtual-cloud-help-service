# Timeweb Amnezia pilot: current state

- Audit date: 2026-08-31
- Audited revision: `2daf7a3` (merge of PR #6)
- Scope: read-only repository and Timeweb account inventory for EPIC 0
- Pilot target: one existing Timeweb VPS, at most 10 users, official AmneziaVPN

This document preserves the evidence at the audited revision. The current branch
has since added the provider-neutral node model, Timeweb read-only adapter and
fail-closed lifecycle seam, pilot access/test-result migrations and admin workflow,
privacy-safe reports/metrics, recovery/diagnostic runbooks, and a safer future-host
stack at `infra/timeweb`. None of those changes is evidence that a VPS or Amnezia
installation exists.

## Evidence boundary

The repository audit is complete for the files present at the audited revision.
A read-only request to the project-scoped Timeweb API returned `server_count=0`.
Consequently there is no VPS to inspect and no SSH endpoint on which to run the
required host inventory. No server, firewall, container, database, listener, or
service state is inferred from Terraform or documentation.

The following evidence is still required before any host change:

- the existing VPS must appear in the Timeweb project or be identified explicitly;
- SSH access must be provided through an ignored local key or other approved secret
  channel;
- the read-only commands from the pilot requirement must be captured and sanitized;
- existing listeners, firewall rules, Docker objects, databases, mounts, restart
  policies, and service state must be reviewed before choosing ports or installing
  Amnezia.

No `apt upgrade`, container lifecycle command, firewall mutation, Terraform apply,
or Amnezia installation was performed during this audit.

## Existing binaries and build outputs

The repository contains source for four Go commands:

- `cmd/control-plane`: the HTTP manifest issuer;
- `cmd/manifest-keygen`: creates Ed25519 signing key files without overwriting
  existing files;
- `cmd/manifest-key-policy`: creates an offline-root-signed online-key policy;
- `cmd/artifact-fetch`: downloads one reviewed artifact with host, size, TLS, and
  SHA-256 enforcement.

No compiled binaries are tracked. `Dockerfile` builds only `control-plane` into a
minimal `scratch` image. `deploy/data-plane/artifacts.lock.json` records two
AmneziaWG 2.x source archives and one Xray binary as laboratory candidates; the
fetcher neither installs nor executes them. These artifacts are not evidence of an
installed VPN data plane and are not the official Amnezia installation boundary
defined for the current pilot.

## Existing application services

Only the Go control-plane service is implemented. It loads signing material, the
root-signed key policy, an unsigned node catalog, and durable issuer state, then
starts one HTTP server. Graceful SIGTERM/SIGINT shutdown is implemented.

There is no service manager unit, Docker Compose file, Amnezia service, Xray
service, monitoring agent, reverse proxy configuration, backup job, or application
deployment definition in the repository. Runtime service state cannot be reported
until a VPS exists and the server inventory is run.

## Database usage

`migrations/000001_initial.sql` defines PostgreSQL tables for:

- `accounts`;
- `devices` with an account foreign key, public identity key, status, and revocation
  timestamp;
- `nodes` with provider, region, ASN, and lifecycle status;
- `manifest_revisions`;
- privacy-limited `admin_audit_events`.

This is DDL only. The Go module has no PostgreSQL driver, connection configuration,
repository, migration runner, transaction boundary, or runtime database query.
The control plane does not connect to PostgreSQL. There is no `VPNAccess` model and
no place to store Amnezia external references, transport, expiry, or access status.

## HTTP listeners and routes

The application default is `127.0.0.1:8080`. The container image changes the
default to `0.0.0.0:8080` and declares port 8080. Implemented routes are:

- `GET|HEAD /healthz`: process liveness only;
- `GET|HEAD /readyz`: manifest issuer readiness;
- `GET|HEAD /v1/manifest`: current signed manifest envelope.

Other methods return 405. Requests are concurrency-limited and responses receive
basic security and no-store headers. The application intentionally has no access
logger, but there is also no TLS termination, reverse proxy, authentication,
authorization, admin route, Prometheus route, or server inventory endpoint.

No real host listener has been observed. TCP/443, UDP/585, TCP/22, PostgreSQL, and
container port availability remain unknown.

## Docker-related code

The only Docker artifact is the multi-stage control-plane `Dockerfile`. It runs as
UID/GID 65532 and contains no shell or package manager. There is no:

- Docker Compose or container orchestration definition;
- Docker client or SDK dependency in Go;
- Amnezia container adapter;
- declared Docker network, volume, restart policy, or health check;
- PostgreSQL container definition.

The repository therefore cannot describe any actual Amnezia container name, image,
mount, port, network, restart policy, or health state yet.

## Provisioning code

At the audited revision, `infra/timeweb-pilot` was a future/disposable-host
Terraform stack. It has since moved to `infra/timeweb` and now avoids package
upgrades and ruleset flushes, installs the baseline Docker/monitoring packages, and
defines explicit reviewed firewall rules. It still creates rather than inventories
a server and must not be applied to an existing VPS.

It must not be applied to satisfy the new existing-VPS pilot requirement:

- it creates rather than inventories a server;
- Frankfurt capacity was preorder-only at audit time;
- any port still requires observed listener evidence before use;
- a plan creates billable resources and is not an import plan;
- official Amnezia installation and post-install inventory remain manual gates;
- `prevent_destroy` must remain unless a separately reviewed teardown is approved.

The stack remains useful as preparation for a later disposable VM, but it is not an
import or management plan for an existing server.

## Device and enrollment code

The database DDL models accounts and devices, and signed manifest endpoints contain
a `credential_ref` for credentials already present on a device. There is no:

- account or device repository implementation;
- device authentication or enrollment endpoint;
- `User -> Device -> VPNAccess` aggregate;
- per-device Amnezia access registration;
- revoke command/service;
- admin authentication or audit-writing service.

The manifest model correctly avoids transporting client private keys. No plaintext
VPN client keys are present in the repository.

## Manifest and signing code

This is the most complete subsystem. It includes:

- Ed25519-signed schema-v3 manifests;
- an offline-root-signed policy for online signing-key epochs;
- bounded strict JSON decoding and canonical ordering;
- catalog rollback and same-revision equivocation rejection;
- durable monotonic issuer state written before publication;
- a Linux single-process lock for the file-backed issuer;
- client verification with expiry, rollback, policy, key-epoch, and equivocation
  checks;
- bounded sequential HTTPS discovery using TLS 1.3;
- deterministic endpoint planning with provider/ASN diversity and cooldowns.

This architecture should be preserved. It is not integrated with official
AmneziaVPN, PostgreSQL, an enrollment workflow, or a real node inventory.

## Health and diagnostics code

The HTTP service exposes process liveness and manifest readiness only.
`internal/selector` contains a pure privacy-preserving probe-evidence classifier.
It requires protected DNS, tunnel-route confirmation, and at least 64 KiB upload and
download before considering a path healthy; it does not perform those probes.

Missing runtime health evidence includes:

- node READY/DEGRADED/DOWN state;
- AmneziaWG and Reality container/process state;
- public port reachability;
- server outbound connectivity;
- CPU, memory, network, active-connection, and config-revision metrics;
- DNS, IPv4, IPv6, upload, and download checks through an actual tunnel.

## Pilot-relevant unfinished work

The repository roadmap and readiness gate already identify most gaps:

- no installed VPN data plane;
- no official AmneziaVPN self-hosted installation inventory;
- no PostgreSQL runtime integration;
- no enrollment, per-device credential issuance, or revocation;
- no real transfer probes, DNS/IPv6 leak tests, or platform acceptance suite;
- no Prometheus metrics or privacy-safe pilot result store;
- no application/database/Amnezia backup and restore exercise;
- no provider-independent `VPNNode` or Timeweb adapter;
- no authenticated admin workflow for recording manual access;
- no server reboot, Docker restart, backend restart, or PostgreSQL restart evidence.

There is also a version-policy conflict to resolve with evidence: the new pilot
requires AmneziaWG 3.1 through official Amnezia, while ADR 0004 deliberately pins
2.x laboratory sources and defers 3.x because of open regressions at its evidence
cutoff. The repository must not implement or install either line itself for this
pilot. The official installer result and exact deployed versions must be inventoried
after a disposable/existing host is available, then acceptance-tested before use.
