# Timeweb Amnezia pilot: gap analysis

- Analysis date: 2026-08-31
- Inputs: repository audit at `2daf7a3` and read-only Timeweb server listing
- Target: one existing Timeweb VPS, official AmneziaVPN, at most 10 pilot users

## Existing

- A small Go control plane with bounded HTTP handling, liveness, manifest
  readiness, and graceful shutdown.
- A strong signed-manifest and offline-root key-policy design that should remain
  independent of the VPN engine.
- PostgreSQL DDL for accounts, devices, nodes, manifest revisions, and
  administrative audit events.
- Public node/endpoint catalog types for `amneziawg` and `vless-reality`.
- Pure endpoint ranking, cooldown, and full-transfer success classification.
- A privacy boundary that excludes browsing destinations, DNS history, payloads,
  full client addresses, and private client keys.
- A future Timeweb Terraform/cloud-init stack and a checksum-enforcing artifact
  downloader, neither of which has been applied to a pilot host.
- CI for formatting, race tests, vet, vulnerability checks, command builds, and the
  pinned control-plane image.

## Missing

### Infrastructure evidence

- The Timeweb project currently has zero servers. There is no existing VPS ID,
  public address, operating system, SSH inventory, listener list, firewall state,
  Docker state, database state, or service state to audit.
- The existing-server ownership/import boundary is undefined. Applying the current
  Terraform would create a new server and is outside the current pilot instruction.

### Pilot domain and adapters

- A provider-independent `VPNNode` contract and transport capability types.
- A read-only Timeweb/host adapter for health, inventory, and metrics.
- Future provider operation interfaces that do not expose Timeweb API structs to
  the domain layer.
- A sanitized `testdata/amnezia-node-layout.json` based on real post-install
  inventory.

### Access workflow and persistence

- `VPNAccess` operational metadata linked to the existing device and node models.
- Migration and repository code for access registration and revocation state.
- An authenticated internal/admin command or `POST /admin/pilot/access` endpoint.
- Administrative audit writes and tests.
- A rule that external Amnezia references are metadata only and private client keys
  never enter PostgreSQL.

### Runtime and operations

- Official AmneziaVPN self-hosted installation and its sanitized inventory.
- Independently verified AmneziaWG 3.1 and XRay VLESS Reality operation.
- A conflict-free port plan based on observed host listeners and Docker mappings.
- Runtime node/transport health, Prometheus metrics, and privacy-safe test results.
- VPN diagnostic, Timeweb restore, and application recovery runbooks.
- Idempotent host bootstrap tested only on a disposable VM.
- The reboot/restart, DNS, IPv4/IPv6 leak, upload, download, revoke, and restore
  acceptance suite.

## Unsafe assumptions

1. **An existing VPS is available.** The authenticated Timeweb API currently returns
   zero servers. Documentation or Terraform cannot substitute for server evidence.
2. **Frankfurt can be launched immediately.** The panel showed preorder-only
   capacity at audit time. This may change, but it must be rechecked before an
   order.
3. **The current Terraform is safe for the new pilot.** It creates a server, runs
   package upgrades, replaces nftables configuration, and opens ports. It must not
   touch a future existing VPS without a separate import and change plan.
4. **Preferred ports are free.** TCP/443 may already serve a backend/reverse proxy;
   UDP/585 and TCP/22 are also unverified. No firewall or port mutation is safe
   before `ss`, Docker, and firewall inventory.
5. **PostgreSQL is already used.** Only DDL exists; the application has no database
   dependency or queries.
6. **The Docker image is a deployment.** It builds only the control plane and has no
   volumes, health check, secrets, database, reverse proxy, or Amnezia containers.
7. **Pinned artifacts are an Amnezia installer.** They are laboratory inputs owned
   by this repository's old build path. The current pilot assigns initial server
   installation and VPN engines to official AmneziaVPN.
8. **AmneziaWG 3.1 is already approved by repository evidence.** ADR 0004 records
   unresolved 3.x regressions and pins 2.x laboratory sources. The official
   installer may deploy a different build; its exact version and behavior require
   post-install inventory and acceptance tests.
9. **A handshake proves success.** The existing classifier correctly requires DNS,
   route, upload, and download evidence, but no runtime probe produces it.
10. **The manifest is consumed by official AmneziaVPN.** No such integration exists;
    manual provisioning is the required first pilot workflow.
11. **A cloud firewall is sufficient.** Its effective policy and rules are not
    specified in the current Terraform, and host/container forwarding rules remain
    unobserved.
12. **Co-locating backend, PostgreSQL, VPN containers, and monitoring is safe by
    default.** It is an accepted pilot compromise only after ports, secrets, memory,
    storage, backup, and failure boundaries are documented.

## Minimal changes required

Changes should be delivered in small EPIC-scoped pull requests and must not mutate
a server until the corresponding read-only evidence exists.

1. **Complete the host half of EPIC 0.** Obtain or identify the single VPS, run only
   the approved inventory commands, sanitize the results, and append observed
   listeners, firewall, Docker, services, and database state to the current-state
   document.
2. **Record the pilot architecture (EPIC 1).** Add an ADR for official AmneziaVPN,
   AWG primary, Reality fallback, pilot-only co-location, and the migration path to
   provider abstraction. Reconcile rather than delete ADRs 0001, 0003, and 0004.
3. **Create the observed network plan (EPIC 2).** Reserve TCP/443 and UDP/585 only
   if inventory proves them free. Keep the backend private or document a minimal
   reverse-proxy coexistence layout. Do not apply firewall changes in this step.
4. **Use the official installation boundary (EPIC 3).** Let official AmneziaVPN
   perform initial self-hosted setup. Then collect names/images, mounts, ports,
   networks, restart policies, and health without secrets and create the sanitized
   layout fixture.
5. **Add read-only domain seams first (EPIC 4/11).** Introduce provider-neutral node,
   transport, health, inventory, and metrics types plus a Timeweb infrastructure
   adapter. Keep create/delete/IP operations as typed interfaces or explicit
   unsupported stubs until needed.
6. **Extend the existing schema (EPIC 5/6).** Add a migration for `VPNAccess`, a
   repository/service, and an authenticated manual access-registration/revocation
   workflow. Preserve the signing/manifest subsystem and do not store private
   client keys.
7. **Add observable health and telemetry (EPIC 7/9).** Start with adapter-fed
   container/process state and coarse Prometheus metrics. Add privacy-safe test
   results only with bounded enums/buckets and no traffic history.
8. **Add recovery and acceptance evidence (EPIC 8/10/14).** Write the diagnostic
   and restore runbooks, implement application-level backup/restore fixtures, then
   execute the connection and restart matrix before inviting testers.
9. **Keep Terraform and bootstrap non-destructive (EPIC 12/13).** Move future-host
   code toward `infra/timeweb/`, add required-secret documentation, and test
   bootstrap only on a disposable VM. Do not import, recreate, or modify the pilot
   VPS without a separately reviewed plan.

The immediate next implementation after this documentation is not a VPN installer.
It is either the missing read-only VPS inventory, or—if no VPS exists yet—the
provider-independent domain interface and architecture ADR developed against a
sanitized fixture while provisioning remains paused.

