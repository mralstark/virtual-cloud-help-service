# Timeweb pilot backup and restore

This procedure separates short-lived rollback, provider backup, encrypted
off-server backup, and application recovery. A Timeweb snapshot is never the only
copy. Full-disk restore and snapshot rollback are destructive actions and require
an explicit maintenance window and operator approval.

Current Timeweb documentation states that a server can have one free snapshot,
that it expires after seven days, and that backups cannot be created while a
snapshot exists. It also warns that provider-side copies do not cover every server
or account failure and recommends a remote copy. See the
[Timeweb backup documentation](https://timeweb.cloud/docs/cloud-servers/manage-servers/backup).

## Recovery objectives for the pilot

- PostgreSQL operational metadata: daily encrypted off-server copy; target RPO 24h.
- Manifest issuer state and configuration: copy after every approved change;
  target RPO one approved change.
- Amnezia server state: Timeweb disk backup plus post-install inventory; take a
  fresh provider backup before structural changes.
- Operator Amnezia settings: encrypted backup after access/protocol changes. The
  official client can back up connected servers, protocols, and services from
  Settings -> Backup; later client backups may not restore correctly into an older
  app version. See the
  [official Amnezia backup instructions](https://docs.amnezia.org/documentation/instructions/backup-and-restore/).
- Initial pilot target: RTO four hours after infrastructure is available. This is
  a target to validate, not a measured guarantee.

## Backup layers

### 1. Before a structural change

1. Confirm there is no in-progress backup/restore and record the current server ID.
2. Run the read-only inventory from the pilot audit and capture sanitized versions,
   image digests, listeners, restart policies, Docker networks, and volume names.
3. Create a PostgreSQL logical backup and verify it before changing the host.
4. Create a Timeweb disk backup. Use the seven-day snapshot only for an immediate
   rollback when its incompatibility with backups is acceptable.
5. Copy application and operator backups to encrypted storage outside this VPS and
   outside the single Timeweb account where practical.

Creating provider backups may incur charges. Do not enable or restore them without
the account owner approving the displayed cost.

### 2. PostgreSQL logical backup

Run as a restricted backup identity. Supply credentials through a protected
environment/file, never a command-line password:

```sh
umask 077
pg_dump --format=custom --no-owner --no-acl --file=vchs.dump --dbname='service=vchs-backup'
pg_restore --list vchs.dump >vchs.dump.list
sha256sum vchs.dump vchs.dump.list >SHA256SUMS
```

Encrypt the dump and checksum manifest with an approved recipient-based tool before
off-server transfer. Do not delete the local source until the encrypted remote
object has been downloaded and its checksum verified. Rotation must retain at
least one known-good copy outside the VPS.

### 3. Application state

Back up these paths from the deployed configuration, not assumed defaults:

- manifest issuer state (`MANIFEST_STATE_PATH`);
- manifest node catalog;
- root public key and signing-key policy;
- the manifest signing private key, encrypted separately with stricter access;
- deployment unit/compose definitions and their exact image digests;
- applied migration list and release commit SHA.

Never include `.env`, API tokens, database URLs, raw admin tokens, SSH private
keys, or decrypted signing keys in a plaintext archive.

### 4. Amnezia state

After official installation, inventory container names/images, Docker networks,
named volumes, bind mounts, exposed ports, restart policies, and health without
reading secret values. Add the sanitized result to
`testdata/amnezia-node-layout.json`. Only then define the server-side backup set:

- every named volume/bind mount proven to hold Amnezia configuration;
- the exact official client version and an encrypted Settings -> Backup export;
- a redacted list of individually issued access records.

Do not guess volume paths and do not copy private profiles into this repository.
The client settings export complements a server/disk backup; it is not evidence
that a lost VPS can be reconstructed at the same address.

## Restore order

1. Declare an incident, stop issuing access, choose the restore point, and preserve
   current evidence. Record whether IP and DNS will change.
2. Prefer mounting a Timeweb backup read-only for partial file recovery. A full
   backup/snapshot restore replaces current disk state; Timeweb recommends stopping
   the server first, and all newer changes will be lost.
3. For an application rebuild, prepare a compatible Ubuntu host, secure SSH, install
   Docker/PostgreSQL, and validate time synchronization before exposing services.
4. Restore database roles with least privilege, apply schema migrations only up to
   the release being restored, then run `pg_restore --exit-on-error --no-owner
   --no-acl --dbname='service=vchs-recovery' vchs.dump` only against an empty,
   explicitly named recovery database. Never target the live database by default.
5. Restore the public manifest configuration, encrypted signing key, and durable
   issuer state with original ownership and restrictive permissions. Start the
   control plane on loopback and verify `/healthz`, `/readyz`, schema checks, and a
   signed manifest before enabling a proxy.
6. If the full Timeweb disk was restored, verify Amnezia containers, mounts,
   networks, restart policies, listeners, and both transports without recreating
   them. For a new host, use the official AmneziaVPN self-hosted setup; do not
   synthesize protocol internals from old container files.
7. Reissue or revoke tester access as required. Treat an IP change as a forced
   re-enrollment event unless the official client proves otherwise.
8. Execute `docs/pilot/acceptance-suite.md` for AWG and Reality. Restore normal
   issuance only after DNS, HTTPS, upload, download, leak, reconnect, and revoke
   checks pass.

## Restore-test evidence

At least monthly and before inviting testers:

- restore `vchs.dump` into an empty disposable PostgreSQL database;
- run all migrations/schema checks and `go test ./...` against the restored schema;
- verify row counts for accounts/devices/nodes/access/results without exporting
  identities;
- start the application with disposable keys/state and pass health/readiness/admin
  authentication tests;
- destroy only the explicitly named disposable database after evidence is signed
  off;
- record timestamps, release SHA, backup checksum, duration, and pass/fail.

This test remains blocked until a disposable PostgreSQL runtime is available; a
successful `pg_restore --list` is integrity evidence but is not a restore test.
