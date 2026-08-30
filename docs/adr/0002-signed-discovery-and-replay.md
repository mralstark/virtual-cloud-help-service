# ADR 0002: Signed discovery and monotonic replay state

- Status: accepted for bootstrap implementation
- Date: 2026-08-30

## Context

Rotating only data-plane IP addresses does not help when the single control-plane
hostname is blocked. Trusting HTTPS alone also lets a compromised delivery path feed
an old but correctly signed manifest to a client. A restarted signer must not reuse
the same manifest version for different bytes.

The design follows the relevant lessons from The Update Framework: bound untrusted
metadata before parsing, pin an offline-established trust root, persist the highest
accepted metadata version, reject rollback and freeze, and use multiple mirrors.
This repository is not a TUF implementation and must not claim TUF compatibility.

## Decision

1. The operator catalog has an explicit `revision`. Any public content change must
   increment it.
2. The issuer maintains a separate monotonically increasing `version`, plus the
   canonical catalog digest and last issuance time, on durable storage.
3. State is synced before a newly signed envelope is made available. A crash may
   skip a version but cannot safely reuse one.
4. A Linux advisory lock is held for the entire issuer lifetime. The file-backed
   implementation is single-active and is not an HA coordination mechanism.
5. Signed payloads carry one to sixteen HTTPS discovery mirrors. Clients bootstrap
   with at least one built-in URL and one or more pinned Ed25519 public keys, then
   retain the last-known-good signed mirror set.
6. The client bounds the complete envelope and encoded fields before Base64 decode,
   rejects redirects, and tries at most a configured number of mirrors
   sequentially.
7. Client trusted state contains the highest version, issuance time, and exact
   signed-payload SHA-256. An identical payload from another mirror is valid;
   different bytes at the same version are equivocation.

## Operational requirements

- `MANIFEST_STATE_PATH` must be durable, writable only by the service user, and
  included in atomic encrypted backups with the signing key.
- Restoring either file independently or to an older snapshot is prohibited.
- Loss or suspected corruption requires a documented signing-root rotation, not
  deletion of the state file.
- Do not share the file store over NFS or start multiple replicas. HA requires a
  transactional compare-and-swap allocator with equivalent durability semantics.
- Client trusted state must eventually use the platform secure store. Deleting it
  weakens rollback protection to first-use trust.
- Mirror operators may cache exact envelopes but must never decode and rewrite the
  signed payload.

## Consequences

Availability no longer depends on one discovery hostname, and replay protection
survives ordinary process restarts. The state file becomes security-critical and
requires explicit backup/restore procedures. Root key rotation and freeze detection
when no fresh manifest is reachable remain separate work.

## References

- [The Update Framework specification](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)
- [Go Ed25519 package](https://pkg.go.dev/crypto/ed25519)
