# Production-readiness gate

Status: **not approved for production**. This checklist distinguishes a hardened
control-plane bootstrap from a complete VPN product. No operator may interpret a
green unit-test run as authorization to launch for users.

## Implemented baseline

- bounded schema-v3 manifests with Ed25519 online signatures;
- pinned offline root and root-signed, non-overlapping online-key version grants;
- manifest, key-policy, catalog, clock, and same-version rollback/equivocation
  protection with durable pre-publish state;
- one active Linux issuer enforced with a process lock;
- signed multi-mirror discovery with redirect, TLS 1.3, size, concurrency, per-attempt,
  and shared overall time bounds;
- deterministic endpoint planning across transports, providers, and ASNs with
  cooldown primitives;
- pinned build image, immutable GitHub Action revisions, race tests, vet, build,
  govulncheck, and container-build CI gates;
- threat model and blocked-node/signing-key rotation runbooks.

## Release blockers

- [ ] Implement and independently audit an end-user client that persists
  `TrustedState` in each OS secure store.
- [ ] Integrate maintained, checksum-pinned data-plane implementations; this
  repository currently starts no VPN tunnel.
- [ ] Implement device enrollment, per-device credentials, revocation, abuse limits,
  and account repository code.
- [ ] Add kill-switch, DNS/IPv6 leak, MTU, suspend/resume, captive-portal, and
  uninstall cleanup tests on every supported OS.
- [ ] Add consented full-transfer probes and complete the Russian operator/region
  field matrix. A handshake-only check is not sufficient.
- [ ] Add reproducible infrastructure, secret-manager integration, encrypted atomic
  backup/restore, alerting, SLOs, capacity limits, and disaster exercises.
- [ ] Replace the file state store with transactional compare-and-swap before any HA
  or multi-replica deployment.
- [ ] Design and rehearse offline-root recovery/rotation. Only online-key rotation is
  implemented.
- [ ] Produce SBOM and signed release provenance, scan deployed upstream binaries,
  and validate canary rollback.
- [ ] Complete an independent code/cryptography review and resolve every high or
  medium finding.
- [ ] Complete provider-terms, privacy, data-retention, abuse, and applicable legal
  review before accepting external users.

## Launch rule

Every blocker must have an owner, evidence link, reviewer, and dated approval.
Closed beta begins with a small opt-in cohort only after all blockers are complete.
Any signing-state loss, manifest equivocation, traffic leak, unexplained transfer
stall, or inability to revoke one device independently is a release stop.
