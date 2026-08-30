# Delivery roadmap

## Milestone 0 — foundations

- [x] Record the transport ADR and threat model.
- [x] Define a signed public endpoint manifest.
- [x] Add a minimal HTTP control-plane process and key generator.
- [x] Add initial PostgreSQL entities without traffic-history fields.
- [x] Add bounded decoding and an initial security review of manifest issuance.
- [x] Persist monotonic issuer state and reject rollback/equivocation.
- [x] Sign discovery mirrors and add pinned-key sequential fallback.
- [ ] Complete an independent external review and key-rotation ceremony design.

Exit criterion: CI validates the manifest against tampering and expiry; no secret is
required to build or test the repository.

## Milestone 1 — disposable laboratory node

- [ ] Choose the first VPS providers and record the decision.
- [ ] Pin data-plane artifacts by version and checksum.
- [ ] Provision a hardened disposable host from Terraform and Ansible.
- [ ] Deploy one AmneziaWG path and one REALITY path.
- [ ] Add DNS, IPv4/IPv6, MTU, suspend/resume, and kill-switch tests.

Exit criterion: a clean node can be rebuilt from code and both transports work on
all initially supported operating systems in an unrestricted network.

## Milestone 2 — field test matrix

- [ ] Deploy at least three nodes across two providers and ASN.
- [ ] Build an opt-in probe that stores no browsing destinations or full client IP.
- [ ] Test mobile and fixed networks across multiple Russian regions and operators.
- [ ] Detect connections that handshake successfully but freeze during transfer.

Exit criterion: every supported network has a measured primary and fallback path;
failures are classified rather than shown as a generic connection error.

## Milestone 3 — enrollment and revocation

- [ ] Implement short-lived, single-use enrollment tokens.
- [ ] Accept client-generated public keys; never upload device private keys.
- [ ] Issue per-device transport credentials.
- [ ] Revoke one device without rotating every other user.
- [ ] Add signed manifest key rotation with an overlap window.

Exit criterion: a lost device can be revoked without interrupting other devices, and
the control plane can be restored from an encrypted backup.

## Milestone 4 — client orchestration and operations

- [x] Provide a verification library that rejects replay/downgrade/equivocation.
- [ ] Persist trusted state in each supported OS secure store.
- [x] Add a pure endpoint planner for transfer observations and ASN diversity.
- [ ] Integrate real handshake plus randomized bidirectional transfer probes.
- [x] Add bounded sequential fallback and exponential cooldown primitives.
- [ ] Add platform entropy-backed retry jitter in each client.
- [ ] Add runbooks, alerts, canary updates, and a blocked-node replacement workflow.
- [ ] Run failure exercises for UDP loss, blocked IP, DNS failure, and control-plane
  outage.

Exit criterion: common failures recover within the documented SLO without user action.

## Milestone 5 — closed beta

- [ ] Invite 20–50 trusted users gradually.
- [ ] Obtain explicit consent for privacy-preserving diagnostic reports.
- [ ] Complete an independent security review.
- [ ] Measure reliability, abuse load, and cost per active user for two weeks.

Public launch, payments, and a custom GUI are intentionally out of scope until these
criteria are met.
