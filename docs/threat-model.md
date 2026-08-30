# Threat model

## Assets

- availability of at least one working data path;
- device private keys and per-device transport credentials;
- manifest signing keys and trusted public-key set;
- account and revocation state;
- integrity of software releases and infrastructure definitions;
- privacy of browsing destinations, DNS requests, and client network identifiers.

## Adversaries and failures

### Passive network observer and DPI

Can observe addresses, ports, timing, sizes, direction, TLS metadata, and connection
success/failure. It may correlate flows and classify nested encrypted traffic. It
cannot break correctly implemented modern cryptography.

Mitigations: maintained censorship-resistant transports, independent UDP/TCP paths,
provider/ASN diversity, limited and deliberate probing, and field measurement. The
project does not claim to defeat global traffic correlation.

### Active network censor

Can block DNS/SNI/IP/subnets, reset or throttle flows, filter UDP, actively probe a
server, and impose a temporary allowlist.

Mitigations: authenticated transports resistant to active probing, signed endpoint
rotation, realistic fallback behavior, multiple providers, and fast disposable-node
replacement. There is no software-only mitigation when every route to the service is
outside a strict allowlist.

### Compromised data-plane host or provider

Can inspect traffic after tunnel termination, record source metadata, modify the host,
or steal credentials present on that node.

Mitigations: TLS for end-to-end applications, one-node credential scope, no signing
key/database secret on data-plane nodes, deny-by-default firewall, immutable rebuilds,
minimal logs, fast revocation, and provider diversity. Destination privacy from the
chosen egress provider is explicitly not guaranteed.

### Compromised control plane

Can issue malicious node metadata or revoke devices. It must not be able to recover
device private keys because clients generate and retain them.

Mitigations: mounted signing secret, least privilege, administrative audit events,
offline recovery key, short manifest lifetime, client-side key pinning, two-person
release procedure before public scale, and planned key-rotation transparency.

### Stolen or malicious client device

Can use its own credentials and inspect its local traffic/configuration. It must not
impersonate another device or retrieve global secrets.

Mitigations: one key per device, OS secret storage, narrow enrollment tokens, remote
revocation, quotas, and no shared configuration files.

### Malicious user and abuse reporter

Can generate prohibited traffic, exhaust capacity, share credentials, or cause the
hosting provider to suspend a node.

Mitigations: per-device quotas and rate limits, connection concurrency limits, a
documented abuse process, rapid node isolation, and closed enrollment. Payload and
destination logging is not introduced as an abuse shortcut.

### Supply-chain attacker

Can compromise upstream binaries, containers, dependencies, or update delivery.

Mitigations: minimal standard-library control plane, pinned versions and checksums,
signed releases, SBOM/provenance in a later milestone, canary rollout, and rollback.

## Privacy rules

The application must not log URL, destination SNI/IP, DNS history, packet contents,
or full client IP. Operational events may contain a random device identifier, node,
coarse time bucket, error category, and aggregate byte count with a documented short
retention period. Packet capture is permitted only in a lab or with explicit,
time-bounded tester consent.

## Security invariants

1. A manifest is accepted only when its signature, key ID, schema, lifetime, and
   monotonic version are valid.
2. A data-plane compromise does not disclose the manifest signing key or database.
3. A device private key never leaves that device.
4. Revoking one device does not rotate unrelated device credentials.
5. Failure to refresh metadata keeps a bounded last-known-good configuration; it does
   not silently accept unsigned data.
6. Readiness fails closed when the catalog or signing material is invalid.

## Deferred validation

- external review of canonical encoding and signing-key rotation;
- leak tests on every supported OS;
- confirmation of data deletion and backup restore procedures;
- reproducible field measurements across operators/regions;
- legal review before offering access beyond a private pilot.
