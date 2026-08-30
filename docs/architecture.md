# Architecture overview

## Design goals

The system separates the control plane from the VPN data plane. A blocked or
compromised VPN node must not expose the manifest signing key, other nodes, or the
account database. A failed control plane must not terminate already established
tunnels.

```text
                      signed, short-lived manifest
Control plane  -------------------------------------------->  Client orchestrator
     |                                                              |
     | provisions public metadata                                   | selects and
     | and revokes credentials                                       | health-checks
     v                                                              v
Node pool A / ASN A  <----- encrypted user traffic ----->  AmneziaWG or REALITY
Node pool B / ASN B  <----- encrypted user traffic ----->  independent fallback
```

## Trust boundaries

### Control plane

Owns accounts, public device keys, revocation state, public node inventory, and one
online manifest signing key. It never receives the offline root private key and does
not forward user traffic. In the bootstrap implementation it reads a public catalog
and root-signed key policy from disk and emits an Ed25519-signed envelope.

### Client orchestrator

Pins one offline root public key. It rejects invalid, expired, downgraded, or
replayed manifests; stores per-device transport credentials in the OS secret store;
and measures both handshake and bidirectional data transfer before declaring an
endpoint healthy.

### Data plane

Terminates the selected VPN/proxy transport and forwards user traffic. A node gets
only the credentials required for its own peers. It never receives the manifest
private key or control-plane database credentials.

## Signed manifest protocol

`GET /v1/manifest` returns an envelope:

```json
{
  "algorithm": "Ed25519",
  "key_id": "base64url-sha256-public-key",
  "payload": "base64url-encoded-canonical-json",
  "signature": "base64url-ed25519-signature"
}
```

The decoded payload is schema version 3 and contains a durable issuer version, an
operator-controlled catalog revision, issuance/expiry timestamps, signed discovery
mirrors, an offline-root-signed online-key policy, provider/ASN metadata, and public
endpoints. `credential_ref` names credentials already provisioned to one device; the
manifest never carries a device private key.

The issuer records the highest manifest and key-policy versions, both canonical
digests, the signing-key epoch, catalog revision, and issuance time before publishing
an envelope. It rejects a lower or same-version-changed policy, an unauthorized key,
a backwards clock, a catalog rollback, or a changed catalog at the same revision.
Clients pin only the offline root public key and persist the corresponding accepted
state. The same bytes may arrive from multiple mirrors; different bytes at the same
version are rejected.

The current file store takes a non-blocking Linux process lock for the issuer's full
lifetime so two local processes cannot allocate the same next version. It supports
one active replica only. A future HA deployment must replace it with a transactional
compare-and-swap state store; a shared network filesystem is not sufficient.

The current encoder uses a Go struct without maps, giving deterministic field order.
The signature is over the exact decoded payload bytes. Future schema changes must
define canonicalization explicitly or keep signing opaque payload bytes.

## Availability behavior

- `/healthz` proves only that the process is alive.
- `/readyz` validates that the issuer can return a current envelope.
- `/v1/manifest` returns the cached envelope and refreshes it at a bounded interval.
- Refreshes are serialized, persisted before publish, and protected by an HTTP
  concurrency limit. A transient catalog error keeps only a still-unexpired cached
  envelope.
- Responses use `Cache-Control: no-store`; a later CDN/edge design must preserve
  expiry semantics and must not rewrite the signed payload.
- The application deliberately omits access logging. Aggregate edge metrics must be
  configured without storing full client IPs.

## Not implemented yet

- enrollment and device authentication;
- PostgreSQL repository code;
- data-plane provisioning;
- transport-specific credential issuance;
- integration of the endpoint planner with an end-user client and real transfer
  probes;
- revocation delivery and offline-root rotation/recovery;
- multi-region probes and privacy-preserving telemetry.
