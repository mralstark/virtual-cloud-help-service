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

Owns accounts, public device keys, revocation state, public node inventory, and the
offline-capable manifest signing key. It does not forward user traffic. In the
bootstrap implementation it reads a public catalog from disk and emits an
Ed25519-signed envelope.

### Client orchestrator

Pins one or more manifest public keys. It rejects invalid, expired, downgraded, or
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
  "key_id": "base64url-sha256-public-key-prefix",
  "payload": "base64url-encoded-canonical-json",
  "signature": "base64url-ed25519-signature"
}
```

The decoded payload is schema version 1 and contains an increasing catalog version,
issuance/expiry timestamps, and public endpoints. `credential_ref` names credentials
already provisioned to one device; the manifest never carries a device private key.

The current encoder uses a Go struct without maps, giving deterministic field order.
The signature is over the exact decoded payload bytes. Future schema changes must
define canonicalization explicitly or keep signing opaque payload bytes.

## Availability behavior

- `/healthz` proves only that the process is alive.
- `/readyz` reloads, validates, and signs the current catalog.
- `/v1/manifest` repeats that operation and returns `503` on invalid configuration.
- Responses use `Cache-Control: no-store`; a later CDN/edge design must preserve
  expiry semantics and must not rewrite the signed payload.
- The application deliberately omits access logging. Aggregate edge metrics must be
  configured without storing full client IPs.

## Not implemented yet

- enrollment and device authentication;
- PostgreSQL repository code;
- data-plane provisioning;
- transport-specific credential issuance;
- client health scoring and failover;
- revocation delivery and signing-key rotation;
- multi-region probes and privacy-preserving telemetry.
