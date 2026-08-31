# ADR 0003: Timeweb Cloud Frankfurt single-provider pilot

- Status: accepted for pilot implementation
- Date: 2026-08-31

## Context

The first customer demonstration must be payable from Russia and small enough to
operate as one disposable environment. Timeweb Cloud provides a Frankfurt zone,
API tokens, Terraform, cloud-init, movable public IPv4 addresses, and Russian
payment methods.

A single-provider pilot cannot survive provider- or ASN-wide filtering. More
importantly, no transport can reach an ordinary Frankfurt address through a strict
destination allowlist that contains no authorized route to that address. The pilot
must demonstrate resistance to protocol/DPI interference without claiming that it
can cross every allowlist.

## Decision

Use one Timeweb Cloud server in availability zone `fra-1` (`de-1`) for the pilot.
Expose two independently maintained transports on the same node:

1. a pinned AmneziaWG-family UDP transport for normal and UDP-capable networks;
2. a pinned HTTPS-shaped TCP/443 fallback using a domain controlled by the
   operator and valid public TLS. The initial implementation may evaluate Xray
   REALITY/WebSocket-style upstream transports, but must not impersonate or front
   an unrelated allowlisted domain.

Keep the control-plane listener private and publish it through a hardened HTTPS
reverse proxy. Clients declare a path healthy only after protected DNS plus a
bounded bidirectional transfer succeeds. A TLS handshake alone is insufficient.

Terraform creates only the project, SSH key, server, and attachment metadata.
Host firewall and operating-system hardening are applied by cloud-init. Applying a
Terraform plan remains a manual, billable action. API credentials are read only
from `TWC_TOKEN` and are never stored in source or Terraform variables.

## Allowlist modes used in the demonstration

- **Protocol/DPI block:** exercise UDP failure and TCP/443 fallback.
- **Destination IP block:** classify the endpoint as unreachable; do not retry in
  a tight loop.
- **Strict destination allowlist:** fail closed unless the customer/operator has
  explicitly approved the pilot IP or domain.
- **Approved enterprise allowlist:** use the customer-approved hostname/IP; do not
  use third-party SNI, CDN tenancy, or domain-fronting behavior without written
  authorization from the infrastructure owner.

## Promotion gates

- Rebuild a clean host from reviewed code.
- Verify SSH key-only access, disabled root/password login, host firewall, automatic
  security updates, and no committed secrets.
- Verify DNS and IPv6 leak prevention, kill switch, MTU behavior, suspend/resume,
  UDP loss fallback, and post-handshake transfer stalls.
- Pin every data-plane artifact by version and SHA-256 before installation.
- Record actual Timeweb location, public IP, provider ASN, and domain in a new
  catalog revision only after deployment.
- Obtain customer acceptance of the strict-allowlist limitation.

## Consequences

The pilot is inexpensive and reproducible, but the single server, provider, ASN,
and discovery domain are explicit failure domains. Production still requires at
least a second provider/ASN and an independently hosted discovery mirror.
