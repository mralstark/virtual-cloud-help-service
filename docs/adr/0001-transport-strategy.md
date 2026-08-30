# ADR 0001: Two independent maintained transports

- Status: accepted for field testing
- Date: 2026-08-30

## Context

Plain WireGuard and OpenVPN have recognizable traffic properties and are routinely
unsuitable as the only path in networks using DPI. A single obfuscated transport is
also a single failure domain: filtering may target its packet signature, traffic
shape, server IP/ASN, UDP, TLS behavior, or long-lived connections.

The project must not invent cryptography or promise that a software tunnel can pass
a network that exposes only an explicit allowlist with no route to our infrastructure.

## Decision

Field-test two independently implemented paths:

1. the current stable AmneziaWG family as the preferred low-latency UDP path;
2. Xray-core VLESS + REALITY over TCP/443 as the independent fallback, beginning
   with the combination recommended by current upstream documentation.

Keep normal WireGuard/OpenVPN only as optional compatibility transports in networks
without restrictive DPI. Pin upstream versions and checksums, use a canary node for
updates, and promote a version only after tests in the target network matrix.

The manifest describes endpoints and references credentials already stored on the
device. Protocol secrets are never shared across devices. The client measures a
small bidirectional transfer after handshake because some filtering begins only
after a connection has moved data.

## Consequences

- The client needs orchestration rather than a single tunnel configuration.
- Operations must maintain at least two server implementations and test paths.
- Nodes must be distributed across providers and ASN; protocol diversity alone does
  not survive IP-range filtering.
- Mobile battery use and fallback latency must be measured.
- Neither transport is permanently designated “unblockable”; the decision is
  revisited from field measurements at least monthly.

## Upstream references

- https://docs.amnezia.org/documentation/amnezia-wg/
- https://docs.amnezia.org/documentation/protocols-info/
- https://xtls.github.io/en/config/transport.html
- https://xtls.github.io/en/config/transports/reality.html
