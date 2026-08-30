# Censorship-resilience engineering notes

Evidence cutoff: **2026-08-30**. September 2026 has not started at the time of this
review, so no claim in this document is described as verified “for September”.
Filtering behavior changes by operator, region, access type, and sometimes within a
day. Field observations below are signals for testing, not universal facts.

## Guarantee boundary

No VPN can guarantee access through every block. If a network exposes only a strict
allowlist and none of its permitted destinations provides an authorized path to the
service, software has no route to use. Domain fronting through infrastructure that
does not explicitly authorize it is not part of this design. Every relay/CDN option
requires provider-terms and legal review.

The engineering objective is narrower and testable: avoid one protocol, IP, ASN,
hostname, or discovery channel being a single failure domain; detect partial
failures; rotate safely; and preserve user privacy.

## Current observations that affect the design

- Russian mobile-network allowlist reports show reachability can vary between
  regions and even between SIM profiles. The project therefore needs real operator
  measurements and cannot ship a static “working list”. See the ongoing
  [net4people field report](https://github.com/net4people/bbs/issues/650).
- Reports against TLS-like tunnels describe classification using destination
  subnet/ASN, SNI, client fingerprint, and connection bursts, sometimes followed by
  temporary freezes. The client therefore attempts fallbacks sequentially, caps
  connection concurrency, and adds cooldown rather than spraying addresses. See
  [Xray issue 6293](https://github.com/XTLS/Xray-core/issues/6293).
- Other observations show policing only after roughly tens of kilobytes on a TCP
  flow. A TCP/TLS handshake alone is not a health check. See
  [Xray issue 4846](https://github.com/XTLS/Xray-core/issues/4846).
- REALITY can complete setup yet stall during application transfer under partial
  DPI. Health must include a bounded randomized upload and download through the
  tunnel. See [Xray issue 5908](https://github.com/XTLS/Xray-core/issues/5908).
- Obfuscation releases can regress in the exact networks they target. A current
  AmneziaWG 3.1 report involving `RandomTrailers` reinforces the need for staged
  canaries and automated rollback rather than blind latest-version updates. See
  [AmneziaWG issue 226](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/issues/226).

These are community reports, not controlled experiments. Each hypothesis belongs in
the field-test matrix before it changes a production default.

## Transport and cryptography policy

Do not design a new cipher, handshake, or obfuscation layer in this repository.

- Use maintained AmneziaWG releases for the UDP path only after canary validation.
  Its WireGuard-derived cryptographic core uses established primitives; version and
  artifact checksums must be pinned.
- Use a separately implemented TLS-like TCP/443 fallback based on current Xray
  upstream guidance. TLS policy is TLS 1.3 with normal certificate validation where
  HTTPS is used. REALITY keys/configuration are device-specific and held outside the
  public manifest.
- Ed25519 signs control metadata. SHA-256 identifies exact keys and payloads. These
  choices protect authenticity; they do not make traffic unclassifiable.
- Post-quantum or hybrid handshakes may be adopted only through audited upstream
  implementations after interoperability and performance tests. They do not solve
  IP, SNI, timing, or allowlist blocking.
- Evaluate an HTTPS-shaped third path through a maintained modular project such as
  the [Outline SDK](https://github.com/OutlineFoundation/outline-sdk). It is a
  candidate, not an implemented or approved dependency.

## Safe address and discovery rotation

1. Operate at least three canary-capable nodes across at least two providers and
   ASNs. Provider names and ASNs are signed manifest fields and feed client ranking.
2. Publish at least two independently hosted HTTPS discovery mirrors. Bootstrap
   URLs and Ed25519 roots ship with the client; later mirror lists remain signed.
3. Change catalog contents only with a higher catalog revision. The issuer writes a
   higher durable manifest version before publish, and clients persist the highest
   accepted version and digest.
4. Mark a suspect endpoint draining, publish replacement endpoints, wait at least
   one manifest lifetime, and only then destroy the old node. Never recycle its
   device credentials.
5. Clients try a bounded sequence. They prefer a different provider/ASN after a
   failure, skip UDP when it is unavailable, and exponentially cool failed paths.
   Platform clients add up to 20% cryptographically random jitter.
6. Never run unbounded background probes, scan address ranges, or open many
   fingerprint-identical TLS connections. Besides abuse risk, burst behavior itself
   may be a classifier.

DNS names and direct IP discovery endpoints are both useful failure domains, but an
HTTPS IP endpoint still needs a certificate valid for the URL host. Do not disable
certificate verification to make direct IP work.

## Health classification

A candidate is healthy only after all required checks succeed:

1. DNS/address resolution, where applicable;
2. transport handshake within a network-specific deadline;
3. protected DNS resolution through the tunnel;
4. randomized upload and download large enough to cross observed partial-filter
   thresholds, with a strict byte/time cap;
5. confirmation that traffic used the tunnel and did not leak through the default
   route.

Record only coarse error class, random device ID, node ID, transport, coarse time
bucket, and aggregate bytes with short retention and explicit consent. Never record
destinations, queries, packet payloads, SNI, or full client IPs.

## Promotion gates

- Validate each upstream version on unrestricted networks first, then on opt-in
  canaries across the supported Russian operator/region matrix.
- Exercise UDP loss, DNS poisoning, blocked IP, blocked ASN, TLS handshake-only
  success, transfer stall, discovery outage, stale manifest, and clock skew.
- Require automated rollback when transfer success or time-to-connect regresses.
- Pin binaries/images by digest, generate SBOM and provenance before beta, and run
  upstream vulnerability scans in CI.
- Revisit transport defaults from measurements at least monthly. A working protocol
  is evidence for one network and time window, never a permanent guarantee.

## Related implementations

- [Mullvad client architecture](https://github.com/mullvad/mullvadvpn-app/blob/main/docs/architecture.md)
  documents a direct API path plus a bridge fallback.
- [Outline SDK](https://github.com/OutlineFoundation/outline-sdk) provides modular
  network transports and interference-protection building blocks.
- [The Update Framework](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)
  informs the metadata size, mirror, rollback, and freeze requirements.
