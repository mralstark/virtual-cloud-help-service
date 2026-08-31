# ADR 0004: Pinned pilot data-plane candidates

- Status: accepted for laboratory build; not approved for production
- Date: 2026-08-31

## Context

The Timeweb pilot needs one UDP path and one independently implemented TCP/443
path. Installing an unversioned package, cloning a moving branch, or piping a remote
script to a shell would make the host irreproducible and would turn an upstream
compromise into immediate code execution.

The newest AmneziaWG kernel-module line is not automatically the safest choice.
As of the evidence cutoff, open upstream reports describe regressions in the 3.1
line involving `RandomTrailers`, `HeaderProtectionKey`, and `PersistentKeepalive`:

- https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/issues/226
- https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/issues/216
- https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/issues/198

Xray also publishes prereleases separately from its latest stable GitHub release.
The pilot must not silently promote a prerelease.

## Decision

Record the following laboratory candidates in
`deploy/data-plane/artifacts.lock.json`:

- `amneziawg-go` v0.2.16 at commit
  `730d6c39d0c4e348a3d080bebe496664215e5c99`;
- `amneziawg-tools` v1.0.20260618-2 at commit
  `61e741780e8465a67a7d7fb6cffe14a8a15d624a`;
- stable Xray-core v26.3.27 at commit
  `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`.

Each entry pins an HTTPS URL, exact output filename, SHA-256 digest, and maximum
download size. The source archives were independently downloaded and hashed on the
decision date. The Xray digest also matches its upstream `.dgst` release asset.

Use `cmd/artifact-fetch` as the only repository-provided downloader. It permits a
small allowlist of GitHub artifact hosts, requires TLS 1.3, bounds redirects and
size, verifies SHA-256 before publication, uses a private directory, and refuses to
overwrite an existing artifact.

## Not decided

- The lock does not approve a production binary built from the AmneziaWG sources.
  The build environment, compiler image, transitive modules, output digest, SBOM,
  and provenance still need to be pinned and reviewed.
- The lock does not contain credentials or transport configuration.
- The listed versions are candidates for unrestricted-network and opt-in canary
  testing, not permanent defaults.
- AmneziaWG 3.x may be reconsidered only after its relevant regressions are fixed
  upstream and the exact release passes the field matrix.

## Consequences

Deployments fail closed when bytes differ from review. Updating any component now
requires a visible lock-file diff and test evidence. Availability still depends on
GitHub during initial artifact staging, so production promotion requires an
operator-controlled, signed artifact mirror with identical digests.
