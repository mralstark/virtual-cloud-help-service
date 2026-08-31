# ADR 0005: Timeweb single-node official Amnezia pilot

- Status: accepted for a closed pilot; runtime acceptance evidence pending
- Date: 2026-08-31
- Evidence cutoff: 2026-08-31

## Context

The immediate objective is a closed pilot for at most 10 users, not a production
multi-provider VPN. The pilot client and initial VPN server installer are the
official AmneziaVPN application. This repository must not fork the client,
reimplement AmneziaWG or Xray, or mutate undocumented Amnezia container state.

Official Amnezia documentation supports self-hosted installation through the
client, AmneziaWG 3.1 with AmneziaVPN 5.0.1.5 or later, and XRay VLESS Reality. It
also recommends selecting an unused low UDP port such as 585 after checking current
listeners:

- https://docs.amnezia.org/documentation/instructions/install-vpn-on-server/
- https://docs.amnezia.org/documentation/instructions/install-configure-protocols/
- https://docs.amnezia.org/faq/
- https://docs.amnezia.org/documentation/xray/

Current upstream reports include AmneziaWG 3.1 cases where a handshake succeeds but
DNS and transfer fail, plus an XRay settings workflow that can regenerate or lose
Reality configuration. These reports are not proof that every deployment fails,
but they prohibit treating installation or handshake as acceptance evidence:

- https://github.com/amnezia-vpn/amnezia-client/issues/3082
- https://github.com/amnezia-vpn/amnezia-client/issues/3043
- https://github.com/amnezia-vpn/amnezia-client/issues/2958

The authenticated Timeweb account contained zero servers at the decision date. The
topology below is therefore a target architecture, not a claim about deployed
infrastructure.

## Decision

### Pilot topology

Run the following on one existing Timeweb VPS only after a read-only server
inventory and an approved port plan:

- the existing Go application backend;
- one PostgreSQL instance;
- Amnezia-managed Docker containers;
- a privacy-preserving monitoring agent.

Control-plane and data-plane co-location is accepted only for this closed pilot.
The backend must remain on loopback or a private container network unless a reviewed
reverse proxy is required. PostgreSQL must not listen publicly. Amnezia containers
remain owned by official AmneziaVPN.

### Transport policy

- Primary target: AmneziaWG 3.1 on an observed-free UDP port, preferably UDP/585.
- Fallback target: XRay VLESS Reality on TCP/443 when that listener is free.
- Client: official AmneziaVPN; no custom client or fork.

"Primary" means connection preference after the acceptance suite passes. It does
not waive canary validation. A transport is ready only when the tunnel establishes,
protected DNS works, HTTPS works, and bounded upload and download succeed. If the
current AmneziaWG 3.1 transfer regressions reproduce, the pilot is not released with
AWG as primary; the issue is documented and escalated rather than patched by
reimplementing protocol internals.

### Ownership boundaries

- Official AmneziaVPN owns initial installation, VPN engines, protocol
  configuration, guest access creation, and protocol-specific secrets.
- This repository owns application metadata, manual access registration,
  revocation status, signed public manifests, aggregate health, metrics, and
  operational runbooks.
- PostgreSQL stores operational references and state, never plaintext client
  private keys.
- Provider-specific APIs and structs stay behind infrastructure adapters.

ADR 0004 remains a record of a previous laboratory artifact path. Its downloader
and pins are not used to install the current pilot. The official installer boundary
in this ADR supersedes any implication that this repository should build or install
AmneziaWG/Xray for the pilot.

## Migration path

The domain model remains stable across these stages:

1. one existing Timeweb node with manual Amnezia provisioning;
2. multiple Timeweb nodes using the same `VPNNode`, device, and access contracts;
3. provider operations implemented behind provider-neutral interfaces;
4. OVH, Hetzner, or other provider adapters without changing user/device/access
   domain types;
5. production separation of control plane, PostgreSQL, monitoring, and VPN data
   plane after pilot evidence justifies it.

## Consequences

- A single node/provider/ASN and co-located failure domain are explicit pilot risks.
- Manual official-client installation is required before sanitized container
  fixtures or adapters can be finalized.
- TCP/443 and UDP/585 are preferences, not reservations, until inventory proves
  them free.
- Existing signing/manifest code is preserved, but official AmneziaVPN does not
  currently consume that manifest; pilot provisioning remains manual.
- No production claim, automatic IP rotation, whitelist bypass claim, or automatic
  protocol mutation follows from this ADR.
