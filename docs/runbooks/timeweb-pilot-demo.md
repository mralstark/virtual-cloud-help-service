# Runbook: Timeweb Frankfurt pilot demonstration

## Purpose and claim boundary

The pilot demonstrates recovery from common protocol and DPI interference using a
single Timeweb Frankfurt node. It does not claim to reach that node through a
strict destination allowlist unless the customer or network operator explicitly
allows the pilot IP or domain.

## Required inputs

- a Timeweb account with a reviewed balance and spending owner;
- an existing, dedicated Timeweb project;
- a short-lived API token scoped to that project, with cloud-server and network
  management only, supplied as `TWC_TOKEN`;
- a dedicated Ed25519 SSH public key;
- the operator's current public IPv4 `/32` for administration;
- an operator-controlled domain whose A record can be changed for the pilot;
- written confirmation of whether the customer test network uses protocol
  filtering, destination blocking, or an approved enterprise allowlist.

Never paste tokens or private keys into tickets, chat, Terraform variables, cloud-init,
or the repository.

## Pre-deployment gate

1. Review the current Timeweb price for the exact `fra-1` configuration and confirm
   the zone has immediately available capacity rather than a preorder queue.
   Timeweb's managed cloud-server DDoS option is not available in Frankfurt and
   must remain disabled. Terraform's resource guard permits at most 2 vCPU, 4 GiB
   RAM, and 40 GiB disk unless code review explicitly changes it.
2. Run `terraform init`, `terraform fmt -check`, `terraform validate`, and
   `terraform plan`. Save no plan file containing sensitive provider values.
3. Confirm the plan reuses the reviewed project and creates one SSH public key, one
   server, and one firewall attachment only. It must not create another project.
4. Obtain explicit approval before `terraform apply`; it creates billable resources.
5. Confirm the cloud firewall policy in the Timeweb panel. The host nftables policy
   is DROP and permits SSH only from the configured `/32`, UDP/51820, and TCP/80/443.

## Deployment phases

### Phase A — hardened host

- Apply the reviewed Terraform plan.
- Confirm the server is in Frankfurt and record its actual provider ASN.
- Verify cloud-init completed, nftables is active, SSH password login is rejected,
  and security updates are enabled.
- Point the pilot domain to the assigned IP only after the host firewall is active.

### Phase B — pinned data plane

- Install only reviewed upstream artifacts whose version, download URL, SHA-256,
  SBOM, and license are recorded in the release manifest.
- Use unique device credentials. Never reuse a demonstration credential for a real
  user or another server.
- Bind the UDP and TCP/443 transports independently. The HTTPS endpoint must use
  infrastructure and a domain controlled or explicitly authorized by the operator.
- Keep the Go control plane on a private listener behind the HTTPS edge.

### Phase C — signed publication

- Replace every `.invalid` and documentation address in the pilot catalog.
- Set the actual Timeweb provider ASN and increase the catalog revision.
- Issue and verify the signed manifest before distributing a client profile.
- Confirm a client rejects an expired, changed-at-same-version, or improperly signed
  manifest.

## Demonstration matrix

1. **Baseline:** both transports complete protected DNS, upload, download, and route
   confirmation.
2. **UDP unavailable:** block UDP in the test network; the client cools the UDP path
   and succeeds over TCP/443.
3. **Handshake-only stall:** permit setup but drop transfer after the handshake; the
   client reports `transfer`, not healthy.
4. **DNS interference:** poison or deny the ordinary resolver; protected resolution
   must succeed after the tunnel is established without leaking to the default path.
5. **Destination block:** deny the pilot IP; the client fails closed and applies a
   bounded cooldown.
6. **Strict allowlist:** keep an explicitly approved witness reachable while the
   pilot destination is not. Report `suspected-allowlist`, explain that this is a
   conservative inference, and do not spray alternate addresses.
7. **Approved allowlist:** repeat only after the customer/operator adds the pilot
   destination; record the approval and demonstrate the same transfer checks.

## Acceptance criteria

- no DNS, IPv4, or IPv6 traffic escapes the protected route while connected;
- a path is never marked healthy before at least 64 KiB succeeds in each direction;
- UDP failure falls back without user action and without unbounded parallel probes;
- a suspected allowlist enters a 15-minute-to-6-hour exponential cooldown;
- service removal revokes demonstration credentials and destroys the billable node;
- logs contain no browsing destinations, DNS queries, packet contents, SNI, tokens,
  private keys, or full client addresses.

## Stop conditions

Stop the demonstration on a traffic leak, signing-state error, unreviewed binary,
unexpected Terraform resource, unexpected charge, provider abuse alert, or inability
to revoke the demonstration device independently.
