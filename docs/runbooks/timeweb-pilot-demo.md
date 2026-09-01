# Runbook: Timeweb Frankfurt pilot demonstration

## Claim boundary

The demonstration uses one Timeweb node and the official AmneziaVPN client. It
tests AmneziaWG 3.1 and XRay VLESS Reality independently. It does not claim that a
server can be reached through a strict destination allowlist unless the customer
or network operator explicitly approves that server IP/domain. It does not use a
custom client, custom VPN engine, automatic IP rotation, or undocumented Amnezia
container mutation.

## Required inputs

- a visible Timeweb VPS and identified billing owner;
- an approved maintenance window and current backup;
- a dedicated Ed25519 SSH key in an ignored local path;
- the administrator's current IPv4 `/32`;
- the official AmneziaVPN client version selected for the pilot;
- written confirmation of which customer networks/platforms may be tested.

Tokens, passwords, profiles, QR codes, and private keys must never be pasted into
tickets, chat, Terraform variables, cloud-init, logs, or this repository.

## Pre-deployment gate

1. Confirm the Timeweb API/panel shows exactly the intended server. If it shows zero
   servers, stop: documentation and Terraform are not a substitute for a VPS.
2. Complete the approved read-only inventory and update
   `docs/pilot/network-plan.md`. Confirm TCP/443 and UDP/585 are free or record the
   observed replacement ports. Do not replace existing firewall/Docker state.
3. Confirm current price, balance, capacity, backup cost, deletion protection, and
   the owner who may approve billable actions.
4. If a future disposable server is required, run `terraform fmt -check`,
   `terraform validate`, and `terraform plan` in `infra/timeweb`. Review every
   resource and the firewall DROP postcondition. `terraform apply` requires a new,
   explicit approval because it creates paid infrastructure.
5. Verify SSH key access before disabling any remaining password path. Do not lock
   out the official installer or operator.

## Phase A — inventory and backup

- Capture OS/kernel, uptime, memory, disks, addresses/routes, listeners, Docker
  objects, running services, firewall state, PostgreSQL state, and current project
  services using only read-only commands.
- Redact addresses and identifiers before committing a sanitized inventory.
- Take a Timeweb backup/snapshot and an encrypted off-server application backup as
  described in `docs/runbooks/timeweb-restore.md`.
- Stop if a listener, firewall rule, database, container, or volume is not understood.

## Phase B — official Amnezia installation

- Use official AmneziaVPN self-hosted setup. Select the observed AWG UDP port; use
  Reality TCP/443 only when inventory proves it is available.
- Do not install the repository's laboratory artifact lock as the pilot data plane.
- After installation, inventory names, image digests, mounts, published ports,
  Docker networks, restart policies, and health without inspecting secret values.
- Create `testdata/amnezia-node-layout.json` only from that sanitized observation.
  Do not fabricate it before the installation exists.

## Phase C — application layer

- Apply PostgreSQL migrations 000001–000003 in order using a migration identity;
  run the service with a restricted application role.
- Keep PostgreSQL, the admin API, node exporter, and the Go backend on
  loopback/private listeners. Put only an explicitly required public HTTP route
  behind a reviewed TLS proxy.
- Register each manually issued tester access with an opaque reference and expiry;
  never send the connection profile or private key to the backend.
- Verify `/healthz`, `/readyz`, signed-manifest policy, admin authentication, and
  the privacy-safe report before distributing access.

## Demonstration matrix

Run the sequence in `docs/runbooks/pilot-vpn-not-working.md` once with AmneziaWG
selected and once with Reality selected:

1. connect;
2. DNS through the VPN;
3. HTTPS through the VPN;
4. bounded upload;
5. bounded download;
6. IPv4 and IPv6 leak checks;
7. disconnect/reconnect;
8. revoke one tester without affecting the others.

Record only the bounded result fields through `POST /admin/pilot/test-results`.
Changing ports, blocking protocols, or rebooting services is a separately approved
change test, not part of initial validation.

## Stop conditions

Stop on a traffic leak, signing-state error, unexpected listener/container/charge,
unreviewed binary, failed backup, inability to revoke one tester, or any need to
print a secret for diagnosis. Preserve evidence first; do not reset firewalls,
prune Docker, recreate containers, or destroy the node as a troubleshooting step.
