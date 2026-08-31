# Timeweb Amnezia pilot network plan

- Status: proposed; blocked on existing-VPS inventory
- Updated: 2026-08-31
- Applies to: one Timeweb VPS, at most 10 pilot users

## Evidence gate

The Timeweb project currently contains zero servers, so no listener, Docker network,
route, or firewall rule has been observed. Before installation, record sanitized
output from `ip addr`, `ip route`, `ss -lntup`, Docker inventory, systemd services,
and every active firewall implementation. Do not reserve or open a port from this
document alone.

## Preferred public listeners

Use this layout only if inventory proves the ports are free:

| Purpose | Listener | Exposure | Owner |
| --- | --- | --- | --- |
| SSH administration | TCP/22 | One approved admin IPv4 `/32`; IPv6 only after an equivalent rule | OS/operator |
| XRay VLESS Reality | TCP/443 | Public | Official AmneziaVPN |
| AmneziaWG 3.1 | UDP/585 | Public | Official AmneziaVPN |
| Application backend | `127.0.0.1:8080` | Loopback only | This repository |
| PostgreSQL | Unix socket or private/loopback TCP/5432 | Never public | Application stack |
| Metrics | Loopback/private network | Never public without authenticated gateway | Monitoring stack |

Amnezia documentation notes that XRay should normally retain TCP/443 and that the
selected port must not conflict with another protocol. It recommends moving
AmneziaWG from a random high UDP port to an unused port below 10000, such as 585.

## Conflict handling

If TCP/443 is already in use:

1. identify its process/container, bind addresses, reverse-proxy configuration,
   certificates, and upstreams;
2. document whether it is the backend edge or an unrelated service;
3. do not stop, reconfigure, or replace it automatically;
4. prefer keeping the existing edge and selecting an official-Amnezia-supported
   alternate Reality port for the pilot;
5. test the official client on that port before changing any firewall rule.

Do not attempt transparent multiplexing, SNI routing, port sharing, or container
network surgery in the first pilot unless official Amnezia supports the exact
layout and it has an isolated rollback test.

## Container listeners and Docker networks

Actual Amnezia container names, images, ports, mounts, and networks must be copied
only into the sanitized post-install fixture. Until then:

- preserve every Amnezia-created network and restart policy;
- do not attach the backend or PostgreSQL to an Amnezia-managed network;
- use an application-private Docker network if the backend and PostgreSQL are
  containerized;
- publish only the two approved VPN listeners;
- bind backend, database, and metrics endpoints to loopback/private interfaces;
- inventory Docker's nftables/iptables changes after installation before adding
  host rules.

## Firewall policy

The intended effective ingress policy is deny by default with explicit allowances
for:

- established and related traffic;
- loopback;
- bounded ICMP/ICMPv6 required for correct networking and path MTU discovery;
- SSH from the approved admin source only;
- the observed AmneziaWG UDP port;
- the observed Reality TCP port.

Both Timeweb cloud firewall and host firewall behavior must be inspected. Docker may
insert forwarding/NAT rules that bypass assumptions about the host input chain.
Rules must be added incrementally, tested from a second administrative session, and
rolled back automatically if SSH reachability fails. The current Terraform
cloud-init replaces `/etc/nftables.conf`; it must not run on an existing server.

## Backend connectivity

For the pilot, the Go backend may share the VPS but must not be reachable directly
from the public Internet. Preferred flow:

```text
operator/admin -> authenticated edge (future) -> loopback backend :8080
backend -> private PostgreSQL
backend -> read-only node observer -> sanitized health/inventory/metrics
official AmneziaVPN -> SSH during operator-controlled installation only
pilot clients -> UDP/585 or TCP/443 -> Amnezia containers
```

The current public manifest endpoint has no authentication and is safe only for
public metadata. Any new `/admin/pilot/*` route requires authentication and must not
be exposed directly.

## Threat boundaries

- A compromised Amnezia container must not receive PostgreSQL credentials or the
  manifest signing key.
- A compromised backend must not receive client private VPN keys or unrestricted
  Docker control unless a later review explicitly accepts that risk.
- Docker socket access is root-equivalent and is not granted to the backend for the
  initial pilot.
- Metrics and logs must not contain visited URLs, destination domains, DNS history,
  packet contents, VPN private keys, API tokens, or full client IP addresses.
- Co-location means CPU, memory, disk, kernel, Docker daemon, provider, and public IP
  remain shared failure domains; monitoring must make that visible.

## Validation before applying any rule

1. Capture the existing listeners and firewall state.
2. Select observed-free ports in official AmneziaVPN.
3. Install one protocol at a time through the official client.
4. Re-inventory listeners, Docker mappings, routes, and firewall rules.
5. Verify SSH from a second session before closing the first.
6. Test tunnel, protected DNS, HTTPS, upload, download, and IPv4/IPv6 leak behavior.
7. Add only the minimal documented cloud/host rules required by observed traffic.

