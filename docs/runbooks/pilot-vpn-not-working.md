# Pilot VPN is not working

This runbook is for the single-node Timeweb/Amnezia pilot. It is diagnostic by
default: do not restart containers, change firewall rules, rotate ports, or remove
configuration until the failing layer has been identified and current state has
been captured.

## Privacy and evidence rules

- Record timestamps, coarse outcomes, platform, optional ISP label, transport, and
  failure stage only.
- Do not paste connection profiles, QR codes, private keys, complete container
  environment variables, DNS history, visited destinations, or client public IPs
  into tickets or telemetry.
- Redact server IPs, usernames, volume paths containing identifiers, and tokens
  before attaching command output.
- A handshake is evidence for only one step. It is not a successful pilot test.

## Preconditions

Have the server ID, an approved administrator source address, the official
AmneziaVPN client, a current operator backup, and the expected port map from
`docs/pilot/network-plan.md`. Use a UTC timestamp for every observation. If the
observed ports differ from the plan, stop and update the inventory; do not force
the documented ports onto the host.

## Diagnostic sequence

### 1. Server health

Confirm in the Timeweb panel that the instance is running and its CPU, memory,
disk, and network graphs are plausible. On the host, collect read-only evidence:

```sh
date -u
uptime
free -h
df -h
systemctl --failed --no-pager
systemctl --type=service --state=running --no-pager
```

Fail this stage if the host is unreachable, disk is full, memory is exhausted, or
a required service is failed. Do not reboot before preserving evidence.

### 2. Public IP availability

Compare the public IP assigned in Timeweb with the expected, redacted inventory.
On the server use `ip -brief address` and `ip route`; do not rely on DNS alone.
From an approved external machine, confirm SSH or another known-safe public port
is reachable. Do not scan unrelated ports.

Fail this stage on a detached/changed address, missing default route, provider
incident, or routing mismatch.

### 3. Transport container/process

Capture sanitized runtime state:

```sh
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
docker network ls
```

Use `docker inspect --format '{{.Name}} {{.State.Status}} {{.State.Health.Status}} {{.HostConfig.RestartPolicy.Name}}' CONTAINER`
only for the expected Amnezia container. Do not dump `.Config.Env` or complete
mount contents. Record the exact image digest and restart count separately.

Fail `transport` if the expected workload is absent, exited, restarting, or
unhealthy. Preserve logs with secrets redacted before any operator-approved
restart.

### 4. Port

On the server compare listeners and Docker mappings with the observed network
plan:

```sh
ss -lntup
docker port CONTAINER
```

From an approved external machine test only the expected transport port. TCP can
be checked with `nc -vz -w 5 HOST PORT`; UDP reachability cannot be proven by a
successful local listener alone and must be confirmed by the actual AmneziaWG
transfer test. Check Timeweb cloud firewall, host firewall, and Docker forwarding
as separate layers. Never reset a firewall as a diagnostic shortcut.

### 5. Server outbound Internet

Verify route, DNS resolution, HTTPS, and time without changing resolver settings:

```sh
ip route
getent ahosts example.com
curl --fail --silent --show-error --max-time 10 --output /dev/null https://example.com/
timedatectl status
```

Fail `server_outbound` if name resolution, TLS, routing, or clock synchronization
is broken. Do not use a tester's browsing destinations as probes.

### 6. AmneziaWG 3.1

In the official client select AmneziaWG explicitly, connect, and record whether a
tunnel was established. Continue through DNS, HTTPS, upload, and download below;
do not mark success yet. If it fails, preserve the official client's sanitized
diagnostic log and record `tunnel` or the earlier server-side stage.

### 7. XRay VLESS Reality

Disconnect AWG, select Reality explicitly, reconnect, and repeat the full sequence.
This is an independent fallback test, not proof that AWG is healthy. A TCP/443
connection by itself is not sufficient.

### 8. DNS through the VPN

While the selected tunnel is active, resolve a neutral operator-approved hostname
and verify the query uses the intended VPN DNS path. Do not upload resolver logs.
Record only pass/fail. Fail `dns` if resolution bypasses the intended path or does
not work.

### 9. IPv4 leak

Using an approved IP-check endpoint, verify that the observed IPv4 belongs to the
VPN server/provider rather than the client's access ISP. Do not store either
address in pilot telemetry. Fail `ipv4_leak` on any client-address exposure.

### 10. IPv6 leak

If IPv6 is supported by the configured tunnel, the observed IPv6 must be the
server-side address. If it is intentionally unsupported, IPv6 requests must fail
closed rather than use the client's native IPv6. Test on every supported client
platform and fail `ipv6_leak` if the access-ISP address is visible.

### 11. Small upload and download

Use an operator-controlled endpoint or an approved neutral speed-test target.
Transfer a small bounded payload in both directions; avoid personal content.
Record only the configured throughput bucket, never the target URL or payload.
Fail `upload` or `download` independently.

## Success criterion

A transport passes only when the following chain completes in one test session:

```text
tunnel established -> DNS through VPN -> HTTPS through VPN
-> small upload -> small download -> disconnect/reconnect
```

After testing, record the result through `POST /admin/pilot/test-results`. Test AWG
and Reality separately. If the problem remains, attach only the sanitized evidence
and the first failing stage; do not make speculative firewall or container changes.
