# Single-server pilot setup

Both the control plane and an actual VPN transfer must pass before a customer
demonstration. These instructions do not purchase resources.

## 1. Verify the existing server

Required inputs: Timeweb API token, existing server ID, SSH host/key, and a test
client device. Frankfurt should report availability zone `fra-1`.

```sh
read -r -s -p 'Timeweb API token: ' TWC_TOKEN; echo
export TWC_TOKEN
go run ./cmd/pilot-check -server-id 123456 -zone fra-1
unset TWC_TOKEN
```

Resolve stopped/unpaid state, missing IP or wrong zone in Timeweb before continuing.
This check does not validate SSH or VPN. Use [Terraform](../infra/timeweb/README.md)
only when provisioning a new paid host.

## 2. Install and test VPN transport

Follow [official Amnezia instructions](https://docs.amnezia.org/documentation/instructions/).
The official client installs/manages AmneziaWG and Xray. Record installed versions,
image digests and actual ports. Allow those ports in provider and host firewalls.
The laboratory artifacts in `deploy/data-plane/` are not an installation workflow.

Connect a dedicated test device. Check DNS, HTTPS, bounded upload/download,
reconnection and IPv4/IPv6 leaks using the [acceptance suite](pilot/acceptance-suite.md).
Repeat with UDP and TCP fallback from the actual source network in Russia.
Server health alone cannot prove client reachability. Revoke client profiles in
Amnezia; the database stores metadata and does not synchronize VPN credentials.

## 3. Build

On Linux/WSL with Go 1.27.1+:

```sh
make check
make build
```

For local development, `make init && make run` creates development trust files
and serves the sample catalog. For deployment, prepare signing material using the
key tools and [rotation runbook](runbooks/signing-key-rotation.md). Keep the root
private key on the operator machine; transfer only the online key, root public
key, signed policy and real catalog to the VPS.

The catalog needs actual endpoint addresses, measured ASN, REALITY server name
and credential references. Increase its revision on every change. Publish discovery
URLs through HTTPS. The stock Amnezia client does not consume the signed catalog
automatically; it uses profiles distributed through the official client.

## 4. Install the service

Prepare `/etc/acvpn/` with the real catalog, online private key, root public key,
signed policy and `control-plane.env` from `deploy/control-plane.env.example`.
The private key must be owned by `acvpn-service` with mode `0600`; the environment
file should be root-owned with mode `0600`.

```sh
# Create this account once, on first installation.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin acvpn-service
sudo install -d -m 0755 /opt/acvpn/bin
sudo install -m 0755 bin/control-plane /opt/acvpn/bin/control-plane
sudo install -d -o acvpn-service -g acvpn-service -m 0700 /etc/acvpn
# Transfer the real configuration files into /etc/acvpn before starting.
sudo install -m 0644 deploy/control-plane.service /etc/systemd/system/acvpn-control-plane.service
sudo systemctl daemon-reload
sudo systemctl enable --now acvpn-control-plane
```

systemd creates `/var/lib/acvpn` with the required state permissions. For metadata,
apply the appropriate migrations, create the dedicated database login and set both
database/admin-token values. See [configuration](configuration.md). Enroll account,
device and node records before access registration.

From the operator machine:

```sh
ssh -N -L 8080:127.0.0.1:8080 acvpn@SERVER_IP
```

The cloud-init template allows local SSH forwarding only to loopback ports 8080
and 9100. Existing hosts need the equivalent setting, validated with `sshd -t`
before reload. Keep the backend and admin API private.

## 5. Demonstrate

```sh
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
curl --fail http://127.0.0.1:8080/v1/manifest
```

Verify the authenticated report and rejection of unauthenticated admin requests.
Check restart preserves the issuer sequence and rehearse restore. Repeat a full
client transfer, revoke that device in Amnezia and confirm it disconnects. Record
dated evidence in the acceptance suite; use the
[troubleshooting runbook](runbooks/pilot-vpn-not-working.md) for failures.
