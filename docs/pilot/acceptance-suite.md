# Timeweb Amnezia pilot acceptance suite

Do not invite testers until every required row has dated evidence. `PASS` means the
observable outcome was reproduced, not inferred from configuration. Use only the
privacy-safe fields defined by `pilot_test_results`.

## Entry gates

- A Timeweb VPS exists and its server ID, region, IP assignment, OS, resources, and
  billing owner have been verified.
- Read-only host, listener, firewall, Docker, service, and database inventory is
  complete and sanitized.
- Official AmneziaVPN installed AmneziaWG 3.1 and XRay VLESS Reality; exact client
  and server image versions are recorded without secrets.
- TCP/443 and the observed AWG UDP port do not conflict with the backend, SSH, or
  reverse proxy.
- Standard PostgreSQL has migrations 000001 through 000003 applied. Supabase
  instead has every version under `supabase/migrations/` applied. In both cases
  the service login is unprivileged; on Supabase it inherits only
  `vchs_runtime`.
- A provider backup, encrypted off-server application backup, and rollback owner
  exist.

If any gate is missing, mark the suite `BLOCKED`; do not substitute documentation
or a handshake for evidence.

## Infrastructure recovery

| Test | Required evidence | Pass condition |
|---|---|---|
| Server reboot | before/after inventory and uptime | expected services return without manual repair |
| Docker restart | container states and restart policies | official Amnezia workloads recover with the same mounts/networks |
| Backend restart | health/readiness and manifest signature | loopback service recovers and revision remains monotonic |
| PostgreSQL restart | schema check and authenticated admin request | no data loss; registration/reporting recover |
| Disk pressure | alert/test on disposable data | operator is warned before DB or Docker corruption risk |

Reboot/restart tests are change operations. Schedule and approve them only after a
verified backup; never execute them during initial inventory.

## Transport matrix

Run each row on every supported platform and at least two pilot access networks
where available.

| Transport | Connect | DNS | HTTPS | Upload | Download | Reconnect | IPv4 leak | IPv6 leak |
|---|---|---|---|---|---|---|---|---|
| AmneziaWG 3.1 | required | required | required | required | required | required | none | none/fail closed |
| XRay VLESS Reality | required | required | required | required | required | required | none | none/fail closed |

Record one result per transport/session. Success requires the complete chain in
`docs/runbooks/pilot-vpn-not-working.md`; an established tunnel alone is a failure.

## Access lifecycle

1. Create a tester device/account record without personal browsing data.
2. Issue individual access manually in official AmneziaVPN.
3. Register only its opaque reference through `POST /admin/pilot/access` with an
   expiry no more than 90 days away.
4. Confirm another tester cannot use or see the record through the admin API.
5. Revoke in the official Amnezia workflow, mark the backend record revoked, and
   prove a new connection fails while unrelated testers still connect.
6. Confirm re-running backend revoke is idempotent and preserves the first
   revocation timestamp.

## Security gates

- SSH password authentication is disabled only after an approved key login was
  proven; root/password brute-force exposure is absent.
- Timeweb and host firewalls match the observed minimum port plan; no reset or
  broad allow rule was used.
- PostgreSQL listens on loopback/private networking only and the application role
  has only the required table privileges.
- Admin endpoints require the 32+ character token and are exposed only on
  loopback/private authenticated ingress. Unauthorized, oversized, unknown-field,
  and wrong-method requests fail closed.
- Secrets are absent from Git history/current tree and are not printed by service
  logs, Docker inspection, diagnostics, metrics, or telemetry.
- Manifest signing key permissions and offline-root policy pass repository tools.
- DNS, IPv4, and IPv6 leak tests pass on each supported platform.

## Recovery gates

- `pg_restore --list` validates the latest logical dump.
- The dump has been restored into an explicitly disposable database and application
  schema checks pass.
- Encrypted off-server issuer/config backup has been decrypted in a controlled test
  and checksums match.
- The runbook identifies all observed Amnezia volumes/mounts and the operator has a
  compatible official-client Settings backup.
- An operator unfamiliar with the implementation can rebuild the application
  layer by following `docs/runbooks/timeweb-restore.md`.

## Exit decision

After 5–10 testers, export `GET /admin/pilot/report` and complete
`docs/pilot/results.template.md`. Keep one node only if both transport reliability,
peak utilization, support workload, and recovery evidence meet the agreed target.
Otherwise add a second node before automating fallback or provisioning.
