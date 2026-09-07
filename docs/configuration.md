# Configuration

The Linux service reads environment variables; it does not load dotenv files.
Use `deploy/control-plane.env.example` for deployment and `.env.example` as a
development reference.

- `LISTEN_ADDRESS`: `127.0.0.1:8080`; use loopback/private listeners for the admin API.
- `MANIFEST_CATALOG_PATH`: public catalog, default `config/nodes.json`. Increase
  `revision` whenever endpoints, discovery or node metadata change.
- `MANIFEST_SIGNING_KEY_PATH`: required online private key, mode `0600`.
- `MANIFEST_ROOT_PUBLIC_KEY_PATH`: required pinned offline-root public key.
- `MANIFEST_KEY_POLICY_PATH`: required root-signed online-key policy.
- `MANIFEST_STATE_PATH`: required durable issuer state; file `0600`, directory `0700`.
- `MANIFEST_TTL`: `15m`, allowed `1m`–`1h`.
- `MANIFEST_CACHE_TTL`: `30s`, allowed `1s`–half the manifest TTL.
- `MAX_IN_FLIGHT`: `64`, allowed `1`–`1024`.
- `SHUTDOWN_TIMEOUT`: `10s`, allowed `1s`–`1m`.
- `DATABASE_URL` and `PILOT_ADMIN_TOKEN`: optional, but must be set together.
  Generate the 32–512 byte token with a cryptographic random generator.
- `TWC_TOKEN`: used only by `pilot-check` and Terraform, not by the running service.

## Database

For fresh standard PostgreSQL, apply `migrations/000001` through `000004` with a
migration identity. For Supabase, apply only `supabase/migrations/`. These are
alternative installation paths. Do not rerun CREATE TABLE migrations on an
existing database. An older installation with tables in `public` needs a reviewed
forward migration and backup; fresh-schema files do not upgrade it automatically.

Create a dedicated LOGIN role outside version control and grant it `vchs_runtime`.
Assign its password with psql's `\password` or a secret manager. Keep it separate
from the schema owner and Supabase's `postgres`/`service_role`. Startup checks
each required permission and rejects superuser, CREATEDB, CREATEROLE and BYPASSRLS.

Use direct PostgreSQL, or the Supabase **session pooler on port 5432** for an
IPv4-only VPS. Copy the exact host/username from the dashboard. The transaction
pooler on 6543 is outside this deployment contract: it does not preserve the
session/prepared-statement behavior used here. Remote connections require
`sslmode=verify-full` with a trusted CA. `sslmode=require` is rejected.
Loopback/Unix-socket connections may be plaintext.

The service uses at most five connections, a 5-second statement timeout, a
2-second lock timeout and a 5-second idle-transaction timeout. Application queries
explicitly use `app_private`; anon/authenticated roles must have no access.

## Private metadata API

- `POST /admin/pilot/access`: record an opaque reference issued manually in Amnezia.
- `POST /admin/pilot/access/{id}/revoke`: record manual revocation; retries return
  the same revoked record without another audit event.
- `POST /admin/pilot/test-results`: record a coarse acceptance result.
- `GET /admin/pilot/report`: return the 30-day report.

Use `Authorization: Bearer …` and `Content-Type: application/json` for JSON writes.
Registration requires account, device and node records to exist. Enroll these
through the operator's database workflow; runtime intentionally cannot create
accounts/nodes. Never submit VPN private keys or full connection profiles.

Each telemetry write deletes up to 1,000 expired rows, skipping locked rows.
Reports exclude older records even while idle. Without new writes, physical
deletion requires scheduled operator cleanup: this is not a strict wall-clock
deletion guarantee.

## Recovery

The issuer is single-active on Linux with a local persistent filesystem. Do not
use NFS or multiple replicas. Back up signing key and issuer state atomically.
Never recover by deleting state. Keep the root private key offline, away from the
service host. See [key rotation](runbooks/signing-key-rotation.md) and
[restore](runbooks/timeweb-restore.md).

Sources: [Supabase connection modes](https://supabase.com/docs/guides/database/connecting-to-postgres),
[Data API protection](https://supabase.com/docs/guides/api/securing-your-api).
