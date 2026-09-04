BEGIN;

CREATE SCHEMA IF NOT EXISTS app_private;
REVOKE ALL ON SCHEMA app_private FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA app_private REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA app_private REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA app_private REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE app_private.accounts (
    id uuid PRIMARY KEY,
    status text NOT NULL CHECK (status IN ('active', 'suspended', 'closed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (updated_at >= created_at)
);

CREATE TABLE app_private.devices (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES app_private.accounts(id) ON DELETE CASCADE,
    label text NOT NULL CHECK (
        char_length(label) BETWEEN 1 AND 100 AND octet_length(label) <= 400
    ),
    identity_public_key text NOT NULL UNIQUE CHECK (
        char_length(identity_public_key) BETWEEN 32 AND 512
        AND identity_public_key !~ '[[:space:]]'
    ),
    status text NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX devices_account_id_idx ON app_private.devices(account_id);

CREATE TABLE app_private.nodes (
    id text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    region text NOT NULL CHECK (char_length(region) BETWEEN 1 AND 100),
    country_code char(2) NOT NULL CHECK (country_code ~ '^[A-Z]{2}$'),
    provider text NOT NULL CHECK (char_length(provider) BETWEEN 1 AND 100),
    autonomous_system_number bigint CHECK (autonomous_system_number > 0),
    status text NOT NULL CHECK (status IN ('provisioning', 'active', 'draining', 'retired')),
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz,
    CHECK (retired_at IS NULL OR retired_at >= created_at)
);

CREATE TABLE app_private.manifest_revisions (
    version bigint PRIMARY KEY CHECK (version > 0),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by text NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128)
);

CREATE TABLE app_private.admin_audit_events (
    id uuid PRIMARY KEY,
    actor text NOT NULL CHECK (char_length(actor) BETWEEN 1 AND 128),
    action text NOT NULL CHECK (char_length(action) BETWEEN 1 AND 128),
    object_type text NOT NULL CHECK (char_length(object_type) BETWEEN 1 AND 128),
    object_id text NOT NULL CHECK (char_length(object_id) BETWEEN 1 AND 256),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
        jsonb_typeof(metadata) = 'object' AND octet_length(metadata::text) <= 8192
    )
);

CREATE INDEX admin_audit_events_occurred_at_idx
    ON app_private.admin_audit_events(occurred_at DESC);

COMMENT ON TABLE app_private.admin_audit_events IS
    'Administrative changes only. Never store browsing destinations, DNS queries, packet data, or full client IP addresses.';

REVOKE ALL ON ALL TABLES IN SCHEMA app_private FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA app_private FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA app_private FROM PUBLIC;

COMMIT;
