BEGIN;

CREATE TABLE accounts (
    id uuid PRIMARY KEY,
    status text NOT NULL CHECK (status IN ('active', 'suspended', 'closed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id uuid PRIMARY KEY,
    account_id uuid NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 100),
    identity_public_key text NOT NULL UNIQUE,
    status text NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
);

CREATE INDEX devices_account_id_idx ON devices(account_id);

CREATE TABLE nodes (
    id text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    region text NOT NULL,
    country_code char(2) NOT NULL CHECK (country_code ~ '^[A-Z]{2}$'),
    provider text NOT NULL,
    autonomous_system_number bigint CHECK (autonomous_system_number > 0),
    status text NOT NULL CHECK (status IN ('provisioning', 'active', 'draining', 'retired')),
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz
);

CREATE TABLE manifest_revisions (
    version bigint PRIMARY KEY CHECK (version > 0),
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by text NOT NULL
);

CREATE TABLE admin_audit_events (
    id uuid PRIMARY KEY,
    actor text NOT NULL,
    action text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX admin_audit_events_occurred_at_idx
    ON admin_audit_events(occurred_at DESC);

COMMENT ON TABLE admin_audit_events IS
    'Administrative changes only. Never store browsing destinations, DNS queries, packet data, or full client IP addresses.';

COMMIT;
