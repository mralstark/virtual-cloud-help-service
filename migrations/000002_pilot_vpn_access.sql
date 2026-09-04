BEGIN;

CREATE TABLE app_private.vpn_accesses (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES app_private.devices(id) ON DELETE CASCADE,
    node_id text NOT NULL REFERENCES app_private.nodes(id) ON DELETE RESTRICT,
    transport text NOT NULL CHECK (transport IN ('amneziawg', 'xray_reality')),
    external_reference text NOT NULL CHECK (char_length(external_reference) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '90 days'),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    UNIQUE (node_id, transport, external_reference)
);

CREATE INDEX vpn_accesses_device_id_idx ON app_private.vpn_accesses(device_id);
CREATE INDEX vpn_accesses_node_status_idx ON app_private.vpn_accesses(node_id, status);
CREATE INDEX vpn_accesses_expires_at_idx
    ON app_private.vpn_accesses(expires_at)
    WHERE status = 'active';

COMMENT ON TABLE app_private.vpn_accesses IS
    'Operational references to access issued manually through official AmneziaVPN. Never store client private keys or connection profiles.';

COMMENT ON COLUMN app_private.vpn_accesses.external_reference IS
    'Opaque operator-visible identifier from Amnezia; it must not contain a private key or complete connection profile.';

REVOKE ALL ON app_private.vpn_accesses FROM PUBLIC;

COMMIT;
