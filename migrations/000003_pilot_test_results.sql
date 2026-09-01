BEGIN;

CREATE TABLE pilot_test_results (
    id uuid PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    client_platform text NOT NULL CHECK (
        client_platform IN ('android', 'ios', 'linux', 'macos', 'windows')
    ),
    isp text CHECK (isp IS NULL OR char_length(isp) BETWEEN 1 AND 100),
    transport text NOT NULL CHECK (transport IN ('amneziawg', 'xray_reality')),
    occurred_at timestamptz NOT NULL,
    success boolean NOT NULL,
    failure_stage text CHECK (
        failure_stage IS NULL OR failure_stage IN (
            'server_health', 'public_ip', 'transport', 'port', 'server_outbound',
            'tunnel', 'dns', 'https', 'ipv4_leak', 'ipv6_leak', 'upload',
            'download', 'reconnect'
        )
    ),
    connection_time_bucket text NOT NULL CHECK (
        connection_time_bucket IN ('lt_3s', '3_10s', '10_30s', 'gt_30s', 'unknown')
    ),
    throughput_bucket text CHECK (
        throughput_bucket IS NULL OR throughput_bucket IN (
            'lt_1_mbps', '1_10_mbps', '10_50_mbps', 'gte_50_mbps'
        )
    ),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    CHECK (success = (failure_stage IS NULL))
);

CREATE INDEX pilot_test_results_device_time_idx
    ON pilot_test_results(device_id, occurred_at DESC);
CREATE INDEX pilot_test_results_transport_time_idx
    ON pilot_test_results(transport, occurred_at DESC);
CREATE INDEX pilot_test_results_failures_idx
    ON pilot_test_results(failure_stage, occurred_at DESC)
    WHERE success = false;

COMMENT ON TABLE pilot_test_results IS
    'Privacy-preserving pilot outcomes. Never store URLs, destination domains, DNS history, packet contents, or client public IP addresses.';

COMMENT ON COLUMN pilot_test_results.isp IS
    'Optional tester-provided ISP label. It must not contain an IP address or subscriber identifier.';

COMMIT;
