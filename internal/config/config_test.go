package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("MANIFEST_SIGNING_KEY_PATH", "/run/secrets/manifest-key")
	t.Setenv("MANIFEST_ROOT_PUBLIC_KEY_PATH", "/run/config/manifest-root.pub")
	t.Setenv("MANIFEST_KEY_POLICY_PATH", "/run/config/manifest-key-policy.json")
	t.Setenv("MANIFEST_STATE_PATH", "/var/lib/vchs/issuer-state.json")
	t.Setenv("LISTEN_ADDRESS", "")
	t.Setenv("MANIFEST_CATALOG_PATH", "")
	t.Setenv("MANIFEST_TTL", "")
	t.Setenv("MANIFEST_CACHE_TTL", "")
	t.Setenv("SHUTDOWN_TIMEOUT", "")
	t.Setenv("MAX_IN_FLIGHT", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("PILOT_ADMIN_TOKEN", "")

	config, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.ListenAddress != defaultListenAddress || config.ManifestTTL != 15*time.Minute {
		t.Fatalf("Load() defaults = %+v", config)
	}
	if config.IssuerStatePath != "/var/lib/vchs/issuer-state.json" {
		t.Fatalf("IssuerStatePath = %q", config.IssuerStatePath)
	}
}

func TestLoadPilotAccessRequiresPairedSecrets(t *testing.T) {
	t.Setenv("MANIFEST_SIGNING_KEY_PATH", "key")
	t.Setenv("MANIFEST_ROOT_PUBLIC_KEY_PATH", "root.pub")
	t.Setenv("MANIFEST_KEY_POLICY_PATH", "policy.json")
	t.Setenv("MANIFEST_STATE_PATH", "state.json")
	t.Setenv("DATABASE_URL", "postgres://pilot")
	t.Setenv("PILOT_ADMIN_TOKEN", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a database without an admin token")
	}

	t.Setenv("PILOT_ADMIN_TOKEN", "0123456789abcdef0123456789abcdef")
	config, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !config.PilotAccess {
		t.Fatal("pilot access was not enabled")
	}
}

func TestLoadRequiresKeyAndBoundsDurations(t *testing.T) {
	t.Setenv("MANIFEST_SIGNING_KEY_PATH", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a missing signing key")
	}

	t.Setenv("MANIFEST_SIGNING_KEY_PATH", "key")
	t.Setenv("MANIFEST_STATE_PATH", "state.json")
	t.Setenv("MANIFEST_ROOT_PUBLIC_KEY_PATH", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a missing offline root public key")
	}
	t.Setenv("MANIFEST_ROOT_PUBLIC_KEY_PATH", "root.pub")
	t.Setenv("MANIFEST_KEY_POLICY_PATH", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a missing signing key policy")
	}
	t.Setenv("MANIFEST_KEY_POLICY_PATH", "policy.json")
	t.Setenv("MANIFEST_STATE_PATH", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a missing durable issuer state path")
	}
	t.Setenv("MANIFEST_STATE_PATH", "state.json")
	t.Setenv("MANIFEST_TTL", "61m")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted an excessive manifest TTL")
	}
	t.Setenv("MANIFEST_TTL", "15m")
	t.Setenv("MAX_IN_FLIGHT", "0")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted an invalid concurrency limit")
	}
}
