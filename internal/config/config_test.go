package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("MANIFEST_SIGNING_KEY_PATH", "/run/secrets/manifest-key")
	t.Setenv("LISTEN_ADDRESS", "")
	t.Setenv("MANIFEST_CATALOG_PATH", "")
	t.Setenv("MANIFEST_TTL", "")
	t.Setenv("SHUTDOWN_TIMEOUT", "")

	config, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if config.ListenAddress != defaultListenAddress || config.ManifestTTL != 15*time.Minute {
		t.Fatalf("Load() defaults = %+v", config)
	}
}

func TestLoadRequiresKeyAndBoundsDurations(t *testing.T) {
	t.Setenv("MANIFEST_SIGNING_KEY_PATH", "")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted a missing signing key")
	}

	t.Setenv("MANIFEST_SIGNING_KEY_PATH", "key")
	t.Setenv("MANIFEST_TTL", "61m")
	if _, err := Load(); err == nil {
		t.Fatal("Load() accepted an excessive manifest TTL")
	}
}
