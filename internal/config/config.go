package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	defaultListenAddress = "127.0.0.1:8080"
	defaultCatalogPath   = "config/nodes.json"
	defaultManifestTTL   = 15 * time.Minute
	defaultShutdown      = 10 * time.Second
)

type Config struct {
	ListenAddress  string
	CatalogPath    string
	SigningKeyPath string
	ManifestTTL    time.Duration
	Shutdown       time.Duration
}

func Load() (Config, error) {
	manifestTTL, err := durationFromEnvironment("MANIFEST_TTL", defaultManifestTTL)
	if err != nil {
		return Config{}, err
	}
	if manifestTTL < time.Minute || manifestTTL > time.Hour {
		return Config{}, errors.New("MANIFEST_TTL must be between 1m and 1h")
	}
	shutdown, err := durationFromEnvironment("SHUTDOWN_TIMEOUT", defaultShutdown)
	if err != nil {
		return Config{}, err
	}
	if shutdown < time.Second || shutdown > time.Minute {
		return Config{}, errors.New("SHUTDOWN_TIMEOUT must be between 1s and 1m")
	}

	result := Config{
		ListenAddress:  stringFromEnvironment("LISTEN_ADDRESS", defaultListenAddress),
		CatalogPath:    stringFromEnvironment("MANIFEST_CATALOG_PATH", defaultCatalogPath),
		SigningKeyPath: strings.TrimSpace(os.Getenv("MANIFEST_SIGNING_KEY_PATH")),
		ManifestTTL:    manifestTTL,
		Shutdown:       shutdown,
	}
	if result.SigningKeyPath == "" {
		return Config{}, errors.New("MANIFEST_SIGNING_KEY_PATH is required")
	}
	return result, nil
}

func stringFromEnvironment(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func durationFromEnvironment(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}
