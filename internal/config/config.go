package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultListenAddress = "127.0.0.1:8080"
	defaultCatalogPath   = "config/nodes.json"
	defaultManifestTTL   = 15 * time.Minute
	defaultManifestCache = 30 * time.Second
	defaultShutdown      = 10 * time.Second
	defaultMaxInFlight   = 64
)

type Config struct {
	ListenAddress   string
	CatalogPath     string
	SigningKeyPath  string
	RootKeyPath     string
	KeyPolicyPath   string
	IssuerStatePath string
	ManifestTTL     time.Duration
	ManifestCache   time.Duration
	Shutdown        time.Duration
	MaxInFlight     int
}

func Load() (Config, error) {
	manifestTTL, err := durationFromEnvironment("MANIFEST_TTL", defaultManifestTTL)
	if err != nil {
		return Config{}, err
	}
	if manifestTTL < time.Minute || manifestTTL > time.Hour {
		return Config{}, errors.New("MANIFEST_TTL must be between 1m and 1h")
	}
	manifestCache, err := durationFromEnvironment("MANIFEST_CACHE_TTL", defaultManifestCache)
	if err != nil {
		return Config{}, err
	}
	if manifestCache < time.Second || manifestCache > manifestTTL/2 {
		return Config{}, errors.New("MANIFEST_CACHE_TTL must be between 1s and half MANIFEST_TTL")
	}
	shutdown, err := durationFromEnvironment("SHUTDOWN_TIMEOUT", defaultShutdown)
	if err != nil {
		return Config{}, err
	}
	if shutdown < time.Second || shutdown > time.Minute {
		return Config{}, errors.New("SHUTDOWN_TIMEOUT must be between 1s and 1m")
	}

	maxInFlight, err := integerFromEnvironment("MAX_IN_FLIGHT", defaultMaxInFlight)
	if err != nil {
		return Config{}, err
	}
	if maxInFlight < 1 || maxInFlight > 1024 {
		return Config{}, errors.New("MAX_IN_FLIGHT must be between 1 and 1024")
	}

	result := Config{
		ListenAddress:   stringFromEnvironment("LISTEN_ADDRESS", defaultListenAddress),
		CatalogPath:     stringFromEnvironment("MANIFEST_CATALOG_PATH", defaultCatalogPath),
		SigningKeyPath:  strings.TrimSpace(os.Getenv("MANIFEST_SIGNING_KEY_PATH")),
		RootKeyPath:     strings.TrimSpace(os.Getenv("MANIFEST_ROOT_PUBLIC_KEY_PATH")),
		KeyPolicyPath:   strings.TrimSpace(os.Getenv("MANIFEST_KEY_POLICY_PATH")),
		IssuerStatePath: strings.TrimSpace(os.Getenv("MANIFEST_STATE_PATH")),
		ManifestTTL:     manifestTTL,
		ManifestCache:   manifestCache,
		Shutdown:        shutdown,
		MaxInFlight:     maxInFlight,
	}
	if result.SigningKeyPath == "" {
		return Config{}, errors.New("MANIFEST_SIGNING_KEY_PATH is required")
	}
	if result.RootKeyPath == "" {
		return Config{}, errors.New("MANIFEST_ROOT_PUBLIC_KEY_PATH is required")
	}
	if result.KeyPolicyPath == "" {
		return Config{}, errors.New("MANIFEST_KEY_POLICY_PATH is required")
	}
	if result.IssuerStatePath == "" {
		return Config{}, errors.New("MANIFEST_STATE_PATH is required and must be on durable storage")
	}
	return result, nil
}

func integerFromEnvironment(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
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
