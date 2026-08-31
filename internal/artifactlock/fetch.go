package artifactlock

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func NewHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	return &http.Client{
		Transport: transport,
		Timeout:   2 * time.Minute,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("artifact fetch: too many redirects")
			}
			if request.URL.Scheme != "https" || !AllowedHost(request.URL.Hostname()) {
				return errors.New("artifact fetch: redirect target is not approved")
			}
			return nil
		},
	}
}

// Fetch downloads one already-validated artifact, verifies its exact digest and
// maximum size, then atomically publishes it without overwriting an existing file.
func Fetch(ctx context.Context, client *http.Client, artifact Artifact, outputDirectory string) (string, error) {
	if err := validateArtifact(artifact); err != nil {
		return "", err
	}
	if client == nil {
		return "", errors.New("artifact fetch: HTTP client is required")
	}
	if err := os.MkdirAll(outputDirectory, 0o700); err != nil {
		return "", fmt.Errorf("artifact fetch: create output directory: %w", err)
	}
	outputDirectory, err := filepath.Abs(outputDirectory)
	if err != nil {
		return "", fmt.Errorf("artifact fetch: resolve output directory: %w", err)
	}
	destination := filepath.Join(outputDirectory, artifact.FileName)
	if _, err := os.Lstat(destination); err == nil {
		return "", errors.New("artifact fetch: destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("artifact fetch: inspect destination: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return "", fmt.Errorf("artifact fetch: create request: %w", err)
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("User-Agent", "virtual-cloud-help-service-artifact-fetch/1")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("artifact fetch: request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("artifact fetch: unexpected HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > artifact.MaxBytes {
		return "", errors.New("artifact fetch: declared content length exceeds maximum")
	}
	if finalURL := response.Request.URL; finalURL.Scheme != "https" || !AllowedHost(finalURL.Hostname()) {
		return "", errors.New("artifact fetch: final response URL is not approved")
	}

	temporary, err := os.CreateTemp(outputDirectory, ".artifact-*.tmp")
	if err != nil {
		return "", fmt.Errorf("artifact fetch: create temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	published := false
	defer func() {
		_ = temporary.Close()
		if !published {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return "", fmt.Errorf("artifact fetch: secure temporary file: %w", err)
	}

	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, hasher), io.LimitReader(response.Body, artifact.MaxBytes+1))
	if err != nil {
		return "", fmt.Errorf("artifact fetch: download: %w", err)
	}
	if written == 0 || written > artifact.MaxBytes {
		return "", errors.New("artifact fetch: downloaded size is invalid")
	}
	if digest := hex.EncodeToString(hasher.Sum(nil)); digest != artifact.SHA256 {
		return "", errors.New("artifact fetch: SHA-256 mismatch")
	}
	if err := temporary.Sync(); err != nil {
		return "", fmt.Errorf("artifact fetch: sync temporary file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("artifact fetch: close temporary file: %w", err)
	}
	if err := publishExclusive(temporaryPath, destination); err != nil {
		return "", err
	}
	published = true
	return destination, nil
}

func publishExclusive(source, destination string) error {
	// The temporary file lives in the destination directory, so a hard link gives
	// us an atomic no-overwrite publication primitive on the same filesystem.
	if err := os.Link(source, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("artifact fetch: destination already exists")
		}
		return fmt.Errorf("artifact fetch: publish verified file: %w", err)
	}
	if err := os.Remove(source); err != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("artifact fetch: remove temporary link: %w", err)
	}
	return nil
}
