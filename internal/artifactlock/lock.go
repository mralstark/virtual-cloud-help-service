package artifactlock

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"time"
)

const (
	SchemaVersion = 1
	maxLockBytes  = 1 << 20
	maxArtifact   = 512 << 20
)

var (
	namePattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	filePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	hexSHA256      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hexCommit      = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type Lock struct {
	SchemaVersion  int        `json:"schema_version"`
	EvidenceCutoff string     `json:"evidence_cutoff"`
	Artifacts      []Artifact `json:"artifacts"`
}

type Artifact struct {
	Name     string `json:"name"`
	FileName string `json:"file_name"`
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Kind     string `json:"kind"`
	URL      string `json:"url"`
	SHA256   string `json:"sha256"`
	MaxBytes int64  `json:"max_bytes"`
	Purpose  string `json:"purpose"`
}

func Load(path string) (Lock, error) {
	file, err := os.Open(path)
	if err != nil {
		return Lock{}, fmt.Errorf("artifact lock: open: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxLockBytes+1))
	if err != nil {
		return Lock{}, fmt.Errorf("artifact lock: read: %w", err)
	}
	if len(data) == 0 || len(data) > maxLockBytes {
		return Lock{}, errors.New("artifact lock: invalid size")
	}

	var lock Lock
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lock); err != nil {
		return Lock{}, fmt.Errorf("artifact lock: decode: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Lock{}, err
	}
	if err := Validate(lock); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

func Validate(lock Lock) error {
	if lock.SchemaVersion != SchemaVersion {
		return fmt.Errorf("artifact lock: unsupported schema version %d", lock.SchemaVersion)
	}
	cutoff, err := time.Parse("2006-01-02", lock.EvidenceCutoff)
	if err != nil || cutoff.Format("2006-01-02") != lock.EvidenceCutoff {
		return errors.New("artifact lock: evidence_cutoff must be YYYY-MM-DD")
	}
	if len(lock.Artifacts) == 0 || len(lock.Artifacts) > 32 {
		return errors.New("artifact lock: artifacts must contain between 1 and 32 entries")
	}

	names := make(map[string]struct{}, len(lock.Artifacts))
	files := make(map[string]struct{}, len(lock.Artifacts))
	for index, artifact := range lock.Artifacts {
		if err := validateArtifact(artifact); err != nil {
			return fmt.Errorf("artifact lock: artifact %d: %w", index, err)
		}
		if _, exists := names[artifact.Name]; exists {
			return fmt.Errorf("artifact lock: duplicate name %q", artifact.Name)
		}
		names[artifact.Name] = struct{}{}
		if _, exists := files[artifact.FileName]; exists {
			return fmt.Errorf("artifact lock: duplicate file_name %q", artifact.FileName)
		}
		files[artifact.FileName] = struct{}{}
	}
	return nil
}

func Find(lock Lock, name string) (Artifact, error) {
	for _, artifact := range lock.Artifacts {
		if artifact.Name == name {
			return artifact, nil
		}
	}
	return Artifact{}, fmt.Errorf("artifact lock: artifact %q not found", name)
}

func AllowedHost(host string) bool {
	switch host {
	case "github.com", "codeload.github.com", "release-assets.githubusercontent.com":
		return true
	default:
		return false
	}
}

func validateArtifact(artifact Artifact) error {
	if !namePattern.MatchString(artifact.Name) {
		return errors.New("name is invalid")
	}
	if !filePattern.MatchString(artifact.FileName) {
		return errors.New("file_name is invalid")
	}
	if !versionPattern.MatchString(artifact.Version) {
		return errors.New("version is invalid")
	}
	if !hexCommit.MatchString(artifact.Commit) {
		return errors.New("commit must be a lowercase 40-character SHA")
	}
	if artifact.Kind != "source" && artifact.Kind != "binary" {
		return errors.New("kind must be source or binary")
	}
	parsed, err := url.ParseRequestURI(artifact.URL)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !AllowedHost(parsed.Hostname()) {
		return errors.New("url must be an approved HTTPS GitHub artifact URL without credentials, query, or fragment")
	}
	if !hexSHA256.MatchString(artifact.SHA256) {
		return errors.New("sha256 must be a lowercase 64-character digest")
	}
	if artifact.MaxBytes < 1 || artifact.MaxBytes > maxArtifact {
		return fmt.Errorf("max_bytes must be between 1 and %d", maxArtifact)
	}
	if len(artifact.Purpose) < 1 || len(artifact.Purpose) > 256 {
		return errors.New("purpose must contain between 1 and 256 characters")
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("artifact lock: decode trailing data: %w", err)
	}
	return errors.New("artifact lock: contains multiple JSON values")
}
