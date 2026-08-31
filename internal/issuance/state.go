package issuance

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const maxStateBytes = 16 << 10

type State struct {
	KeyID           string    `json:"key_id"`
	KeyEpoch        uint64    `json:"key_epoch"`
	PolicyVersion   uint64    `json:"policy_version"`
	PolicySHA256    string    `json:"policy_sha256"`
	LastVersion     uint64    `json:"last_version"`
	CatalogRevision uint64    `json:"catalog_revision"`
	CatalogSHA256   string    `json:"catalog_sha256"`
	LastIssuedAt    time.Time `json:"last_issued_at"`
}

type FileStore struct {
	Path string
}

func (store FileStore) Load() (State, bool, error) {
	if store.Path == "" {
		return State{}, false, errors.New("issuer state path is required")
	}
	if err := checkDirectory(filepath.Dir(store.Path)); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return State{}, false, err
		}
	}
	file, err := os.Open(store.Path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, fmt.Errorf("open issuer state: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return State{}, false, fmt.Errorf("stat issuer state: %w", err)
	}
	if !info.Mode().IsRegular() {
		return State{}, false, errors.New("issuer state must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return State{}, false, errors.New("issuer state permissions must not allow group or other access")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		return State{}, false, fmt.Errorf("read issuer state: %w", err)
	}
	if len(data) == 0 || len(data) > maxStateBytes {
		return State{}, false, errors.New("issuer state size is invalid")
	}
	var state State
	if err := decodeStrict(data, &state); err != nil {
		return State{}, false, fmt.Errorf("decode issuer state: %w", err)
	}
	if err := validate(state, true); err != nil {
		return State{}, false, err
	}
	return state, true, nil
}

func (store FileStore) Save(state State) error {
	if store.Path == "" {
		return errors.New("issuer state path is required")
	}
	if err := validate(state, false); err != nil {
		return err
	}
	directory := filepath.Dir(store.Path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create issuer state directory: %w", err)
	}
	if err := checkDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".issuer-state-*")
	if err != nil {
		return fmt.Errorf("create temporary issuer state: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("restrict temporary issuer state: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(state); err != nil {
		cleanup()
		return fmt.Errorf("encode issuer state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync issuer state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("close issuer state: %w", err)
	}
	if err := os.Rename(temporaryPath, store.Path); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("replace issuer state: %w", err)
	}
	if runtime.GOOS != "windows" {
		// #nosec G304 -- the directory is derived from trusted MANIFEST_STATE_PATH configuration.
		directoryHandle, err := os.Open(directory)
		if err != nil {
			return fmt.Errorf("open issuer state directory: %w", err)
		}
		defer directoryHandle.Close()
		if err := directoryHandle.Sync(); err != nil {
			return fmt.Errorf("sync issuer state directory: %w", err)
		}
	}
	return nil
}

func checkDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat issuer state directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("issuer state parent must be a directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o022 != 0 {
		return errors.New("issuer state directory must not be writable by group or others")
	}
	return nil
}

func validate(state State, allowLegacy bool) error {
	if state.KeyID == "" || state.LastVersion == 0 || state.CatalogRevision == 0 || state.LastIssuedAt.IsZero() {
		return errors.New("issuer state is incomplete")
	}
	digest, err := base64.RawURLEncoding.DecodeString(state.CatalogSHA256)
	if err != nil || len(digest) != 32 {
		return errors.New("issuer state catalog digest is invalid")
	}
	legacyPolicyState := state.KeyEpoch == 0 && state.PolicyVersion == 0 && state.PolicySHA256 == ""
	if legacyPolicyState && allowLegacy {
		return nil
	}
	if state.KeyEpoch == 0 || state.PolicyVersion == 0 || state.PolicySHA256 == "" {
		return errors.New("issuer state key policy fields are incomplete")
	}
	policyDigest, err := base64.RawURLEncoding.DecodeString(state.PolicySHA256)
	if err != nil || len(policyDigest) != 32 {
		return errors.New("issuer state key policy digest is invalid")
	}
	return nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("issuer state contains multiple JSON values")
}
