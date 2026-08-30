package signingkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("signing key loading is supported only on Linux")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open signing key: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat signing key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("signing key must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("signing key permissions must not allow group or other access")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, 257))
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > 256 {
		return nil, errors.New("signing key size is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(append([]byte(nil), raw...)), nil
	default:
		return nil, fmt.Errorf("signing key has %d bytes, expected %d-byte seed or %d-byte private key", len(raw), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func GenerateFiles(privatePath, publicPath string) (ed25519.PublicKey, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("signing key generation is supported only on Linux; use WSL for development")
	}
	if privatePath == "" || publicPath == "" {
		return nil, errors.New("private and public output paths are required")
	}
	if filepath.Clean(privatePath) == filepath.Clean(publicPath) {
		return nil, errors.New("private and public output paths must differ")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	if err := ensureParent(privatePath, 0o700); err != nil {
		return nil, err
	}
	if err := ensureParent(publicPath, 0o755); err != nil {
		return nil, err
	}
	privateText := base64.RawURLEncoding.EncodeToString(privateKey) + "\n"
	if err := writeExclusive(privatePath, []byte(privateText), 0o600); err != nil {
		return nil, fmt.Errorf("write private key: %w", err)
	}
	publicText := base64.RawURLEncoding.EncodeToString(publicKey) + "\n"
	if err := writeExclusive(publicPath, []byte(publicText), 0o644); err != nil {
		_ = os.Remove(privatePath)
		return nil, fmt.Errorf("write public key: %w", err)
	}
	return publicKey, nil
}

func ensureParent(path string, mode os.FileMode) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, mode); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("stat key directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("key parent must be a directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("key directory must not be writable by group or others")
	}
	return nil
}

func writeExclusive(path string, contents []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	succeeded = true
	return nil
}
