package signingkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func LoadPrivate(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat signing key: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("signing key permissions must not allow group or other access")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
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
	if parent == "." {
		return nil
	}
	if err := os.MkdirAll(parent, mode); err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	return nil
}

func writeExclusive(path string, contents []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
