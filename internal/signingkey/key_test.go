package signingkey

import (
	"bytes"
	"crypto/ed25519"
	"path/filepath"
	"testing"
)

func TestGenerateAndLoadPrivateKey(t *testing.T) {
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.key")
	publicPath := filepath.Join(directory, "public.key")
	publicKey, err := GenerateFiles(privatePath, publicPath)
	if err != nil {
		t.Fatalf("GenerateFiles() error = %v", err)
	}
	privateKey, err := LoadPrivate(privatePath)
	if err != nil {
		t.Fatalf("LoadPrivate() error = %v", err)
	}
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		t.Fatal("loaded private key does not match generated public key")
	}
	if _, err := GenerateFiles(privatePath, publicPath); err == nil {
		t.Fatal("GenerateFiles() overwrote existing key files")
	}
}
