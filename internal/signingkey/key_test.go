package signingkey

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateAndLoadPrivateKey(t *testing.T) {
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.key")
	publicPath := filepath.Join(directory, "public.key")
	if runtime.GOOS != "linux" {
		if _, err := GenerateFiles(privatePath, publicPath); err == nil {
			t.Fatal("GenerateFiles() did not fail closed outside Linux")
		}
		if _, err := LoadPrivate(privatePath); err == nil {
			t.Fatal("LoadPrivate() did not fail closed outside Linux")
		}
		return
	}
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

func TestLoadPrivateRejectsOversizedFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("key loading deliberately fails before reading files outside Linux")
	}
	path := filepath.Join(t.TempDir(), "oversized.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte("A"), 257), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivate(path); err == nil {
		t.Fatal("LoadPrivate() accepted an oversized key file")
	}
}
