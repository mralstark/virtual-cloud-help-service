package artifactlock

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryLockIsValid(t *testing.T) {
	lock, err := Load(filepath.Join("..", "..", "deploy", "data-plane", "artifacts.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Artifacts) != 3 {
		t.Fatalf("artifacts = %d, want 3", len(lock.Artifacts))
	}
}

func TestValidateRejectsUnapprovedOrAmbiguousArtifacts(t *testing.T) {
	valid := testLock([]byte("artifact"))
	tests := []struct {
		name   string
		mutate func(*Lock)
	}{
		{"HTTP URL", func(lock *Lock) { lock.Artifacts[0].URL = "http://github.com/file" }},
		{"unapproved host", func(lock *Lock) { lock.Artifacts[0].URL = "https://example.com/file" }},
		{"query", func(lock *Lock) { lock.Artifacts[0].URL += "?token=secret" }},
		{"path traversal", func(lock *Lock) { lock.Artifacts[0].FileName = "../file" }},
		{"uppercase digest", func(lock *Lock) { lock.Artifacts[0].SHA256 = strings.ToUpper(lock.Artifacts[0].SHA256) }},
		{"duplicate name", func(lock *Lock) {
			lock.Artifacts = append(lock.Artifacts, lock.Artifacts[0])
			lock.Artifacts[1].FileName = "other.bin"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Artifacts = append([]Artifact(nil), valid.Artifacts...)
			test.mutate(&candidate)
			if err := Validate(candidate); err == nil {
				t.Fatal("Validate() accepted invalid lock")
			}
		})
	}
}

func TestFetchVerifiesAndPublishesWithoutOverwrite(t *testing.T) {
	payload := []byte("verified artifact")
	artifact := testLock(payload).Artifacts[0]
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(payload)),
			Request:    request,
			Header:     make(http.Header),
		}, nil
	})}
	directory := t.TempDir()
	path, err := Fetch(context.Background(), client, artifact, directory)
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents, payload) {
		t.Fatalf("downloaded contents = %q", contents)
	}
	if _, err := Fetch(context.Background(), client, artifact, directory); err == nil {
		t.Fatal("Fetch() overwrote an existing artifact")
	}
}

func TestFetchRejectsDigestMismatchWithoutPublishing(t *testing.T) {
	artifact := testLock([]byte("expected")).Artifacts[0]
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("tampered")),
			Request:    request,
			Header:     make(http.Header),
		}, nil
	})}
	directory := t.TempDir()
	if _, err := Fetch(context.Background(), client, artifact, directory); err == nil {
		t.Fatal("Fetch() accepted a digest mismatch")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary files remain after failure: %v", entries)
	}
}

func testLock(payload []byte) Lock {
	digest := sha256.Sum256(payload)
	return Lock{
		SchemaVersion: SchemaVersion, EvidenceCutoff: "2026-08-31",
		Artifacts: []Artifact{{
			Name: "test-artifact", FileName: "test.bin", Version: "v1.0.0",
			Commit: strings.Repeat("a", 40), Kind: "binary",
			URL:    "https://github.com/example/releases/test.bin",
			SHA256: hex.EncodeToString(digest[:]), MaxBytes: 1024, Purpose: "test fixture",
		}},
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
