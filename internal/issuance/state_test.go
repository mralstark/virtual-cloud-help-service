package issuance

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestFileStoreRoundTrip(t *testing.T) {
	store := FileStore{Path: filepath.Join(t.TempDir(), "issuer-state.json")}
	want := State{
		KeyID:           "test-key",
		KeyEpoch:        1,
		PolicyVersion:   1,
		PolicySHA256:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		LastVersion:     4,
		CatalogRevision: 2,
		CatalogSHA256:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		LastIssuedAt:    time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC),
	}
	if err := store.Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, exists, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !exists || got != want {
		t.Fatalf("Load() = %+v, %v, want %+v, true", got, exists, want)
	}

	if runtime.GOOS != "windows" {
		want.LastVersion++
		want.LastIssuedAt = want.LastIssuedAt.Add(time.Minute)
		if err := store.Save(want); err != nil {
			t.Fatalf("second Save() error = %v", err)
		}
		got, _, err = store.Load()
		if err != nil || got != want {
			t.Fatalf("Load() after replacement = %+v, %v, want %+v", got, err, want)
		}
	}
}

func TestFileStoreRejectsInvalidOrBroadState(t *testing.T) {
	store := FileStore{Path: filepath.Join(t.TempDir(), "issuer-state.json")}
	if err := store.Save(State{}); err == nil {
		t.Fatal("Save() accepted incomplete state")
	}
	if runtime.GOOS == "windows" {
		return
	}
	contents := []byte(`{"key_id":"k","key_epoch":1,"policy_version":1,"policy_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","last_version":1,"catalog_revision":1,"catalog_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","last_issued_at":"2026-08-30T12:00:00Z"}`)
	if err := os.WriteFile(store.Path, contents, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Load(); err == nil {
		t.Fatal("Load() accepted group/world-readable state")
	}
}

func TestFileStoreLoadsLegacyStateForAuthenticatedMigration(t *testing.T) {
	store := FileStore{Path: filepath.Join(t.TempDir(), "issuer-state.json")}
	contents := []byte(`{"key_id":"legacy-key","last_version":7,"catalog_revision":3,"catalog_sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","last_issued_at":"2026-08-30T12:00:00Z"}`)
	if err := os.WriteFile(store.Path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	state, exists, err := store.Load()
	if err != nil || !exists {
		t.Fatalf("Load() legacy state = %+v, %v, %v", state, exists, err)
	}
	if state.PolicyVersion != 0 || state.KeyEpoch != 0 {
		t.Fatalf("legacy state unexpectedly acquired policy fields: %+v", state)
	}
	if err := store.Save(state); err == nil {
		t.Fatal("Save() accepted legacy state without authenticated migration fields")
	}
}
