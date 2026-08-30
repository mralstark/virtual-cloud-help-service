//go:build linux

package issuance

import (
	"path/filepath"
	"testing"
)

func TestProcessLockIsExclusive(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "issuer-state.json")
	first, err := AcquireProcessLock(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireProcessLock(statePath); err == nil {
		t.Fatal("AcquireProcessLock() allowed a second issuer")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireProcessLock(statePath)
	if err != nil {
		t.Fatalf("AcquireProcessLock() after release: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}
