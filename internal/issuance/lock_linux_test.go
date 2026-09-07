//go:build linux

package issuance

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestProcessLockRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "public"} {
		t.Run(kind, func(t *testing.T) {
			statePath := filepath.Join(t.TempDir(), "issuer-state.json")
			lockPath := statePath + ".lock"
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink("target", lockPath)
			case "fifo":
				err = syscall.Mkfifo(lockPath, 0o600)
			case "public":
				err = os.WriteFile(lockPath, nil, 0o600)
				if err == nil {
					err = os.Chmod(lockPath, 0o644)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			lock, err := AcquireProcessLock(statePath)
			if err == nil {
				_ = lock.Close()
				t.Fatal("accepted unsafe lock file")
			}
		})
	}
}

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
