//go:build !linux

package issuance

import "testing"

func TestProcessLockFailsClosedOutsideLinux(t *testing.T) {
	if _, err := AcquireProcessLock("state.json"); err == nil {
		t.Fatal("AcquireProcessLock() returned a no-op lock outside Linux")
	}
}
