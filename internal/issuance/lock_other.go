//go:build !linux

package issuance

import "errors"

type ProcessLock struct{}

// Fail closed even for direct library callers. Tests that exercise issuer logic on
// non-Linux platforms inject an in-memory lock instead.
func AcquireProcessLock(string) (*ProcessLock, error) {
	return nil, errors.New("issuer process locking is supported only on Linux")
}

func (lock *ProcessLock) Close() error {
	return nil
}
