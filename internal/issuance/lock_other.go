//go:build !linux

package issuance

type ProcessLock struct{}

// Signing-key loading fails closed outside Linux, so this exists only to keep
// platform-independent library tests buildable. It is not a production lock.
func AcquireProcessLock(string) (*ProcessLock, error) {
	return &ProcessLock{}, nil
}

func (lock *ProcessLock) Close() error {
	return nil
}
