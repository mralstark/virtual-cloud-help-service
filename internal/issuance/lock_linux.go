//go:build linux

package issuance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type ProcessLock struct {
	file *os.File
}

// AcquireProcessLock prevents split-brain version allocation by issuers sharing a
// local state path. High-availability deployments need a transactional state store
// instead of sharing this file over a network filesystem.
func AcquireProcessLock(statePath string) (*ProcessLock, error) {
	if statePath == "" {
		return nil, errors.New("issuer state path is required")
	}
	directory := filepath.Dir(statePath)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create issuer state directory: %w", err)
	}
	if err := checkDirectory(directory); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(statePath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open issuer process lock: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat issuer process lock: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, errors.New("issuer process lock must be a private regular file")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("lock issuer state (another issuer may be active): %w", err)
	}
	return &ProcessLock{file: file}, nil
}

func (lock *ProcessLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	file := lock.file
	lock.file = nil
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_UN); err != nil {
		_ = file.Close()
		return fmt.Errorf("unlock issuer state: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close issuer process lock: %w", err)
	}
	return nil
}
