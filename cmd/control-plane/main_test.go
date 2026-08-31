package main

import "testing"

func TestValidateDatabaseTransport(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		shouldFail bool
	}{
		{name: "remote require without verification", url: "postgres://user:secret@db.example.com/vchs?sslmode=require", shouldFail: true},
		{name: "remote verify full", url: "postgres://user:secret@db.example.com/vchs?sslmode=verify-full"},
		{name: "loopback plaintext", url: "postgres://user:secret@127.0.0.1/vchs?sslmode=disable"},
		{name: "remote disabled", url: "postgres://user:secret@db.example.com/vchs?sslmode=disable", shouldFail: true},
		{name: "remote plaintext fallback", url: "postgres://user:secret@db.example.com/vchs?sslmode=prefer", shouldFail: true},
		{name: "invalid", url: "%", shouldFail: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateDatabaseTransport(test.url)
			if test.shouldFail && err == nil {
				t.Fatal("expected failure")
			}
			if !test.shouldFail && err != nil {
				t.Fatalf("unexpected failure: %v", err)
			}
		})
	}
}
