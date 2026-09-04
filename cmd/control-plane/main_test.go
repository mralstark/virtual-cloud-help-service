package main

import (
	"context"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

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

func TestSecureDatabaseConfigEnforcesServerSideGuards(t *testing.T) {
	config, err := secureDatabaseConfig("postgres://user:secret@db.example.com/vchs?sslmode=verify-full&statement_timeout=0&search_path=public")
	if err != nil {
		t.Fatal(err)
	}
	hardenDatabaseConfig(config)
	expected := map[string]string{
		"search_path":                         "pg_catalog",
		"statement_timeout":                   "5000",
		"lock_timeout":                        "2000",
		"idle_in_transaction_session_timeout": "5000",
	}
	for key, value := range expected {
		if config.RuntimeParams[key] != value {
			t.Fatalf("%s = %q, want %q", key, config.RuntimeParams[key], value)
		}
	}
}

func TestValidateDatabaseIdentity(t *testing.T) {
	tests := []struct {
		name       string
		attributes []driver.Value
		shouldFail bool
	}{
		{name: "least privilege", attributes: []driver.Value{false, false, false, false}},
		{name: "superuser", attributes: []driver.Value{true, false, false, false}, shouldFail: true},
		{name: "create role", attributes: []driver.Value{false, true, false, false}, shouldFail: true},
		{name: "create database", attributes: []driver.Value{false, false, true, false}, shouldFail: true},
		{name: "bypass RLS", attributes: []driver.Value{false, false, false, true}, shouldFail: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			database, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			mock.ExpectQuery("SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls").
				WillReturnRows(sqlmock.NewRows([]string{
					"rolsuper", "rolcreaterole", "rolcreatedb", "rolbypassrls",
				}).AddRow(test.attributes...))
			err = validateDatabaseIdentity(context.Background(), database)
			if test.shouldFail != (err != nil) {
				t.Fatalf("error = %v, shouldFail = %v", err, test.shouldFail)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateDatabaseIdentityPropagatesQueryFailure(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	mock.ExpectQuery("SELECT rolsuper").WillReturnError(errors.New("database unavailable"))
	if err := validateDatabaseIdentity(context.Background(), database); err == nil {
		t.Fatal("expected identity query failure")
	}
}
