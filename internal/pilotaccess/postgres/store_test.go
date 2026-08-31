package postgres

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mralstark/virtual-cloud-help-service/internal/pilotaccess"
	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

var accessColumns = []string{
	"id", "device_id", "node_id", "transport", "external_reference",
	"created_at", "expires_at", "revoked_at", "status",
}

func TestCreateAndIdempotentRevoke(t *testing.T) {
	database, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := New(database)
	if err != nil {
		t.Fatal(err)
	}

	access := postgresTestAccess()
	mock.ExpectQuery(regexp.QuoteMeta("INSERT INTO vpn_accesses")).
		WithArgs(access.ID, access.DeviceID, access.NodeID, access.Transport, access.ExternalReference,
			access.CreatedAt, access.ExpiresAt, access.RevokedAt, access.Status).
		WillReturnRows(accessRow(access))
	created, err := store.Create(context.Background(), access)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != access.ID || created.ExpiresAt == nil {
		t.Fatalf("unexpected created access: %+v", created)
	}

	revokedAt := access.CreatedAt.Add(time.Hour)
	revoked := access
	revoked.Status = pilotaccess.StatusRevoked
	revoked.RevokedAt = &revokedAt
	mock.ExpectQuery(regexp.QuoteMeta("UPDATE vpn_accesses")).
		WithArgs(access.ID, revokedAt).
		WillReturnRows(accessRow(revoked))
	result, err := store.Revoke(context.Background(), access.ID, revokedAt)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != pilotaccess.StatusRevoked || result.RevokedAt == nil {
		t.Fatalf("unexpected revoked access: %+v", result)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateClassifiesConstraintErrors(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	access := postgresTestAccess()
	mock.ExpectQuery("INSERT INTO vpn_accesses").
		WithArgs(access.ID, access.DeviceID, access.NodeID, access.Transport, access.ExternalReference,
			access.CreatedAt, access.ExpiresAt, access.RevokedAt, access.Status).
		WillReturnError(&pgconn.PgError{Code: "23505"})
	if _, err := store.Create(context.Background(), access); !errors.Is(err, pilotaccess.ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestRevokeClassifiesMissingAccess(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("UPDATE vpn_accesses").WillReturnError(sql.ErrNoRows)
	if _, err := store.Revoke(context.Background(), "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff11", time.Now()); !errors.Is(err, pilotaccess.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func postgresTestAccess() pilotaccess.Access {
	createdAt := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	expiresAt := createdAt.Add(24 * time.Hour)
	return pilotaccess.Access{
		ID: "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff11", DeviceID: "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff12",
		NodeID: "pilot-1", Transport: vpnnode.TransportAmneziaWG,
		ExternalReference: "guest-01", CreatedAt: createdAt, ExpiresAt: &expiresAt,
		Status: pilotaccess.StatusActive,
	}
}

func accessRow(access pilotaccess.Access) *sqlmock.Rows {
	return sqlmock.NewRows(accessColumns).AddRow(
		access.ID, access.DeviceID, access.NodeID, access.Transport, access.ExternalReference,
		access.CreatedAt, access.ExpiresAt, access.RevokedAt, access.Status,
	)
}
