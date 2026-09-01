package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mralstark/virtual-cloud-help-service/internal/pilotaccess"
	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

type Store struct {
	db         *sql.DB
	newAuditID func() (string, error)
}

func New(db *sql.DB) (*Store, error) {
	return NewWithIDGenerator(db, newUUID)
}

func NewWithIDGenerator(db *sql.DB, newAuditID func() (string, error)) (*Store, error) {
	if db == nil {
		return nil, errors.New("pilot access postgres: database is required")
	}
	if newAuditID == nil {
		return nil, errors.New("pilot access postgres: audit ID generator is required")
	}
	return &Store{db: db, newAuditID: newAuditID}, nil
}

func (store *Store) CheckSchema(ctx context.Context) error {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, device_id, node_id, transport, external_reference,
		       created_at, expires_at, revoked_at, status
		FROM vpn_accesses
		WHERE false`)
	if err != nil {
		return fmt.Errorf("pilot access postgres: check schema: %w", err)
	}
	return rows.Close()
}

func (store *Store) Create(ctx context.Context, access pilotaccess.Access) (pilotaccess.Access, error) {
	auditID, err := store.newAuditID()
	if err != nil {
		return pilotaccess.Access{}, fmt.Errorf("pilot access postgres: generate audit ID: %w", err)
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return pilotaccess.Access{}, fmt.Errorf("pilot access postgres: begin create: %w", err)
	}
	defer transaction.Rollback()
	row := transaction.QueryRowContext(ctx, `
		INSERT INTO vpn_accesses (
			id, device_id, node_id, transport, external_reference,
			created_at, expires_at, revoked_at, status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, device_id, node_id, transport, external_reference,
		          created_at, expires_at, revoked_at, status`,
		access.ID, access.DeviceID, access.NodeID, access.Transport,
		access.ExternalReference, access.CreatedAt, access.ExpiresAt,
		access.RevokedAt, access.Status,
	)
	result, err := scan(row)
	if err != nil {
		return pilotaccess.Access{}, classify("create", err)
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO admin_audit_events (
			id, actor, action, object_type, object_id, metadata
		) VALUES (
			$1, 'pilot-admin-api', 'pilot_access_registered', 'vpn_access', $2,
			jsonb_build_object('node_id', $3, 'transport', $4, 'expires_at', $5)
		)`, auditID, result.ID, result.NodeID, result.Transport, result.ExpiresAt); err != nil {
		return pilotaccess.Access{}, fmt.Errorf("pilot access postgres: audit create: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return pilotaccess.Access{}, fmt.Errorf("pilot access postgres: commit create: %w", err)
	}
	return result, nil
}

func (store *Store) Revoke(ctx context.Context, id string, at time.Time) (pilotaccess.Access, error) {
	auditID, err := store.newAuditID()
	if err != nil {
		return pilotaccess.Access{}, fmt.Errorf("pilot access postgres: generate audit ID: %w", err)
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return pilotaccess.Access{}, fmt.Errorf("pilot access postgres: begin revoke: %w", err)
	}
	defer transaction.Rollback()
	row := transaction.QueryRowContext(ctx, `
		UPDATE vpn_accesses
		SET status = 'revoked', revoked_at = COALESCE(revoked_at, $2)
		WHERE id = $1
		RETURNING id, device_id, node_id, transport, external_reference,
		          created_at, expires_at, revoked_at, status`, id, at)
	result, err := scan(row)
	if err != nil {
		return pilotaccess.Access{}, classify("revoke", err)
	}
	if _, err := transaction.ExecContext(ctx, `
		INSERT INTO admin_audit_events (id, actor, action, object_type, object_id)
		VALUES ($1, 'pilot-admin-api', 'pilot_access_revoked', 'vpn_access', $2)`, auditID, result.ID); err != nil {
		return pilotaccess.Access{}, fmt.Errorf("pilot access postgres: audit revoke: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return pilotaccess.Access{}, fmt.Errorf("pilot access postgres: commit revoke: %w", err)
	}
	return result, nil
}

type scanner interface {
	Scan(...any) error
}

func scan(row scanner) (pilotaccess.Access, error) {
	var (
		result    pilotaccess.Access
		transport string
		status    string
		expiresAt sql.NullTime
		revokedAt sql.NullTime
	)
	err := row.Scan(
		&result.ID, &result.DeviceID, &result.NodeID, &transport,
		&result.ExternalReference, &result.CreatedAt, &expiresAt, &revokedAt, &status,
	)
	if err != nil {
		return pilotaccess.Access{}, err
	}
	result.Transport = vpnnode.Transport(transport)
	result.Status = pilotaccess.Status(status)
	if expiresAt.Valid {
		result.ExpiresAt = &expiresAt.Time
	}
	if revokedAt.Valid {
		result.RevokedAt = &revokedAt.Time
	}
	return result, nil
}

func classify(operation string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: %s", pilotaccess.ErrNotFound, operation)
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23505":
			return fmt.Errorf("%w: duplicate operational reference", pilotaccess.ErrConflict)
		case "23503", "23514":
			return fmt.Errorf("%w: referenced device/node or value is invalid", pilotaccess.ErrInvalid)
		}
	}
	return fmt.Errorf("pilot access postgres: %s: %w", operation, err)
}

func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}
