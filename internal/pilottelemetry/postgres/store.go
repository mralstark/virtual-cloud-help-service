package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mralstark/virtual-cloud-help-service/internal/pilottelemetry"
	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

type Store struct {
	db *sql.DB
}

func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("pilot telemetry postgres: database is required")
	}
	return &Store{db: db}, nil
}

func (store *Store) CheckSchema(ctx context.Context) error {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, device_id, client_platform, isp, transport, occurred_at,
		       success, failure_stage, connection_time_bucket, throughput_bucket,
		       recorded_at
		FROM pilot_test_results
		WHERE false`)
	if err != nil {
		return fmt.Errorf("pilot telemetry postgres: check schema: %w", err)
	}
	return rows.Close()
}

func (store *Store) Create(ctx context.Context, result pilottelemetry.TestResult) (pilottelemetry.TestResult, error) {
	row := store.db.QueryRowContext(ctx, `
		INSERT INTO pilot_test_results (
			id, device_id, client_platform, isp, transport, occurred_at,
			success, failure_stage, connection_time_bucket, throughput_bucket,
			recorded_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, device_id, client_platform, isp, transport, occurred_at,
		          success, failure_stage, connection_time_bucket, throughput_bucket,
		          recorded_at`,
		result.ID, result.DeviceID, result.ClientPlatform, result.ISP, result.Transport,
		result.OccurredAt, result.Success, result.FailureStage,
		result.ConnectionTimeBucket, result.ThroughputBucket, result.RecordedAt,
	)
	stored, err := scan(row)
	if err != nil {
		return pilottelemetry.TestResult{}, classifyCreate(err)
	}
	return stored, nil
}

func (store *Store) Aggregate(ctx context.Context, at time.Time) (aggregate pilottelemetry.Aggregate, returnErr error) {
	transaction, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return aggregate, fmt.Errorf("pilot telemetry postgres: begin report: %w", err)
	}
	defer func() {
		if rollbackErr := transaction.Rollback(); returnErr == nil && rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			returnErr = fmt.Errorf("pilot telemetry postgres: roll back report: %w", rollbackErr)
		}
	}()

	transportRows, err := transaction.QueryContext(ctx, `
		SELECT transport, count(*)::bigint,
		       count(*) FILTER (WHERE success)::bigint
		FROM pilot_test_results
		GROUP BY transport
		ORDER BY transport`)
	if err != nil {
		return aggregate, fmt.Errorf("pilot telemetry postgres: aggregate transports: %w", err)
	}
	for transportRows.Next() {
		var summary pilottelemetry.TransportSummary
		var transport string
		if err := transportRows.Scan(&transport, &summary.Tests, &summary.Successes); err != nil {
			_ = transportRows.Close()
			return aggregate, fmt.Errorf("pilot telemetry postgres: scan transport aggregate: %w", err)
		}
		summary.Transport = vpnnode.Transport(transport)
		aggregate.Transports = append(aggregate.Transports, summary)
	}
	if err := transportRows.Err(); err != nil {
		_ = transportRows.Close()
		return aggregate, fmt.Errorf("pilot telemetry postgres: read transport aggregate: %w", err)
	}
	if err := transportRows.Close(); err != nil {
		return aggregate, fmt.Errorf("pilot telemetry postgres: close transport aggregate: %w", err)
	}

	failureRows, err := transaction.QueryContext(ctx, `
		SELECT failure_stage, count(*)::bigint
		FROM pilot_test_results
		WHERE success = false
		GROUP BY failure_stage
		ORDER BY failure_stage`)
	if err != nil {
		return aggregate, fmt.Errorf("pilot telemetry postgres: aggregate failure stages: %w", err)
	}
	for failureRows.Next() {
		var summary pilottelemetry.FailureSummary
		var stage string
		if err := failureRows.Scan(&stage, &summary.Failures); err != nil {
			_ = failureRows.Close()
			return aggregate, fmt.Errorf("pilot telemetry postgres: scan failure aggregate: %w", err)
		}
		summary.Stage = pilottelemetry.FailureStage(stage)
		aggregate.FailuresByStage = append(aggregate.FailuresByStage, summary)
	}
	if err := failureRows.Err(); err != nil {
		_ = failureRows.Close()
		return aggregate, fmt.Errorf("pilot telemetry postgres: read failure aggregate: %w", err)
	}
	if err := failureRows.Close(); err != nil {
		return aggregate, fmt.Errorf("pilot telemetry postgres: close failure aggregate: %w", err)
	}

	ispRows, err := transaction.QueryContext(ctx, `
		SELECT isp, count(*)::bigint
		FROM pilot_test_results
		WHERE success = false AND isp IS NOT NULL
		GROUP BY isp
		ORDER BY count(*) DESC, isp
		LIMIT 100`)
	if err != nil {
		return aggregate, fmt.Errorf("pilot telemetry postgres: aggregate ISP failures: %w", err)
	}
	for ispRows.Next() {
		var failure pilottelemetry.ISPFailure
		if err := ispRows.Scan(&failure.ISP, &failure.Failures); err != nil {
			_ = ispRows.Close()
			return aggregate, fmt.Errorf("pilot telemetry postgres: scan ISP aggregate: %w", err)
		}
		aggregate.FailuresByISP = append(aggregate.FailuresByISP, failure)
	}
	if err := ispRows.Err(); err != nil {
		_ = ispRows.Close()
		return aggregate, fmt.Errorf("pilot telemetry postgres: read ISP aggregate: %w", err)
	}
	if err := ispRows.Close(); err != nil {
		return aggregate, fmt.Errorf("pilot telemetry postgres: close ISP aggregate: %w", err)
	}

	if err := transaction.QueryRowContext(ctx, `
		SELECT count(DISTINCT access.device_id)::bigint,
		       count(DISTINCT device.account_id)::bigint
		FROM vpn_accesses AS access
		JOIN devices AS device ON device.id = access.device_id
		WHERE access.status = 'active' AND access.expires_at > $1`, at).
		Scan(&aggregate.ActiveDevices, &aggregate.ActiveUsers); err != nil {
		return aggregate, fmt.Errorf("pilot telemetry postgres: count active devices: %w", err)
	}
	var firstTestAt, lastTestAt sql.NullTime
	if err := transaction.QueryRowContext(ctx, `
		SELECT min(occurred_at), max(occurred_at)
		FROM pilot_test_results`).Scan(&firstTestAt, &lastTestAt); err != nil {
		return aggregate, fmt.Errorf("pilot telemetry postgres: read test period: %w", err)
	}
	if firstTestAt.Valid {
		aggregate.FirstTestAt = &firstTestAt.Time
	}
	if lastTestAt.Valid {
		aggregate.LastTestAt = &lastTestAt.Time
	}
	if err := transaction.Commit(); err != nil {
		return aggregate, fmt.Errorf("pilot telemetry postgres: commit report: %w", err)
	}
	return aggregate, nil
}

type scanner interface {
	Scan(...any) error
}

func scan(row scanner) (pilottelemetry.TestResult, error) {
	var (
		result           pilottelemetry.TestResult
		platform         string
		isp              sql.NullString
		transport        string
		failureStage     sql.NullString
		connectionBucket string
		throughputBucket sql.NullString
	)
	if err := row.Scan(
		&result.ID, &result.DeviceID, &platform, &isp, &transport, &result.OccurredAt,
		&result.Success, &failureStage, &connectionBucket, &throughputBucket,
		&result.RecordedAt,
	); err != nil {
		return pilottelemetry.TestResult{}, err
	}
	result.ClientPlatform = pilottelemetry.Platform(platform)
	result.Transport = vpnnode.Transport(transport)
	result.ConnectionTimeBucket = pilottelemetry.ConnectionTimeBucket(connectionBucket)
	if isp.Valid {
		result.ISP = &isp.String
	}
	if failureStage.Valid {
		value := pilottelemetry.FailureStage(failureStage.String)
		result.FailureStage = &value
	}
	if throughputBucket.Valid {
		value := pilottelemetry.ThroughputBucket(throughputBucket.String)
		result.ThroughputBucket = &value
	}
	return result, nil
}

func classifyCreate(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "23505":
			return fmt.Errorf("%w: duplicate result", pilottelemetry.ErrConflict)
		case "23503", "23514":
			return fmt.Errorf("%w: referenced device or value is invalid", pilottelemetry.ErrInvalid)
		}
	}
	return fmt.Errorf("pilot telemetry postgres: create: %w", err)
}
