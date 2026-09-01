package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mralstark/virtual-cloud-help-service/internal/pilottelemetry"
	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

var resultColumns = []string{
	"id", "device_id", "client_platform", "isp", "transport", "occurred_at",
	"success", "failure_stage", "connection_time_bucket", "throughput_bucket", "recorded_at",
}

func TestCreateResult(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	result := postgresTestResult()
	mock.ExpectQuery("INSERT INTO pilot_test_results").
		WithArgs(
			result.ID, result.DeviceID, result.ClientPlatform, result.ISP, result.Transport,
			result.OccurredAt, result.Success, result.FailureStage,
			result.ConnectionTimeBucket, result.ThroughputBucket, result.RecordedAt,
		).
		WillReturnRows(resultRow(result))
	stored, err := store.Create(context.Background(), result)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ID != result.ID || stored.ISP == result.ISP || stored.ThroughputBucket == nil {
		t.Fatalf("unexpected stored result: %+v", stored)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateClassifiesConstraintError(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	result := postgresTestResult()
	mock.ExpectQuery("INSERT INTO pilot_test_results").WillReturnError(&pgconn.PgError{Code: "23503"})
	if _, err := store.Create(context.Background(), result); !errors.Is(err, pilottelemetry.ErrInvalid) {
		t.Fatalf("expected invalid result, got %v", err)
	}
}

func TestAggregateUsesConsistentReadTransaction(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	store, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT transport").WillReturnRows(
		sqlmock.NewRows([]string{"transport", "tests", "successes"}).
			AddRow("amneziawg", int64(4), int64(3)).
			AddRow("xray_reality", int64(2), int64(1)),
	)
	mock.ExpectQuery("SELECT failure_stage").WillReturnRows(
		sqlmock.NewRows([]string{"failure_stage", "failures"}).AddRow("dns", int64(1)),
	)
	mock.ExpectQuery("SELECT isp").WillReturnRows(
		sqlmock.NewRows([]string{"isp", "failures"}).AddRow("Example ISP", int64(2)),
	)
	mock.ExpectQuery("SELECT count\\(DISTINCT access.device_id\\)").WithArgs(at).
		WillReturnRows(sqlmock.NewRows([]string{"active_devices", "active_users"}).AddRow(int64(3), int64(2)))
	mock.ExpectQuery("SELECT min\\(occurred_at\\), max\\(occurred_at\\)").WillReturnRows(
		sqlmock.NewRows([]string{"first_test_at", "last_test_at"}).AddRow(at.Add(-time.Hour), at),
	)
	mock.ExpectCommit()
	aggregate, err := store.Aggregate(context.Background(), at)
	if err != nil {
		t.Fatal(err)
	}
	if aggregate.ActiveDevices != 3 || aggregate.ActiveUsers != 2 || aggregate.FirstTestAt == nil || aggregate.LastTestAt == nil ||
		len(aggregate.Transports) != 2 || len(aggregate.FailuresByStage) != 1 || len(aggregate.FailuresByISP) != 1 {
		t.Fatalf("unexpected aggregate: %+v", aggregate)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func postgresTestResult() pilottelemetry.TestResult {
	occurredAt := time.Date(2026, 8, 31, 11, 59, 0, 0, time.UTC)
	recordedAt := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	isp := "Example ISP"
	throughput := pilottelemetry.Throughput10To50Mbps
	return pilottelemetry.TestResult{
		ID: "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff21", DeviceID: "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff22",
		ClientPlatform: pilottelemetry.PlatformAndroid, ISP: &isp,
		Transport: vpnnode.TransportAmneziaWG, OccurredAt: occurredAt, Success: true,
		ConnectionTimeBucket: pilottelemetry.Connection3To10S, ThroughputBucket: &throughput,
		RecordedAt: recordedAt,
	}
}

func resultRow(result pilottelemetry.TestResult) *sqlmock.Rows {
	return sqlmock.NewRows(resultColumns).AddRow(
		result.ID, result.DeviceID, result.ClientPlatform, valueOrNil(result.ISP), result.Transport,
		result.OccurredAt, result.Success, valueOrNil(result.FailureStage),
		result.ConnectionTimeBucket, valueOrNil(result.ThroughputBucket), result.RecordedAt,
	)
}

func valueOrNil[T ~string](value *T) any {
	if value == nil {
		return nil
	}
	return string(*value)
}
