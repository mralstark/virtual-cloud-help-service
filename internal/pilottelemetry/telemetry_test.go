package pilottelemetry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

const (
	testResultID = "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff21"
	testDeviceID = "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff22"
)

type memoryStore struct {
	created   TestResult
	aggregate Aggregate
	err       error
}

func (store *memoryStore) Create(_ context.Context, result TestResult) (TestResult, error) {
	store.created = result
	return result, store.err
}

func (store *memoryStore) Aggregate(context.Context, time.Time) (Aggregate, error) {
	return store.aggregate, store.err
}

type metricsSource struct {
	metrics vpnnode.Metrics
	err     error
}

func (source metricsSource) Metrics(context.Context) (vpnnode.Metrics, error) {
	return source.metrics, source.err
}

func TestRecordCanonicalizesAndPersistsPrivacySafeResult(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	store := &memoryStore{}
	service, err := NewService(store, func() time.Time { return now }, func() (string, error) { return testResultID, nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	isp := "  Ростелеком  "
	throughput := Throughput10To50Mbps
	result, err := service.Record(context.Background(), RecordInput{
		DeviceID: testDeviceID, ClientPlatform: PlatformAndroid, ISP: &isp,
		Transport: vpnnode.TransportAmneziaWG, OccurredAt: now.Add(-time.Minute), Success: true,
		ConnectionTimeBucket: Connection3To10S, ThroughputBucket: &throughput,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ISP == nil || *result.ISP != "Ростелеком" || store.created.ID != testResultID {
		t.Fatalf("unexpected stored result: %+v", result)
	}
	if result.ISP == &isp || result.ThroughputBucket == &throughput {
		t.Fatal("input pointer was retained")
	}
}

func TestRecordRejectsInconsistentOrOldResult(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	service, err := NewService(&memoryStore{}, func() time.Time { return now }, func() (string, error) { return testResultID, nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	stage := FailureDNS
	for _, input := range []RecordInput{
		{
			DeviceID: testDeviceID, ClientPlatform: PlatformAndroid,
			Transport: vpnnode.TransportAmneziaWG, OccurredAt: now, Success: true,
			FailureStage: &stage, ConnectionTimeBucket: ConnectionLT3S,
		},
		{
			DeviceID: testDeviceID, ClientPlatform: PlatformAndroid,
			Transport: vpnnode.TransportAmneziaWG, OccurredAt: now.Add(-31 * 24 * time.Hour), Success: true,
			ConnectionTimeBucket: ConnectionLT3S,
		},
	} {
		if _, err := service.Record(context.Background(), input); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected invalid input, got %v", err)
		}
	}
}

func TestReportComputesRatesAndDegradesMetricsIndependently(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	store := &memoryStore{aggregate: Aggregate{
		ActiveUsers: 2, ActiveDevices: 3,
		Transports: []TransportSummary{
			{Transport: vpnnode.TransportXRayReality, Tests: 2, Successes: 1},
			{Transport: vpnnode.TransportAmneziaWG, Tests: 4, Successes: 3},
		},
		FailuresByStage: []FailureSummary{{Stage: FailureDNS, Failures: 1}},
		FailuresByISP:   []ISPFailure{{ISP: "Example", Failures: 2}},
	}}
	service, err := NewService(store, func() time.Time { return now }, nil, metricsSource{err: errors.New("unavailable")})
	if err != nil {
		t.Fatal(err)
	}
	report, err := service.Report(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.TotalTests != 6 || report.ActiveUsers != 2 || report.Transports[0].Transport != vpnnode.TransportAmneziaWG ||
		report.Transports[0].SuccessRate != 0.75 || report.ServerMetricsStatus != MetricsUnavailable {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestGeneratedUUIDIsCanonical(t *testing.T) {
	identifier, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	if !uuidPattern.MatchString(identifier) {
		t.Fatalf("generated UUID is invalid: %q", identifier)
	}
}
