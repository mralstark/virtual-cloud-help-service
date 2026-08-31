package pilottelemetry

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

const (
	maximumResultAge     = 30 * 24 * time.Hour
	maximumClockSkew     = 5 * time.Minute
	maximumISPCodepoints = 100
)

var (
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

	ErrInvalid  = errors.New("pilot telemetry: invalid input")
	ErrConflict = errors.New("pilot telemetry: conflict")
)

type Platform string

const (
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
	PlatformLinux   Platform = "linux"
	PlatformMacOS   Platform = "macos"
	PlatformWindows Platform = "windows"
)

type FailureStage string

const (
	FailureServerHealth   FailureStage = "server_health"
	FailurePublicIP       FailureStage = "public_ip"
	FailureTransport      FailureStage = "transport"
	FailurePort           FailureStage = "port"
	FailureServerOutbound FailureStage = "server_outbound"
	FailureTunnel         FailureStage = "tunnel"
	FailureDNS            FailureStage = "dns"
	FailureHTTPS          FailureStage = "https"
	FailureIPv4Leak       FailureStage = "ipv4_leak"
	FailureIPv6Leak       FailureStage = "ipv6_leak"
	FailureUpload         FailureStage = "upload"
	FailureDownload       FailureStage = "download"
	FailureReconnect      FailureStage = "reconnect"
)

type ConnectionTimeBucket string

const (
	ConnectionLT3S    ConnectionTimeBucket = "lt_3s"
	Connection3To10S  ConnectionTimeBucket = "3_10s"
	Connection10To30S ConnectionTimeBucket = "10_30s"
	ConnectionGT30S   ConnectionTimeBucket = "gt_30s"
	ConnectionUnknown ConnectionTimeBucket = "unknown"
)

type ThroughputBucket string

const (
	ThroughputLT1Mbps    ThroughputBucket = "lt_1_mbps"
	Throughput1To10Mbps  ThroughputBucket = "1_10_mbps"
	Throughput10To50Mbps ThroughputBucket = "10_50_mbps"
	ThroughputGTE50Mbps  ThroughputBucket = "gte_50_mbps"
)

type TestResult struct {
	ID                   string
	DeviceID             string
	ClientPlatform       Platform
	ISP                  *string
	Transport            vpnnode.Transport
	OccurredAt           time.Time
	Success              bool
	FailureStage         *FailureStage
	ConnectionTimeBucket ConnectionTimeBucket
	ThroughputBucket     *ThroughputBucket
	RecordedAt           time.Time
}

type RecordInput struct {
	DeviceID             string
	ClientPlatform       Platform
	ISP                  *string
	Transport            vpnnode.Transport
	OccurredAt           time.Time
	Success              bool
	FailureStage         *FailureStage
	ConnectionTimeBucket ConnectionTimeBucket
	ThroughputBucket     *ThroughputBucket
}

type TransportSummary struct {
	Transport   vpnnode.Transport `json:"transport"`
	Tests       uint64            `json:"tests"`
	Successes   uint64            `json:"successes"`
	SuccessRate float64           `json:"success_rate"`
}

type ISPFailure struct {
	ISP      string `json:"isp"`
	Failures uint64 `json:"failures"`
}

type FailureSummary struct {
	Stage    FailureStage `json:"stage"`
	Failures uint64       `json:"failures"`
}

type Aggregate struct {
	ActiveUsers     uint64
	ActiveDevices   uint64
	FirstTestAt     *time.Time
	LastTestAt      *time.Time
	Transports      []TransportSummary
	FailuresByStage []FailureSummary
	FailuresByISP   []ISPFailure
}

type MetricsStatus string

const (
	MetricsNotConfigured MetricsStatus = "not_configured"
	MetricsAvailable     MetricsStatus = "available"
	MetricsUnavailable   MetricsStatus = "unavailable"
)

type Report struct {
	GeneratedAt         time.Time          `json:"generated_at"`
	TotalTests          uint64             `json:"total_tests"`
	FirstTestAt         *time.Time         `json:"first_test_at,omitempty"`
	LastTestAt          *time.Time         `json:"last_test_at,omitempty"`
	ActiveUsers         uint64             `json:"active_users"`
	ActiveDevices       uint64             `json:"active_devices"`
	Transports          []TransportSummary `json:"transports"`
	FailuresByStage     []FailureSummary   `json:"failures_by_stage"`
	FailuresByISP       []ISPFailure       `json:"failures_by_isp"`
	ServerMetricsStatus MetricsStatus      `json:"server_metrics_status"`
	ServerMetrics       *vpnnode.Metrics   `json:"server_metrics,omitempty"`
}

type Store interface {
	Create(context.Context, TestResult) (TestResult, error)
	Aggregate(context.Context, time.Time) (Aggregate, error)
}

type MetricsSource interface {
	Metrics(context.Context) (vpnnode.Metrics, error)
}

type Service struct {
	store   Store
	now     func() time.Time
	newID   func() (string, error)
	metrics MetricsSource
}

func NewService(store Store, now func() time.Time, newID func() (string, error), metrics MetricsSource) (*Service, error) {
	if store == nil {
		return nil, errors.New("pilot telemetry: store is required")
	}
	if now == nil {
		now = time.Now
	}
	if newID == nil {
		newID = newUUID
	}
	return &Service{store: store, now: now, newID: newID, metrics: metrics}, nil
}

func (service *Service) Record(ctx context.Context, input RecordInput) (TestResult, error) {
	now := service.now().UTC().Truncate(time.Second)
	identifier, err := service.newID()
	if err != nil {
		return TestResult{}, fmt.Errorf("pilot telemetry: generate ID: %w", err)
	}
	result := TestResult{
		ID: identifier, DeviceID: input.DeviceID, ClientPlatform: input.ClientPlatform,
		ISP: cloneString(input.ISP), Transport: input.Transport,
		OccurredAt: input.OccurredAt.UTC().Truncate(time.Second), Success: input.Success,
		FailureStage: cloneFailureStage(input.FailureStage), ConnectionTimeBucket: input.ConnectionTimeBucket,
		ThroughputBucket: cloneThroughputBucket(input.ThroughputBucket), RecordedAt: now,
	}
	if result.ISP != nil {
		trimmed := strings.TrimSpace(*result.ISP)
		result.ISP = &trimmed
	}
	if result.OccurredAt.Before(now.Add(-maximumResultAge)) || result.OccurredAt.After(now.Add(maximumClockSkew)) {
		return TestResult{}, fmt.Errorf("%w: occurrence time is outside the 30-day pilot window", ErrInvalid)
	}
	if err := Validate(result); err != nil {
		return TestResult{}, err
	}
	stored, err := service.store.Create(ctx, result)
	if err != nil {
		return TestResult{}, err
	}
	if err := Validate(stored); err != nil {
		return TestResult{}, fmt.Errorf("pilot telemetry: store returned invalid result: %w", err)
	}
	return stored, nil
}

func (service *Service) Report(ctx context.Context) (Report, error) {
	now := service.now().UTC().Truncate(time.Second)
	aggregate, err := service.store.Aggregate(ctx, now)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		GeneratedAt: now, ActiveUsers: aggregate.ActiveUsers, ActiveDevices: aggregate.ActiveDevices,
		FirstTestAt: cloneTime(aggregate.FirstTestAt), LastTestAt: cloneTime(aggregate.LastTestAt),
		Transports:          append([]TransportSummary{}, aggregate.Transports...),
		FailuresByStage:     append([]FailureSummary{}, aggregate.FailuresByStage...),
		FailuresByISP:       append([]ISPFailure{}, aggregate.FailuresByISP...),
		ServerMetricsStatus: MetricsNotConfigured,
	}
	if (report.FirstTestAt == nil) != (report.LastTestAt == nil) ||
		(report.FirstTestAt != nil && report.LastTestAt.Before(*report.FirstTestAt)) {
		return Report{}, fmt.Errorf("pilot telemetry: store returned invalid test period")
	}
	for index := range report.Transports {
		summary := &report.Transports[index]
		if err := vpnnode.ValidateTransport(summary.Transport); err != nil || summary.Successes > summary.Tests {
			return Report{}, fmt.Errorf("pilot telemetry: store returned invalid aggregate")
		}
		report.TotalTests += summary.Tests
		if summary.Tests > 0 {
			summary.SuccessRate = float64(summary.Successes) / float64(summary.Tests)
		}
	}
	sort.Slice(report.Transports, func(i, j int) bool { return report.Transports[i].Transport < report.Transports[j].Transport })
	for _, failure := range report.FailuresByStage {
		if !validFailureStage(failure.Stage) || failure.Failures == 0 {
			return Report{}, fmt.Errorf("pilot telemetry: store returned invalid failure aggregate")
		}
	}
	if service.metrics != nil {
		report.ServerMetricsStatus = MetricsUnavailable
		metrics, metricErr := service.metrics.Metrics(ctx)
		if metricErr == nil && vpnnode.ValidateMetrics(metrics) == nil {
			report.ServerMetricsStatus = MetricsAvailable
			report.ServerMetrics = &metrics
		}
	}
	return report, nil
}

func Validate(result TestResult) error {
	if !uuidPattern.MatchString(result.ID) || !uuidPattern.MatchString(result.DeviceID) {
		return fmt.Errorf("%w: result and device IDs must be canonical UUIDs", ErrInvalid)
	}
	if err := validatePlatform(result.ClientPlatform); err != nil {
		return err
	}
	if err := vpnnode.ValidateTransport(result.Transport); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if result.OccurredAt.IsZero() || result.RecordedAt.IsZero() {
		return fmt.Errorf("%w: occurrence and recording times are required", ErrInvalid)
	}
	if result.ISP != nil && !validISP(*result.ISP) {
		return fmt.Errorf("%w: ISP label is invalid", ErrInvalid)
	}
	if result.Success != (result.FailureStage == nil) {
		return fmt.Errorf("%w: success and failure stage are inconsistent", ErrInvalid)
	}
	if result.FailureStage != nil && !validFailureStage(*result.FailureStage) {
		return fmt.Errorf("%w: failure stage is invalid", ErrInvalid)
	}
	if !validConnectionBucket(result.ConnectionTimeBucket) {
		return fmt.Errorf("%w: connection time bucket is invalid", ErrInvalid)
	}
	if result.ThroughputBucket != nil && !validThroughputBucket(*result.ThroughputBucket) {
		return fmt.Errorf("%w: throughput bucket is invalid", ErrInvalid)
	}
	return nil
}

func validatePlatform(value Platform) error {
	switch value {
	case PlatformAndroid, PlatformIOS, PlatformLinux, PlatformMacOS, PlatformWindows:
		return nil
	default:
		return fmt.Errorf("%w: client platform is invalid", ErrInvalid)
	}
}

func validFailureStage(value FailureStage) bool {
	switch value {
	case FailureServerHealth, FailurePublicIP, FailureTransport, FailurePort,
		FailureServerOutbound, FailureTunnel, FailureDNS, FailureHTTPS,
		FailureIPv4Leak, FailureIPv6Leak, FailureUpload, FailureDownload, FailureReconnect:
		return true
	default:
		return false
	}
}

func validConnectionBucket(value ConnectionTimeBucket) bool {
	switch value {
	case ConnectionLT3S, Connection3To10S, Connection10To30S, ConnectionGT30S, ConnectionUnknown:
		return true
	default:
		return false
	}
}

func validThroughputBucket(value ThroughputBucket) bool {
	switch value {
	case ThroughputLT1Mbps, Throughput1To10Mbps, Throughput10To50Mbps, ThroughputGTE50Mbps:
		return true
	default:
		return false
	}
}

func validISP(value string) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) {
		return false
	}
	if net.ParseIP(value) != nil {
		return false
	}
	count := utf8.RuneCountInString(value)
	if count < 1 || count > maximumISPCodepoints {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
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

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneFailureStage(value *FailureStage) *FailureStage {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneThroughputBucket(value *ThroughputBucket) *ThroughputBucket {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := value.UTC().Truncate(time.Second)
	return &result
}
