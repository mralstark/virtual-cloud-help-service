package pilotapi

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/pilotaccess"
	"github.com/mralstark/virtual-cloud-help-service/internal/pilottelemetry"
	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

const testToken = "0123456789abcdef0123456789abcdef"

type fakeService struct {
	registered pilotaccess.RegisterInput
	access     pilotaccess.Access
	err        error
}

type fakeTelemetry struct {
	recorded pilottelemetry.RecordInput
	result   pilottelemetry.TestResult
	report   pilottelemetry.Report
	err      error
}

func (service *fakeTelemetry) Record(_ context.Context, input pilottelemetry.RecordInput) (pilottelemetry.TestResult, error) {
	service.recorded = input
	return service.result, service.err
}

func (service *fakeTelemetry) Report(context.Context) (pilottelemetry.Report, error) {
	return service.report, service.err
}

func (service *fakeService) Register(_ context.Context, input pilotaccess.RegisterInput) (pilotaccess.Access, error) {
	service.registered = input
	return service.access, service.err
}

func (service *fakeService) Revoke(context.Context, string) (pilotaccess.Access, error) {
	return service.access, service.err
}

func TestRegisterRequiresAuthenticationAndStrictJSON(t *testing.T) {
	service := &fakeService{access: testAccess()}
	handler, err := New(service, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, "/admin/pilot/access", strings.NewReader(`{}`)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	request := httptest.NewRequest(http.MethodPost, "/admin/pilot/access", strings.NewReader(`{
		"device_id":"018f5962-9d2a-4ea2-8f6d-9c2e8b6bff12",
		"node_id":"pilot-1",
		"transport":"amneziawg",
		"external_reference":"guest-01",
		"expires_at":"2026-09-07T12:00:00Z"
	}`))
	request.Header.Set("Authorization", "bearer "+testToken)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	if service.registered.ExternalReference != "guest-01" || strings.Contains(response.Body.String(), testToken) {
		t.Fatalf("unexpected response or registration: %s %+v", response.Body.String(), service.registered)
	}

	unknown := httptest.NewRequest(http.MethodPost, "/admin/pilot/access", strings.NewReader(`{"unknown":true}`))
	unknown.Header.Set("Authorization", "Bearer "+testToken)
	unknown.Header.Set("Content-Type", "application/json")
	unknownResponse := httptest.NewRecorder()
	handler.ServeHTTP(unknownResponse, unknown)
	if unknownResponse.Code != http.StatusBadRequest {
		t.Fatalf("unknown-field status = %d", unknownResponse.Code)
	}

	oversized := httptest.NewRequest(http.MethodPost, "/admin/pilot/access", strings.NewReader(`{"padding":"`+strings.Repeat("a", maxRequestBytes)+`"}`))
	oversized.Header.Set("Authorization", "Bearer "+testToken)
	oversized.Header.Set("Content-Type", "application/json")
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversized)
	if oversizedResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status = %d", oversizedResponse.Code)
	}
}

func TestNewRejectsWhitespaceInAdminToken(t *testing.T) {
	if _, err := New(&fakeService{}, strings.Repeat("a", 31)+" ", nil); err == nil {
		t.Fatal("New accepted an admin token containing whitespace")
	}
}

func TestNewRejectsExampleAdminToken(t *testing.T) {
	if _, err := New(&fakeService{}, "replace-with-at-least-32-random-characters", nil); err == nil {
		t.Fatal("New accepted the example admin token")
	}
}

func TestTelemetryEndpointsAreAuthenticatedAndOptional(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	telemetry := &fakeTelemetry{
		result: pilottelemetry.TestResult{
			ID: "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff21", DeviceID: "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff12",
			ClientPlatform: pilottelemetry.PlatformAndroid, Transport: vpnnode.TransportAmneziaWG,
			OccurredAt: now, Success: true, ConnectionTimeBucket: pilottelemetry.Connection3To10S, RecordedAt: now,
		},
		report: pilottelemetry.Report{GeneratedAt: now, ServerMetricsStatus: pilottelemetry.MetricsNotConfigured},
	}
	handler, err := NewWithTelemetry(&fakeService{}, telemetry, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	record := httptest.NewRequest(http.MethodPost, "/admin/pilot/test-results", strings.NewReader(`{
		"device_id":"018f5962-9d2a-4ea2-8f6d-9c2e8b6bff12",
		"client_platform":"android",
		"transport":"amneziawg",
		"occurred_at":"2026-08-31T12:00:00Z",
		"success":true,
		"connection_time_bucket":"3_10s"
	}`))
	record.Header.Set("Authorization", "Bearer "+testToken)
	record.Header.Set("Content-Type", "application/json")
	recordResponse := httptest.NewRecorder()
	handler.ServeHTTP(recordResponse, record)
	if recordResponse.Code != http.StatusCreated || telemetry.recorded.ClientPlatform != pilottelemetry.PlatformAndroid {
		t.Fatalf("record status=%d input=%+v body=%s", recordResponse.Code, telemetry.recorded, recordResponse.Body.String())
	}

	reportRequest := httptest.NewRequest(http.MethodGet, "/admin/pilot/report", nil)
	reportRequest.Header.Set("Authorization", "Bearer "+testToken)
	reportResponse := httptest.NewRecorder()
	handler.ServeHTTP(reportResponse, reportRequest)
	if reportResponse.Code != http.StatusOK || !strings.Contains(reportResponse.Body.String(), `"server_metrics_status":"not_configured"`) {
		t.Fatalf("report status=%d body=%s", reportResponse.Code, reportResponse.Body.String())
	}

	withoutTelemetry, err := New(&fakeService{}, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	disabledRequest := httptest.NewRequest(http.MethodGet, "/admin/pilot/report", nil)
	disabledRequest.Header.Set("Authorization", "Bearer "+testToken)
	disabledResponse := httptest.NewRecorder()
	withoutTelemetry.ServeHTTP(disabledResponse, disabledRequest)
	if disabledResponse.Code != http.StatusNotFound {
		t.Fatalf("disabled telemetry status=%d", disabledResponse.Code)
	}
}

func TestServiceErrorDoesNotLogSensitiveDetails(t *testing.T) {
	var output bytes.Buffer
	service := &fakeService{err: errors.New("database failed with secret=value")}
	handler, err := New(service, testToken, log.New(&output, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/pilot/access/018f5962-9d2a-4ea2-8f6d-9c2e8b6bff11/revoke", nil)
	request.Header.Set("Authorization", "Bearer "+testToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", response.Code)
	}
	if strings.Contains(output.String(), "secret=value") {
		t.Fatalf("sensitive error was logged: %q", output.String())
	}
}

func testAccess() pilotaccess.Access {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	return pilotaccess.Access{
		ID: "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff11", DeviceID: "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff12",
		NodeID: "pilot-1", Transport: vpnnode.TransportAmneziaWG,
		ExternalReference: "guest-01", CreatedAt: now, Status: pilotaccess.StatusActive,
	}
}
