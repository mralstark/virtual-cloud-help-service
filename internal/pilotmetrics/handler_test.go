package pilotmetrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

type fakeNode struct {
	health  vpnnode.Health
	metrics vpnnode.Metrics
	err     error
}

func (fakeNode) ID() string       { return "pilot-1" }
func (fakeNode) Provider() string { return `timeweb\"cloud` }
func (node fakeNode) Health(context.Context) (vpnnode.Health, error) {
	return node.health, node.err
}
func (fakeNode) Capabilities(context.Context) ([]vpnnode.Transport, error) { return nil, nil }
func (fakeNode) Inventory(context.Context) (vpnnode.Inventory, error) {
	return vpnnode.Inventory{}, nil
}
func (node fakeNode) Metrics(context.Context) (vpnnode.Metrics, error) { return node.metrics, node.err }

func TestHandlerExportsPrivacySafePrometheusMetrics(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	connections := uint64(3)
	handler, err := New(fakeNode{
		health: vpnnode.Health{State: vpnnode.StateDegraded, ObservedAt: now, Transports: []vpnnode.TransportHealth{
			{Transport: vpnnode.TransportAmneziaWG, Up: true},
			{Transport: vpnnode.TransportXRayReality, Up: false},
		}},
		metrics: vpnnode.Metrics{
			CPUPercent: 12.5, MemoryTotalBytes: 1024, MemoryUsedBytes: 512,
			NetworkRXBytes: 100, NetworkTXBytes: 200, ActiveConnectionCount: &connections,
			ConfigRevision: "rev-1", ObservedAt: now,
		},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := response.Body.String()
	for _, expected := range []string{
		`vchs_node_up{node_id="pilot-1",provider="timeweb\\\"cloud"} 1`,
		`transport="amneziawg"} 1`,
		`transport="xray_reality"} 0`,
		`vchs_node_cpu_percent`,
		`vchs_node_active_connections`,
		`revision="rev-1"} 1`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("metric output does not contain %q:\n%s", expected, body)
		}
	}
}

func TestHandlerReturnsScrapeFailureWithoutLeakingError(t *testing.T) {
	handler, err := New(fakeNode{err: errors.New("secret=value")}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "vchs_node_metrics_scrape_success") ||
		strings.Contains(response.Body.String(), "secret=value") {
		t.Fatalf("unexpected failure response: %d %s", response.Code, response.Body.String())
	}
}
