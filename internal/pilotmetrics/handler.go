package pilotmetrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

const defaultObservationTimeout = 3 * time.Second

type Handler struct {
	node    vpnnode.Node
	timeout time.Duration
}

func New(node vpnnode.Node, timeout time.Duration) (*Handler, error) {
	if node == nil {
		return nil, fmt.Errorf("pilot metrics: node is required")
	}
	if err := vpnnode.ValidateID(node.ID()); err != nil {
		return nil, err
	}
	if timeout == 0 {
		timeout = defaultObservationTimeout
	}
	if timeout < 100*time.Millisecond || timeout > 10*time.Second {
		return nil, fmt.Errorf("pilot metrics: timeout must be between 100ms and 10s")
	}
	return &Handler{node: node, timeout: timeout}, nil
}

func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		writer.Header().Set("Allow", "GET, HEAD")
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	ctx, cancel := context.WithTimeout(request.Context(), handler.timeout)
	defer cancel()
	body := handler.collect(ctx)
	writer.WriteHeader(http.StatusOK)
	if request.Method == http.MethodGet {
		_, _ = io.WriteString(writer, body)
	}
}

func (handler *Handler) collect(ctx context.Context) string {
	labels := `node_id="` + escapeLabel(handler.node.ID()) + `",provider="` + escapeLabel(handler.node.Provider()) + `"`
	var output strings.Builder
	writeHelpType(&output, "vchs_node_up", "Whether the node process and transports are observable.", "gauge")
	writeHelpType(&output, "vchs_transport_up", "Whether an individual VPN transport is healthy.", "gauge")
	health, healthErr := handler.node.Health(ctx)
	healthValid := healthErr == nil && vpnnode.ValidateHealth(health) == nil
	nodeUp := 0
	if healthValid && health.State != vpnnode.StateDown {
		nodeUp = 1
	}
	fmt.Fprintf(&output, "vchs_node_up{%s} %d\n", labels, nodeUp)
	if healthValid {
		for _, transport := range health.Transports {
			up := 0
			if transport.Up {
				up = 1
			}
			fmt.Fprintf(&output, "vchs_transport_up{%s,transport=\"%s\"} %d\n", labels, escapeLabel(string(transport.Transport)), up)
		}
	}

	metrics, metricsErr := handler.node.Metrics(ctx)
	metricsValid := metricsErr == nil && vpnnode.ValidateMetrics(metrics) == nil
	writeHelpType(&output, "vchs_node_metrics_scrape_success", "Whether health and resource observations were valid.", "gauge")
	scrapeSuccess := 0
	if healthValid && metricsValid {
		scrapeSuccess = 1
	}
	fmt.Fprintf(&output, "vchs_node_metrics_scrape_success{%s} %d\n", labels, scrapeSuccess)
	if !metricsValid {
		return output.String()
	}
	writeHelpType(&output, "vchs_node_cpu_percent", "Current node CPU utilization percentage.", "gauge")
	fmt.Fprintf(&output, "vchs_node_cpu_percent{%s} %s\n", labels, strconv.FormatFloat(metrics.CPUPercent, 'f', -1, 64))
	writeHelpType(&output, "vchs_node_memory_total_bytes", "Total node memory in bytes.", "gauge")
	fmt.Fprintf(&output, "vchs_node_memory_total_bytes{%s} %d\n", labels, metrics.MemoryTotalBytes)
	writeHelpType(&output, "vchs_node_memory_used_bytes", "Used node memory in bytes.", "gauge")
	fmt.Fprintf(&output, "vchs_node_memory_used_bytes{%s} %d\n", labels, metrics.MemoryUsedBytes)
	writeHelpType(&output, "vchs_node_network_rx_bytes_total", "Node received network bytes.", "counter")
	fmt.Fprintf(&output, "vchs_node_network_rx_bytes_total{%s} %d\n", labels, metrics.NetworkRXBytes)
	writeHelpType(&output, "vchs_node_network_tx_bytes_total", "Node transmitted network bytes.", "counter")
	fmt.Fprintf(&output, "vchs_node_network_tx_bytes_total{%s} %d\n", labels, metrics.NetworkTXBytes)
	if metrics.ActiveConnectionCount != nil {
		writeHelpType(&output, "vchs_node_active_connections", "Safely observable active VPN connection count.", "gauge")
		fmt.Fprintf(&output, "vchs_node_active_connections{%s} %d\n", labels, *metrics.ActiveConnectionCount)
	}
	if metrics.ConfigRevision != "" {
		writeHelpType(&output, "vchs_node_config_revision_info", "Current sanitized node configuration revision.", "gauge")
		fmt.Fprintf(&output, "vchs_node_config_revision_info{%s,revision=\"%s\"} 1\n", labels, escapeLabel(metrics.ConfigRevision))
	}
	return output.String()
}

func writeHelpType(output *strings.Builder, name, help, metricType string) {
	fmt.Fprintf(output, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
}

func escapeLabel(value string) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) && character != '\n' {
			return ' '
		}
		return character
	}, value)
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return strings.ReplaceAll(value, `"`, `\"`)
}
