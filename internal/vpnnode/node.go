package vpnnode

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"time"
)

var identifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

type Transport string

const (
	TransportAmneziaWG   Transport = "amneziawg"
	TransportXRayReality Transport = "xray_reality"
)

type State string

const (
	StateReady    State = "READY"
	StateDegraded State = "DEGRADED"
	StateDown     State = "DOWN"
)

type TransportHealth struct {
	Transport Transport
	Up        bool
}

type Health struct {
	State      State
	Transports []TransportHealth
	ObservedAt time.Time
}

type Listener struct {
	Network string
	Address string
	Port    uint16
	Owner   string
	Public  bool
}

type Workload struct {
	Name          string
	Image         string
	Runtime       string
	State         string
	RestartPolicy string
}

type Inventory struct {
	OS         string
	Kernel     string
	Listeners  []Listener
	Workloads  []Workload
	ObservedAt time.Time
}

type Metrics struct {
	CPUPercent            float64
	MemoryTotalBytes      uint64
	MemoryUsedBytes       uint64
	NetworkRXBytes        uint64
	NetworkTXBytes        uint64
	ActiveConnectionCount *uint64
	ConfigRevision        string
	ObservedAt            time.Time
}

// Node exposes provider-independent, read-only pilot operations. Provisioning and
// protocol mutation deliberately remain outside this interface.
type Node interface {
	ID() string
	Provider() string
	Health(context.Context) (Health, error)
	Capabilities(context.Context) ([]Transport, error)
	Inventory(context.Context) (Inventory, error)
	Metrics(context.Context) (Metrics, error)
}

func ValidateID(value string) error {
	if !identifierPattern.MatchString(value) {
		return fmt.Errorf("vpnnode: invalid identifier %q", value)
	}
	return nil
}

func ValidateTransport(value Transport) error {
	switch value {
	case TransportAmneziaWG, TransportXRayReality:
		return nil
	default:
		return fmt.Errorf("vpnnode: unsupported transport %q", value)
	}
}

func ValidateCapabilities(values []Transport) error {
	if len(values) == 0 || len(values) > 8 {
		return errors.New("vpnnode: capabilities must contain between 1 and 8 transports")
	}
	seen := make(map[Transport]struct{}, len(values))
	for _, value := range values {
		if err := ValidateTransport(value); err != nil {
			return err
		}
		if _, exists := seen[value]; exists {
			return fmt.Errorf("vpnnode: duplicate transport %q", value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func CanonicalCapabilities(values []Transport) ([]Transport, error) {
	result := append([]Transport(nil), values...)
	if err := ValidateCapabilities(result); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result, nil
}

func ValidateHealth(value Health) error {
	switch value.State {
	case StateReady, StateDegraded, StateDown:
	default:
		return fmt.Errorf("vpnnode: invalid node state %q", value.State)
	}
	if value.ObservedAt.IsZero() {
		return errors.New("vpnnode: health observation time is required")
	}
	if len(value.Transports) == 0 || len(value.Transports) > 8 {
		return errors.New("vpnnode: transport health must contain between 1 and 8 entries")
	}
	seen := make(map[Transport]struct{}, len(value.Transports))
	upCount := 0
	for _, transport := range value.Transports {
		if err := ValidateTransport(transport.Transport); err != nil {
			return err
		}
		if _, exists := seen[transport.Transport]; exists {
			return fmt.Errorf("vpnnode: duplicate transport health %q", transport.Transport)
		}
		seen[transport.Transport] = struct{}{}
		if transport.Up {
			upCount++
		}
	}
	if value.State == StateReady && upCount != len(value.Transports) {
		return errors.New("vpnnode: READY requires every transport to be up")
	}
	if value.State == StateDegraded && (upCount == 0 || upCount == len(value.Transports)) {
		return errors.New("vpnnode: DEGRADED requires both healthy and unhealthy transports")
	}
	if value.State == StateDown && upCount != 0 {
		return errors.New("vpnnode: DOWN requires every transport to be down")
	}
	return nil
}

func ValidateInventory(value Inventory) error {
	if value.ObservedAt.IsZero() {
		return errors.New("vpnnode: inventory observation time is required")
	}
	if value.OS == "" || value.Kernel == "" {
		return errors.New("vpnnode: inventory OS and kernel are required")
	}
	if len(value.Listeners) > 256 || len(value.Workloads) > 256 {
		return errors.New("vpnnode: inventory exceeds pilot bounds")
	}
	for _, listener := range value.Listeners {
		if listener.Network != "tcp" && listener.Network != "udp" {
			return fmt.Errorf("vpnnode: unsupported listener network %q", listener.Network)
		}
		if listener.Port == 0 || listener.Owner == "" || net.ParseIP(listener.Address) == nil {
			return errors.New("vpnnode: listener requires an IP address, port, and owner")
		}
	}
	for _, workload := range value.Workloads {
		if workload.Name == "" || workload.Runtime == "" || workload.State == "" {
			return errors.New("vpnnode: workload name, runtime, and state are required")
		}
	}
	return nil
}

func ValidateMetrics(value Metrics) error {
	if value.ObservedAt.IsZero() {
		return errors.New("vpnnode: metrics observation time is required")
	}
	if value.CPUPercent < 0 || value.CPUPercent > 100 {
		return errors.New("vpnnode: CPU percent must be between 0 and 100")
	}
	if value.MemoryTotalBytes == 0 || value.MemoryUsedBytes > value.MemoryTotalBytes {
		return errors.New("vpnnode: memory values are invalid")
	}
	if len(value.ConfigRevision) > 128 {
		return errors.New("vpnnode: config revision is too long")
	}
	return nil
}
