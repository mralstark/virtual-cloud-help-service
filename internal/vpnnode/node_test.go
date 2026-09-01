package vpnnode

import (
	"math"
	"testing"
	"time"
)

func TestValidateHealthStateMatchesTransportState(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name   string
		health Health
		valid  bool
	}{
		{
			name: "ready",
			health: Health{State: StateReady, ObservedAt: now, Transports: []TransportHealth{
				{Transport: TransportAmneziaWG, Up: true},
				{Transport: TransportXRayReality, Up: true},
			}},
			valid: true,
		},
		{
			name: "degraded",
			health: Health{State: StateDegraded, ObservedAt: now, Transports: []TransportHealth{
				{Transport: TransportAmneziaWG, Up: true},
				{Transport: TransportXRayReality, Up: false},
			}},
			valid: true,
		},
		{
			name: "inconsistent ready",
			health: Health{State: StateReady, ObservedAt: now, Transports: []TransportHealth{
				{Transport: TransportAmneziaWG, Up: false},
			}},
		},
		{
			name: "duplicate",
			health: Health{State: StateDown, ObservedAt: now, Transports: []TransportHealth{
				{Transport: TransportAmneziaWG},
				{Transport: TransportAmneziaWG},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateHealth(test.health)
			if test.valid && err != nil {
				t.Fatalf("expected valid health: %v", err)
			}
			if !test.valid && err == nil {
				t.Fatal("expected invalid health")
			}
		})
	}
}

func TestCanonicalCapabilitiesSortsWithoutMutating(t *testing.T) {
	input := []Transport{TransportXRayReality, TransportAmneziaWG}
	result, err := CanonicalCapabilities(input)
	if err != nil {
		t.Fatal(err)
	}
	if result[0] != TransportAmneziaWG || input[0] != TransportXRayReality {
		t.Fatalf("unexpected canonicalization: result=%v input=%v", result, input)
	}
}

func TestValidateMetricsRejectsImpossibleMemory(t *testing.T) {
	err := ValidateMetrics(Metrics{
		CPUPercent:       10,
		MemoryTotalBytes: 10,
		MemoryUsedBytes:  11,
		ObservedAt:       time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("expected invalid metrics")
	}
}

func TestValidateMetricsRejectsNonFiniteCPU(t *testing.T) {
	for _, cpu := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		err := ValidateMetrics(Metrics{
			CPUPercent: cpu, MemoryTotalBytes: 10, MemoryUsedBytes: 5,
			ObservedAt: time.Now().UTC(),
		})
		if err == nil {
			t.Fatalf("accepted non-finite CPU value %v", cpu)
		}
	}
}
