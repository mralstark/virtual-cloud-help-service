package timeweb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

type fakeObserver struct {
	health       vpnnode.Health
	capabilities []vpnnode.Transport
	inventory    vpnnode.Inventory
	metrics      vpnnode.Metrics
	err          error
}

func (observer fakeObserver) Health(context.Context, string) (vpnnode.Health, error) {
	return observer.health, observer.err
}

func (observer fakeObserver) Capabilities(context.Context, string) ([]vpnnode.Transport, error) {
	return observer.capabilities, observer.err
}

func (observer fakeObserver) Inventory(context.Context, string) (vpnnode.Inventory, error) {
	return observer.inventory, observer.err
}

func (observer fakeObserver) Metrics(context.Context, string) (vpnnode.Metrics, error) {
	return observer.metrics, observer.err
}

func TestNodeExposesValidatedReadOnlyObservations(t *testing.T) {
	now := time.Now().UTC()
	observer := fakeObserver{
		health: vpnnode.Health{State: vpnnode.StateReady, ObservedAt: now, Transports: []vpnnode.TransportHealth{
			{Transport: vpnnode.TransportAmneziaWG, Up: true},
			{Transport: vpnnode.TransportXRayReality, Up: true},
		}},
		capabilities: []vpnnode.Transport{vpnnode.TransportXRayReality, vpnnode.TransportAmneziaWG},
		inventory: vpnnode.Inventory{
			OS: "ubuntu", Kernel: "linux", ObservedAt: now,
			Listeners: []vpnnode.Listener{{Network: "udp", Address: "0.0.0.0", Port: 585, Owner: "amnezia", Public: true}},
		},
		metrics: vpnnode.Metrics{CPUPercent: 1, MemoryTotalBytes: 1024, MemoryUsedBytes: 512, ObservedAt: now},
	}
	node, err := NewNode("pilot-1", observer)
	if err != nil {
		t.Fatal(err)
	}
	if node.Provider() != ProviderName || node.ID() != "pilot-1" {
		t.Fatalf("unexpected identity: %s/%s", node.Provider(), node.ID())
	}
	capabilities, err := node.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if capabilities[0] != vpnnode.TransportAmneziaWG {
		t.Fatalf("capabilities are not canonical: %v", capabilities)
	}
	if _, err := node.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Inventory(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Metrics(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNodeRejectsInvalidObservation(t *testing.T) {
	node, err := NewNode("pilot-1", fakeObserver{health: vpnnode.Health{State: vpnnode.StateReady}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.Health(context.Background()); err == nil {
		t.Fatal("expected invalid health observation")
	}
}

func TestNodeWrapsObserverError(t *testing.T) {
	node, err := NewNode("pilot-1", fakeObserver{err: errors.New("unavailable")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.Metrics(context.Background()); err == nil {
		t.Fatal("expected observer error")
	}
}
