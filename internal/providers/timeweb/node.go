package timeweb

import (
	"context"
	"errors"
	"fmt"

	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

const ProviderName = "timeweb-cloud"

// Observer is implemented by the eventual read-only SSH/monitoring collector. It
// deliberately contains no provisioning or protocol mutation operations.
type Observer interface {
	Health(context.Context, string) (vpnnode.Health, error)
	Capabilities(context.Context, string) ([]vpnnode.Transport, error)
	Inventory(context.Context, string) (vpnnode.Inventory, error)
	Metrics(context.Context, string) (vpnnode.Metrics, error)
}

type Node struct {
	id       string
	observer Observer
}

func NewNode(id string, observer Observer) (*Node, error) {
	if err := vpnnode.ValidateID(id); err != nil {
		return nil, err
	}
	if observer == nil {
		return nil, errors.New("timeweb: observer is required")
	}
	return &Node{id: id, observer: observer}, nil
}

func (node *Node) ID() string {
	return node.id
}

func (node *Node) Provider() string {
	return ProviderName
}

func (node *Node) Health(ctx context.Context) (vpnnode.Health, error) {
	value, err := node.observer.Health(ctx, node.id)
	if err != nil {
		return vpnnode.Health{}, fmt.Errorf("timeweb: observe health: %w", err)
	}
	if err := vpnnode.ValidateHealth(value); err != nil {
		return vpnnode.Health{}, fmt.Errorf("timeweb: invalid health observation: %w", err)
	}
	return value, nil
}

func (node *Node) Capabilities(ctx context.Context) ([]vpnnode.Transport, error) {
	values, err := node.observer.Capabilities(ctx, node.id)
	if err != nil {
		return nil, fmt.Errorf("timeweb: observe capabilities: %w", err)
	}
	values, err = vpnnode.CanonicalCapabilities(values)
	if err != nil {
		return nil, fmt.Errorf("timeweb: invalid capabilities observation: %w", err)
	}
	return values, nil
}

func (node *Node) Inventory(ctx context.Context) (vpnnode.Inventory, error) {
	value, err := node.observer.Inventory(ctx, node.id)
	if err != nil {
		return vpnnode.Inventory{}, fmt.Errorf("timeweb: observe inventory: %w", err)
	}
	if err := vpnnode.ValidateInventory(value); err != nil {
		return vpnnode.Inventory{}, fmt.Errorf("timeweb: invalid inventory observation: %w", err)
	}
	return value, nil
}

func (node *Node) Metrics(ctx context.Context) (vpnnode.Metrics, error) {
	value, err := node.observer.Metrics(ctx, node.id)
	if err != nil {
		return vpnnode.Metrics{}, fmt.Errorf("timeweb: observe metrics: %w", err)
	}
	if err := vpnnode.ValidateMetrics(value); err != nil {
		return vpnnode.Metrics{}, fmt.Errorf("timeweb: invalid metrics observation: %w", err)
	}
	return value, nil
}

var _ vpnnode.Node = (*Node)(nil)
