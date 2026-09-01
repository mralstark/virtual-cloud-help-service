package timeweb

import (
	"context"
	"fmt"

	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

// Provider is a typed lifecycle boundary for future Timeweb automation. Every
// operation remains explicitly unsupported for the existing-node pilot so that a
// call cannot accidentally create billable infrastructure or destroy the node.
type Provider struct{}

func NewProvider() *Provider {
	return &Provider{}
}

func (*Provider) CreateNode(context.Context, vpnnode.CreateNodeInput) (vpnnode.NodeRecord, error) {
	return vpnnode.NodeRecord{}, unsupported("create node")
}

func (*Provider) DeleteNode(context.Context, string) error {
	return unsupported("delete node")
}

func (*Provider) GetNode(context.Context, string) (vpnnode.NodeRecord, error) {
	return vpnnode.NodeRecord{}, unsupported("get node")
}

func (*Provider) AttachPublicIP(context.Context, string) (vpnnode.PublicIP, error) {
	return vpnnode.PublicIP{}, unsupported("attach public IP")
}

func (*Provider) DetachPublicIP(context.Context, string, string) error {
	return unsupported("detach public IP")
}

func unsupported(operation string) error {
	return fmt.Errorf("timeweb: %s: %w", operation, vpnnode.ErrOperationUnsupported)
}

var _ vpnnode.ProviderOperations = (*Provider)(nil)
