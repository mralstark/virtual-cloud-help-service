package timeweb

import (
	"context"
	"errors"
	"testing"

	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

func TestProviderLifecycleOperationsFailClosed(t *testing.T) {
	provider := NewProvider()
	ctx := context.Background()
	_, createErr := provider.CreateNode(ctx, vpnnode.CreateNodeInput{})
	deleteErr := provider.DeleteNode(ctx, "pilot-1")
	_, getErr := provider.GetNode(ctx, "pilot-1")
	_, attachErr := provider.AttachPublicIP(ctx, "pilot-1")
	detachErr := provider.DetachPublicIP(ctx, "pilot-1", "ip-1")
	for operation, err := range map[string]error{
		"create": createErr, "delete": deleteErr, "get": getErr,
		"attach": attachErr, "detach": detachErr,
	} {
		if !errors.Is(err, vpnnode.ErrOperationUnsupported) {
			t.Fatalf("%s returned %v", operation, err)
		}
	}
}
