package vpnnode

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
)

var (
	regionPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

	ErrOperationUnsupported = errors.New("vpnnode: provider operation is not supported")
)

type ProvisioningStatus string

const (
	ProvisioningPending ProvisioningStatus = "pending"
	ProvisioningReady   ProvisioningStatus = "ready"
	ProvisioningFailed  ProvisioningStatus = "failed"
)

type CreateNodeInput struct {
	Region                string
	SSHPublicKeyReference string
	Labels                map[string]string
}

type NodeRecord struct {
	ID       string
	Provider string
	Region   string
	Status   ProvisioningStatus
}

type PublicIP struct {
	ID      string
	Address netip.Addr
}

// ProviderOperations defines future infrastructure lifecycle seams. The pilot
// uses an existing node and must not call these mutation methods.
type ProviderOperations interface {
	CreateNode(context.Context, CreateNodeInput) (NodeRecord, error)
	DeleteNode(context.Context, string) error
	GetNode(context.Context, string) (NodeRecord, error)
	AttachPublicIP(context.Context, string) (PublicIP, error)
	DetachPublicIP(context.Context, string, string) error
}

func ValidateCreateNodeInput(input CreateNodeInput) error {
	if !regionPattern.MatchString(input.Region) {
		return fmt.Errorf("vpnnode: invalid region %q", input.Region)
	}
	if input.SSHPublicKeyReference == "" || len(input.SSHPublicKeyReference) > 256 {
		return errors.New("vpnnode: SSH public key reference must contain between 1 and 256 bytes")
	}
	if len(input.Labels) > 32 {
		return errors.New("vpnnode: too many labels")
	}
	for key, value := range input.Labels {
		if !identifierPattern.MatchString(key) || value == "" || len(value) > 128 {
			return errors.New("vpnnode: invalid provisioning label")
		}
	}
	return nil
}

func ValidateNodeRecord(record NodeRecord) error {
	if err := ValidateID(record.ID); err != nil {
		return err
	}
	if record.Provider == "" || len(record.Provider) > 64 || !regionPattern.MatchString(record.Region) {
		return errors.New("vpnnode: node provider and region are invalid")
	}
	switch record.Status {
	case ProvisioningPending, ProvisioningReady, ProvisioningFailed:
		return nil
	default:
		return fmt.Errorf("vpnnode: invalid provisioning status %q", record.Status)
	}
}

func ValidatePublicIP(value PublicIP) error {
	if value.ID == "" || len(value.ID) > 128 || !value.Address.IsValid() || value.Address.IsUnspecified() {
		return errors.New("vpnnode: public IP is invalid")
	}
	return nil
}
