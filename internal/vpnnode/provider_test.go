package vpnnode

import (
	"net/netip"
	"testing"
)

func TestValidateProviderTypes(t *testing.T) {
	input := CreateNodeInput{
		Region: "de-fra-1", SSHPublicKeyReference: "ssh-key/pilot-admin",
		Labels: map[string]string{"environment": "pilot"},
	}
	if err := ValidateCreateNodeInput(input); err != nil {
		t.Fatal(err)
	}
	if err := ValidateNodeRecord(NodeRecord{ID: "pilot-1", Provider: "timeweb-cloud", Region: "de-fra-1", Status: ProvisioningReady}); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicIP(PublicIP{ID: "ip-1", Address: netip.MustParseAddr("203.0.113.10")}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProviderTypesRejectUnsafeBounds(t *testing.T) {
	if err := ValidateCreateNodeInput(CreateNodeInput{Region: "Frankfurt", SSHPublicKeyReference: "key"}); err == nil {
		t.Fatal("accepted a non-canonical region")
	}
	if err := ValidatePublicIP(PublicIP{ID: "ip-1", Address: netip.IPv4Unspecified()}); err == nil {
		t.Fatal("accepted an unspecified address")
	}
	if err := ValidatePublicIP(PublicIP{ID: "ip-1", Address: netip.MustParseAddr("10.0.0.1")}); err == nil {
		t.Fatal("accepted a private address as public")
	}
}
