package pilotaccess

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

const (
	testAccessID = "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff11"
	testDeviceID = "018f5962-9d2a-4ea2-8f6d-9c2e8b6bff12"
)

type memoryStore struct {
	created Access
	revoked Access
	err     error
}

func (store *memoryStore) Create(_ context.Context, access Access) (Access, error) {
	store.created = access
	return access, store.err
}

func (store *memoryStore) Revoke(_ context.Context, id string, at time.Time) (Access, error) {
	if store.err != nil {
		return Access{}, store.err
	}
	revoked := store.created
	revoked.ID = id
	revoked.Status = StatusRevoked
	revoked.RevokedAt = &at
	store.revoked = revoked
	return revoked, nil
}

func TestRegisterAndRevoke(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	store := &memoryStore{}
	service, err := NewService(store, func() time.Time { return now }, func() (string, error) { return testAccessID, nil })
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(24 * time.Hour)
	created, err := service.Register(context.Background(), RegisterInput{
		DeviceID: testDeviceID, NodeID: "pilot-1", Transport: vpnnode.TransportAmneziaWG,
		ExternalReference: "guest-device-01", ExpiresAt: &expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.Status != StatusActive || created.ExpiresAt == &expires {
		t.Fatalf("unexpected created access: %+v", created)
	}
	revoked, err := service.Revoke(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != StatusRevoked || revoked.RevokedAt == nil {
		t.Fatalf("unexpected revoked access: %+v", revoked)
	}
}

func TestRegisterRejectsPrivateKeyLikeReference(t *testing.T) {
	service, err := NewService(&memoryStore{}, time.Now, func() (string, error) { return testAccessID, nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range []string{
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"___________________________________________",
	} {
		_, err = service.Register(context.Background(), RegisterInput{
			DeviceID: testDeviceID, NodeID: "pilot-1", Transport: vpnnode.TransportAmneziaWG,
			ExternalReference: reference,
		})
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected %q to be rejected, got %v", reference, err)
		}
	}
}

func TestGeneratedUUIDIsCanonical(t *testing.T) {
	identifier, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	if !uuidPattern.MatchString(identifier) {
		t.Fatalf("generated UUID is invalid: %q", identifier)
	}
}
