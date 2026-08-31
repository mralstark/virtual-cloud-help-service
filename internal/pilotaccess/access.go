package pilotaccess

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

const maximumPilotAccessLifetime = 90 * 24 * time.Hour

var (
	uuidPattern              = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	externalReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/+\-=]{0,255}$`)

	ErrInvalid  = errors.New("pilot access: invalid input")
	ErrNotFound = errors.New("pilot access: not found")
	ErrConflict = errors.New("pilot access: conflict")
)

type Status string

const (
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
)

type Access struct {
	ID                string
	DeviceID          string
	NodeID            string
	Transport         vpnnode.Transport
	ExternalReference string
	CreatedAt         time.Time
	ExpiresAt         *time.Time
	RevokedAt         *time.Time
	Status            Status
}

type RegisterInput struct {
	DeviceID          string
	NodeID            string
	Transport         vpnnode.Transport
	ExternalReference string
	ExpiresAt         *time.Time
}

type Store interface {
	Create(context.Context, Access) (Access, error)
	Revoke(context.Context, string, time.Time) (Access, error)
}

type Service struct {
	store Store
	now   func() time.Time
	newID func() (string, error)
}

func NewService(store Store, now func() time.Time, newID func() (string, error)) (*Service, error) {
	if store == nil {
		return nil, errors.New("pilot access: store is required")
	}
	if now == nil {
		now = time.Now
	}
	if newID == nil {
		newID = newUUID
	}
	return &Service{store: store, now: now, newID: newID}, nil
}

func (service *Service) Register(ctx context.Context, input RegisterInput) (Access, error) {
	now := service.now().UTC().Truncate(time.Second)
	identifier, err := service.newID()
	if err != nil {
		return Access{}, fmt.Errorf("pilot access: generate ID: %w", err)
	}
	access := Access{
		ID:                identifier,
		DeviceID:          input.DeviceID,
		NodeID:            input.NodeID,
		Transport:         input.Transport,
		ExternalReference: input.ExternalReference,
		CreatedAt:         now,
		ExpiresAt:         cloneTime(input.ExpiresAt),
		Status:            StatusActive,
	}
	if err := Validate(access); err != nil {
		return Access{}, err
	}
	result, err := service.store.Create(ctx, access)
	if err != nil {
		return Access{}, err
	}
	if err := Validate(result); err != nil {
		return Access{}, fmt.Errorf("pilot access: store returned invalid access: %w", err)
	}
	return result, nil
}

func (service *Service) Revoke(ctx context.Context, id string) (Access, error) {
	if !uuidPattern.MatchString(id) {
		return Access{}, fmt.Errorf("%w: access ID is invalid", ErrInvalid)
	}
	result, err := service.store.Revoke(ctx, id, service.now().UTC().Truncate(time.Second))
	if err != nil {
		return Access{}, err
	}
	if err := Validate(result); err != nil {
		return Access{}, fmt.Errorf("pilot access: store returned invalid access: %w", err)
	}
	return result, nil
}

func Validate(access Access) error {
	if !uuidPattern.MatchString(access.ID) || !uuidPattern.MatchString(access.DeviceID) {
		return fmt.Errorf("%w: access and device IDs must be canonical UUIDs", ErrInvalid)
	}
	if err := vpnnode.ValidateID(access.NodeID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := vpnnode.ValidateTransport(access.Transport); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if !externalReferencePattern.MatchString(access.ExternalReference) {
		return fmt.Errorf("%w: external reference is invalid", ErrInvalid)
	}
	if resemblesSecret(access.ExternalReference) {
		return fmt.Errorf("%w: external reference resembles key material", ErrInvalid)
	}
	if access.CreatedAt.IsZero() {
		return fmt.Errorf("%w: creation time is required", ErrInvalid)
	}
	if access.ExpiresAt == nil || !access.ExpiresAt.After(access.CreatedAt) ||
		access.ExpiresAt.After(access.CreatedAt.Add(maximumPilotAccessLifetime)) {
		return fmt.Errorf("%w: expiry must be after creation and within 90 days", ErrInvalid)
	}
	switch access.Status {
	case StatusActive:
		if access.RevokedAt != nil {
			return fmt.Errorf("%w: active access cannot have a revocation time", ErrInvalid)
		}
	case StatusRevoked:
		if access.RevokedAt == nil || access.RevokedAt.Before(access.CreatedAt) {
			return fmt.Errorf("%w: revoked access requires a valid revocation time", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported status %q", ErrInvalid, access.Status)
	}
	return nil
}

func resemblesSecret(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "private") || strings.HasPrefix(lower, "vpn://") ||
		strings.HasPrefix(value, "-----BEGIN") {
		return true
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		raw, err := encoding.DecodeString(value)
		if err == nil && len(raw) >= 32 {
			return true
		}
	}
	return false
}

func newUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := value.UTC().Truncate(time.Second)
	return &result
}
