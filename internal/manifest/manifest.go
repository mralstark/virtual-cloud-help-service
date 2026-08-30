package manifest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"sort"
	"strconv"
	"time"
)

const (
	SchemaVersion      = 1
	Algorithm          = "Ed25519"
	maxManifestBytes   = 1 << 20
	maxManifestLife    = time.Hour
	allowedClockSkew   = 2 * time.Minute
	TransportAmneziaWG = "amneziawg"
	TransportReality   = "vless-reality"
)

var (
	idPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	regionPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	countryPattern    = regexp.MustCompile(`^[A-Z]{2}$`)
	hostnamePattern   = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?)$`)
	credentialPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
)

// Catalog is the unsigned operator-maintained source document.
type Catalog struct {
	Version uint64 `json:"version"`
	Nodes   []Node `json:"nodes"`
}

// Document is the exact payload protected by an Ed25519 signature.
type Document struct {
	SchemaVersion int       `json:"schema_version"`
	Version       uint64    `json:"version"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Nodes         []Node    `json:"nodes"`
}

type Node struct {
	ID          string     `json:"id"`
	Region      string     `json:"region"`
	CountryCode string     `json:"country_code"`
	Endpoints   []Endpoint `json:"endpoints"`
}

// Endpoint contains public routing metadata only. CredentialRef points to
// device-specific credentials already stored on the client.
type Endpoint struct {
	ID            string `json:"id"`
	Transport     string `json:"transport"`
	Address       string `json:"address"`
	ServerName    string `json:"server_name,omitempty"`
	CredentialRef string `json:"credential_ref"`
	Priority      uint16 `json:"priority"`
}

// Envelope keeps the signed bytes opaque so intermediaries cannot alter JSON and
// accidentally invalidate the signature.
type Envelope struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Issue validates and canonicalizes a catalog, applies a bounded lifetime, and
// signs the exact serialized payload.
func Issue(catalog Catalog, now time.Time, ttl time.Duration, privateKey ed25519.PrivateKey) (Envelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("manifest: invalid Ed25519 private key")
	}
	if ttl < time.Minute || ttl > maxManifestLife {
		return Envelope{}, fmt.Errorf("manifest: ttl must be between 1m and %s", maxManifestLife)
	}

	now = now.UTC().Truncate(time.Second)
	document := Document{
		SchemaVersion: SchemaVersion,
		Version:       catalog.Version,
		IssuedAt:      now,
		ExpiresAt:     now.Add(ttl),
		Nodes:         canonicalNodes(catalog.Nodes),
	}
	if err := Validate(document); err != nil {
		return Envelope{}, err
	}

	payload, err := json.Marshal(document)
	if err != nil {
		return Envelope{}, fmt.Errorf("manifest: encode payload: %w", err)
	}
	if len(payload) > maxManifestBytes {
		return Envelope{}, errors.New("manifest: encoded payload exceeds 1 MiB")
	}

	publicKey := privateKey.Public().(ed25519.PublicKey)
	signature := ed25519.Sign(privateKey, payload)
	return Envelope{
		Algorithm: Algorithm,
		KeyID:     KeyID(publicKey),
		Payload:   base64.RawURLEncoding.EncodeToString(payload),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

// Verify authenticates an envelope, validates its lifetime, and enforces a caller-
// supplied minimum version to prevent rollback to an older catalog.
func Verify(envelope Envelope, publicKey ed25519.PublicKey, now time.Time, minimumVersion uint64) (Document, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return Document{}, errors.New("manifest: invalid Ed25519 public key")
	}
	if envelope.Algorithm != Algorithm {
		return Document{}, fmt.Errorf("manifest: unsupported algorithm %q", envelope.Algorithm)
	}
	if envelope.KeyID != KeyID(publicKey) {
		return Document{}, errors.New("manifest: signing key ID does not match pinned key")
	}

	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return Document{}, fmt.Errorf("manifest: decode payload: %w", err)
	}
	if len(payload) == 0 || len(payload) > maxManifestBytes {
		return Document{}, errors.New("manifest: payload size is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return Document{}, fmt.Errorf("manifest: decode signature: %w", err)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return Document{}, errors.New("manifest: signature verification failed")
	}

	var document Document
	if err := decodeStrict(payload, &document); err != nil {
		return Document{}, fmt.Errorf("manifest: decode signed document: %w", err)
	}
	if err := Validate(document); err != nil {
		return Document{}, err
	}
	if document.Version < minimumVersion {
		return Document{}, fmt.Errorf("manifest: version %d is older than minimum %d", document.Version, minimumVersion)
	}

	now = now.UTC()
	if now.Before(document.IssuedAt.Add(-allowedClockSkew)) {
		return Document{}, errors.New("manifest: document is not valid yet")
	}
	if !now.Before(document.ExpiresAt) {
		return Document{}, errors.New("manifest: document has expired")
	}
	return document, nil
}

func Validate(document Document) error {
	if document.SchemaVersion != SchemaVersion {
		return fmt.Errorf("manifest: unsupported schema version %d", document.SchemaVersion)
	}
	if document.Version == 0 {
		return errors.New("manifest: version must be greater than zero")
	}
	if document.IssuedAt.IsZero() || document.ExpiresAt.IsZero() {
		return errors.New("manifest: issuance and expiry times are required")
	}
	if !document.ExpiresAt.After(document.IssuedAt) {
		return errors.New("manifest: expiry must be after issuance")
	}
	if document.ExpiresAt.Sub(document.IssuedAt) > maxManifestLife {
		return fmt.Errorf("manifest: lifetime exceeds %s", maxManifestLife)
	}
	if len(document.Nodes) == 0 || len(document.Nodes) > 1000 {
		return errors.New("manifest: nodes must contain between 1 and 1000 entries")
	}

	nodeIDs := make(map[string]struct{}, len(document.Nodes))
	endpointIDs := make(map[string]struct{})
	for nodeIndex, node := range document.Nodes {
		if !idPattern.MatchString(node.ID) {
			return fmt.Errorf("manifest: node %d has invalid id %q", nodeIndex, node.ID)
		}
		if _, exists := nodeIDs[node.ID]; exists {
			return fmt.Errorf("manifest: duplicate node id %q", node.ID)
		}
		nodeIDs[node.ID] = struct{}{}
		if !regionPattern.MatchString(node.Region) {
			return fmt.Errorf("manifest: node %q has invalid region", node.ID)
		}
		if !countryPattern.MatchString(node.CountryCode) {
			return fmt.Errorf("manifest: node %q has invalid country code", node.ID)
		}
		if len(node.Endpoints) == 0 || len(node.Endpoints) > 8 {
			return fmt.Errorf("manifest: node %q must have between 1 and 8 endpoints", node.ID)
		}

		for endpointIndex, endpoint := range node.Endpoints {
			if err := validateEndpoint(endpoint); err != nil {
				return fmt.Errorf("manifest: node %q endpoint %d: %w", node.ID, endpointIndex, err)
			}
			if _, exists := endpointIDs[endpoint.ID]; exists {
				return fmt.Errorf("manifest: duplicate endpoint id %q", endpoint.ID)
			}
			endpointIDs[endpoint.ID] = struct{}{}
		}
	}
	return nil
}

func validateEndpoint(endpoint Endpoint) error {
	if !idPattern.MatchString(endpoint.ID) {
		return fmt.Errorf("invalid id %q", endpoint.ID)
	}
	host, portText, err := net.SplitHostPort(endpoint.Address)
	if err != nil || !validHost(host) {
		return fmt.Errorf("address %q must be host:port", endpoint.Address)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("address %q has invalid port", endpoint.Address)
	}
	if !credentialPattern.MatchString(endpoint.CredentialRef) {
		return errors.New("credential_ref is invalid")
	}
	if endpoint.Priority == 0 || endpoint.Priority > 1000 {
		return errors.New("priority must be between 1 and 1000")
	}
	switch endpoint.Transport {
	case TransportAmneziaWG:
		if endpoint.ServerName != "" {
			return errors.New("server_name is not valid for amneziawg")
		}
	case TransportReality:
		if len(endpoint.ServerName) > 253 || net.ParseIP(endpoint.ServerName) != nil || !hostnamePattern.MatchString(endpoint.ServerName) {
			return errors.New("server_name is required for vless-reality")
		}
	default:
		return fmt.Errorf("unsupported transport %q", endpoint.Transport)
	}
	return nil
}

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	return len(host) <= 253 && hostnamePattern.MatchString(host)
}

func KeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return base64.RawURLEncoding.EncodeToString(digest[:12])
}

func canonicalNodes(nodes []Node) []Node {
	result := make([]Node, len(nodes))
	for index, node := range nodes {
		result[index] = node
		result[index].Endpoints = append([]Endpoint(nil), node.Endpoints...)
		sort.Slice(result[index].Endpoints, func(i, j int) bool {
			left, right := result[index].Endpoints[i], result[index].Endpoints[j]
			if left.Priority == right.Priority {
				return left.ID < right.ID
			}
			return left.Priority < right.Priority
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("decode trailing JSON data: %w", err)
	}
	return errors.New("unexpected trailing JSON value")
}
