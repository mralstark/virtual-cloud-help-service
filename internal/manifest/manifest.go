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
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"time"
)

const (
	SchemaVersion      = 2
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

// Catalog is the unsigned operator-maintained source document. Revision changes
// only when its public discovery or data-plane contents change. Signed manifest
// Version values are allocated independently by the durable issuer state.
type Catalog struct {
	Revision  uint64              `json:"revision"`
	Discovery []DiscoveryEndpoint `json:"discovery"`
	Nodes     []Node              `json:"nodes"`
}

// Document is the exact payload protected by an Ed25519 signature.
type Document struct {
	SchemaVersion   int                 `json:"schema_version"`
	Version         uint64              `json:"version"`
	CatalogRevision uint64              `json:"catalog_revision"`
	IssuedAt        time.Time           `json:"issued_at"`
	ExpiresAt       time.Time           `json:"expires_at"`
	Discovery       []DiscoveryEndpoint `json:"discovery"`
	Nodes           []Node              `json:"nodes"`
}

// DiscoveryEndpoint is a signed manifest mirror. Clients retain the last-known-good
// set and try sources sequentially with backoff instead of probing them in parallel.
type DiscoveryEndpoint struct {
	ID       string `json:"id"`
	URL      string `json:"url"`
	Priority uint16 `json:"priority"`
}

type Node struct {
	ID          string     `json:"id"`
	Region      string     `json:"region"`
	CountryCode string     `json:"country_code"`
	Provider    string     `json:"provider"`
	ASN         uint32     `json:"asn"`
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

// TrustedState is persisted by a client after accepting a manifest. The payload
// digest rejects equivocation at the same version; Version and IssuedAt reject
// rollback. It contains no user or network identifiers.
type TrustedState struct {
	Version       uint64    `json:"version"`
	IssuedAt      time.Time `json:"issued_at"`
	PayloadSHA256 string    `json:"payload_sha256"`
}

// Issue validates and canonicalizes a catalog, applies a bounded lifetime, and
// signs the exact serialized payload using an issuer-allocated monotonic version.
func Issue(catalog Catalog, version uint64, now time.Time, ttl time.Duration, privateKey ed25519.PrivateKey) (Envelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("manifest: invalid Ed25519 private key")
	}
	if version == 0 {
		return Envelope{}, errors.New("manifest: issued version must be greater than zero")
	}
	if ttl < time.Minute || ttl > maxManifestLife {
		return Envelope{}, fmt.Errorf("manifest: ttl must be between 1m and %s", maxManifestLife)
	}

	now = now.UTC().Truncate(time.Second)
	document := Document{
		SchemaVersion:   SchemaVersion,
		Version:         version,
		CatalogRevision: catalog.Revision,
		IssuedAt:        now,
		ExpiresAt:       now.Add(ttl),
		Discovery:       canonicalDiscovery(catalog.Discovery),
		Nodes:           canonicalNodes(catalog.Nodes),
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

// DecodeEnvelope bounds the complete untrusted response before JSON or Base64
// processing. Discovery clients should use it instead of decoding directly.
func DecodeEnvelope(reader io.Reader) (Envelope, error) {
	maxEnvelopeBytes := base64.RawURLEncoding.EncodedLen(maxManifestBytes) + 1024
	data, err := io.ReadAll(io.LimitReader(reader, int64(maxEnvelopeBytes+1)))
	if err != nil {
		return Envelope{}, fmt.Errorf("manifest: read envelope: %w", err)
	}
	if len(data) == 0 || len(data) > maxEnvelopeBytes {
		return Envelope{}, errors.New("manifest: envelope size is invalid")
	}
	var envelope Envelope
	if err := decodeStrict(data, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("manifest: decode envelope: %w", err)
	}
	return envelope, nil
}

// Verify authenticates an envelope, validates its lifetime, and advances a caller's
// durable anti-replay state. An exact same-version payload from another mirror is
// accepted; different bytes at that version are rejected as equivocation.
func Verify(envelope Envelope, publicKey ed25519.PublicKey, now time.Time, trusted TrustedState) (Document, TrustedState, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return Document{}, trusted, errors.New("manifest: invalid Ed25519 public key")
	}
	if envelope.Algorithm != Algorithm {
		return Document{}, trusted, fmt.Errorf("manifest: unsupported algorithm %q", envelope.Algorithm)
	}
	if envelope.KeyID != KeyID(publicKey) {
		return Document{}, trusted, errors.New("manifest: signing key ID does not match pinned key")
	}

	maxEncodedPayload := base64.RawURLEncoding.EncodedLen(maxManifestBytes)
	if len(envelope.Payload) == 0 || len(envelope.Payload) > maxEncodedPayload {
		return Document{}, trusted, errors.New("manifest: encoded payload size is invalid")
	}
	expectedEncodedSignature := base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize)
	if len(envelope.Signature) != expectedEncodedSignature {
		return Document{}, trusted, errors.New("manifest: encoded signature size is invalid")
	}

	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return Document{}, trusted, fmt.Errorf("manifest: decode payload: %w", err)
	}
	if len(payload) == 0 || len(payload) > maxManifestBytes {
		return Document{}, trusted, errors.New("manifest: payload size is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return Document{}, trusted, fmt.Errorf("manifest: decode signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, payload, signature) {
		return Document{}, trusted, errors.New("manifest: signature verification failed")
	}

	var document Document
	if err := decodeStrict(payload, &document); err != nil {
		return Document{}, trusted, fmt.Errorf("manifest: decode signed document: %w", err)
	}
	if err := Validate(document); err != nil {
		return Document{}, trusted, err
	}

	now = now.UTC()
	if now.Before(document.IssuedAt.Add(-allowedClockSkew)) {
		return Document{}, trusted, errors.New("manifest: document is not valid yet")
	}
	if !now.Before(document.ExpiresAt) {
		return Document{}, trusted, errors.New("manifest: document has expired")
	}

	payloadDigest := sha256.Sum256(payload)
	candidate := TrustedState{
		Version:       document.Version,
		IssuedAt:      document.IssuedAt,
		PayloadSHA256: base64.RawURLEncoding.EncodeToString(payloadDigest[:]),
	}
	if err := validateTransition(trusted, candidate); err != nil {
		return Document{}, trusted, err
	}
	if trusted.Version == candidate.Version {
		return document, trusted, nil
	}
	return document, candidate, nil
}

// CatalogDigest returns the digest of the validated canonical public catalog. The
// issuer persists it to reject changed content at an unchanged catalog revision.
func CatalogDigest(catalog Catalog) (string, error) {
	document := Document{
		SchemaVersion:   SchemaVersion,
		Version:         1,
		CatalogRevision: catalog.Revision,
		IssuedAt:        time.Unix(0, 0).UTC(),
		ExpiresAt:       time.Unix(0, 0).UTC().Add(time.Minute),
		Discovery:       canonicalDiscovery(catalog.Discovery),
		Nodes:           canonicalNodes(catalog.Nodes),
	}
	if err := Validate(document); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(Catalog{
		Revision:  document.CatalogRevision,
		Discovery: document.Discovery,
		Nodes:     document.Nodes,
	})
	if err != nil {
		return "", fmt.Errorf("manifest: encode canonical catalog: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func Validate(document Document) error {
	if document.SchemaVersion != SchemaVersion {
		return fmt.Errorf("manifest: unsupported schema version %d", document.SchemaVersion)
	}
	if document.Version == 0 {
		return errors.New("manifest: version must be greater than zero")
	}
	if document.CatalogRevision == 0 {
		return errors.New("manifest: catalog revision must be greater than zero")
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
	if err := validateDiscovery(document.Discovery); err != nil {
		return err
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
		if !idPattern.MatchString(node.Provider) {
			return fmt.Errorf("manifest: node %q has invalid provider", node.ID)
		}
		if node.ASN == 0 {
			return fmt.Errorf("manifest: node %q must have a positive ASN", node.ID)
		}
		if len(node.Endpoints) == 0 || len(node.Endpoints) > 16 {
			return fmt.Errorf("manifest: node %q must have between 1 and 16 endpoints", node.ID)
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

func validateDiscovery(discovery []DiscoveryEndpoint) error {
	if len(discovery) == 0 || len(discovery) > 16 {
		return errors.New("manifest: discovery must contain between 1 and 16 entries")
	}
	ids := make(map[string]struct{}, len(discovery))
	for index, source := range discovery {
		if !idPattern.MatchString(source.ID) {
			return fmt.Errorf("manifest: discovery %d has invalid id %q", index, source.ID)
		}
		if _, exists := ids[source.ID]; exists {
			return fmt.Errorf("manifest: duplicate discovery id %q", source.ID)
		}
		ids[source.ID] = struct{}{}
		if source.Priority == 0 || source.Priority > 1000 {
			return fmt.Errorf("manifest: discovery %q priority must be between 1 and 1000", source.ID)
		}
		parsed, err := url.ParseRequestURI(source.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return fmt.Errorf("manifest: discovery %q must be an HTTPS URL without credentials, query, or fragment", source.ID)
		}
		if !validHost(parsed.Hostname()) {
			return fmt.Errorf("manifest: discovery %q has invalid host", source.ID)
		}
		if portText := parsed.Port(); portText != "" {
			port, err := strconv.Atoi(portText)
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("manifest: discovery %q has invalid port", source.ID)
			}
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

func validateTransition(trusted, candidate TrustedState) error {
	if trusted.Version == 0 {
		if trusted.PayloadSHA256 != "" || !trusted.IssuedAt.IsZero() {
			return errors.New("manifest: trusted state is internally inconsistent")
		}
		return nil
	}
	if trusted.PayloadSHA256 == "" || trusted.IssuedAt.IsZero() {
		return errors.New("manifest: trusted state is incomplete")
	}
	if candidate.Version < trusted.Version {
		return fmt.Errorf("manifest: version %d is older than trusted version %d", candidate.Version, trusted.Version)
	}
	if candidate.Version == trusted.Version {
		if candidate.PayloadSHA256 != trusted.PayloadSHA256 || !candidate.IssuedAt.Equal(trusted.IssuedAt) {
			return errors.New("manifest: same-version payload equivocation detected")
		}
		return nil
	}
	if candidate.IssuedAt.Before(trusted.IssuedAt) {
		return errors.New("manifest: issuance time moved backwards")
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
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func canonicalDiscovery(discovery []DiscoveryEndpoint) []DiscoveryEndpoint {
	result := append([]DiscoveryEndpoint(nil), discovery...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].Priority == result[j].Priority {
			return result[i].ID < result[j].ID
		}
		return result[i].Priority < result[j].Priority
	})
	return result
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
