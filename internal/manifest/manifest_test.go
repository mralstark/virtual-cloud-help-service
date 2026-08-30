package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestIssueAndVerifyRoundTrip(t *testing.T) {
	publicKey, privateKey := testKey(t)
	rootPublicKey, keyPolicy := testKeyPolicy(t, publicKey)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	envelope, err := Issue(testCatalog(), 42, keyPolicy, rootPublicKey, now, 15*time.Minute, privateKey)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	document, state, err := Verify(envelope, rootPublicKey, now.Add(time.Minute), TrustedState{})
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if document.Version != 42 || state.Version != 42 {
		t.Fatalf("versions = document %d state %d, want 42", document.Version, state.Version)
	}
	if state.PolicyVersion != 1 || state.SigningKeyID != KeyID(publicKey) || state.SigningKeyEpoch != 1 {
		t.Fatalf("trusted signing state = %+v", state)
	}
	if document.CatalogRevision != 7 {
		t.Fatalf("CatalogRevision = %d, want 7", document.CatalogRevision)
	}
	if got := document.Discovery[0].ID; got != "control-primary" {
		t.Fatalf("canonical first discovery = %q, want control-primary", got)
	}
	if got := document.Nodes[0].ID; got != "node-a" {
		t.Fatalf("canonical first node = %q, want node-a", got)
	}
	if got := document.Nodes[1].Endpoints[0].ID; got != "node-b-awg" {
		t.Fatalf("canonical first endpoint = %q, want node-b-awg", got)
	}
	if envelope.KeyID != KeyID(publicKey) {
		t.Fatalf("KeyID = %q, want %q", envelope.KeyID, KeyID(publicKey))
	}

	_, sameState, err := Verify(envelope, rootPublicKey, now.Add(2*time.Minute), state)
	if err != nil {
		t.Fatalf("Verify() exact mirrored payload error = %v", err)
	}
	if sameState != state {
		t.Fatal("exact mirrored payload unexpectedly changed trusted state")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	publicKey, privateKey := testKey(t)
	rootPublicKey, keyPolicy := testKeyPolicy(t, publicKey)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	envelope, err := Issue(testCatalog(), 1, keyPolicy, rootPublicKey, now, 15*time.Minute, privateKey)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)/2] ^= 1
	envelope.Payload = base64.RawURLEncoding.EncodeToString(payload)
	if _, _, err := Verify(envelope, rootPublicKey, now, TrustedState{}); err == nil {
		t.Fatal("Verify() accepted a tampered payload")
	}
}

func TestVerifyRejectsExpiredRollbackAndEquivocation(t *testing.T) {
	publicKey, privateKey := testKey(t)
	rootPublicKey, keyPolicy := testKeyPolicy(t, publicKey)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	current, err := Issue(testCatalog(), 7, keyPolicy, rootPublicKey, now, 5*time.Minute, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	_, trusted, err := Verify(current, rootPublicKey, now.Add(time.Minute), TrustedState{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(current, rootPublicKey, now.Add(5*time.Minute), TrustedState{}); err == nil {
		t.Fatal("Verify() accepted an expired manifest")
	}

	older, err := Issue(testCatalog(), 6, keyPolicy, rootPublicKey, now.Add(time.Minute), 5*time.Minute, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(older, rootPublicKey, now.Add(2*time.Minute), trusted); err == nil {
		t.Fatal("Verify() accepted a version rollback")
	}

	equivocation, err := Issue(testCatalog(), 7, keyPolicy, rootPublicKey, now.Add(time.Minute), 5*time.Minute, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(equivocation, rootPublicKey, now.Add(2*time.Minute), trusted); err == nil {
		t.Fatal("Verify() accepted different payload bytes at the same version")
	}
}

func TestVerifyBoundsEncodedFieldsBeforeDecode(t *testing.T) {
	publicKey, _ := testKey(t)
	envelope := Envelope{
		Algorithm: Algorithm,
		KeyID:     KeyID(publicKey),
		Payload:   strings.Repeat("A", base64.RawURLEncoding.EncodedLen(maxManifestBytes)+1),
		Signature: strings.Repeat("A", base64.RawURLEncoding.EncodedLen(ed25519.SignatureSize)),
	}
	if _, _, err := Verify(envelope, publicKey, time.Now(), TrustedState{}); err == nil {
		t.Fatal("Verify() accepted an oversized encoded payload")
	}
}

func TestDecodeEnvelopeBoundsOuterResponse(t *testing.T) {
	oversized := strings.Repeat("x", base64.RawURLEncoding.EncodedLen(maxManifestBytes)+1025)
	if _, err := DecodeEnvelope(strings.NewReader(oversized)); err == nil {
		t.Fatal("DecodeEnvelope() accepted an oversized response")
	}
	if _, err := DecodeEnvelope(strings.NewReader(`{"algorithm":"Ed25519","key_id":"k","payload":"p","signature":"s","unknown":true}`)); err == nil {
		t.Fatal("DecodeEnvelope() accepted an unknown field")
	}
}

func TestCatalogDigestIsCanonicalAndDetectsChange(t *testing.T) {
	catalog := testCatalog()
	first, err := CatalogDigest(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalog.Nodes[0], catalog.Nodes[1] = catalog.Nodes[1], catalog.Nodes[0]
	catalog.Discovery[0], catalog.Discovery[1] = catalog.Discovery[1], catalog.Discovery[0]
	second, err := CatalogDigest(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("canonical digest changed only because input order changed")
	}
	catalog.Nodes[0].Region = "eu-change"
	changed, err := CatalogDigest(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if first == changed {
		t.Fatal("catalog digest did not change with catalog contents")
	}
}

func TestIssueRejectsInvalidEndpoint(t *testing.T) {
	_, privateKey := testKey(t)
	rootPublicKey, keyPolicy := testKeyPolicy(t, privateKey.Public().(ed25519.PublicKey))
	catalog := testCatalog()
	catalog.Nodes[0].Endpoints[0].Address = "missing-port"
	if _, err := Issue(catalog, 1, keyPolicy, rootPublicKey, time.Now(), 15*time.Minute, privateKey); err == nil {
		t.Fatal("Issue() accepted an endpoint without a port")
	}
}

func TestIssueRejectsInconsistentPrivateKey(t *testing.T) {
	publicKey, privateKey := testKey(t)
	rootPublicKey, keyPolicy := testKeyPolicy(t, publicKey)
	corrupted := append(ed25519.PrivateKey(nil), privateKey...)
	corrupted[len(corrupted)-1] ^= 1
	if _, err := Issue(testCatalog(), 1, keyPolicy, rootPublicKey, time.Now(), 15*time.Minute, corrupted); err == nil {
		t.Fatal("Issue() accepted a private key whose public half did not match its seed")
	}
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func testKeyPolicy(t *testing.T, signingPublicKey ed25519.PublicKey) (ed25519.PublicKey, KeyPolicy) {
	t.Helper()
	rootPublicKey, rootPrivateKey := testKey(t)
	grant, err := NewKeyGrant(signingPublicKey, 1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := SignKeyPolicy(rootPrivateKey, 1, []KeyGrant{grant})
	if err != nil {
		t.Fatal(err)
	}
	return rootPublicKey, policy
}

func testCatalog() Catalog {
	return Catalog{
		Revision: 7,
		Discovery: []DiscoveryEndpoint{
			{ID: "control-backup", URL: "https://203.0.113.10/v1/manifest", Priority: 20},
			{ID: "control-primary", URL: "https://control.example/v1/manifest", Priority: 10},
		},
		Nodes: []Node{
			{
				ID:          "node-b",
				Region:      "eu-west",
				CountryCode: "DE",
				Provider:    "provider-b",
				ASN:         64502,
				Endpoints: []Endpoint{
					{ID: "node-b-reality", Transport: TransportReality, Address: "vpn-b.example:443", ServerName: "cover.example", CredentialRef: "reality-main", Priority: 20},
					{ID: "node-b-awg", Transport: TransportAmneziaWG, Address: "vpn-b.example:51820", CredentialRef: "awg-main", Priority: 10},
				},
			},
			{
				ID:          "node-a",
				Region:      "eu-north",
				CountryCode: "FI",
				Provider:    "provider-a",
				ASN:         64501,
				Endpoints: []Endpoint{
					{ID: "node-a-awg", Transport: TransportAmneziaWG, Address: "vpn-a.example:51820", CredentialRef: "awg-main", Priority: 10},
				},
			},
		},
	}
}
