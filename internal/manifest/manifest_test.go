package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestIssueAndVerifyRoundTrip(t *testing.T) {
	publicKey, privateKey := testKey(t)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	envelope, err := Issue(testCatalog(), now, 15*time.Minute, privateKey)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	document, err := Verify(envelope, publicKey, now.Add(time.Minute), 1)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if document.Version != 7 {
		t.Fatalf("Version = %d, want 7", document.Version)
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
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	publicKey, privateKey := testKey(t)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	envelope, err := Issue(testCatalog(), now, 15*time.Minute, privateKey)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[len(payload)/2] ^= 1
	envelope.Payload = base64.RawURLEncoding.EncodeToString(payload)
	if _, err := Verify(envelope, publicKey, now, 1); err == nil {
		t.Fatal("Verify() accepted a tampered payload")
	}
}

func TestVerifyRejectsExpiredAndRolledBackManifest(t *testing.T) {
	publicKey, privateKey := testKey(t)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	envelope, err := Issue(testCatalog(), now, 5*time.Minute, privateKey)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if _, err := Verify(envelope, publicKey, now.Add(5*time.Minute), 1); err == nil {
		t.Fatal("Verify() accepted an expired manifest")
	}
	if _, err := Verify(envelope, publicKey, now.Add(time.Minute), 8); err == nil {
		t.Fatal("Verify() accepted a manifest below the minimum version")
	}
}

func TestIssueRejectsInvalidEndpoint(t *testing.T) {
	_, privateKey := testKey(t)
	catalog := testCatalog()
	catalog.Nodes[0].Endpoints[0].Address = "missing-port"
	if _, err := Issue(catalog, time.Now(), 15*time.Minute, privateKey); err == nil {
		t.Fatal("Issue() accepted an endpoint without a port")
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

func testCatalog() Catalog {
	return Catalog{
		Version: 7,
		Nodes: []Node{
			{
				ID:          "node-b",
				Region:      "eu-west",
				CountryCode: "DE",
				Endpoints: []Endpoint{
					{ID: "node-b-reality", Transport: TransportReality, Address: "vpn-b.example:443", ServerName: "cover.example", CredentialRef: "reality-main", Priority: 20},
					{ID: "node-b-awg", Transport: TransportAmneziaWG, Address: "vpn-b.example:51820", CredentialRef: "awg-main", Priority: 10},
				},
			},
			{
				ID:          "node-a",
				Region:      "eu-north",
				CountryCode: "FI",
				Endpoints: []Endpoint{
					{ID: "node-a-awg", Transport: TransportAmneziaWG, Address: "vpn-a.example:51820", CredentialRef: "awg-main", Priority: 10},
				},
			},
		},
	}
}
