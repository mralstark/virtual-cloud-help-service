package selector

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
)

func TestRankRespectsUDPBackoffAndDiversity(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	document := selectorDocument(t, now)
	observations := map[string]Observation{
		"a-reality": {CooldownUntil: now.Add(time.Minute)},
	}
	plan, err := Rank(document, observations, now, Options{UDPAvailable: false, MaxCandidates: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) != 2 {
		t.Fatalf("candidates = %d, want 2", len(plan.Candidates))
	}
	if plan.Candidates[0].Endpoint.ID != "b-reality" || plan.Candidates[1].Endpoint.ID != "c-reality" {
		t.Fatalf("candidate order = %q, %q", plan.Candidates[0].Endpoint.ID, plan.Candidates[1].Endpoint.ID)
	}
	if !plan.RetryAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("RetryAt = %s", plan.RetryAt)
	}
	for _, candidate := range plan.Candidates {
		if candidate.Endpoint.Transport == manifest.TransportAmneziaWG {
			t.Fatal("Rank() included a UDP endpoint while UDP was unavailable")
		}
	}
}

func TestRankPrefersProviderAndASNDiversity(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	plan, err := Rank(selectorDocument(t, now), nil, now, Options{UDPAvailable: true, MaxCandidates: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Candidates) != 3 {
		t.Fatalf("candidates = %d, want 3", len(plan.Candidates))
	}
	if plan.Candidates[0].NodeID != "node-a" || plan.Candidates[1].NodeID != "node-b" || plan.Candidates[2].NodeID != "node-c" {
		t.Fatalf("node order = %q, %q, %q", plan.Candidates[0].NodeID, plan.Candidates[1].NodeID, plan.Candidates[2].NodeID)
	}
}

func TestRankDoesNotTradeHealthForDiversity(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	observations := map[string]Observation{
		"b-reality": {ConsecutiveFailures: 1},
		"c-reality": {ConsecutiveFailures: 1},
	}
	plan, err := Rank(selectorDocument(t, now), observations, now, Options{UDPAvailable: true, MaxCandidates: 2})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Candidates[0].NodeID != "node-a" || plan.Candidates[1].NodeID != "node-a" {
		t.Fatalf("Rank() preferred a failed diverse path: %+v", plan.Candidates)
	}
}

func TestCooldownIsExponentialAndCapped(t *testing.T) {
	delay, err := Cooldown(FailureSuspected, 2)
	if err != nil || delay != 4*time.Minute {
		t.Fatalf("Cooldown() = %s, %v", delay, err)
	}
	delay, err = Cooldown(FailureSuspected, 100)
	if err != nil || delay != 30*time.Minute {
		t.Fatalf("capped Cooldown() = %s, %v", delay, err)
	}
	if _, err := Cooldown(FailureClass("invalid"), 1); err == nil {
		t.Fatal("Cooldown() accepted an unknown failure class")
	}
}

func selectorDocument(t *testing.T, now time.Time) manifest.Document {
	t.Helper()
	signingPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, rootPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := manifest.NewKeyGrant(signingPublicKey, 1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	keyPolicy, err := manifest.SignKeyPolicy(rootPrivateKey, 1, []manifest.KeyGrant{grant})
	if err != nil {
		t.Fatal(err)
	}
	return manifest.Document{
		SchemaVersion: manifest.SchemaVersion, Version: 1, CatalogRevision: 1,
		IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute), KeyPolicy: keyPolicy,
		Discovery: []manifest.DiscoveryEndpoint{{ID: "control", URL: "https://control.example/v1/manifest", Priority: 10}},
		Nodes: []manifest.Node{
			{
				ID: "node-a", Region: "eu-west", CountryCode: "DE", Provider: "provider-a", ASN: 64501,
				Endpoints: []manifest.Endpoint{
					{ID: "a-awg", Transport: manifest.TransportAmneziaWG, Address: "a.example:51820", CredentialRef: "a-awg", Priority: 1},
					{ID: "a-reality", Transport: manifest.TransportReality, Address: "a.example:443", ServerName: "cover-a.example", CredentialRef: "a-reality", Priority: 2},
				},
			},
			{
				ID: "node-b", Region: "eu-north", CountryCode: "FI", Provider: "provider-b", ASN: 64502,
				Endpoints: []manifest.Endpoint{{ID: "b-reality", Transport: manifest.TransportReality, Address: "b.example:443", ServerName: "cover-b.example", CredentialRef: "b-reality", Priority: 3}},
			},
			{
				ID: "node-c", Region: "eu-central", CountryCode: "NL", Provider: "provider-c", ASN: 64503,
				Endpoints: []manifest.Endpoint{{ID: "c-reality", Transport: manifest.TransportReality, Address: "c.example:443", ServerName: "cover-c.example", CredentialRef: "c-reality", Priority: 4}},
			},
		},
	}
}
