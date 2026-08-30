package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
)

func TestFetchUsesSequentialPriorityFallbackAndVerifies(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	catalog := discoveryCatalog()
	rootPublicKey, rootPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := manifest.NewKeyGrant(publicKey, 1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	keyPolicy, err := manifest.SignKeyPolicy(rootPrivateKey, 1, []manifest.KeyGrant{grant})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := manifest.Issue(catalog, 9, keyPolicy, rootPublicKey, now, 15*time.Minute, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	var failedCalls atomic.Int64
	var successfulCalls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/unavailable":
			failedCalls.Add(1)
			http.Error(writer, "unavailable", http.StatusServiceUnavailable)
		case "/manifest":
			successfulCalls.Add(1)
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(envelope)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	sources := []manifest.DiscoveryEndpoint{
		{ID: "primary", URL: server.URL + "/unavailable", Priority: 10},
		{ID: "secondary", URL: server.URL + "/unavailable", Priority: 20},
		{ID: "tertiary", URL: server.URL + "/unavailable", Priority: 30},
		{ID: "backup", URL: server.URL + "/manifest", Priority: 40},
	}
	client := Client{
		HTTP:    server.Client(),
		RootKey: rootPublicKey,
		Now:     func() time.Time { return now.Add(time.Minute) },
	}
	result, err := client.Fetch(context.Background(), sources, manifest.TrustedState{})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if result.SourceID != "backup" || result.Document.Version != 9 || result.Trusted.Version != 9 {
		t.Fatalf("Fetch() result = %+v", result)
	}
	if failedCalls.Load() != 3 || successfulCalls.Load() != 1 {
		t.Fatalf("calls = failed %d successful %d, want 3 and 1", failedCalls.Load(), successfulCalls.Load())
	}
}

func TestFetchRejectsRedirectToAnotherOrigin(t *testing.T) {
	var targetCalls atomic.Int64
	redirectTarget := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		targetCalls.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{}`))
	}))
	defer redirectTarget.Close()
	redirector := httptest.NewTLSServer(http.RedirectHandler(redirectTarget.URL, http.StatusFound))
	defer redirector.Close()

	client := Client{
		HTTP:        redirector.Client(),
		RootKey:     make(ed25519.PublicKey, ed25519.PublicKeySize),
		MaxAttempts: 1,
	}
	_, err := client.Fetch(context.Background(), []manifest.DiscoveryEndpoint{{ID: "source", URL: redirector.URL, Priority: 1}}, manifest.TrustedState{})
	if err == nil {
		t.Fatal("Fetch() accepted a cross-origin redirect")
	}
	if targetCalls.Load() != 0 {
		t.Fatal("Fetch() followed a redirect before rejecting the changed origin")
	}
}

func discoveryCatalog() manifest.Catalog {
	return manifest.Catalog{
		Revision: 1,
		Discovery: []manifest.DiscoveryEndpoint{
			{ID: "control", URL: "https://control.example/v1/manifest", Priority: 10},
		},
		Nodes: []manifest.Node{
			{
				ID: "node-a", Region: "eu-west", CountryCode: "DE", Provider: "provider-a", ASN: 64501,
				Endpoints: []manifest.Endpoint{
					{ID: "node-a-awg", Transport: manifest.TransportAmneziaWG, Address: "vpn.example:51820", CredentialRef: "awg", Priority: 10},
				},
			},
		},
	}
}
