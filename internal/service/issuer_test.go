package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/issuance"
	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
)

func TestIssuerCachesConcurrentRequestsAndPersistsVersion(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "issuer-state.json")
	var loads atomic.Int64
	issuer, err := NewIssuer(IssuerOptions{
		CatalogPath: "ignored",
		StatePath:   statePath,
		TTL:         5 * time.Minute,
		CacheFor:    30 * time.Second,
		PrivateKey:  privateKey,
		Now:         func() time.Time { return now },
		LoadCatalog: func(string) (manifest.Catalog, error) {
			loads.Add(1)
			return serviceCatalog(1, "eu-west"), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = issuer.Close() })

	const callers = 32
	envelopes := make(chan manifest.Envelope, callers)
	errorsChannel := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			envelope, err := issuer.Issue()
			envelopes <- envelope
			errorsChannel <- err
		}()
	}
	wait.Wait()
	close(envelopes)
	close(errorsChannel)
	if loads.Load() != 1 {
		t.Fatalf("catalog loads = %d, want 1", loads.Load())
	}
	var first manifest.Envelope
	for envelope := range envelopes {
		if first.Payload == "" {
			first = envelope
		} else if envelope != first {
			t.Fatal("concurrent cached callers received different envelopes")
		}
	}
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("Issue() error = %v", err)
		}
	}
	state, exists, err := (issuance.FileStore{Path: statePath}).Load()
	if err != nil || !exists || state.LastVersion != 1 {
		t.Fatalf("durable state = %+v, %v, %v", state, exists, err)
	}

	if runtime.GOOS != "windows" {
		now = now.Add(31 * time.Second)
		if _, err := issuer.Issue(); err != nil {
			t.Fatalf("Issue() refresh error = %v", err)
		}
		state, _, err = (issuance.FileStore{Path: statePath}).Load()
		if err != nil || state.LastVersion != 2 {
			t.Fatalf("refreshed durable version = %d, %v, want 2", state.LastVersion, err)
		}
	}
}

func TestIssuerRejectsCatalogRollbackAndSameRevisionChange(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "issuer-state.json")
	original, err := NewIssuer(IssuerOptions{
		CatalogPath: "ignored", StatePath: statePath, TTL: 5 * time.Minute,
		CacheFor: 30 * time.Second, PrivateKey: privateKey, Now: func() time.Time { return now },
		LoadCatalog: func(string) (manifest.Catalog, error) { return serviceCatalog(2, "eu-west"), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := original.Issue(); err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}

	tests := []manifest.Catalog{
		serviceCatalog(1, "eu-west"),
		serviceCatalog(2, "eu-changed"),
	}
	for _, candidate := range tests {
		candidate := candidate
		issuer, err := NewIssuer(IssuerOptions{
			CatalogPath: "ignored", StatePath: statePath, TTL: 5 * time.Minute,
			CacheFor: 30 * time.Second, PrivateKey: privateKey, Now: func() time.Time { return now.Add(time.Minute) },
			LoadCatalog: func(string) (manifest.Catalog, error) { return candidate, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := issuer.Issue(); err == nil {
			t.Fatalf("Issue() accepted catalog revision %d region %q", candidate.Revision, candidate.Nodes[0].Region)
		}
		if err := issuer.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func serviceCatalog(revision uint64, region string) manifest.Catalog {
	return manifest.Catalog{
		Revision: revision,
		Discovery: []manifest.DiscoveryEndpoint{
			{ID: "control-primary", URL: "https://control.example/v1/manifest", Priority: 10},
		},
		Nodes: []manifest.Node{
			{
				ID: "node-a", Region: region, CountryCode: "DE", Provider: "provider-a", ASN: 64501,
				Endpoints: []manifest.Endpoint{
					{ID: "node-a-awg", Transport: manifest.TransportAmneziaWG, Address: "vpn.example:51820", CredentialRef: "awg-main", Priority: 10},
				},
			},
		},
	}
}
