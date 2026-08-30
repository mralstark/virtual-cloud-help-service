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
	rootKey, keyPolicy := singleKeyPolicy(t, privateKey)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "issuer-state.json")
	var loads atomic.Int64
	issuer, err := NewIssuer(IssuerOptions{
		CatalogPath: "ignored",
		StatePath:   statePath,
		TTL:         5 * time.Minute,
		CacheFor:    30 * time.Second,
		PrivateKey:  privateKey,
		RootKey:     rootKey,
		KeyPolicy:   keyPolicy,
		acquireLock: acquireTestLock,
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
	issuedAt := now
	now = issuedAt.Add(-time.Second)
	if _, err := issuer.Issue(); err == nil {
		t.Fatal("Issue() returned a cached envelope after the wall clock moved backwards")
	}
	now = issuedAt

	if runtime.GOOS != "windows" {
		now = issuedAt.Add(31 * time.Second)
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
	rootKey, keyPolicy := singleKeyPolicy(t, privateKey)
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "issuer-state.json")
	original, err := NewIssuer(IssuerOptions{
		CatalogPath: "ignored", StatePath: statePath, TTL: 5 * time.Minute,
		CacheFor: 30 * time.Second, PrivateKey: privateKey, Now: func() time.Time { return now },
		RootKey: rootKey, KeyPolicy: keyPolicy,
		acquireLock: acquireTestLock,
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
			RootKey: rootKey, KeyPolicy: keyPolicy,
			acquireLock: acquireTestLock,
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

func TestIssuerRotatesSigningKeyWithRootPolicyContinuity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("durable replacement and production locking are Linux-only")
	}
	rootPublicKey, rootPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldPublicKey, oldPrivateKey, _ := ed25519.GenerateKey(rand.Reader)
	newPublicKey, newPrivateKey, _ := ed25519.GenerateKey(rand.Reader)
	oldOpenGrant, _ := manifest.NewKeyGrant(oldPublicKey, 1, 1, 0)
	initialPolicy, err := manifest.SignKeyPolicy(rootPrivateKey, 1, []manifest.KeyGrant{oldOpenGrant})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "issuer-state.json")
	oldIssuer, err := NewIssuer(IssuerOptions{
		CatalogPath: "ignored", StatePath: statePath, TTL: 5 * time.Minute, CacheFor: 30 * time.Second,
		PrivateKey: oldPrivateKey, RootKey: rootPublicKey, KeyPolicy: initialPolicy,
		Now: func() time.Time { return now }, LoadCatalog: func(string) (manifest.Catalog, error) { return serviceCatalog(1, "eu-west"), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	oldEnvelope, err := oldIssuer.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if err := oldIssuer.Close(); err != nil {
		t.Fatal(err)
	}

	oldBoundedGrant, _ := manifest.NewKeyGrant(oldPublicKey, 1, 1, 1)
	newGrant, _ := manifest.NewKeyGrant(newPublicKey, 2, 2, 0)
	rotatedPolicy, err := manifest.SignKeyPolicy(rootPrivateKey, 2, []manifest.KeyGrant{oldBoundedGrant, newGrant})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	newIssuer, err := NewIssuer(IssuerOptions{
		CatalogPath: "ignored", StatePath: statePath, TTL: 5 * time.Minute, CacheFor: 30 * time.Second,
		PrivateKey: newPrivateKey, RootKey: rootPublicKey, KeyPolicy: rotatedPolicy,
		Now: func() time.Time { return now }, LoadCatalog: func(string) (manifest.Catalog, error) { return serviceCatalog(1, "eu-west"), nil },
	})
	if err != nil {
		t.Fatalf("NewIssuer() rejected the root-authorized replacement key: %v", err)
	}
	newEnvelope, err := newIssuer.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if err := newIssuer.Close(); err != nil {
		t.Fatal(err)
	}

	_, trusted, err := manifest.Verify(oldEnvelope, rootPublicKey, now.Add(-30*time.Second), manifest.TrustedState{})
	if err != nil {
		t.Fatal(err)
	}
	_, rotated, err := manifest.Verify(newEnvelope, rootPublicKey, now.Add(time.Second), trusted)
	if err != nil {
		t.Fatalf("Verify() rejected issuer rotation continuity: %v", err)
	}
	if rotated.Version != 2 || rotated.SigningKeyEpoch != 2 || rotated.SigningKeyID != manifest.KeyID(newPublicKey) {
		t.Fatalf("rotated state = %+v", rotated)
	}

	if _, err := NewIssuer(IssuerOptions{
		CatalogPath: "ignored", StatePath: statePath, TTL: 5 * time.Minute, CacheFor: 30 * time.Second,
		PrivateKey: oldPrivateKey, RootKey: rootPublicKey, KeyPolicy: rotatedPolicy,
		Now: func() time.Time { return now.Add(time.Minute) }, LoadCatalog: func(string) (manifest.Catalog, error) { return serviceCatalog(1, "eu-west"), nil },
	}); err == nil {
		t.Fatal("NewIssuer() allowed the retired key to resume issuance")
	}
}

type testLock struct{}

func acquireTestLock(string) (processLocker, error) {
	return testLock{}, nil
}

func (testLock) Close() error { return nil }

func singleKeyPolicy(t *testing.T, signingPrivateKey ed25519.PrivateKey) (ed25519.PublicKey, manifest.KeyPolicy) {
	t.Helper()
	rootPublicKey, rootPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := manifest.NewKeyGrant(signingPrivateKey.Public().(ed25519.PublicKey), 1, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := manifest.SignKeyPolicy(rootPrivateKey, 1, []manifest.KeyGrant{grant})
	if err != nil {
		t.Fatal(err)
	}
	return rootPublicKey, policy
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
