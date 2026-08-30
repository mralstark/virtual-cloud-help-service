package service

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/catalog"
	"github.com/mralstark/virtual-cloud-help-service/internal/issuance"
	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
)

type CatalogLoader func(path string) (manifest.Catalog, error)

type IssuerOptions struct {
	CatalogPath string
	StatePath   string
	TTL         time.Duration
	CacheFor    time.Duration
	PrivateKey  ed25519.PrivateKey
	Now         func() time.Time
	LoadCatalog CatalogLoader
}

type Issuer struct {
	mu          sync.Mutex
	catalogPath string
	ttl         time.Duration
	cacheFor    time.Duration
	privateKey  ed25519.PrivateKey
	keyID       string
	now         func() time.Time
	loadCatalog CatalogLoader
	stateStore  issuance.FileStore
	processLock *issuance.ProcessLock
	state       issuance.State
	cached      manifest.Envelope
	cacheUntil  time.Time
	validUntil  time.Time
	retryAt     time.Time
	lastError   error
	closed      bool
}

func NewIssuer(options IssuerOptions) (*Issuer, error) {
	if len(options.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("issuer: invalid Ed25519 private key")
	}
	if options.TTL < time.Minute || options.TTL > time.Hour {
		return nil, errors.New("issuer: TTL must be between 1m and 1h")
	}
	if options.CacheFor < time.Second || options.CacheFor > options.TTL/2 {
		return nil, errors.New("issuer: cache duration must be between 1s and half the manifest TTL")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.LoadCatalog == nil {
		options.LoadCatalog = catalog.LoadFile
	}
	store := issuance.FileStore{Path: options.StatePath}
	processLock, err := issuance.AcquireProcessLock(options.StatePath)
	if err != nil {
		return nil, err
	}
	state, exists, err := store.Load()
	if err != nil {
		_ = processLock.Close()
		return nil, err
	}
	keyID := manifest.KeyID(options.PrivateKey.Public().(ed25519.PublicKey))
	if exists && state.KeyID != keyID {
		_ = processLock.Close()
		return nil, fmt.Errorf("issuer: state belongs to signing key %q, current key is %q", state.KeyID, keyID)
	}
	return &Issuer{
		catalogPath: options.CatalogPath,
		ttl:         options.TTL,
		cacheFor:    options.CacheFor,
		privateKey:  options.PrivateKey,
		keyID:       keyID,
		now:         options.Now,
		loadCatalog: options.LoadCatalog,
		stateStore:  store,
		processLock: processLock,
		state:       state,
	}, nil
}

// Issue serializes refresh work behind one mutex and caches both success and failure.
// A cached, still-valid envelope remains usable during a temporary catalog failure.
func (issuer *Issuer) Issue() (manifest.Envelope, error) {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if issuer.closed {
		return manifest.Envelope{}, errors.New("issuer: closed")
	}

	now := issuer.now().UTC().Truncate(time.Second)
	if issuer.cached.Payload != "" && now.Before(issuer.cacheUntil) {
		return issuer.cached, nil
	}
	if issuer.lastError != nil && now.Before(issuer.retryAt) {
		if issuer.cached.Payload != "" && now.Before(issuer.validUntil) {
			return issuer.cached, nil
		}
		return manifest.Envelope{}, issuer.lastError
	}

	envelope, err := issuer.refresh(now)
	if err != nil {
		issuer.lastError = err
		issuer.retryAt = now.Add(minDuration(5*time.Second, issuer.cacheFor))
		if issuer.cached.Payload != "" && now.Before(issuer.validUntil) {
			issuer.cacheUntil = minTime(issuer.retryAt, issuer.validUntil)
			return issuer.cached, nil
		}
		return manifest.Envelope{}, err
	}
	issuer.lastError = nil
	issuer.retryAt = time.Time{}
	issuer.cached = envelope
	issuer.cacheUntil = now.Add(issuer.cacheFor)
	issuer.validUntil = now.Add(issuer.ttl)
	return envelope, nil
}

func (issuer *Issuer) Close() error {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	if issuer.closed {
		return nil
	}
	issuer.closed = true
	return issuer.processLock.Close()
}

func (issuer *Issuer) refresh(now time.Time) (manifest.Envelope, error) {
	catalogDocument, err := issuer.loadCatalog(issuer.catalogPath)
	if err != nil {
		return manifest.Envelope{}, fmt.Errorf("issuer: load manifest catalog: %w", err)
	}
	catalogDigest, err := manifest.CatalogDigest(catalogDocument)
	if err != nil {
		return manifest.Envelope{}, fmt.Errorf("issuer: validate manifest catalog: %w", err)
	}
	if issuer.state.LastVersion > 0 {
		if catalogDocument.Revision < issuer.state.CatalogRevision {
			return manifest.Envelope{}, fmt.Errorf("issuer: catalog revision %d is older than durable revision %d", catalogDocument.Revision, issuer.state.CatalogRevision)
		}
		if catalogDocument.Revision == issuer.state.CatalogRevision && catalogDigest != issuer.state.CatalogSHA256 {
			return manifest.Envelope{}, errors.New("issuer: catalog changed without increasing its revision")
		}
		if now.Before(issuer.state.LastIssuedAt) {
			return manifest.Envelope{}, errors.New("issuer: system clock moved behind the last issuance time")
		}
		if issuer.state.LastVersion == math.MaxUint64 {
			return manifest.Envelope{}, errors.New("issuer: manifest version space exhausted")
		}
	}
	nextVersion := issuer.state.LastVersion + 1
	envelope, err := manifest.Issue(catalogDocument, nextVersion, now, issuer.ttl, issuer.privateKey)
	if err != nil {
		return manifest.Envelope{}, fmt.Errorf("issuer: sign manifest: %w", err)
	}
	nextState := issuance.State{
		KeyID:           issuer.keyID,
		LastVersion:     nextVersion,
		CatalogRevision: catalogDocument.Revision,
		CatalogSHA256:   catalogDigest,
		LastIssuedAt:    now,
	}
	if err := issuer.stateStore.Save(nextState); err != nil {
		return manifest.Envelope{}, fmt.Errorf("issuer: persist monotonic state before publish: %w", err)
	}
	issuer.state = nextState
	return envelope, nil
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

func minTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}
	return right
}
