package service

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/catalog"
	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
)

type Issuer struct {
	CatalogPath string
	TTL         time.Duration
	PrivateKey  ed25519.PrivateKey
	Now         func() time.Time
}

func (issuer Issuer) Issue() (manifest.Envelope, error) {
	now := issuer.Now
	if now == nil {
		now = time.Now
	}
	catalogDocument, err := catalog.LoadFile(issuer.CatalogPath)
	if err != nil {
		return manifest.Envelope{}, fmt.Errorf("load manifest catalog: %w", err)
	}
	envelope, err := manifest.Issue(catalogDocument, now(), issuer.TTL, issuer.PrivateKey)
	if err != nil {
		return manifest.Envelope{}, fmt.Errorf("issue manifest: %w", err)
	}
	return envelope, nil
}
