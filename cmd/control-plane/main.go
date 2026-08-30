package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mralstark/virtual-cloud-help-service/internal/api"
	"github.com/mralstark/virtual-cloud-help-service/internal/config"
	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
	"github.com/mralstark/virtual-cloud-help-service/internal/service"
	"github.com/mralstark/virtual-cloud-help-service/internal/signingkey"
)

func main() {
	logger := log.New(os.Stderr, "control-plane: ", log.LstdFlags|log.LUTC)
	if err := run(logger); err != nil {
		logger.Fatal(err)
	}
}

func run(logger *log.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	privateKey, err := signingkey.LoadPrivate(cfg.SigningKeyPath)
	if err != nil {
		return err
	}
	rootKey, err := signingkey.LoadPublic(cfg.RootKeyPath)
	if err != nil {
		return err
	}
	policyFile, err := os.Open(cfg.KeyPolicyPath)
	if err != nil {
		return err
	}
	keyPolicy, policyErr := manifest.DecodeKeyPolicy(policyFile)
	closeErr := policyFile.Close()
	if policyErr != nil {
		return policyErr
	}
	if closeErr != nil {
		return closeErr
	}
	issuer, err := service.NewIssuer(service.IssuerOptions{
		CatalogPath: cfg.CatalogPath,
		StatePath:   cfg.IssuerStatePath,
		TTL:         cfg.ManifestTTL,
		CacheFor:    cfg.ManifestCache,
		PrivateKey:  privateKey,
		RootKey:     rootKey,
		KeyPolicy:   keyPolicy,
		Now:         time.Now,
	})
	if err != nil {
		return err
	}
	defer issuer.Close()
	if _, err := issuer.Issue(); err != nil {
		return err
	}

	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           api.New(issuer.Issue, logger, cfg.MaxInFlight),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          logger,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverErrors := make(chan error, 1)
	go func() {
		logger.Printf("listening on %s", cfg.ListenAddress)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), cfg.Shutdown)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return err
		}
		if err := <-serverErrors; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
