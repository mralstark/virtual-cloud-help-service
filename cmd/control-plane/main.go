package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/mralstark/virtual-cloud-help-service/internal/api"
	"github.com/mralstark/virtual-cloud-help-service/internal/config"
	"github.com/mralstark/virtual-cloud-help-service/internal/manifest"
	"github.com/mralstark/virtual-cloud-help-service/internal/pilotaccess"
	pilotpostgres "github.com/mralstark/virtual-cloud-help-service/internal/pilotaccess/postgres"
	"github.com/mralstark/virtual-cloud-help-service/internal/pilotapi"
	"github.com/mralstark/virtual-cloud-help-service/internal/pilottelemetry"
	telemetrypostgres "github.com/mralstark/virtual-cloud-help-service/internal/pilottelemetry/postgres"
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

	httpHandler := api.New(issuer.Issue, logger, cfg.MaxInFlight)
	var database *sql.DB
	if cfg.PilotAccess {
		database, err = openPilotDatabase(cfg.DatabaseURL)
		if err != nil {
			return err
		}
		defer database.Close()
		store, err := pilotpostgres.New(database)
		if err != nil {
			return err
		}
		telemetryStore, err := telemetrypostgres.New(database)
		if err != nil {
			return err
		}
		checkContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = store.CheckSchema(checkContext)
		if err != nil {
			cancel()
			return err
		}
		err = telemetryStore.CheckSchema(checkContext)
		cancel()
		if err != nil {
			return err
		}
		accessService, err := pilotaccess.NewService(store, time.Now, nil)
		if err != nil {
			return err
		}
		telemetryService, err := pilottelemetry.NewService(telemetryStore, time.Now, nil, nil)
		if err != nil {
			return err
		}
		adminHandler, err := pilotapi.NewWithTelemetry(accessService, telemetryService, cfg.PilotAdminToken, logger)
		if err != nil {
			return err
		}
		databaseReady := func(ctx context.Context) error {
			pingContext, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if err := database.PingContext(pingContext); err != nil {
				return errors.New("pilot database unavailable")
			}
			return nil
		}
		httpHandler = api.NewWithPilotAdminAndReadiness(issuer.Issue, logger, cfg.MaxInFlight, adminHandler, databaseReady)
	}

	server := &http.Server{
		Addr:              cfg.ListenAddress,
		Handler:           httpHandler,
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

func openPilotDatabase(databaseURL string) (*sql.DB, error) {
	connectionConfig, err := secureDatabaseConfig(databaseURL)
	if err != nil {
		return nil, err
	}
	hardenDatabaseConfig(connectionConfig)
	database := stdlib.OpenDB(*connectionConfig)
	database.SetMaxOpenConns(5)
	database.SetMaxIdleConns(2)
	database.SetConnMaxIdleTime(5 * time.Minute)
	database.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := database.PingContext(ctx); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("connect pilot database: %w", err)
	}
	if err := validateDatabaseIdentity(ctx, database); err != nil {
		_ = database.Close()
		return nil, err
	}
	return database, nil
}

func validateDatabaseIdentity(ctx context.Context, database *sql.DB) error {
	var superuser, createRole, createDatabase, bypassRLS bool
	if err := database.QueryRowContext(ctx, `
		SELECT rolsuper, rolcreaterole, rolcreatedb, rolbypassrls
		FROM pg_catalog.pg_roles
		WHERE rolname = current_user`).
		Scan(&superuser, &createRole, &createDatabase, &bypassRLS); err != nil {
		return fmt.Errorf("validate pilot database identity: %w", err)
	}
	if superuser || createRole || createDatabase || bypassRLS {
		return errors.New("pilot database identity must not be privileged or bypass row security")
	}
	return nil
}

func validateDatabaseTransport(databaseURL string) error {
	_, err := secureDatabaseConfig(databaseURL)
	return err
}

func hardenDatabaseConfig(config *pgx.ConnConfig) {
	config.RuntimeParams["search_path"] = "pg_catalog"
	config.RuntimeParams["statement_timeout"] = "5000"
	config.RuntimeParams["lock_timeout"] = "2000"
	config.RuntimeParams["idle_in_transaction_session_timeout"] = "5000"
}

func secureDatabaseConfig(databaseURL string) (*pgx.ConnConfig, error) {
	connectionConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, errors.New("invalid DATABASE_URL")
	}
	if !secureDatabaseEndpoint(connectionConfig.Host, connectionConfig.TLSConfig) {
		return nil, errors.New("remote PostgreSQL connections require certificate-verified TLS without a plaintext fallback")
	}
	for _, fallback := range connectionConfig.Fallbacks {
		if !secureDatabaseEndpoint(fallback.Host, fallback.TLSConfig) {
			return nil, errors.New("remote PostgreSQL connections require certificate-verified TLS without a plaintext fallback")
		}
	}
	return connectionConfig, nil
}

func secureDatabaseEndpoint(host string, tlsConfig *tls.Config) bool {
	if strings.HasPrefix(host, "/") || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return true
	}
	return tlsConfig != nil && !tlsConfig.InsecureSkipVerify && tlsConfig.ServerName != ""
}
