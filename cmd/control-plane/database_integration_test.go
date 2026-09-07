package main

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/mralstark/virtual-cloud-help-service/internal/pilotaccess"
	accesspg "github.com/mralstark/virtual-cloud-help-service/internal/pilotaccess/postgres"
	"github.com/mralstark/virtual-cloud-help-service/internal/pilottelemetry"
	telemetrypg "github.com/mralstark/virtual-cloud-help-service/internal/pilottelemetry/postgres"
	"github.com/mralstark/virtual-cloud-help-service/internal/vpnnode"
)

// Run only against the disposable vchs_test database, with migrations applied.
// These tests exercise actual pgx parameter inference and runtime permissions.
func TestDatabaseIntegration(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; see make integration")
	}
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		t.Fatal("invalid TEST_DATABASE_URL")
	}
	if cfg.Database != "vchs_test" {
		t.Fatal("integration database must be named vchs_test")
	}
	admin := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { admin.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := admin.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := validateDatabaseIdentity(ctx, admin); err == nil {
		t.Fatal("accepted administrative identity")
	}
	// The runtime group has exactly the same permissions as a dedicated login
	// inheriting it. No password or LOGIN role is created by this test.
	hardenDatabaseConfig(cfg)
	runtimeDB := stdlib.OpenDB(*cfg, stdlib.OptionAfterConnect(func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE vchs_runtime")
		return err
	}))
	runtimeDB.SetMaxOpenConns(5)
	t.Cleanup(func() { runtimeDB.Close() })
	if err := validateDatabaseIdentity(ctx, runtimeDB); err != nil {
		t.Fatal(err)
	}
	if err := validateDatabasePrivileges(ctx, runtimeDB); err != nil {
		t.Fatal(err)
	}
	// Fixtures are scoped to this disposable database and rolled back/removed.
	const account = "00000000-0000-4000-8000-000000009001"
	const device = "00000000-0000-4000-8000-000000009002"
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := admin.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO app_private.accounts(id,status) VALUES($1,'active')", account)
	t.Cleanup(func() {
		cleanupCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		for _, query := range []string{
			"DELETE FROM app_private.admin_audit_events WHERE object_id IN (SELECT id::text FROM app_private.vpn_accesses WHERE device_id=$1)",
			"DELETE FROM app_private.accounts WHERE id=(SELECT account_id FROM app_private.devices WHERE id=$1)",
		} {
			if _, err := admin.ExecContext(cleanupCtx, query, device); err != nil {
				t.Error(err)
			}
		}
		if _, err := admin.ExecContext(cleanupCtx, "DELETE FROM app_private.nodes WHERE id='integration-node'"); err != nil {
			t.Error(err)
		}
	})
	exec("INSERT INTO app_private.devices(id,account_id,label,identity_public_key,status) VALUES($1,$2,'integration',repeat('k',32),'active')", device, account)
	exec("INSERT INTO app_private.nodes(id,region,country_code,provider,status) VALUES('integration-node','de-fra','DE','timeweb-cloud','active')")
	store, _ := accesspg.New(runtimeDB)
	service, _ := pilotaccess.NewService(store, nil, nil)
	expires := time.Now().UTC().Add(time.Hour)
	access, err := service.Register(ctx, pilotaccess.RegisterInput{DeviceID: device, NodeID: "integration-node", Transport: vpnnode.TransportAmneziaWG, ExternalReference: "integration-access", ExpiresAt: &expires})
	if err != nil {
		t.Fatal(err)
	}
	var auditCount int
	if err := admin.QueryRowContext(ctx, "SELECT count(*) FROM app_private.admin_audit_events WHERE object_id=$1", access.ID).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("registration audit count=%d, err=%v", auditCount, err)
	}
	var wait sync.WaitGroup
	for range 5 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := service.Revoke(ctx, access.ID)
			if err != nil || result.Status != pilotaccess.StatusRevoked {
				t.Errorf("revoke retry: %v", err)
			}
		}()
	}
	wait.Wait()
	if err := admin.QueryRowContext(ctx, "SELECT count(*) FROM app_private.admin_audit_events WHERE object_id=$1", access.ID).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("expected exactly 2 audit events, got %d: %v", auditCount, err)
	}
	telemetry, _ := telemetrypg.New(runtimeDB)
	telemetryService, _ := pilottelemetry.NewService(telemetry, nil, nil, nil)
	_, err = telemetryService.Record(ctx, pilottelemetry.RecordInput{DeviceID: device, ClientPlatform: pilottelemetry.PlatformLinux, Transport: vpnnode.TransportAmneziaWG, OccurredAt: time.Now(), Success: true, ConnectionTimeBucket: pilottelemetry.ConnectionLT3S})
	if err != nil {
		t.Fatal(err)
	}
	report, err := telemetryService.Report(ctx)
	if err != nil || report.TotalTests != 1 || report.ActiveDevices != 0 {
		t.Fatalf("report: %+v, %v", report, err)
	}
	// Revoking one required privilege must fail startup, even with SELECT intact.
	exec("REVOKE INSERT ON app_private.vpn_accesses FROM vchs_runtime")
	t.Cleanup(func() {
		if _, err := admin.Exec("GRANT INSERT ON app_private.vpn_accesses TO vchs_runtime"); err != nil {
			t.Error(err)
		}
	})
	if err := validateDatabasePrivileges(ctx, runtimeDB); err == nil {
		t.Fatal("missing INSERT was not detected")
	}
	if _, err := runtimeDB.ExecContext(ctx, "DELETE FROM app_private.admin_audit_events"); err == nil {
		t.Fatal("runtime deleted audit events")
	}
	if _, err := store.Revoke(ctx, "00000000-0000-4000-8000-000000000000", time.Now()); !errors.Is(err, pilotaccess.ErrNotFound) {
		t.Fatalf("missing access: %v", err)
	}
}
