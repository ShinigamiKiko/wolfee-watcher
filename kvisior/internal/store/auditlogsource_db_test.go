package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAuditLogSourceRoundTrip(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_DSN")
	if dsn == "" {
		t.Skip("set AUDIT_TEST_DSN to a disposable database migrated with central-migrate")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st, err := NewFromPool(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	cluster := fmt.Sprintf("log-source-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		for _, table := range []string{"audit_log_settings", "audit_log_nodes", "audit_trusted_proxies"} {
			if _, err := pool.Exec(ctx, "DELETE FROM "+table+" WHERE cluster_id=$1", cluster); err != nil {
				t.Error(err)
			}
		}
	})
	scope := st.Cluster(cluster)

	if defaults, err := scope.AuditTrustedProxies(ctx); err != nil || defaults.HeadersSanitized || defaults.Proxies != "" {
		t.Fatalf("without explicit settings forwarded headers must not be trusted: %+v %v", defaults, err)
	}
	for _, verified := range []bool{false, true, false} {
		want := AuditProxySettings{Proxies: "203.0.113.48", HeadersSanitized: verified}
		if err := scope.SaveAuditTrustedProxies(ctx, want, "admin"); err != nil {
			t.Fatal(err)
		}
		if got, err := scope.AuditTrustedProxies(ctx); err != nil || got != want {
			t.Fatalf("proxy settings round trip: got=%+v want=%+v err=%v", got, want, err)
		}
	}

	if _, managed, err := scope.AuditLogSettings(ctx); err != nil || managed {
		t.Fatalf("a cluster without settings is unmanaged: managed=%v err=%v", managed, err)
	}
	if err := scope.MarkAuditLogApplied(ctx, "r0", ""); err != nil {
		t.Fatal(err)
	}
	if err := scope.ReplaceDetectedAuditLogNodes(ctx, []AuditLogNode{
		{Node: "cp-1", APIServer: true, AuditEnabled: true, DetectedPath: "/var/log/kubernetes/audit.log"},
		{Node: "cp-2", APIServer: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := scope.RequestAuditLogProbe(ctx, "cp-1", "probe-0"); err != ErrAuditLogReaderOffline {
		t.Fatalf("a node whose reader never reported cannot be probed: %v", err)
	}
	at := time.Now().UTC().Truncate(time.Second)
	if pending, err := scope.UpsertAuditLogTail(ctx, AuditLogNode{
		Node: "cp-1", TailPath: "/var/log/kubernetes/audit.log", TailState: "reading", LastRecordAt: &at, Lines: 10, Sent: 3,
	}); err != nil || pending != "" {
		t.Fatalf("pending=%q err=%v", pending, err)
	}
	if err := scope.RequestAuditLogProbe(ctx, "cp-1", "probe-1"); err != nil {
		t.Fatal(err)
	}
	status := AuditLogNode{Node: "cp-1", TailPath: "/var/log/kubernetes/audit.log", TailState: "delivery-failing", TailError: "down"}
	if pending, err := scope.UpsertAuditLogTail(ctx, status); err != nil || pending != "probe-1" {
		t.Fatalf("the next status report must receive the probe request: pending=%q err=%v", pending, err)
	}
	answer := status
	answer.ProbeDone, answer.ProbeOK, answer.ProbeDetail = "probe-1", true, "readable"
	if pending, err := scope.UpsertAuditLogTail(ctx, answer); err != nil || pending != "" {
		t.Fatalf("an answered probe must not be handed out again: pending=%q err=%v", pending, err)
	}
	if pending, err := scope.UpsertAuditLogTail(ctx, status); err != nil || pending != "" {
		t.Fatalf("pending=%q err=%v", pending, err)
	}
	if err := scope.ReplaceDetectedAuditLogNodes(ctx, []AuditLogNode{
		{Node: "cp-1", APIServer: true, AuditEnabled: true, DetectedPath: "/var/log/kubernetes/audit.log"},
	}); err != nil {
		t.Fatal(err)
	}
	nodes, err := scope.ListAuditLogNodes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Node != "cp-1" || nodes[0].TailState != "delivery-failing" || nodes[0].TailError != "down" {
		t.Fatalf("nodes %+v", nodes)
	}
	if nodes[0].LastRecordAt == nil || !nodes[0].LastRecordAt.Equal(at) || nodes[0].DetectedAt == nil || nodes[0].TailSeenAt == nil {
		t.Fatalf("a status without a new record must keep the last record time: %+v", nodes[0])
	}
	if nodes[0].ProbeDone != "probe-1" || !nodes[0].ProbeOK || nodes[0].ProbeDetail != "readable" || nodes[0].ProbeAt == nil {
		t.Fatalf("a later status report must keep the probe answer: %+v", nodes[0])
	}

	want := AuditLogSettings{Enabled: true, Path: "/logs/audit.log", NodePaths: map[string]string{"cp-2": "/other/audit.log"}, UpdatedBy: "admin"}
	if err := scope.SaveAuditLogSettings(ctx, want); err != nil {
		t.Fatal(err)
	}
	plan := PlanAuditLog(want, true, nodes)
	if err := scope.MarkAuditLogApplied(ctx, plan.Rev, "boom"); err != nil {
		t.Fatal(err)
	}
	got, managed, err := scope.AuditLogSettings(ctx)
	if err != nil || !managed || !got.Enabled || got.Path != want.Path || got.NodePaths["cp-2"] != "/other/audit.log" || got.UpdatedBy != "admin" {
		t.Fatalf("settings %+v managed=%v err=%v", got, managed, err)
	}
	if got.AppliedRev != "" || got.ApplyError != "boom" || got.AppliedAt != nil {
		t.Fatalf("a failed apply must not be recorded as applied: %+v", got)
	}
	if err := scope.MarkAuditLogApplied(ctx, plan.Rev, ""); err != nil {
		t.Fatal(err)
	}
	if got, _, _ = scope.AuditLogSettings(ctx); got.AppliedRev != plan.Rev || got.ApplyError != "" || got.AppliedAt == nil {
		t.Fatalf("applied state %+v", got)
	}
}

func TestLegacyProxySettingsRemainReadableWithoutTrustingHeaders(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_DSN")
	if dsn == "" {
		t.Skip("set AUDIT_TEST_DSN to a disposable database migrated with central-migrate")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	name := fmt.Sprintf("legacy_proxy_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	if _, err := pool.Exec(ctx, "CREATE TABLE "+quoted+`.audit_trusted_proxies (cluster_id text PRIMARY KEY, proxies text NOT NULL);
		INSERT INTO `+quoted+`.audit_trusted_proxies VALUES ('legacy', '203.0.113.48')`); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = name + ",public"
	legacy, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(legacy.Close)
	st, err := NewFromPool(ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Cluster("legacy").AuditTrustedProxies(ctx)
	if err != nil || got.Proxies != "203.0.113.48" || got.HeadersSanitized {
		t.Fatalf("legacy settings must preserve the list without trusting headers: %+v %v", got, err)
	}
}
