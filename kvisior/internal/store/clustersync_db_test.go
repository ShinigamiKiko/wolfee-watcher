package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func routedTestStores(t *testing.T) (*Store, *pgxpool.Pool, string) {
	t.Helper()
	hubDSN, dataDSN := os.Getenv("AUDIT_TEST_DSN"), os.Getenv("AUDIT_TEST_ROUTED_DSN")
	if hubDSN == "" || dataDSN == "" {
		t.Skip("set AUDIT_TEST_DSN and AUDIT_TEST_ROUTED_DSN to two disposable databases migrated with central-migrate")
	}
	ctx := context.Background()
	hubPool, err := pgxpool.New(ctx, hubDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(hubPool.Close)
	dataPool, err := pgxpool.New(ctx, dataDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dataPool.Close)
	hub, err := NewFromPool(ctx, hubPool)
	if err != nil {
		t.Fatal(err)
	}
	cluster := fmt.Sprintf("rt-%d", time.Now().UnixNano())
	r := NewRouter()
	hub.SetRouter(r)
	t.Cleanup(r.Close)
	if _, _, err := r.Apply(ctx, map[string]string{cluster: dataDSN}); err != nil {
		t.Fatal(err)
	}
	return hub, dataPool, cluster
}

func TestRoutedClusterWritesLandInItsDatabase(t *testing.T) {
	ctx := context.Background()
	hub, data, cluster := routedTestStores(t)
	alert := IncomingAlert{Timestamp: time.Now(), Source: "test", DetType: "Anomaly", RuleID: "r", Target: "pod", Fingerprint: cluster}
	if err := hub.Cluster(cluster).InsertAlerts(ctx, []IncomingAlert{alert}); err != nil {
		t.Fatal(err)
	}
	count := func(p *pgxpool.Pool) int {
		var n int
		if err := p.QueryRow(ctx, `SELECT count(*) FROM alerts WHERE cluster_id = $1`, cluster).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if got := count(data); got != 1 {
		t.Fatalf("cluster database has %d alerts, want 1", got)
	}
	if got := count(hub.pool); got != 0 {
		t.Fatalf("hub database has %d alerts of a routed cluster", got)
	}
}

func TestSyncRoutedClustersReplicatesConfig(t *testing.T) {
	ctx := context.Background()
	hub, data, cluster := routedTestStores(t)
	policy, stale, setting := cluster+"-policy", cluster+"-stale", cluster+"-setting"
	exec := func(p *pgxpool.Pool, sql string, args ...any) {
		t.Helper()
		if _, err := p.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, p := range []*pgxpool.Pool{hub.pool, data} {
			_, _ = p.Exec(context.Background(), `DELETE FROM runtime_policies WHERE id IN ($1, $2)`, policy, stale)
			_, _ = p.Exec(context.Background(), `DELETE FROM clusters WHERE id = $1`, cluster)
		}
	})
	exec(hub.pool, `INSERT INTO runtime_policies (id, data) VALUES ($1, '{"detType":"Runtime","enabled":false}')`, policy)
	exec(hub.pool, `INSERT INTO platform_settings (key, value, updated_by) VALUES ($1, '{"hours":48}', 'test')`, setting)
	exec(data, `INSERT INTO runtime_policies (id, data) VALUES ($1, '{}')`, stale)
	exec(data, `INSERT INTO clusters (id, name, endpoint, last_seen_at) VALUES ($1, $1, 'https://edge:30443', NOW())`, cluster)

	results := hub.SyncRoutedClusters(ctx)
	if len(results) != 1 || results[0].Err != nil {
		t.Fatalf("sync: %+v", results)
	}
	var enabled bool
	if err := data.QueryRow(ctx, `SELECT enabled FROM runtime_policies WHERE id = $1`, policy).Scan(&enabled); err != nil || enabled {
		t.Fatalf("policy not replicated with its generated columns: enabled=%v err=%v", enabled, err)
	}
	var n int
	if err := data.QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE id = $1`, stale).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a policy deleted on the hub survived in the cluster database: %d %v", n, err)
	}
	var hours string
	if err := data.QueryRow(ctx, `SELECT value->>'hours' FROM platform_settings WHERE key = $1`, setting).Scan(&hours); err != nil || hours != "48" {
		t.Fatalf("setting not replicated: %q %v", hours, err)
	}
	var endpoint string
	if err := hub.pool.QueryRow(ctx, `SELECT endpoint FROM clusters WHERE id = $1`, cluster).Scan(&endpoint); err != nil || endpoint != "https://edge:30443" {
		t.Fatalf("hub registry did not pick up the edge endpoint: %q %v", endpoint, err)
	}

	again := hub.SyncRoutedClusters(ctx)
	if len(again) != 1 || again[0].Err != nil || len(again[0].Copied) != 0 {
		t.Fatalf("an unchanged config was copied again: %+v", again)
	}

	exec(hub.pool, `UPDATE runtime_policies SET data = '{"detType":"Runtime","enabled":true}', updated_at = NOW() WHERE id = $1`, policy)
	third := hub.SyncRoutedClusters(ctx)
	if len(third) != 1 || third[0].Err != nil || len(third[0].Copied) != 1 || third[0].Copied[0] != "runtime_policies" {
		t.Fatalf("a policy change was not replicated alone: %+v", third)
	}
	exec(hub.pool, `DELETE FROM platform_settings WHERE key = $1`, setting)
	exec(data, `DELETE FROM platform_settings WHERE key = $1`, setting)
}
