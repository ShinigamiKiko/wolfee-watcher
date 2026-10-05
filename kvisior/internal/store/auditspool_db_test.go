package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAuditSpoolAlertsEscalateOnceAndResetWhenHealthy(t *testing.T) {
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
	cluster := fmt.Sprintf("spool-%d", time.Now().UnixNano())
	if err := st.EnsureCluster(ctx, cluster); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, q := range []string{"DELETE FROM alerts WHERE cluster_id=$1", "DELETE FROM audit_spool_status WHERE cluster_id=$1", "DELETE FROM clusters WHERE id=$1"} {
			pool.Exec(context.Background(), q, cluster)
		}
	})
	scope := st.Cluster(cluster)
	reset := auditSpoolResetAfter
	auditSpoolResetAfter = 0
	t.Cleanup(func() { auditSpoolResetAfter = reset })
	status := AuditSpoolStatus{Pod: "sentry-audit-0", Durable: true, Capacity: 1000}
	steps := []struct {
		bytes, rejected int64
		want            string
	}{
		{100, 0, ""},
		{850, 0, "audit-delivery-queue-high"},
		{860, 0, ""},
		{960, 0, "audit-delivery-queue-critical"},
		{960, 3, "audit-delivery-loss"},
		{970, 3, ""},
		{970, 5, ""},
		{100, 5, ""},
		{850, 5, "audit-delivery-queue-high"},
		{850, 0, ""},
		{850, 2, "audit-delivery-loss"},
	}
	fired := 0
	for i, step := range steps {
		status.Bytes, status.Rejected = step.bytes, step.rejected
		alert, err := scope.RecordAuditSpool(ctx, status)
		if err != nil {
			t.Fatal(err)
		}
		got := ""
		if alert != nil {
			got = alert.RuleID
			fired++
		}
		if got != step.want {
			t.Fatalf("step %d (%d bytes, %d lost): alert %q, want %q", i, step.bytes, step.rejected, got, step.want)
		}
	}
	var stored int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE cluster_id=$1 AND det_type='audit_delivery'`, cluster).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != fired {
		t.Fatalf("alerts stored %d, fired %d", stored, fired)
	}
	queues, err := scope.ListAuditSpools(ctx)
	if err != nil || len(queues) != 1 || queues[0].Bytes != 850 || queues[0].Rejected != 2 {
		t.Fatalf("queues %+v %v", queues, err)
	}
	auditSpoolResetAfter = reset
	flapping := AuditSpoolStatus{Pod: "sentry-audit-1", Durable: true, Capacity: 1000}
	for i, step := range []struct {
		bytes int64
		alert bool
	}{{850, true}, {100, false}, {850, false}, {100, false}, {860, false}} {
		flapping.Bytes = step.bytes
		alert, err := scope.RecordAuditSpool(ctx, flapping)
		if err != nil {
			t.Fatal(err)
		}
		if (alert != nil) != step.alert {
			t.Fatalf("flapping step %d: alert=%v want %v", i, alert != nil, step.alert)
		}
	}
}
