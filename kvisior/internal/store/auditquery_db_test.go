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

func TestAuditUIQueriesNeverCacheAGenericPlan(t *testing.T) {
	dsn := os.Getenv("AUDIT_TEST_DSN")
	if dsn == "" {
		t.Skip("set AUDIT_TEST_DSN to a disposable database migrated with central-migrate")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st, err := NewFromPool(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	scope := st.Cluster(fmt.Sprintf("plans-%d", time.Now().UnixNano()))
	now := time.Now()
	q := AuditEventQuery{From: now.Add(-24 * time.Hour), To: now, Limit: 50}
	for i := 0; i < 7; i++ {
		if _, err := scope.QueryAuditEvents(ctx, q); err != nil {
			t.Fatal(err)
		}
		if _, _, err := scope.AuditEventHistogram(ctx, q, 24); err != nil {
			t.Fatal(err)
		}
		if _, err := scope.AuditEventGroups(ctx, q, "user", 10); err != nil {
			t.Fatal(err)
		}
		if _, err := scope.AuditSources(ctx); err != nil {
			t.Fatal(err)
		}
		if _, _, err := scope.QueryAuditEventsSince(ctx, "0", 50); err != nil {
			t.Fatal(err)
		}
	}
	var cached string
	if err := pool.QueryRow(ctx,
		`SELECT COALESCE(string_agg(statement, ' | '), '') FROM pg_prepared_statements
		  WHERE statement ILIKE '%FROM audit_events%'`, pgx.QueryExecModeExec).Scan(&cached); err != nil {
		t.Fatal(err)
	}
	if cached != "" {
		t.Fatalf("prepared statements on audit_events switch to a generic plan that locks every partition after five runs: %s", cached)
	}
}
