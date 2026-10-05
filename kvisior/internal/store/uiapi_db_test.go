package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestQueryAlertsSplitsUserAndAction(t *testing.T) {
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
	cluster := fmt.Sprintf("alerts-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, "DELETE FROM alerts WHERE cluster_id=$1", cluster); err != nil {
			t.Error(err)
		}
	})
	scope := st.Cluster(cluster)
	at := time.Now().UTC()
	event := func(id, user string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"id":%q,"user":%q}`, id, user))
	}
	if err := scope.InsertAlerts(ctx, []IncomingAlert{
		{Timestamp: at, Source: "sentry-audit", DetType: "Audit", RuleID: "r1",
			Detail: "kubernetes-admin create serviceaccounts/ww-audit-test/audit-probe-2", Data: event("e1", "kubernetes-admin")},
		{Timestamp: at.Add(time.Second), Source: "sentry-audit", DetType: "Audit", RuleID: "r2",
			Detail: "unknown update validatingwebhookconfigurations/kyverno, 3 times in 5 min", Data: event("e2", "unknown")},
		{Timestamp: at.Add(2 * time.Second), Source: "anomaly-detector", DetType: "Anomaly", RuleID: "r3",
			Detail: "new outbound connection to 10.0.0.7:443", Data: json.RawMessage(`{"user":"root"}`)},
	}); err != nil {
		t.Fatal(err)
	}
	if err := scope.AttachAuditAlertActor(ctx, "e2", at, "m.ivanova", event("e2", "m.ivanova")); err != nil {
		t.Fatal(err)
	}
	rows, _, err := scope.QueryAlerts(ctx, 0, 50)
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	want := []struct{ user, action, detail string }{
		{"kubernetes-admin", "create serviceaccounts/ww-audit-test/audit-probe-2", "kubernetes-admin create serviceaccounts/ww-audit-test/audit-probe-2"},
		{"m.ivanova", "update validatingwebhookconfigurations/kyverno, 3 times in 5 min", "m.ivanova update validatingwebhookconfigurations/kyverno, 3 times in 5 min"},
		{"", "new outbound connection to 10.0.0.7:443", "new outbound connection to 10.0.0.7:443"},
	}
	for i, w := range want {
		if rows[i].User != w.user || rows[i].Action != w.action || rows[i].Detail != w.detail {
			t.Errorf("row %d: user=%q action=%q detail=%q", i, rows[i].User, rows[i].Action, rows[i].Detail)
		}
	}
}

func TestQueryAlertsReadsTimestamps(t *testing.T) {
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
	cluster := fmt.Sprintf("alerts-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, "DELETE FROM alerts WHERE cluster_id=$1", cluster); err != nil {
			t.Error(err)
		}
	})
	scope := st.Cluster(cluster)
	at := time.Date(2026, 10, 1, 14, 45, 21, 430381000, time.UTC)
	if err := scope.InsertAlerts(ctx, []IncomingAlert{
		{Timestamp: at, Source: "sentry-audit", DetType: "Audit", RuleID: "r1", RuleName: "Rule", Severity: "HIGH", Fingerprint: "f1"},
		{Timestamp: at.Add(time.Second), Source: "sentry-audit", DetType: "Audit", RuleID: "r2", RuleName: "Rule", Fingerprint: "f2"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE alerts SET delivered_at = $2 WHERE cluster_id=$1 AND rule_id='r2'", cluster, at.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	first, _, err := scope.QueryAlerts(ctx, 0, 50)
	if err != nil || len(first) != 2 {
		t.Fatalf("rows=%d err=%v", len(first), err)
	}
	for _, since := range []int64{0, first[0].ID - 1} {
		rows, last, err := scope.QueryAlerts(ctx, since, 50)
		if err != nil || len(rows) != 2 || last != rows[1].ID {
			t.Fatalf("since=%d: rows=%d last=%d err=%v", since, len(rows), last, err)
		}
		got, err := time.Parse(time.RFC3339Nano, rows[0].Ts)
		if err != nil || !got.Equal(at) {
			t.Fatalf("ts %q: %v", rows[0].Ts, err)
		}
		if rows[0].DeliveredAt != nil || rows[1].DeliveredAt == nil {
			t.Fatalf("delivered: %v %v", rows[0].DeliveredAt, rows[1].DeliveredAt)
		}
		if delivered, err := time.Parse(time.RFC3339Nano, *rows[1].DeliveredAt); err != nil || !delivered.Equal(at.Add(time.Minute)) {
			t.Fatalf("deliveredAt %q: %v", *rows[1].DeliveredAt, err)
		}
	}
}
