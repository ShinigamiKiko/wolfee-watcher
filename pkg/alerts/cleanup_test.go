package alerts

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeCleanupDB struct {
	results []int64
	err     error
	calls   int
}

func (db *fakeCleanupDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	if db.calls >= len(db.results) {
		db.calls++
		return pgconn.CommandTag{}, db.err
	}
	n := db.results[db.calls]
	db.calls++
	return pgconn.NewCommandTag("DELETE " + strconv.FormatInt(n, 10)), nil
}

func TestDeleteExpiredAlertsLoopsUntilShortBatch(t *testing.T) {
	db := &fakeCleanupDB{results: []int64{100, 100, 40}}
	n, err := deleteExpiredAlerts(context.Background(), db, time.Now(), 100, time.Minute)
	if err != nil || n != 240 || db.calls != 3 {
		t.Fatalf("deleted = %d, calls = %d, err = %v", n, db.calls, err)
	}
}

func TestDeleteExpiredAlertsKeepsProgressOnError(t *testing.T) {
	db := &fakeCleanupDB{results: []int64{100, 100}, err: errors.New("canceling statement due to statement timeout")}
	n, err := deleteExpiredAlerts(context.Background(), db, time.Now(), 100, time.Minute)
	if err == nil || n != 200 {
		t.Fatalf("deleted = %d, err = %v", n, err)
	}
}

func TestDeleteExpiredAlertsStopsAtBudget(t *testing.T) {
	db := &fakeCleanupDB{results: make([]int64, 1000)}
	for i := range db.results {
		db.results[i] = 100
	}
	if _, err := deleteExpiredAlerts(context.Background(), db, time.Now(), 100, 0); err != nil {
		t.Fatal(err)
	}
	if db.calls != 0 {
		t.Fatalf("calls = %d after the budget was spent", db.calls)
	}
}

func TestDeleteExpiredAlertsPostgres(t *testing.T) {
	dsn := os.Getenv("ALERTS_TEST_DSN")
	if dsn == "" {
		t.Skip("ALERTS_TEST_DSN is not set")
	}
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	for _, stmt := range []string{
		`CREATE TEMP TABLE alerts (id BIGSERIAL PRIMARY KEY, ts TIMESTAMPTZ NOT NULL)`,
		`CREATE INDEX ON alerts (ts DESC)`,
		`CREATE TEMP TABLE alert_deliveries (
			alert_id BIGINT NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
			integration TEXT NOT NULL,
			PRIMARY KEY (alert_id, integration))`,
		`INSERT INTO alerts (ts) SELECT NOW() - interval '20 days' + g * interval '1 second' FROM generate_series(1, 25000) g`,
		`INSERT INTO alerts (ts) SELECT NOW() - interval '1 day' FROM generate_series(1, 5000)`,
		`INSERT INTO alert_deliveries SELECT id, 'discord' FROM alerts`,
	} {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	n, err := deleteExpiredAlerts(ctx, conn, time.Now().Add(-AlertsTTL), 10000, time.Minute)
	if err != nil || n != 25000 {
		t.Fatalf("deleted = %d, err = %v", n, err)
	}
	var alerts, deliveries int
	if err := conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM alerts), (SELECT count(*) FROM alert_deliveries)`).Scan(&alerts, &deliveries); err != nil {
		t.Fatal(err)
	}
	if alerts != 5000 || deliveries != 5000 {
		t.Fatalf("left alerts = %d, deliveries = %d", alerts, deliveries)
	}
}
