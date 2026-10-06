package alerts

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeBatchResults struct{ err error }

func (r fakeBatchResults) Exec() (pgconn.CommandTag, error) { return pgconn.CommandTag{}, r.err }
func (r fakeBatchResults) Query() (pgx.Rows, error)         { return nil, r.err }
func (r fakeBatchResults) QueryRow() pgx.Row                { return clusterNameTestRow{err: r.err} }
func (r fakeBatchResults) Close() error                     { return r.err }

type fakeFallbackDB struct {
	batchErr error
	rowErrs  map[string]error
	batches  int
	rows     []string
}

func (db *fakeFallbackDB) SendBatch(_ context.Context, b *pgx.Batch) pgx.BatchResults {
	db.batches++
	return fakeBatchResults{err: db.batchErr}
}

func (db *fakeFallbackDB) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	rule := args[5].(string)
	db.rows = append(db.rows, rule)
	return pgconn.CommandTag{}, db.rowErrs[rule]
}

func fallbackBatch() []AlertLog {
	return []AlertLog{{RuleName: "a"}, {RuleName: "b"}, {RuleName: "c"}}
}

func TestInsertFallbackAlertsSingleRoundTrip(t *testing.T) {
	db := &fakeFallbackDB{}
	batch := fallbackBatch()
	for i, err := range InsertFallbackAlerts(db, "prod-eu", batch) {
		if err != nil {
			t.Fatalf("alert %d: %v", i, err)
		}
		if batch[i].Timestamp.IsZero() {
			t.Fatalf("alert %d timestamp was not set", i)
		}
	}
	if db.batches != 1 || len(db.rows) != 0 {
		t.Fatalf("batches = %d, single inserts = %d", db.batches, len(db.rows))
	}
}

func TestInsertFallbackAlertsIsolatesBadRow(t *testing.T) {
	bad := &pgconn.PgError{Code: "22P02"}
	db := &fakeFallbackDB{batchErr: bad, rowErrs: map[string]error{"b": bad}}
	errs := InsertFallbackAlerts(db, "prod-eu", fallbackBatch())
	if errs[0] != nil || errs[1] == nil || errs[2] != nil {
		t.Fatalf("errors = %v", errs)
	}
}

func TestInsertFallbackAlertsStopsOnConnectionFailure(t *testing.T) {
	down := errors.New("connection refused")
	db := &fakeFallbackDB{batchErr: down}
	for i, err := range InsertFallbackAlerts(db, "prod-eu", fallbackBatch()) {
		if !errors.Is(err, down) {
			t.Fatalf("alert %d: %v", i, err)
		}
	}
	if len(db.rows) != 0 {
		t.Fatalf("retried %d rows against an unavailable database", len(db.rows))
	}
}
