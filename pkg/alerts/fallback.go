package alerts

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	fallbackInsertSQL = `
		INSERT INTO alerts
		  (cluster_id, ts, source, det_type, rule_id, rule_name, severity, namespace, target, syscall, detail, fingerprint, data)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	fallbackBatchTimeout = 10 * time.Second
	fallbackRowTimeout   = 3 * time.Second
)

type FallbackDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	SendBatch(context.Context, *pgx.Batch) pgx.BatchResults
}

func InsertFallbackAlerts(db FallbackDB, clusterID string, batch []AlertLog) []error {
	errs := make([]error, len(batch))
	if len(batch) == 0 {
		return errs
	}
	now := time.Now()
	queued := &pgx.Batch{}
	for i := range batch {
		if batch[i].Timestamp.IsZero() {
			batch[i].Timestamp = now
		}
		queued.Queue(fallbackInsertSQL, fallbackArgs(clusterID, batch[i])...)
	}
	batchCtx, cancel := context.WithTimeout(context.Background(), fallbackBatchTimeout)
	err := db.SendBatch(batchCtx, queued).Close()
	timedOut := batchCtx.Err() != nil
	cancel()
	if err == nil {
		return errs
	}
	if timedOut || !isStatementError(err) {
		for i := range errs {
			errs[i] = err
		}
		return errs
	}
	for i := range batch {
		rowCtx, cancel := context.WithTimeout(context.Background(), fallbackRowTimeout)
		_, errs[i] = db.Exec(rowCtx, fallbackInsertSQL, fallbackArgs(clusterID, batch[i])...)
		cancel()
		if errs[i] != nil && !isStatementError(errs[i]) {
			for j := i + 1; j < len(batch); j++ {
				errs[j] = errs[i]
			}
			break
		}
	}
	return errs
}

func fallbackArgs(clusterID string, al AlertLog) []any {
	return []any{
		clusterID, al.Timestamp, al.Source, al.DetType, al.RuleID, al.RuleName, al.Severity,
		al.Namespace, al.Target, al.Syscall, al.Detail, al.Fingerprint, al.Data,
	}
}

func isStatementError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr)
}
