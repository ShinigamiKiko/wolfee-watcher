package alerts

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	AlertsTTL       = 14 * 24 * time.Hour
	CleanupInterval = 1 * time.Minute

	cleanupLockKey int64 = 0x77770002

	cleanupBatchSize        = 10000
	cleanupStatementTimeout = 10 * time.Second
	cleanupSweepBudget      = 45 * time.Second
)

type cleanupDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func RunCleanup(ctx context.Context, pool *pgxpool.Pool) {
	if pool == nil {
		return
	}
	t := time.NewTicker(CleanupInterval)
	defer t.Stop()
	log.Printf("[cleanup] alerts worker started — TTL=%s sweep=%s", AlertsTTL, CleanupInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			sweepAlertsOnce(ctx, pool)
		}
	}
}

func sweepAlertsOnce(ctx context.Context, pool *pgxpool.Pool) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		log.Printf("[cleanup] alerts sweep acquire: %v", err)
		return
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, cleanupLockKey).Scan(&got); err != nil || !got {
		return
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, cleanupLockKey)
	}()
	n, err := deleteExpiredAlerts(ctx, conn, time.Now().Add(-AlertsTTL), cleanupBatchSize, cleanupSweepBudget)
	if err != nil {
		log.Printf("[cleanup] alerts sweep error after %d row(s): %v", n, err)
		return
	}
	if n > 0 {
		log.Printf("[cleanup] alerts: deleted %d row(s) older than %s", n, AlertsTTL)
	}
}

func deleteExpiredAlerts(ctx context.Context, db cleanupDB, cutoff time.Time, batch int, budget time.Duration) (int64, error) {
	var total int64
	deadline := time.Now().Add(budget)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		cctx, cancel := context.WithTimeout(ctx, cleanupStatementTimeout)
		tag, err := db.Exec(cctx, `
			DELETE FROM alerts
			 WHERE id IN (
			       SELECT id FROM alerts
			        WHERE ts < $1
			        ORDER BY ts
			        LIMIT $2)`, cutoff, batch)
		cancel()
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < int64(batch) {
			break
		}
	}
	return total, nil
}
