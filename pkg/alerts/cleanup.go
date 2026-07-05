package alerts

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	AlertsTTL       = 5 * time.Minute
	CleanupInterval = 1 * time.Minute

	cleanupLockKey int64 = 0x77770002
)

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
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := pool.Begin(cctx)
	if err != nil {
		log.Printf("[cleanup] alerts sweep begin: %v", err)
		return
	}
	defer tx.Rollback(cctx)
	var got bool
	if err := tx.QueryRow(cctx, `SELECT pg_try_advisory_xact_lock($1)`, cleanupLockKey).Scan(&got); err != nil || !got {
		return
	}
	tag, err := tx.Exec(cctx,
		`DELETE FROM alerts WHERE ts < NOW() - $1::interval`,
		fmt.Sprintf("%d milliseconds", AlertsTTL.Milliseconds()),
	)
	if err != nil {
		log.Printf("[cleanup] alerts sweep error: %v", err)
		return
	}
	if err := tx.Commit(cctx); err != nil {
		log.Printf("[cleanup] alerts sweep commit: %v", err)
		return
	}
	if n := tag.RowsAffected(); n > 0 {
		log.Printf("[cleanup] alerts: deleted %d row(s) older than %s", n, AlertsTTL)
	}
}
