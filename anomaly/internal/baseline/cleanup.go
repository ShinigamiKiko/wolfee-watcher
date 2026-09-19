package baseline

import (
	"context"
	"fmt"
	"github.com/wolfee-watcher/pkg/mtls"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	AnomalyEventTTL = 14 * 24 * time.Hour

	AnomalySilentTTL        = 24 * time.Hour
	AnomalyCleanupInterval  = 5 * time.Minute
	anomalyCleanupOpTimeout = 10 * time.Second
)

func RunAnomalyCleanup(ctx context.Context, pool *pgxpool.Pool) {
	if pool == nil {
		return
	}
	t := time.NewTicker(AnomalyCleanupInterval)
	defer t.Stop()
	log.Printf("[cleanup] anomaly_events worker started — activeTTL=%s silentTTL=%s sweep=%s",
		AnomalyEventTTL, AnomalySilentTTL, AnomalyCleanupInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cctx, cancel := context.WithTimeout(ctx, anomalyCleanupOpTimeout)
			sweepAnomalyEvents(cctx, pool)
			cancel()
		}
	}
}

func sweepAnomalyEvents(ctx context.Context, pool *pgxpool.Pool) {
	active, err := pool.Exec(ctx,
		`DELETE FROM anomaly_events
		 WHERE cluster_id = $1 AND silenced_at IS NULL AND ts < NOW() - $2::interval`,
		mtls.ClusterID(),
		fmt.Sprintf("%d milliseconds", AnomalyEventTTL.Milliseconds()),
	)
	if err != nil {
		log.Printf("[cleanup] anomaly_events active sweep error: %v", err)
	} else if n := active.RowsAffected(); n > 0 {
		log.Printf("[cleanup] anomaly_events: deleted %d active row(s) older than %s", n, AnomalyEventTTL)
	}

	silent, err := pool.Exec(ctx,
		`DELETE FROM anomaly_events
		 WHERE cluster_id = $1 AND silenced_at IS NOT NULL AND silenced_at < NOW() - $2::interval`,
		mtls.ClusterID(),
		fmt.Sprintf("%d milliseconds", AnomalySilentTTL.Milliseconds()),
	)
	if err != nil {
		log.Printf("[cleanup] anomaly_events silent sweep error: %v", err)
	} else if n := silent.RowsAffected(); n > 0 {
		log.Printf("[cleanup] anomaly_events: deleted %d silenced row(s) older than %s", n, AnomalySilentTTL)
	}
}
