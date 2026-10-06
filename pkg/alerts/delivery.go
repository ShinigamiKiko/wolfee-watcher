package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	webhookDeliveryInterval   = 10 * time.Second
	webhookDeliveryBatch      = 50
	webhookDeliveryBudget     = time.Minute
	webhookDeliveryLookback   = 10000
	webhookDeliveryLockKey    = int64(0x77770003)
	defaultWebhookMaxAttempts = 10
)

type webhookDB interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Begin(context.Context) (pgx.Tx, error)
}

type webhookDelivery struct {
	alertID  int64
	alert    AlertLog
	kind     string
	config   WebhookConfig
	attempts int
}

func RunWebhookDelivery(ctx context.Context, pool *pgxpool.Pool) {
	if pool == nil {
		return
	}
	hc := NewWebhookHTTPClient(10 * time.Second)
	ticker := time.NewTicker(webhookDeliveryInterval)
	defer ticker.Stop()
	slog.Info("alert_webhook_worker_started",
		"component", "pkg/alerts/webhook-delivery",
		"interval", webhookDeliveryInterval.String())
	for {
		deliverWebhookBatch(ctx, pool, hc)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func deliverWebhookBatch(ctx context.Context, pool *pgxpool.Pool, hc *http.Client) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return
	}
	defer conn.Release()
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, webhookDeliveryLockKey).Scan(&locked); err != nil || !locked {
		return
	}
	defer func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, webhookDeliveryLockKey)
	}()

	maxAttempts := webhookMaxAttempts()
	deadline := time.Now().Add(webhookDeliveryBudget)
	throttled := []string{}
	for ctx.Err() == nil && time.Now().Before(deadline) {
		items, err := loadWebhookDeliveries(ctx, conn, throttled)
		if err != nil {
			slog.Error("alert_webhook_load_failed", "component", "pkg/alerts/webhook-delivery", "error", err)
			return
		}
		queues := make(map[string][]webhookDelivery)
		for _, item := range items {
			queues[item.kind] = append(queues[item.kind], item)
		}
		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			handled int
		)
		for kind, queue := range queues {
			wg.Add(1)
			go func(kind string, queue []webhookDelivery) {
				defer wg.Done()
				n, limited := deliverWebhookQueue(ctx, pool, hc, queue, maxAttempts)
				mu.Lock()
				handled += n
				if limited {
					throttled = append(throttled, kind)
				}
				mu.Unlock()
			}(kind, queue)
		}
		wg.Wait()
		if len(items) < webhookDeliveryBatch || handled == 0 {
			return
		}
	}
}

func deliverWebhookQueue(ctx context.Context, db webhookDB, hc *http.Client, queue []webhookDelivery, maxAttempts int) (handled int, throttled bool) {
	for _, item := range queue {
		if ctx.Err() != nil {
			return handled, false
		}
		if item.attempts >= maxAttempts {
			if markErr := markWebhookExhausted(ctx, db, item, maxAttempts); markErr != nil {
				slog.Error("alert_webhook_exhaust_record_failed",
					"component", "pkg/alerts/webhook-delivery", "alert_id", item.alertID,
					"integration", item.kind, "error", markErr)
				continue
			}
			handled++
			slog.Error("alert_webhook_gave_up",
				"component", "pkg/alerts/webhook-delivery", "alert_id", item.alertID,
				"integration", item.kind, "attempts", item.attempts,
				"max_attempts", maxAttempts, "action", "parked_until_manual_retry")
			continue
		}

		attempts := item.attempts + 1
		if err := reserveWebhookAttempt(ctx, db, item, attempts); err != nil {
			slog.Error("alert_webhook_reserve_failed",
				"component", "pkg/alerts/webhook-delivery", "alert_id", item.alertID,
				"integration", item.kind, "error", err)
			continue
		}
		handled++

		sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := SendWebhookIdempotent(sendCtx, hc, item.kind, item.config, item.alert, webhookIdempotencyKey(item))
		cancel()
		if err != nil {
			if markErr := markWebhookFailure(ctx, db, item, err); markErr != nil {
				slog.Error("alert_webhook_failure_record_failed",
					"component", "pkg/alerts/webhook-delivery", "alert_id", item.alertID,
					"integration", item.kind, "error", markErr)
			}
			slog.Warn("alert_webhook_delivery_failed",
				"component", "pkg/alerts/webhook-delivery", "alert_id", item.alertID,
				"integration", item.kind, "attempt", attempts,
				"max_attempts", maxAttempts, "error", err)
			var statusErr *WebhookStatusError
			if errors.As(err, &statusErr) && statusErr.StatusCode == http.StatusTooManyRequests {
				return handled, true
			}
			continue
		}
		if err := markWebhookDelivered(ctx, db, item, attempts); err != nil {
			slog.Error("alert_webhook_success_record_failed",
				"component", "pkg/alerts/webhook-delivery", "alert_id", item.alertID,
				"integration", item.kind, "error", err)
		}
	}
	return handled, false
}

func webhookMaxAttempts() int {
	return envInt("ALERT_WEBHOOK_MAX_ATTEMPTS", defaultWebhookMaxAttempts)
}

func webhookIdempotencyKey(item webhookDelivery) string {
	return fmt.Sprintf("wolfee-alert-%d-%s", item.alertID, item.kind)
}

func loadWebhookDeliveries(ctx context.Context, conn *pgxpool.Conn, throttled []string) ([]webhookDelivery, error) {
	rows, err := conn.Query(ctx, `
		WITH enabled AS (
			SELECT i.kind, i.config, i.updated_at,
			       COALESCE((SELECT MAX(d.alert_id) FROM alert_deliveries d WHERE d.integration = i.kind), 0) AS seen
			  FROM integrations i
			 WHERE i.enabled = TRUE
			   AND i.kind IN ('discord', 'mattermost')
			   AND i.kind <> ALL($3::text[])
			   AND NULLIF(i.config->>'webhook_url', '') IS NOT NULL
		), pending AS (
			(SELECT d.alert_id, d.integration, d.attempts
			   FROM alert_deliveries d
			   JOIN enabled e ON e.kind = d.integration
			  WHERE d.delivered_at IS NULL
			    AND (d.next_attempt_at IS NULL OR d.next_attempt_at <= NOW())
			  ORDER BY d.alert_id
			  LIMIT $1)
			UNION ALL
			SELECT fresh.id, e.kind, 0
			  FROM enabled e
			  CROSS JOIN LATERAL (
				SELECT CASE
				         WHEN e.seen > 0 THEN e.seen
				         ELSE COALESCE((SELECT f.id FROM alerts f WHERE f.ts >= e.updated_at ORDER BY f.ts LIMIT 1),
				                       9223372036854775807)
				       END - $2 AS after_id) b
			  CROSS JOIN LATERAL (
				SELECT a.id
				  FROM alerts a
				 WHERE a.id > b.after_id
				   AND a.ts >= e.updated_at
				   AND NOT EXISTS (
				         SELECT 1 FROM alert_deliveries d
				          WHERE d.alert_id = a.id AND d.alert_id > b.after_id AND d.integration = e.kind)
				 ORDER BY a.id
				 LIMIT $1) fresh
		)
		SELECT a.id, a.ts, a.cluster_id,
		       COALESCE(NULLIF(BTRIM(c.name), ''), a.cluster_id), a.source, a.det_type,
		       COALESCE(a.rule_id, ''), COALESCE(a.rule_name, ''), COALESCE(a.severity, ''),
		       COALESCE(a.namespace, ''), COALESCE(a.target, ''), COALESCE(a.syscall, ''),
		       COALESCE(a.detail, ''),
		       e.kind, e.config, p.attempts
		  FROM pending p
		  JOIN alerts a ON a.id = p.alert_id
		  JOIN enabled e ON e.kind = p.integration
		  LEFT JOIN clusters c ON c.id = a.cluster_id
		 ORDER BY a.id, e.kind
		 LIMIT $1`, webhookDeliveryBatch, webhookDeliveryLookback, throttled)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]webhookDelivery, 0, webhookDeliveryBatch)
	for rows.Next() {
		var item webhookDelivery
		var raw json.RawMessage
		if err := rows.Scan(
			&item.alertID, &item.alert.Timestamp, &item.alert.ClusterID, &item.alert.ClusterName,
			&item.alert.Source, &item.alert.DetType,
			&item.alert.RuleID, &item.alert.RuleName, &item.alert.Severity,
			&item.alert.Namespace, &item.alert.Target, &item.alert.Syscall,
			&item.alert.Detail, &item.kind, &raw, &item.attempts,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &item.config); err != nil || item.config.WebhookURL == "" {
			continue
		}
		item.alert.ID = item.alertID
		items = append(items, item)
	}
	return items, rows.Err()
}

func reserveWebhookAttempt(ctx context.Context, db webhookDB, item webhookDelivery, attempts int) error {
	backoff := webhookRetryBackoff(attempts)
	_, err := db.Exec(ctx, `
		INSERT INTO alert_deliveries
		  (alert_id, integration, attempts, delivered_at, next_attempt_at, last_error)
		VALUES ($1, $2, $3, NULL, NOW() + $4::interval, NULL)
		ON CONFLICT (alert_id, integration) DO UPDATE SET
		  attempts = EXCLUDED.attempts,
		  next_attempt_at = EXCLUDED.next_attempt_at`,
		item.alertID, item.kind, attempts,
		fmt.Sprintf("%d milliseconds", backoff.Milliseconds()))
	return err
}

func markWebhookDelivered(ctx context.Context, db webhookDB, item webhookDelivery, attempts int) error {
	tx, err := db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `
		INSERT INTO alert_deliveries
		  (alert_id, integration, attempts, delivered_at, next_attempt_at, last_error)
		VALUES ($1, $2, $3, NOW(), NULL, NULL)
		ON CONFLICT (alert_id, integration) DO UPDATE SET
		  attempts = EXCLUDED.attempts,
		  delivered_at = EXCLUDED.delivered_at,
		  next_attempt_at = NULL,
		  last_error = NULL`, item.alertID, item.kind, attempts); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE alerts SET delivered_at = COALESCE(delivered_at, NOW()) WHERE id = $1`, item.alertID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func markWebhookFailure(ctx context.Context, db webhookDB, item webhookDelivery, sendErr error) error {
	message := []rune(sendErr.Error())
	if len(message) > 500 {
		message = message[:500]
	}
	_, err := db.Exec(ctx, `
		UPDATE alert_deliveries
		   SET last_error = $3
		 WHERE alert_id = $1 AND integration = $2`,
		item.alertID, item.kind, string(message))
	return err
}

func markWebhookExhausted(ctx context.Context, db webhookDB, item webhookDelivery, maxAttempts int) error {
	_, err := db.Exec(ctx, `
		INSERT INTO alert_deliveries
		  (alert_id, integration, attempts, delivered_at, next_attempt_at, last_error)
		VALUES ($1, $2, $3, NULL, 'infinity'::timestamptz, $4)
		ON CONFLICT (alert_id, integration) DO UPDATE SET
		  next_attempt_at = 'infinity'::timestamptz,
		  last_error = COALESCE(alert_deliveries.last_error, '') || $4`,
		item.alertID, item.kind, item.attempts,
		fmt.Sprintf(" | gave up after %d attempts", maxAttempts))
	return err
}

func webhookRetryBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	shift := attempts - 1
	if shift > 6 {
		shift = 6
	}
	delay := time.Minute * time.Duration(1<<shift)
	if delay > time.Hour {
		return time.Hour
	}
	return delay
}
