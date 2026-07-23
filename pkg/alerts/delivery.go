package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	webhookDeliveryInterval = 10 * time.Second
	webhookDeliveryBatch    = 25
	webhookDeliveryLockKey  = int64(0x77770003)
)

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

	items, err := loadWebhookDeliveries(ctx, conn)
	if err != nil {
		slog.Error("alert_webhook_load_failed", "component", "pkg/alerts/webhook-delivery", "error", err)
		return
	}
	for _, item := range items {
		if ctx.Err() != nil {
			return
		}
		sendCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := SendWebhook(sendCtx, hc, item.kind, item.config, item.alert)
		cancel()
		if err != nil {
			if markErr := markWebhookFailure(ctx, conn, item, err); markErr != nil {
				slog.Error("alert_webhook_failure_record_failed",
					"component", "pkg/alerts/webhook-delivery", "alert_id", item.alertID,
					"integration", item.kind, "error", markErr)
			}
			slog.Warn("alert_webhook_delivery_failed",
				"component", "pkg/alerts/webhook-delivery", "alert_id", item.alertID,
				"integration", item.kind, "error", err)
			continue
		}
		if err := markWebhookDelivered(ctx, conn, item); err != nil {
			slog.Error("alert_webhook_success_record_failed",
				"component", "pkg/alerts/webhook-delivery", "alert_id", item.alertID,
				"integration", item.kind, "error", err)
		}
	}
}

func loadWebhookDeliveries(ctx context.Context, conn *pgxpool.Conn) ([]webhookDelivery, error) {
	rows, err := conn.Query(ctx, `
		SELECT a.id, a.ts, a.source, a.det_type,
		       COALESCE(a.rule_id, ''), COALESCE(a.rule_name, ''), COALESCE(a.severity, ''),
		       COALESCE(a.namespace, ''), COALESCE(a.target, ''), COALESCE(a.syscall, ''),
		       COALESCE(a.detail, ''), i.kind, i.config, COALESCE(d.attempts, 0)
		  FROM alerts a
		  JOIN integrations i
		    ON i.enabled = TRUE
		   AND i.kind IN ('discord', 'mattermost')
		   AND a.ts >= i.updated_at
		  LEFT JOIN alert_deliveries d
		    ON d.alert_id = a.id AND d.integration = i.kind
		 WHERE d.delivered_at IS NULL
		   AND (d.next_attempt_at IS NULL OR d.next_attempt_at <= NOW())
		 ORDER BY a.id, i.kind
		 LIMIT $1`, webhookDeliveryBatch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]webhookDelivery, 0, webhookDeliveryBatch)
	for rows.Next() {
		var item webhookDelivery
		var raw json.RawMessage
		if err := rows.Scan(
			&item.alertID, &item.alert.Timestamp, &item.alert.Source, &item.alert.DetType,
			&item.alert.RuleID, &item.alert.RuleName, &item.alert.Severity,
			&item.alert.Namespace, &item.alert.Target, &item.alert.Syscall,
			&item.alert.Detail, &item.kind, &raw, &item.attempts,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &item.config); err != nil || item.config.WebhookURL == "" {
			continue
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func markWebhookDelivered(ctx context.Context, conn *pgxpool.Conn, item webhookDelivery) error {
	tx, err := conn.Begin(ctx)
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
		  last_error = NULL`, item.alertID, item.kind, item.attempts+1); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`UPDATE alerts SET delivered_at = COALESCE(delivered_at, NOW()) WHERE id = $1`, item.alertID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func markWebhookFailure(ctx context.Context, conn *pgxpool.Conn, item webhookDelivery, sendErr error) error {
	attempts := item.attempts + 1
	backoff := webhookRetryBackoff(attempts)
	message := []rune(sendErr.Error())
	if len(message) > 500 {
		message = message[:500]
	}
	_, err := conn.Exec(ctx, `
		INSERT INTO alert_deliveries
		  (alert_id, integration, attempts, delivered_at, next_attempt_at, last_error)
		VALUES ($1, $2, $3, NULL, NOW() + $4::interval, $5)
		ON CONFLICT (alert_id, integration) DO UPDATE SET
		  attempts = EXCLUDED.attempts,
		  next_attempt_at = EXCLUDED.next_attempt_at,
		  last_error = EXCLUDED.last_error`,
		item.alertID, item.kind, attempts,
		fmt.Sprintf("%d milliseconds", backoff.Milliseconds()), string(message))
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
